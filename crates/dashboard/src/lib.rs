//! HTTP backend for the mcpglass dashboard.
//!
//! Serves a small REST API over the [`storage`] crate's read side, plus the
//! embedded React frontend bundle (`frontend/dist`, built separately by
//! `pnpm build`). This is the read-only counterpart to the tap path in the
//! `cli` crate: [`serve`] normally opens a single [`Store`] up front and
//! shares it behind `Arc<Mutex<_>>`, since `rusqlite::Connection` is `Send`
//! but not `Sync` — a mutex is enough to hand it across the blocking pool.
//! The tap's writer runs in WAL mode, so this shared reader still sees new
//! rows as they land without needing its own connection per request.
//!
//! The one exception is a legacy Phase-0 (v0) db file: [`storage::Store::open`]
//! hands back an empty in-memory store for it rather than touching the file
//! (destructive migration is the writer's job). Caching that empty store would
//! pin the dashboard to "no data" until process restart even after the tap
//! writer migrates the file. So [`serve`] checks [`storage::is_legacy_v0`]
//! once up front and, only in that case, reopens a fresh `Store` per request
//! instead of caching — see [`StoreHandle`].

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, Query, Request, State};
use axum::http::header::{HOST, ORIGIN};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use proxy_core::Direction;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use storage::{
    InjectCounts, InjectEventRow, MessageDetail, MessageFilter, MessageRow, PruneStats,
    SecurityCounts, SecurityEventRow, SessionSummary, Stats, Store,
};

/// The built frontend, baked into the binary so `mcpglass dashboard` needs no
/// separate static-file directory at runtime.
#[derive(RustEmbed)]
#[folder = "frontend/dist"]
struct Assets;

/// Page size when `limit` is omitted from the query string.
const DEFAULT_LIMIT: u32 = 100;
/// Hard cap on `limit`, regardless of what the caller asks for.
const MAX_LIMIT: u32 = 1000;

/// How the shared state reaches a [`Store`] for a request. See the module
/// doc comment for why the legacy-v0 case can't share the cached path.
#[derive(Clone)]
enum StoreHandle {
    /// The common case: one `Store` opened at startup and shared behind a
    /// mutex, relying on WAL mode so the tap writer's new rows are visible
    /// without reopening.
    Cached(Arc<Mutex<Store>>),
    /// The db was a legacy v0 file when `serve` started. Every request
    /// reopens `Store::open`, which re-runs the v0 check each time — so a
    /// request placed after the tap writer has since migrated the file sees
    /// the migrated data instead of the startup-time empty store.
    PerRequest(PathBuf),
}

/// A successful replay's result, serialized to the dashboard client. Mirrors the
/// CLI's `replay::ReplayResult`; the binary maps one to the other in the [`ReplayFn`]
/// it injects (this crate does not depend on `cli`).
#[derive(Serialize)]
pub struct ReplayOutcome {
    pub transport: String,
    pub response_raw: Option<String>,
    pub note: String,
}

/// Why a replay failed, categorised so the handler can pick the right HTTP status.
pub enum ReplayError {
    /// The message isn't a replayable client->server request -> 400.
    NotReplayable(String),
    /// The exchange exceeded its time budget -> 504.
    Timeout,
    /// The reconstructed server couldn't be reached or driven -> 502.
    Upstream(String),
    /// A local failure (store, client setup, ...) -> 500.
    Internal(String),
}

/// The replay backend, injected by the binary. `dashboard` intentionally does not
/// depend on `cli`, so the actual `replay::run_replay` is wired in here as a boxed
/// async closure keyed by message id. `None` disables the endpoint (it answers 501) —
/// used by tests and any embedding that doesn't provide a replay implementation.
pub type ReplayFn = Arc<
    dyn Fn(i64) -> Pin<Box<dyn Future<Output = Result<ReplayOutcome, ReplayError>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
struct AppState {
    store: StoreHandle,
    replay: Option<ReplayFn>,
}

/// Bind `127.0.0.1:<port>` and serve the dashboard until the process exits.
///
/// `db_path` need not exist yet: [`Store::open`] creates it (and its schema)
/// on first access, so a fresh install just sees empty lists rather than an
/// error.
///
/// `on_ready` runs exactly once, after the listener has successfully bound,
/// with the actual local address (useful when `port == 0`). Callers that print
/// the dashboard URL or open a browser tab should do so from `on_ready` rather
/// than before calling `serve`, so a bind failure (e.g. the port already in
/// use) surfaces as an error instead of a browser tab pointed at the wrong
/// server.
/// `replay` is the optional replay backend (see [`ReplayFn`]); `None` makes the
/// `POST /api/messages/{id}/replay` endpoint answer `501 Not Implemented`.
pub async fn serve(
    db_path: PathBuf,
    port: u16,
    replay: Option<ReplayFn>,
    on_ready: impl FnOnce(SocketAddr),
) -> anyhow::Result<()> {
    // Decide before opening anything: once a legacy v0 file is migrated by
    // the tap writer, a cached handle from this check would never notice.
    let store_handle = if storage::is_legacy_v0(&db_path) {
        StoreHandle::PerRequest(db_path.clone())
    } else {
        let store = Store::open(&db_path)?;
        StoreHandle::Cached(Arc::new(Mutex::new(store)))
    };
    let state = AppState {
        store: store_handle,
        replay,
    };
    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/{id}", delete(delete_session))
        .route("/api/sessions/{id}/messages", get(session_messages))
        .route("/api/sessions/{id}/stats", get(session_stats))
        .route("/api/sessions/{id}/context", get(session_context))
        .route("/api/sessions/{id}/security", get(session_security))
        .route(
            "/api/sessions/{id}/security/counts",
            get(session_security_counts),
        )
        .route("/api/sessions/{id}/inject", get(session_inject))
        .route(
            "/api/sessions/{id}/inject/counts",
            get(session_inject_counts),
        )
        .route("/api/messages/{id}", get(message_detail))
        .route("/api/messages/{id}/replay", post(replay_message))
        .fallback(static_asset)
        .with_state(state)
        // DNS-rebinding / CSRF gate over *every* route (API and static alike). The
        // dashboard only binds loopback, but that alone doesn't stop a malicious web
        // page from driving side effects (e.g. `POST /api/messages/{id}/replay`) via a
        // rebound host or a no-preflight CORS request — see [`loopback_guard`]. Applied
        // as one layer rather than per-handler so any future route is covered by default.
        .layer(middleware::from_fn(loopback_guard));

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    on_ready(listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Get to a `Store` on a blocking thread and run `f` against it. Every
/// handler goes through this rather than touching a connection directly,
/// since rusqlite's `Connection` is `!Sync` — the cached branch's mutex
/// serialises access across the blocking pool; the per-request branch just
/// opens its own (see [`StoreHandle`]).
async fn run_blocking<T, F>(handle: StoreHandle, f: F) -> anyhow::Result<T>
where
    F: FnOnce(&Store) -> anyhow::Result<T> + Send + 'static,
    T: Send + 'static,
{
    let joined = tokio::task::spawn_blocking(move || match handle {
        StoreHandle::Cached(store) => {
            let guard = store
                .lock()
                .map_err(|_| anyhow::anyhow!("dashboard store lock poisoned"))?;
            f(&guard)
        }
        StoreHandle::PerRequest(db_path) => {
            let store = Store::open(&db_path)?;
            f(&store)
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!("blocking task panicked: {e}"))?;
    joined
}

/// Wraps handler failures as an HTTP response. Defaults to 500; use
/// [`AppError::bad_request`] for caller-input errors (e.g. an unparsable
/// `direction` filter).
struct AppError(anyhow::Error, StatusCode);

impl AppError {
    fn bad_request(msg: impl Into<String>) -> Self {
        AppError(anyhow::anyhow!(msg.into()), StatusCode::BAD_REQUEST)
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(err: E) -> Self {
        AppError(err.into(), StatusCode::INTERNAL_SERVER_ERROR)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.1, format!("{:#}", self.0)).into_response()
    }
}

#[derive(Serialize)]
struct HealthResponse {
    version: String,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        version: env!("CARGO_PKG_VERSION").to_owned(),
    })
}

#[derive(Serialize)]
struct SessionSummaryDto {
    id: i64,
    label: String,
    command: String,
    started_at_ms: i64,
    ended_at_ms: Option<i64>,
    message_count: u64,
    /// The MCP protocol version the server selected (or `null` when unobserved).
    protocol_version: Option<String>,
    /// The MCP protocol version the client proposed (or `null` when unobserved).
    client_protocol_version: Option<String>,
    /// How the version was observed: `"initialize"` | `"header"` | `null`.
    protocol_version_source: Option<String>,
}

impl From<SessionSummary> for SessionSummaryDto {
    fn from(s: SessionSummary) -> Self {
        Self {
            id: s.id,
            label: s.label,
            command: s.command,
            started_at_ms: s.started_at_ms,
            ended_at_ms: s.ended_at_ms,
            message_count: s.message_count,
            protocol_version: s.protocol_version,
            client_protocol_version: s.client_protocol_version,
            protocol_version_source: s.protocol_version_source,
        }
    }
}

#[derive(Serialize)]
struct SessionsResponse {
    sessions: Vec<SessionSummaryDto>,
}

async fn list_sessions(State(state): State<AppState>) -> Result<Json<SessionsResponse>, AppError> {
    let sessions = run_blocking(state.store.clone(), |store| store.list_sessions()).await?;
    Ok(Json(SessionsResponse {
        sessions: sessions.into_iter().map(SessionSummaryDto::from).collect(),
    }))
}

/// The row counts removed by a `DELETE /api/sessions/{id}`. Mirrors
/// [`storage::PruneStats`]; `tool_fingerprints` is intentionally never deleted (the
/// cross-session rug-pull baseline), so it does not appear here.
#[derive(Serialize)]
struct DeleteSessionResponse {
    sessions: u64,
    messages: u64,
    security_events: u64,
    inject_events: u64,
}

impl From<PruneStats> for DeleteSessionResponse {
    fn from(s: PruneStats) -> Self {
        Self {
            sessions: s.sessions,
            messages: s.messages,
            security_events: s.security_events,
            inject_events: s.inject_events,
        }
    }
}

/// `DELETE /api/sessions/{id}`: delete one session and all of its messages / security
/// events / inject events (keeping its tool fingerprints). A mutating endpoint, so —
/// like `replay` — it is covered by the loopback [`loopback_guard`] layer. An unknown
/// id answers `404`.
async fn delete_session(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
) -> Result<Response, AppError> {
    let removed = run_blocking(state.store.clone(), move |store| store.delete_session(id)).await?;
    match removed {
        Some(stats) => Ok(Json(DeleteSessionResponse::from(stats)).into_response()),
        None => Ok((StatusCode::NOT_FOUND, "session not found").into_response()),
    }
}

#[derive(Serialize)]
struct MessageRowDto {
    id: i64,
    ts_ms: i64,
    direction: String,
    method: Option<String>,
    rpc_id: Option<String>,
    is_valid_json: bool,
    is_error: bool,
    size: u64,
    preview: String,
}

impl From<MessageRow> for MessageRowDto {
    fn from(m: MessageRow) -> Self {
        Self {
            id: m.id,
            ts_ms: m.ts_ms,
            direction: m.direction.as_str().to_owned(),
            method: m.method,
            rpc_id: m.rpc_id,
            is_valid_json: m.is_valid_json,
            is_error: m.is_error,
            size: m.size,
            preview: m.preview,
        }
    }
}

#[derive(Serialize)]
struct MessagesResponse {
    total: u64,
    messages: Vec<MessageRowDto>,
}

#[derive(Deserialize)]
struct MessagesQuery {
    limit: Option<u32>,
    offset: Option<u32>,
    direction: Option<String>,
    method: Option<String>,
    q: Option<String>,
}

async fn session_messages(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
    Query(q): Query<MessagesQuery>,
) -> Result<Json<MessagesResponse>, AppError> {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let offset = q.offset.unwrap_or(0);
    let direction = match q.direction.as_deref() {
        Some(s) if !s.is_empty() => Some(
            s.parse::<Direction>()
                .map_err(|_| AppError::bad_request(format!("invalid direction {s:?}")))?,
        ),
        _ => None,
    };
    let filter = MessageFilter {
        direction,
        method: q.method.filter(|m| !m.is_empty()),
        q: q.q.filter(|s| !s.is_empty()),
        limit,
        offset,
    };
    let (total, rows) =
        run_blocking(state.store.clone(), move |store| store.messages(id, &filter)).await?;
    Ok(Json(MessagesResponse {
        total,
        messages: rows.into_iter().map(MessageRowDto::from).collect(),
    }))
}

#[derive(Serialize)]
struct MessageDetailDto {
    id: i64,
    session_id: i64,
    ts_ms: i64,
    direction: String,
    method: Option<String>,
    rpc_id: Option<String>,
    is_valid_json: bool,
    is_error: bool,
    size: u64,
    preview: String,
    raw: String,
    /// Original byte length when the frame was recorded metadata-only (`raw` is then
    /// `""`); `null` for a full recording. Lets the UI show "metadata-only, body not
    /// recorded" instead of an empty body.
    raw_len: Option<i64>,
}

impl From<MessageDetail> for MessageDetailDto {
    fn from(m: MessageDetail) -> Self {
        Self {
            id: m.id,
            session_id: m.session_id,
            ts_ms: m.ts_ms,
            direction: m.direction.as_str().to_owned(),
            method: m.method,
            rpc_id: m.rpc_id,
            is_valid_json: m.is_valid_json,
            is_error: m.is_error,
            size: m.size,
            preview: m.preview,
            raw: m.raw,
            raw_len: m.raw_len,
        }
    }
}

async fn message_detail(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
) -> Result<Response, AppError> {
    let detail = run_blocking(state.store.clone(), move |store| store.message(id)).await?;
    match detail {
        Some(d) => Ok(Json(MessageDetailDto::from(d)).into_response()),
        None => Ok((StatusCode::NOT_FOUND, "message not found").into_response()),
    }
}

/// `POST /api/messages/{id}/replay`: re-send the recorded request to its server via
/// the injected [`ReplayFn`]. Off-band and never recorded (the backend guarantees
/// that). Absent backend -> 501; otherwise the [`ReplayError`] category picks the
/// status (400 unreplayable / 504 timeout / 502 upstream / 500 internal). The plain
/// error text is returned as the body so the UI can show what went wrong.
async fn replay_message(State(state): State<AppState>, AxumPath(id): AxumPath<i64>) -> Response {
    let Some(replay) = state.replay.clone() else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "replay is not available in this build",
        )
            .into_response();
    };
    match replay(id).await {
        Ok(outcome) => Json(outcome).into_response(),
        Err(ReplayError::NotReplayable(m)) => (StatusCode::BAD_REQUEST, m).into_response(),
        Err(ReplayError::Timeout) => {
            (StatusCode::GATEWAY_TIMEOUT, "replay timed out").into_response()
        }
        Err(ReplayError::Upstream(m)) => (StatusCode::BAD_GATEWAY, m).into_response(),
        Err(ReplayError::Internal(m)) => (StatusCode::INTERNAL_SERVER_ERROR, m).into_response(),
    }
}

#[derive(Serialize)]
struct MethodStatDto {
    method: String,
    count: u64,
    avg_latency_ms: Option<f64>,
    max_latency_ms: Option<i64>,
}

#[derive(Serialize)]
struct TotalsDto {
    messages: u64,
    invalid: u64,
    errors: u64,
}

#[derive(Serialize)]
struct StatsDto {
    per_method: Vec<MethodStatDto>,
    totals: TotalsDto,
}

impl From<Stats> for StatsDto {
    fn from(s: Stats) -> Self {
        Self {
            per_method: s
                .per_method
                .into_iter()
                .map(|m| MethodStatDto {
                    method: m.method,
                    count: m.count,
                    avg_latency_ms: m.avg_latency_ms,
                    max_latency_ms: m.max_latency_ms,
                })
                .collect(),
            totals: TotalsDto {
                messages: s.totals.messages,
                invalid: s.totals.invalid,
                errors: s.totals.errors,
            },
        }
    }
}

async fn session_stats(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
) -> Result<Json<StatsDto>, AppError> {
    let stats = run_blocking(state.store.clone(), move |store| store.stats(id)).await?;
    Ok(Json(StatsDto::from(stats)))
}

/// One tool's share of a session's estimated context cost. `pct` is
/// `est_tokens / est_total_tokens * 100` (0 when the total is 0).
#[derive(Serialize)]
struct ToolBloatDto {
    name: String,
    total_chars: usize,
    est_tokens: usize,
    description_tokens: usize,
    pct: f64,
}

/// Context-bloat analysis for a session's most recently captured `tools/list`
/// response. `approximate` is always `true`: every count here is the
/// zero-dependency chars/4 heuristic in `proxy_core::bloat`, never a real
/// tokenizer. A session with no captured `tools/list` (or an unparsable one)
/// answers with the zeroed empty shape rather than an error.
#[derive(Serialize)]
struct ContextResponse {
    approximate: bool,
    tool_count: usize,
    total_chars: usize,
    est_total_tokens: usize,
    /// Sorted heaviest-first, mirroring `proxy_core::bloat::BloatReport`.
    tools: Vec<ToolBloatDto>,
    fat_tools: Vec<String>,
}

fn empty_context_response() -> ContextResponse {
    ContextResponse {
        approximate: true,
        tool_count: 0,
        total_chars: 0,
        est_total_tokens: 0,
        tools: Vec::new(),
        fat_tools: Vec::new(),
    }
}

async fn session_context(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
) -> Result<Json<ContextResponse>, AppError> {
    let raw =
        run_blocking(state.store.clone(), move |store| store.latest_tools_list_raw(id)).await?;
    let Some(raw) = raw else {
        return Ok(Json(empty_context_response()));
    };
    // A recorded frame that fails to parse (shouldn't happen for a frame the
    // tap itself validated as a tools/list round-trip) degrades to the empty
    // shape rather than a 500 — this endpoint is read-only analysis, not a
    // integrity check on the store.
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return Ok(Json(empty_context_response()));
    };
    let Some(report) = proxy_core::bloat::analyze_tools_list_response(&value) else {
        return Ok(Json(empty_context_response()));
    };

    let est_total = report.est_total_tokens;
    let tools = report
        .tools
        .into_iter()
        .map(|t| {
            let pct = if est_total > 0 {
                (t.est_tokens as f64 / est_total as f64) * 100.0
            } else {
                0.0
            };
            ToolBloatDto {
                name: t.name,
                total_chars: t.total_chars,
                est_tokens: t.est_tokens,
                description_tokens: t.description_tokens,
                pct,
            }
        })
        .collect();

    Ok(Json(ContextResponse {
        approximate: true,
        tool_count: report.tool_count,
        total_chars: report.total_chars,
        est_total_tokens: est_total,
        tools,
        fat_tools: report.fat_tools,
    }))
}

#[derive(Serialize)]
struct SecurityEventDto {
    id: i64,
    ts_ms: i64,
    kind: String,
    rule: String,
    detail: String,
    tool_name: Option<String>,
    rpc_id: Option<String>,
    action_taken: String,
}

impl From<SecurityEventRow> for SecurityEventDto {
    fn from(e: SecurityEventRow) -> Self {
        Self {
            id: e.id,
            ts_ms: e.ts_ms,
            kind: e.kind.as_str().to_owned(),
            rule: e.rule,
            detail: e.detail,
            tool_name: e.tool_name,
            rpc_id: e.rpc_id,
            action_taken: e.action_taken.as_str().to_owned(),
        }
    }
}

#[derive(Serialize)]
struct SecurityEventsResponse {
    total: u64,
    events: Vec<SecurityEventDto>,
}

#[derive(Deserialize)]
struct SecurityEventsQuery {
    limit: Option<u32>,
    offset: Option<u32>,
}

async fn session_security(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
    Query(q): Query<SecurityEventsQuery>,
) -> Result<Json<SecurityEventsResponse>, AppError> {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let offset = q.offset.unwrap_or(0);
    let (total, rows) = run_blocking(state.store.clone(), move |store| {
        store.security_events(id, limit, offset)
    })
    .await?;
    Ok(Json(SecurityEventsResponse {
        total,
        events: rows.into_iter().map(SecurityEventDto::from).collect(),
    }))
}

#[derive(Serialize)]
struct SecurityCountsDto {
    policy_deny: u64,
    secret_leak: u64,
    fingerprint_change: u64,
    blocked: u64,
}

impl From<SecurityCounts> for SecurityCountsDto {
    fn from(c: SecurityCounts) -> Self {
        Self {
            policy_deny: c.policy_deny,
            secret_leak: c.secret_leak,
            fingerprint_change: c.fingerprint_change,
            blocked: c.blocked,
        }
    }
}

async fn session_security_counts(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
) -> Result<Json<SecurityCountsDto>, AppError> {
    let counts =
        run_blocking(state.store.clone(), move |store| store.security_event_counts(id)).await?;
    Ok(Json(SecurityCountsDto::from(counts)))
}

#[derive(Serialize)]
struct InjectEventDto {
    id: i64,
    ts_ms: i64,
    direction: String,
    rule: String,
    fault: String,
    detail: String,
    method: Option<String>,
    rpc_id: Option<String>,
}

impl From<InjectEventRow> for InjectEventDto {
    fn from(e: InjectEventRow) -> Self {
        Self {
            id: e.id,
            ts_ms: e.ts_ms,
            direction: e.direction.as_str().to_owned(),
            rule: e.rule,
            fault: e.fault.as_str().to_owned(),
            detail: e.detail,
            method: e.method,
            rpc_id: e.rpc_id,
        }
    }
}

#[derive(Serialize)]
struct InjectEventsResponse {
    total: u64,
    events: Vec<InjectEventDto>,
}

#[derive(Deserialize)]
struct InjectEventsQuery {
    limit: Option<u32>,
    offset: Option<u32>,
}

async fn session_inject(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
    Query(q): Query<InjectEventsQuery>,
) -> Result<Json<InjectEventsResponse>, AppError> {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let offset = q.offset.unwrap_or(0);
    let (total, rows) = run_blocking(state.store.clone(), move |store| {
        store.inject_events(id, limit, offset)
    })
    .await?;
    Ok(Json(InjectEventsResponse {
        total,
        events: rows.into_iter().map(InjectEventDto::from).collect(),
    }))
}

#[derive(Serialize)]
struct InjectCountsDto {
    delay: u64,
    error: u64,
    drop: u64,
    truncate: u64,
}

impl From<InjectCounts> for InjectCountsDto {
    fn from(c: InjectCounts) -> Self {
        Self {
            delay: c.delay,
            error: c.error,
            drop: c.drop,
            truncate: c.truncate,
        }
    }
}

async fn session_inject_counts(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
) -> Result<Json<InjectCountsDto>, AppError> {
    let counts =
        run_blocking(state.store.clone(), move |store| store.inject_event_counts(id)).await?;
    Ok(Json(InjectCountsDto::from(counts)))
}

/// Serve an embedded frontend asset by request path, falling back to
/// `index.html` for both the SPA root and any client-side route (anything not
/// found verbatim in the bundle).
async fn static_asset(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    if let Some(content) = Assets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return ([(header::CONTENT_TYPE, mime.as_ref())], content.data.to_vec()).into_response();
    }
    match Assets::get("index.html") {
        Some(content) => (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            content.data.to_vec(),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "dashboard assets not found (frontend not built)",
        )
            .into_response(),
    }
}

/// Middleware: reject a request whose `Origin`/`Host` headers don't look loopback,
/// answering `403` before it reaches any handler. The dashboard binds `127.0.0.1`
/// only, but that doesn't stop a DNS-rebinding attack (a page on an attacker domain
/// that resolves to 127.0.0.1) or a plain no-preflight CORS request from a malicious
/// site reaching this port and triggering side effects like `replay`. This is the
/// dashboard's own copy of the gate the `cli` gateway applies to its reverse proxy —
/// duplicated deliberately, since `dashboard` doesn't depend on `cli`.
async fn loopback_guard(req: Request, next: Next) -> Response {
    if request_allowed(req.headers()) {
        next.run(req).await
    } else {
        (StatusCode::FORBIDDEN, "forbidden: non-loopback origin/host").into_response()
    }
}

/// Both the `Origin` check (for browser clients that send one) and the `Host` check
/// (which closes the gap for a same-origin request carrying no `Origin`) must pass.
fn request_allowed(headers: &HeaderMap) -> bool {
    origin_allowed(headers) && host_allowed(headers)
}

/// Origin gate against DNS-rebinding. A missing `Origin` (typical of non-browser
/// clients, and of curl / same-origin navigations) is allowed; otherwise only a
/// loopback origin passes.
fn origin_allowed(headers: &HeaderMap) -> bool {
    match headers.get(ORIGIN) {
        None => true,
        Some(v) => v.to_str().map(is_localhost_origin).unwrap_or(false),
    }
}

/// Host gate against DNS-rebinding: a browser rebound to an attacker domain resolving
/// to 127.0.0.1 sends a same-origin request with *no* `Origin` header but a `Host`
/// naming the attacker's domain, which `origin_allowed`'s pass-when-absent rule can't
/// catch. `Host` is mandatory on every HTTP/1.1+ request, so a missing or unparsable
/// one is rejected rather than allowed.
fn host_allowed(headers: &HeaderMap) -> bool {
    match headers.get(HOST) {
        None => false,
        Some(v) => v.to_str().map(is_localhost_host).unwrap_or(false),
    }
}

/// True when an `Origin` value's host is loopback (`localhost`, `127.0.0.1`, `::1`),
/// ignoring scheme and port. Anything else (including `null`) is rejected.
fn is_localhost_origin(origin: &str) -> bool {
    let rest = origin.split_once("://").map(|(_, r)| r).unwrap_or(origin);
    matches!(extract_host(rest), "localhost" | "127.0.0.1" | "::1")
}

/// True when a `Host` header's host part is loopback, ignoring port. Same loopback set
/// as [`is_localhost_origin`], just without a scheme to strip first.
fn is_localhost_host(host: &str) -> bool {
    matches!(extract_host(host), "localhost" | "127.0.0.1" | "::1")
}

/// Pull the bare host out of a `host[:port]` or IPv6-literal `[addr]:port` string (no
/// scheme prefix). Shared by the `Origin` and `Host` gates, which differ only in that
/// `Origin` has a `scheme://` prefix to strip before this.
fn extract_host(rest: &str) -> &str {
    if let Some(stripped) = rest.strip_prefix('[') {
        // IPv6 literal: `[::1]:port` -> take up to ']'.
        stripped.split(']').next().unwrap_or("")
    } else {
        rest.split(['/', ':']).next().unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with_origin(origin: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(ORIGIN, HeaderValue::from_str(origin).unwrap());
        // A valid loopback Host so these cases isolate the Origin check.
        h.insert(HOST, HeaderValue::from_static("127.0.0.1:8080"));
        h
    }

    fn headers_with_host(host: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(HOST, HeaderValue::from_str(host).unwrap());
        h
    }

    #[test]
    fn missing_origin_is_allowed_but_missing_host_is_not() {
        // No Origin + loopback Host: the common non-browser / same-origin case.
        assert!(request_allowed(&headers_with_host("127.0.0.1:8080")));
        // No headers at all: Host absent -> rejected.
        assert!(!request_allowed(&HeaderMap::new()));
    }

    #[test]
    fn loopback_origins_pass_others_rejected() {
        for ok in ["http://localhost", "http://127.0.0.1:8080", "http://[::1]:9000"] {
            assert!(request_allowed(&headers_with_origin(ok)), "{ok} should pass");
        }
        for bad in ["http://evil.example", "https://attacker.com:80", "null"] {
            assert!(!request_allowed(&headers_with_origin(bad)), "{bad} should be rejected");
        }
    }

    #[test]
    fn non_loopback_host_rejected() {
        assert!(request_allowed(&headers_with_host("localhost:1234")));
        assert!(!request_allowed(&headers_with_host("evil.example")));
        assert!(!request_allowed(&headers_with_host("evil.example:80")));
    }
}
