//! HTTP backend for the mcpglass dashboard.
//!
//! Serves a small REST API over the [`storage`] crate's read side, plus the
//! embedded React frontend bundle (`frontend/dist`, built separately by
//! `pnpm build`). This is the read-only counterpart to the tap path in the
//! `cli` crate: every request opens its own [`Store`] rather than sharing one,
//! because `rusqlite::Connection` is not `Sync` and the tap's writer already
//! runs in WAL mode so a concurrent reader never blocks it.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use proxy_core::Direction;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use storage::{
    MessageDetail, MessageFilter, MessageRow, SecurityCounts, SecurityEventRow, SessionSummary,
    Stats, Store,
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

#[derive(Clone)]
struct AppState {
    db_path: PathBuf,
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
pub async fn serve(
    db_path: PathBuf,
    port: u16,
    on_ready: impl FnOnce(SocketAddr),
) -> anyhow::Result<()> {
    let state = AppState { db_path };
    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/{id}/messages", get(session_messages))
        .route("/api/sessions/{id}/stats", get(session_stats))
        .route("/api/sessions/{id}/security", get(session_security))
        .route(
            "/api/sessions/{id}/security/counts",
            get(session_security_counts),
        )
        .route("/api/messages/{id}", get(message_detail))
        .fallback(static_asset)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    on_ready(listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Open a fresh `Store` on a blocking thread and run `f` against it. Every
/// handler goes through this rather than holding a shared connection, since
/// rusqlite's `Connection` is `!Sync`.
async fn run_blocking<T, F>(db_path: PathBuf, f: F) -> anyhow::Result<T>
where
    F: FnOnce(&Store) -> anyhow::Result<T> + Send + 'static,
    T: Send + 'static,
{
    let joined = tokio::task::spawn_blocking(move || {
        let store = Store::open(&db_path)?;
        f(&store)
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
        }
    }
}

#[derive(Serialize)]
struct SessionsResponse {
    sessions: Vec<SessionSummaryDto>,
}

async fn list_sessions(State(state): State<AppState>) -> Result<Json<SessionsResponse>, AppError> {
    let sessions = run_blocking(state.db_path, |store| store.list_sessions()).await?;
    Ok(Json(SessionsResponse {
        sessions: sessions.into_iter().map(SessionSummaryDto::from).collect(),
    }))
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
        run_blocking(state.db_path, move |store| store.messages(id, &filter)).await?;
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
        }
    }
}

async fn message_detail(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
) -> Result<Response, AppError> {
    let detail = run_blocking(state.db_path, move |store| store.message(id)).await?;
    match detail {
        Some(d) => Ok(Json(MessageDetailDto::from(d)).into_response()),
        None => Ok((StatusCode::NOT_FOUND, "message not found").into_response()),
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
    let stats = run_blocking(state.db_path, move |store| store.stats(id)).await?;
    Ok(Json(StatsDto::from(stats)))
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
    let (total, rows) = run_blocking(state.db_path, move |store| {
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
        run_blocking(state.db_path, move |store| store.security_event_counts(id)).await?;
    Ok(Json(SecurityCountsDto::from(counts)))
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
