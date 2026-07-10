//! `mcpglass gateway`: a localhost reverse proxy for url-type (Streamable HTTP)
//! MCP servers.
//!
//! A url-type MCP server is normally a *direct* HTTP connection from the client,
//! so — unlike stdio — there is nothing for mcpglass to sit inside. `attach`
//! instead repoints each client at `http://127.0.0.1:<port>/u/<name>` and records
//! the real endpoint in `gateway.toml`; this long-running server forwards each
//! request to the recorded upstream while tapping the traffic into the same
//! session store the stdio `wrap` path uses.
//!
//! The fail-open contract from `wrap` carries over verbatim: the proxy's own tap /
//! parse / policy machinery may never change, delay, or interrupt bytes already in
//! flight to or from the wire. Concretely:
//! * client -> server (`POST` body) is a synchronous, blockable decision
//!   ([`security::decide_c2s_frame`]) — the only leg that can withhold a message;
//! * server -> client (the HTTP response, incl. SSE streams) is a pure side-channel
//!   tap: bytes are forwarded untouched and only a *copy* is recorded;
//! * an upstream that can't be reached yields an honest `502` (plain text), never a
//!   synthesized JSON-RPC message;
//! * recording always happens *after* the wire action, via non-blocking `try_send`.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Path as AxumPath, State};
use axum::http::header::{CONNECTION, CONTENT_TYPE, HOST, ORIGIN};
use axum::http::{HeaderMap, HeaderName, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use policy::{Fault, InjectDirection, InjectHit, Mode, Policy, ServerIdentity};
use proxy_core::{Direction, SseSplitter};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

use storage::{InjectEvent, SecurityEvent, Store};

use crate::gateway_config::{self, GatewayConfig};
use crate::security::{Decision, FrameAction};
use crate::tap::{now_ms, storage_loop, Logger, RecordMode, StorageMsg, TapEvent};
use crate::{fault_kind, inject_decide, log_drop_once, EXIT_POLICY_CONFIG, SharedInjector};

/// Fail-open buffering ceiling, shared by both legs. On the c2s leg, a monitor-mode
/// POST body up to the frame cap is inspected; a larger one is uninspectable and
/// forwarded verbatim (fail-open), but buffering is still bounded so a hostile
/// client can't exhaust memory (enforce mode never reaches this — it caps at the
/// frame size and refuses the rest with 413). On the s2c leg (see
/// [`relay_response`]), a non-SSE response body is buffered and tapped as one frame
/// up to this ceiling; past it the response is uninspectable and switches to an
/// untapped passthrough stream rather than buffering further.
const MAX_BUFFER_BYTES: usize = 256 * 1024 * 1024;

/// Per-upstream routing state: where to forward, the storage session channel, and
/// a one-shot latch so a stalled tap logs its first drop only (see [`log_drop_once`]).
struct Upstream {
    url: String,
    tx: mpsc::Sender<StorageMsg>,
    drop_logged: Arc<AtomicBool>,
    /// One-shot latch: a single delivered `ProtocolHint` is all the storage thread
    /// can ever use (it records the header source at most once per session), so
    /// stop enqueueing hints after the first success instead of competing with
    /// tapped frames for channel capacity on every request.
    hint_sent: Arc<AtomicBool>,
}

#[derive(Clone)]
struct GatewayState {
    client: reqwest::Client,
    policy: Arc<Policy>,
    upstreams: Arc<HashMap<String, Upstream>>,
    logger: Logger,
    /// Frame/inspection cap: a POST body at or under this is inspected; above it is
    /// uninspectable (matches the stdio oversized-frame boundary).
    frame_cap: usize,
    /// Optional fault injector, shared across every route so its counters/RNG
    /// advance in lock-step (`None` unless `--inject` was given). See [`SharedInjector`].
    injector: SharedInjector,
    /// How much of each frame to record (`--record`). `Off` skips every tap; the
    /// per-upstream `storage_loop` applies the `Metadata`/`Full` body difference.
    record: RecordMode,
}

/// Resolve configuration and run the gateway until the process is killed. Returns a
/// process exit code (nonzero only on a startup/bind failure).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    port: u16,
    db: Option<PathBuf>,
    log: Option<PathBuf>,
    policy_path: Option<PathBuf>,
    enforce: bool,
    inject: Option<PathBuf>,
    upstreams_arg: Vec<(String, String)>,
    record: RecordMode,
) -> i32 {
    let data_dir = crate::default_data_dir();
    let log_path = log.or_else(|| data_dir.as_ref().map(|d| d.join("mcpglass.log")));
    let db_path = db
        .or_else(|| data_dir.as_ref().map(|d| d.join("sessions.db")))
        .unwrap_or_else(|| std::env::temp_dir().join("mcpglass").join("sessions.db"));
    let logger = Logger::open(log_path.as_deref());

    // Resolve the security policy BEFORE binding: a malformed security config must
    // fail loud (stderr + nonzero exit), never silently fall open. Safe here because
    // no byte has been forwarded yet — the one legitimate abort point.
    let default_policy_path = data_dir.as_ref().map(|d| d.join("policy.toml"));
    let policy = match crate::security::resolve_policy(policy_path.as_deref(), default_policy_path, enforce)
    {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!("mcpglass: {e}");
            logger.error(format!("policy load failed; aborting before binding: {e}"));
            return EXIT_POLICY_CONFIG;
        }
    };
    logger.info(format!("gateway policy mode={:?}", policy.mode));

    // Fault injection: opt-in, resolved before binding (a broken config aborts while
    // it is still safe — no byte forwarded yet). Reuses the `wrap` resolver so the
    // config format and abort behaviour are identical across transports.
    let injector = match crate::resolve_injector(inject.as_deref(), &logger) {
        Ok(i) => i,
        Err(code) => return code,
    };

    // Upstreams: explicit `--upstream name=url` wins; otherwise read gateway.toml.
    let upstreams: Vec<(String, String)> = if !upstreams_arg.is_empty() {
        upstreams_arg
    } else {
        gateway_config::default_config_path()
            .map(|p| GatewayConfig::load_or_default(&p))
            .unwrap_or_default()
            .servers
            .into_iter()
            .collect()
    };
    if upstreams.is_empty() {
        // Not fatal: bind anyway so the port is live and every request returns an
        // honest 404, but make the misconfiguration visible.
        logger.error("gateway has no upstreams (no --upstream and empty/absent gateway.toml)");
        eprintln!("mcpglass: gateway has no upstreams to route (see gateway.toml or --upstream)");
    }

    let frame_cap = crate::max_line_bytes();
    let result = serve(
        db_path,
        port,
        policy,
        upstreams,
        logger.clone(),
        frame_cap,
        injector,
        record,
        |addr| {
            println!("Gateway listening on http://{addr}  (routes: POST|GET|DELETE /u/<name>)");
        },
    )
    .await;

    match result {
        Ok(()) => 0,
        Err(e) => {
            logger.error(format!("gateway error: {e:#}"));
            eprintln!("mcpglass: gateway error: {e:#}");
            1
        }
    }
}

/// Build the storage sessions and the axum server, bind `127.0.0.1:<port>`, and
/// serve until an error (or forever). `on_ready` fires once with the bound address
/// after a successful bind (mirrors `dashboard::serve`, so callers print the URL
/// only when it's really listening).
#[allow(clippy::too_many_arguments)]
async fn serve(
    db_path: PathBuf,
    port: u16,
    policy: Arc<Policy>,
    upstreams: Vec<(String, String)>,
    logger: Logger,
    frame_cap: usize,
    injector: SharedInjector,
    record: RecordMode,
    on_ready: impl FnOnce(SocketAddr),
) -> anyhow::Result<()> {
    // Create the schema once, up front, so the per-upstream writer connections
    // below all open an already-current db and skip schema creation. Without this a
    // fresh db would have several writers racing to CREATE the tables at once —
    // a read->write promotion that `busy_timeout` can't untangle, so a loser would
    // fail to open and silently drop its whole session. Best-effort: a failure here
    // is logged, and each `storage_loop` still tries to open on its own.
    if let Err(e) = Store::open_with_log(&db_path, &|m| logger.info(m)) {
        logger.error(format!("gateway: initial db open failed: {e:#}"));
    }

    // One storage session per upstream, each on its own blocking thread — exactly
    // like `wrap`, so the fingerprint / correlation pipeline is reused unchanged
    // (label = name, command = url, and the url is the stable server_key).
    let mut map = HashMap::new();
    for (name, url) in upstreams {
        let (tx, rx) = mpsc::channel::<StorageMsg>(8192);
        let db_path = db_path.clone();
        let logger = logger.clone();
        let label = name.clone();
        let command_line = url.clone();
        // The structured HTTP identity (schema v7): the upstream URL verbatim. It is
        // also the legacy scope key (`command_line`), so an existing fingerprint
        // baseline survives the upgrade.
        let identity = ServerIdentity::Http { url: url.clone() };
        tokio::task::spawn_blocking(move || {
            storage_loop(rx, db_path, logger, label, command_line, identity, record);
        });
        map.insert(
            name,
            Upstream {
                url,
                tx,
                drop_logged: Arc::new(AtomicBool::new(false)),
                hint_sent: Arc::new(AtomicBool::new(false)),
            },
        );
    }

    // No automatic redirect following: a 3xx from the upstream is passed straight
    // through to the client so the gateway stays transparent.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building the gateway HTTP client")?;

    let state = GatewayState {
        client,
        policy,
        upstreams: Arc::new(map),
        logger,
        frame_cap,
        injector,
        record,
    };

    let app = Router::new()
        .route(
            "/u/{name}",
            post(handle_post).get(handle_get).delete(handle_delete),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .with_context(|| format!("binding 127.0.0.1:{port}"))?;
    on_ready(listener.local_addr()?);
    axum::serve(listener, app).await.context("serving the gateway")?;
    Ok(())
}

/// `POST /u/{name}`: the client->server leg. Origin-gated, size-checked, decided,
/// then forwarded to the upstream (or answered in-protocol when blocked).
async fn handle_post(
    State(state): State<GatewayState>,
    AxumPath(name): AxumPath<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if !request_allowed(&headers) {
        return (StatusCode::FORBIDDEN, "origin/host not allowed").into_response();
    }
    let Some(up) = state.upstreams.get(&name) else {
        return (StatusCode::NOT_FOUND, "unknown upstream").into_response();
    };
    // Passive protocol-version observation: after the initialize handshake the client
    // MUST carry `MCP-Protocol-Version` on every request. Forward it to the storage
    // thread as a best-effort hint (recorded only when no `initialize` version is
    // known yet). Never gates the wire — a full/closed channel just drops it.
    hint_protocol_version(up, &headers);
    let cap = state.frame_cap;
    let enforce = state.policy.mode == Mode::Enforce;

    // Read the body. Enforce caps at the inspection limit (an uninspectable body is
    // refused); monitor allows a much larger fail-open ceiling so it can still be
    // forwarded. Exceeding the applicable limit -> 413.
    let read_limit = if enforce { cap } else { MAX_BUFFER_BYTES };
    let bytes = match to_bytes(body, read_limit).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response(),
    };
    let url = up.url.clone();

    // Oversized-but-under-ceiling (only reachable in monitor): uninspectable, so
    // fail-open forward verbatim — no decision, no c2s tap — mirroring the stdio
    // oversized-frame handling.
    if bytes.len() > cap {
        return match send_upstream(&state, Method::POST, url, &headers, Some(bytes)).await {
            Ok(resp) => relay_response(&state, up, resp).await,
            Err(resp) => resp,
        };
    }

    // Inspectable frame. `decide_c2s_frame` is pure and infallible today, but this
    // is a security-critical hot path: catch a hypothetical future panic and
    // fail open (forward, no event) so one bad frame can't wedge the gateway.
    let ts = now_ms();
    let decision = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::security::decide_c2s_frame(&bytes, &state.policy, ts)
    })) {
        Ok(d) => d,
        Err(_) => {
            state
                .logger
                .error("gateway: c2s decision panicked; forwarding (fail-open)");
            Decision {
                action: FrameAction::Forward,
                events: Vec::new(),
            }
        }
    };

    match decision.action {
        FrameAction::Forward => {
            // Injection layer: only policy-cleared (Forward) frames are eligible,
            // and only when `--inject` is active. A hit hands the whole wire action
            // (delay / drop / synthesized error / truncate) to `inject_c2s_gateway`.
            let inj_hit = if state.injector.is_some() {
                let (method, id_value, rpc_id) = crate::parse_for_injection(&bytes);
                inject_decide(&state.injector, InjectDirection::C2s, method.as_deref())
                    .map(|hit| (hit, method, id_value, rpc_id))
            } else {
                None
            };
            if let Some((hit, method, id_value, rpc_id)) = inj_hit {
                return inject_c2s_gateway(
                    &state, up, bytes, url, &headers, hit, method, id_value, rpc_id, ts,
                    decision.events,
                )
                .await;
            }

            match send_upstream(&state, Method::POST, url, &headers, Some(bytes.clone())).await {
                Ok(resp) => {
                    // Request wire action done. Record the request (and its events)
                    // *before* relaying the response, so the c2s frame is drained
                    // ahead of the s2c response — fingerprint correlation needs the
                    // tools/list request seen first, even when the response is a
                    // single buffered `application/json` body. `try_send` never
                    // gates the wire, so this ordering stays fail-open.
                    tap_frame(up, &state.logger, state.record, Direction::C2s, ts, bytes.to_vec());
                    emit_events(up, &state.logger, decision.events);
                    relay_response(&state, up, resp).await
                }
                Err(resp) => {
                    // Upstream unreachable (502): still record the attempted request.
                    tap_frame(up, &state.logger, state.record, Direction::C2s, ts, bytes.to_vec());
                    emit_events(up, &state.logger, decision.events);
                    resp
                }
            }
        }
        FrameAction::BlockWithResponse(resp) => {
            // In-protocol JSON-RPC error for a blocked request. The stdio synthesizer
            // appends a framing '\n'; an application/json HTTP body carries none.
            let body = resp.strip_suffix(b"\n").unwrap_or(&resp).to_vec();
            let response = (StatusCode::OK, [(CONTENT_TYPE, "application/json")], body).into_response();
            tap_frame(up, &state.logger, state.record, Direction::C2s, ts, bytes.to_vec());
            emit_events(up, &state.logger, decision.events);
            response
        }
        FrameAction::BlockSilent => {
            // A blocked notification / id-less request: the Streamable HTTP transport
            // acknowledges a non-request with 202 Accepted and no body.
            let response = StatusCode::ACCEPTED.into_response();
            tap_frame(up, &state.logger, state.record, Direction::C2s, ts, bytes.to_vec());
            emit_events(up, &state.logger, decision.events);
            response
        }
    }
}

/// `GET /u/{name}`: open the server->client SSE stream. Pure pass-through with a
/// side-channel tap of each completed SSE event (`Last-Event-ID`, `Accept`, etc.
/// are forwarded verbatim by [`filter_request_headers`]).
async fn handle_get(
    State(state): State<GatewayState>,
    AxumPath(name): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if !request_allowed(&headers) {
        return (StatusCode::FORBIDDEN, "origin/host not allowed").into_response();
    }
    let Some(up) = state.upstreams.get(&name) else {
        return (StatusCode::NOT_FOUND, "unknown upstream").into_response();
    };
    let url = up.url.clone();
    match send_upstream(&state, Method::GET, url, &headers, None).await {
        Ok(resp) => relay_response(&state, up, resp).await,
        Err(resp) => resp,
    }
}

/// `DELETE /u/{name}`: session termination. Pure pass-through.
async fn handle_delete(
    State(state): State<GatewayState>,
    AxumPath(name): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if !request_allowed(&headers) {
        return (StatusCode::FORBIDDEN, "origin/host not allowed").into_response();
    }
    let Some(up) = state.upstreams.get(&name) else {
        return (StatusCode::NOT_FOUND, "unknown upstream").into_response();
    };
    let url = up.url.clone();
    match send_upstream(&state, Method::DELETE, url, &headers, None).await {
        Ok(resp) => relay_response(&state, up, resp).await,
        Err(resp) => resp,
    }
}

/// Forward the request to the recorded upstream. `Ok` is the upstream response;
/// `Err` is an honest `502` response (never a synthesized JSON-RPC body) for an
/// upstream we couldn't reach. This is the *request* wire action, kept separate
/// from [`relay_response`] so the caller can record the c2s frame in between.
async fn send_upstream(
    state: &GatewayState,
    method: Method,
    url: String,
    req_headers: &HeaderMap,
    body: Option<Bytes>,
) -> Result<reqwest::Response, Response> {
    let mut rb = state
        .client
        .request(method, &url)
        .headers(filter_request_headers(req_headers));
    if let Some(b) = body {
        rb = rb.body(b);
    }
    match rb.send().await {
        Ok(r) => Ok(r),
        Err(e) => {
            state
                .logger
                .error(format!("gateway: upstream request to {url} failed: {e}"));
            Err((StatusCode::BAD_GATEWAY, "upstream request failed").into_response())
        }
    }
}

/// Adapt an upstream response for the client (the *response* wire action). An
/// `application/json` body is buffered up to [`MAX_BUFFER_BYTES`], forwarded, then
/// tapped as a single s2c frame — past that ceiling it switches to an untapped
/// passthrough (see below); a `text/event-stream` body is streamed through chunk by
/// chunk with a copy fed to an [`SseSplitter`] so each completed event is tapped.
async fn relay_response(state: &GatewayState, up: &Upstream, resp: reqwest::Response) -> Response {
    let status = resp.status();
    let up_headers = resp.headers().clone();
    let is_sse = up_headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|c| c.trim_start().to_ascii_lowercase().starts_with("text/event-stream"))
        .unwrap_or(false);

    // Rebuild the client response: same status, upstream headers minus hop-by-hop
    // (fixed list plus anything the upstream's own `Connection` header names —
    // Mcp-Session-Id, Content-Type, etc. pass straight through).
    let named = connection_named_headers(&up_headers);
    let mut builder = Response::builder().status(status);
    for (k, v) in up_headers.iter() {
        if is_hop_by_hop(k) || named.contains(k.as_str()) {
            continue;
        }
        builder = builder.header(k, v);
    }

    if is_sse {
        // NOTE: SSE streams are deliberately *not* fault-injected in v1. Injection
        // operates on a whole buffered frame; an SSE body is an open-ended stream of
        // events with no single frame to delay/replace/truncate coherently. The
        // buffered `application/json` branch below is the one that consults the
        // injector. (Documented as a v1 limitation.)
        let tx = up.tx.clone();
        let logger = state.logger.clone();
        let latch = up.drop_logged.clone();
        // `--record off` streams the SSE response straight through with no tap at all.
        let recording = state.record != RecordMode::Off;
        let mut splitter = SseSplitter::new(state.frame_cap);
        // Stream every upstream chunk straight to the client; a copy is fed to the
        // splitter and each completed event is tapped. The chunk is returned
        // unchanged, so a tap failure can never alter or stall the stream.
        let stream = resp.bytes_stream().map(move |item| {
            if recording {
                if let Ok(chunk) = &item {
                    for event in splitter.push(chunk) {
                        if tx
                            .try_send(StorageMsg::Tap(TapEvent {
                                direction: Direction::S2c,
                                ts_ms: now_ms(),
                                raw: event,
                            }))
                            .is_err()
                        {
                            log_drop_once(
                                &latch,
                                &logger,
                                "gateway: s2c SSE tap dropped (channel full/closed)",
                            );
                        }
                    }
                }
            }
            item
        });
        match builder.body(Body::from_stream(stream)) {
            Ok(r) => r,
            Err(e) => {
                state
                    .logger
                    .error(format!("gateway: building SSE response failed: {e}"));
                (StatusCode::BAD_GATEWAY, "bad upstream response").into_response()
            }
        }
    } else {
        // Buffer the body up to the shared ceiling and tap it as one s2c frame,
        // same as always. A response that blows the ceiling is uninspectable
        // (mirrors the monitor-mode oversized c2s frame): fail-open switches to a
        // passthrough stream — the bytes already read, chained with the rest of
        // the upstream stream — forwarded untapped rather than buffered further or
        // refused. Headers and status are unaffected either way.
        let mut stream = resp.bytes_stream();
        let mut buf: Vec<u8> = Vec::new();
        loop {
            match stream.next().await {
                Some(Ok(chunk)) => {
                    buf.extend_from_slice(&chunk);
                    if buf.len() > MAX_BUFFER_BYTES {
                        state.logger.error(
                            "gateway: oversized s2c response not tapped; forwarding untapped (fail-open)",
                        );
                        let head = Bytes::from(std::mem::take(&mut buf));
                        let passthrough = tokio_stream::once(Ok::<_, reqwest::Error>(head)).chain(stream);
                        return match builder.body(Body::from_stream(passthrough)) {
                            Ok(r) => r,
                            Err(e) => {
                                state.logger.error(format!(
                                    "gateway: building oversized response failed: {e}"
                                ));
                                (StatusCode::BAD_GATEWAY, "bad upstream response").into_response()
                            }
                        };
                    }
                }
                Some(Err(e)) => {
                    state
                        .logger
                        .error(format!("gateway: reading upstream body failed: {e}"));
                    return (StatusCode::BAD_GATEWAY, "upstream body read failed").into_response();
                }
                None => break,
            }
        }
        let bytes = Bytes::from(buf);
        // Tap the whole response body as one s2c frame (best-effort, non-blocking).
        // Done before any injection so the recording faithfully reflects what the
        // server emitted; injection only changes what the client is handed.
        tap_frame(up, &state.logger, state.record, Direction::S2c, now_ms(), bytes.to_vec());

        // Injection layer for buffered responses (the SSE branch above opts out).
        if state.injector.is_some() {
            let (method, id_value, rpc_id) = crate::parse_for_injection(&bytes);
            if let Some(hit) = inject_decide(&state.injector, InjectDirection::S2c, method.as_deref())
            {
                return inject_s2c_gateway(state, up, &bytes, builder, id_value, hit, method, rpc_id)
                    .await;
            }
        }

        match builder.body(Body::from(bytes)) {
            Ok(r) => r,
            Err(e) => {
                state
                    .logger
                    .error(format!("gateway: building response failed: {e}"));
                (StatusCode::BAD_GATEWAY, "bad upstream response").into_response()
            }
        }
    }
}

/// Apply an injected fault to a policy-cleared client->server request. Records the
/// original request frame (it did occur) and its policy events first — preserving
/// the c2s-before-s2c ordering fingerprint correlation relies on — then performs the
/// fault's wire action and records the inject event, returning the client response.
///
/// Injection here is the user's explicit, in-protocol intervention (like an enforce
/// block), not a fail-open violation; the fail-open contract still governs the
/// *machinery* — a dropped inject event never changes what is on the wire.
#[allow(clippy::too_many_arguments)]
async fn inject_c2s_gateway(
    state: &GatewayState,
    up: &Upstream,
    bytes: Bytes,
    url: String,
    headers: &HeaderMap,
    hit: InjectHit,
    method: Option<String>,
    id_value: Option<Value>,
    rpc_id: Option<String>,
    ts: i64,
    events: Vec<SecurityEvent>,
) -> Response {
    tap_frame(up, &state.logger, state.record, Direction::C2s, ts, bytes.to_vec());
    emit_events(up, &state.logger, events);

    let kind = fault_kind(&hit.fault);
    let (detail, response) = match hit.fault {
        Fault::Delay { delay_ms } => {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            let resp = match send_upstream(state, Method::POST, url, headers, Some(bytes.clone())).await
            {
                Ok(r) => relay_response(state, up, r).await,
                Err(r) => r,
            };
            (
                format!("delayed c2s request by {delay_ms}ms then forwarded upstream"),
                resp,
            )
        }
        Fault::Drop => {
            // Upstream never contacted; acknowledge like a silent block (202, no body).
            (
                "dropped c2s request (upstream not contacted)".to_owned(),
                StatusCode::ACCEPTED.into_response(),
            )
        }
        Fault::Error { code, message } => {
            // Answer in-protocol without contacting the upstream (mirrors the stdio
            // leg, but HTTP `application/json` carries no framing newline).
            let id = id_value.unwrap_or(Value::Null);
            let body = crate::security::synthesize_error_custom(&id, code, &message);
            let resp = (StatusCode::OK, [(CONTENT_TYPE, "application/json")], body).into_response();
            (
                format!("synthesized error code={code} message={message:?} (upstream not contacted)"),
                resp,
            )
        }
        Fault::Truncate { bytes: n } => {
            let end = n.min(bytes.len());
            let truncated = Bytes::copy_from_slice(&bytes[..end]);
            let resp = match send_upstream(state, Method::POST, url, headers, Some(truncated)).await {
                Ok(r) => relay_response(state, up, r).await,
                Err(r) => r,
            };
            (
                format!(
                    "truncated c2s request body to {end} of {} bytes before forwarding",
                    bytes.len()
                ),
                resp,
            )
        }
    };

    state.logger.info(format!("inject c2s [{}]: {}", kind.as_str(), detail));
    emit_inject(
        up,
        &state.logger,
        InjectEvent {
            ts_ms: ts,
            direction: Direction::C2s,
            rule: hit.rule_label,
            fault: kind,
            detail,
            method,
            rpc_id,
        },
    );
    response
}

/// Apply an injected fault to a buffered server->client response body. The caller
/// already tapped the original server body, so this only changes what the client
/// receives. `builder` holds the upstream status + headers, reused for
/// delay/drop/truncate; an injected `error` replaces the response wholesale with an
/// `application/json` error (and so does not carry the upstream headers).
#[allow(clippy::too_many_arguments)]
async fn inject_s2c_gateway(
    state: &GatewayState,
    up: &Upstream,
    body: &[u8],
    builder: axum::http::response::Builder,
    id_value: Option<Value>,
    hit: InjectHit,
    method: Option<String>,
    rpc_id: Option<String>,
) -> Response {
    let kind = fault_kind(&hit.fault);
    let (detail, response) = match hit.fault {
        Fault::Delay { delay_ms } => {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            (
                format!("delayed s2c response by {delay_ms}ms"),
                build_from(state, builder, Body::from(body.to_vec())),
            )
        }
        Fault::Drop => (
            "dropped s2c response body".to_owned(),
            build_from(state, builder, Body::empty()),
        ),
        Fault::Truncate { bytes: n } => {
            let end = n.min(body.len());
            (
                format!("truncated s2c response to {end} of {} bytes", body.len()),
                build_from(state, builder, Body::from(body[..end].to_vec())),
            )
        }
        Fault::Error { code, message } => {
            let id = id_value.unwrap_or(Value::Null);
            let b = crate::security::synthesize_error_custom(&id, code, &message);
            let resp = (StatusCode::OK, [(CONTENT_TYPE, "application/json")], b).into_response();
            (
                format!("replaced s2c response with error code={code} message={message:?}"),
                resp,
            )
        }
    };
    state.logger.info(format!("inject s2c [{}]: {}", kind.as_str(), detail));
    emit_inject(
        up,
        &state.logger,
        InjectEvent {
            ts_ms: now_ms(),
            direction: Direction::S2c,
            rule: hit.rule_label,
            fault: kind,
            detail,
            method,
            rpc_id,
        },
    );
    response
}

/// Finish a response from `builder`, degrading to a logged 502 if the (upstream)
/// headers can't be re-applied — never a reason to panic the handler.
fn build_from(state: &GatewayState, builder: axum::http::response::Builder, body: Body) -> Response {
    builder.body(body).unwrap_or_else(|e| {
        state
            .logger
            .error(format!("gateway: building injected response failed: {e}"));
        (StatusCode::BAD_GATEWAY, "bad upstream response").into_response()
    })
}

/// Persist a fault-injection event (best-effort, non-blocking).
fn emit_inject(up: &Upstream, logger: &Logger, ev: InjectEvent) {
    if up.tx.try_send(StorageMsg::Inject(ev)).is_err() {
        log_drop_once(
            &up.drop_logged,
            logger,
            "gateway: inject event dropped (channel full/closed)",
        );
    }
}

/// Persist a decision's security events (best-effort, non-blocking).
fn emit_events(up: &Upstream, logger: &Logger, events: Vec<SecurityEvent>) {
    for ev in events {
        if up.tx.try_send(StorageMsg::Security(ev)).is_err() {
            log_drop_once(
                &up.drop_logged,
                logger,
                "gateway: c2s security event dropped (channel full/closed)",
            );
        }
    }
}

/// Forward an inbound `MCP-Protocol-Version` header (if present and valid UTF-8) to
/// the storage thread as a passive hint. Best-effort and non-blocking: a full/closed
/// channel silently drops it (no `log_drop_once` — this is a low-value hint, not a
/// tapped frame; a dropped hint simply retries on the next request). One delivered
/// hint is all the storage thread will ever record, so the `hint_sent` latch stops
/// further sends from competing with tapped frames for channel capacity. Never
/// touches the wire.
fn hint_protocol_version(up: &Upstream, headers: &HeaderMap) {
    if up.hint_sent.load(Ordering::Relaxed) {
        return;
    }
    if let Some(version) = headers
        .get("mcp-protocol-version")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    {
        if up
            .tx
            .try_send(StorageMsg::ProtocolHint {
                version: version.to_owned(),
            })
            .is_ok()
        {
            up.hint_sent.store(true, Ordering::Relaxed);
        }
    }
}

/// Best-effort tap of one framed message. Non-blocking: a full/closed channel just
/// drops it (logged once) and never touches the wire. In `--record off` (`record` ==
/// [`RecordMode::Off`]) the frame is not enqueued at all — the wire action has already
/// happened, so there is simply nothing to record.
fn tap_frame(
    up: &Upstream,
    logger: &Logger,
    record: RecordMode,
    direction: Direction,
    ts_ms: i64,
    raw: Vec<u8>,
) {
    if record == RecordMode::Off {
        return;
    }
    if up
        .tx
        .try_send(StorageMsg::Tap(TapEvent {
            direction,
            ts_ms,
            raw,
        }))
        .is_err()
    {
        log_drop_once(&up.drop_logged, logger, "gateway: tap dropped (channel full/closed)");
    }
}

/// Full DNS-rebinding gate for a request: both the `Origin` check (for browser
/// clients that send one) and the `Host` check (closes the gap for a same-origin
/// request that carries none — see [`host_allowed`]) must pass.
fn request_allowed(headers: &HeaderMap) -> bool {
    origin_allowed(headers) && host_allowed(headers)
}

/// Origin gate against DNS-rebinding (MCP Streamable HTTP security requirement). A
/// missing `Origin` (typical of non-browser MCP clients) is allowed; otherwise only
/// a loopback origin passes.
fn origin_allowed(headers: &HeaderMap) -> bool {
    match headers.get(ORIGIN) {
        None => true,
        Some(v) => v.to_str().map(is_localhost_origin).unwrap_or(false),
    }
}

/// Host gate against DNS-rebinding: a browser that's been rebound to an attacker
/// domain resolving to 127.0.0.1 sends a same-origin `GET` with *no* `Origin`
/// header (per the Fetch spec) but still carries a `Host` header naming the
/// attacker's domain — `origin_allowed`'s pass-when-absent rule doesn't see that.
/// Unlike `Origin`, `Host` is mandatory on every HTTP/1.1+ request, so a missing or
/// unparsable one is rejected rather than allowed.
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

/// True when a `Host` header's host part is loopback, ignoring port. Same loopback
/// set as [`is_localhost_origin`], just without a scheme to strip first.
fn is_localhost_host(host: &str) -> bool {
    matches!(extract_host(host), "localhost" | "127.0.0.1" | "::1")
}

/// Pull the bare host out of a `host[:port]` or IPv6-literal `[addr]:port` string
/// (no scheme prefix). Shared by the `Origin` and `Host` gates, which differ only in
/// that `Origin` has a `scheme://` prefix to strip before this.
fn extract_host(rest: &str) -> &str {
    if let Some(stripped) = rest.strip_prefix('[') {
        // IPv6 literal: `[::1]:port` -> take up to ']'.
        stripped.split(']').next().unwrap_or("")
    } else {
        rest.split(['/', ':']).next().unwrap_or("")
    }
}

/// Standard hop-by-hop headers (RFC 9110 §7.6.1) plus `Content-Length`, which we
/// let the response builder recompute. Stripped from both directions.
fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}

/// Headers singled out by a `Connection` header value on this same message (RFC
/// 9110 §7.6.1): e.g. `Connection: x-custom-hop` marks `x-custom-hop` hop-by-hop
/// for this message only, on top of the fixed list in [`is_hop_by_hop`]. The
/// `Connection` header itself may repeat; every occurrence's comma-separated token
/// list is collected. Matched case-insensitively (header names are already
/// lowercase per the HTTP/2-style axum `HeaderName` representation, and tokens are
/// lowercased here to match).
fn connection_named_headers(headers: &HeaderMap) -> HashSet<String> {
    let mut named = HashSet::new();
    for v in headers.get_all(CONNECTION).iter() {
        let Ok(s) = v.to_str() else { continue };
        for tok in s.split(',') {
            let tok = tok.trim().to_ascii_lowercase();
            if !tok.is_empty() {
                named.insert(tok);
            }
        }
    }
    named
}

/// Request headers to send upstream: everything except hop-by-hop (fixed list plus
/// anything this request's `Connection` header names), plus `Host` and
/// `Accept-Encoding` (reqwest sets its own Host; dropping Accept-Encoding keeps the
/// upstream from compressing so the tap sees plaintext). `Authorization`,
/// `Mcp-Session-Id`, `MCP-Protocol-Version`, `Last-Event-ID`, `Accept`, … pass through.
fn filter_request_headers(headers: &HeaderMap) -> HeaderMap {
    let named = connection_named_headers(headers);
    let mut out = HeaderMap::new();
    for (k, v) in headers.iter() {
        if is_hop_by_hop(k) || named.contains(k.as_str()) || matches!(k.as_str(), "host" | "accept-encoding") {
            continue;
        }
        out.append(k, v.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with_origin(origin: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(ORIGIN, HeaderValue::from_str(origin).unwrap());
        h
    }

    #[test]
    fn origin_missing_is_allowed() {
        assert!(origin_allowed(&HeaderMap::new()));
    }

    #[test]
    fn loopback_origins_are_allowed() {
        for o in [
            "http://localhost",
            "http://localhost:7412",
            "http://127.0.0.1:3000",
            "https://127.0.0.1",
            "http://[::1]:8080",
        ] {
            assert!(origin_allowed(&headers_with_origin(o)), "should allow {o}");
        }
    }

    #[test]
    fn foreign_origins_are_rejected() {
        for o in ["http://evil.com", "https://example.com:7412", "null", "http://169.254.0.1"] {
            assert!(!origin_allowed(&headers_with_origin(o)), "should reject {o}");
        }
    }

    #[test]
    fn hop_by_hop_and_host_are_stripped_from_requests() {
        let mut h = HeaderMap::new();
        h.insert("host", HeaderValue::from_static("client.local"));
        h.insert("connection", HeaderValue::from_static("keep-alive"));
        h.insert("content-length", HeaderValue::from_static("10"));
        h.insert("accept-encoding", HeaderValue::from_static("gzip"));
        h.insert("authorization", HeaderValue::from_static("Bearer t"));
        h.insert("mcp-session-id", HeaderValue::from_static("sess-1"));
        let out = filter_request_headers(&h);
        assert!(out.get("host").is_none());
        assert!(out.get("connection").is_none());
        assert!(out.get("content-length").is_none());
        assert!(out.get("accept-encoding").is_none());
        // Meaningful headers survive.
        assert_eq!(out.get("authorization").unwrap(), "Bearer t");
        assert_eq!(out.get("mcp-session-id").unwrap(), "sess-1");
    }

    fn headers_with_host(host: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(HOST, HeaderValue::from_str(host).unwrap());
        h
    }

    #[test]
    fn host_missing_is_rejected() {
        // Unlike Origin, Host is mandatory on every HTTP/1.1+ request; a request
        // with none is refused rather than allowed.
        assert!(!host_allowed(&HeaderMap::new()));
    }

    #[test]
    fn loopback_hosts_are_allowed() {
        for h in ["localhost", "localhost:7412", "127.0.0.1:3000", "127.0.0.1", "[::1]:8080", "[::1]"] {
            assert!(host_allowed(&headers_with_host(h)), "should allow {h}");
        }
    }

    #[test]
    fn foreign_hosts_are_rejected() {
        // The DNS-rebinding gap this closes: a browser rebound to an attacker
        // domain that resolves to 127.0.0.1 sends a same-origin GET with no
        // Origin header at all, but Host still names the attacker's domain.
        for h in ["evil.example", "evil.example:7412", "169.254.0.1"] {
            assert!(!host_allowed(&headers_with_host(h)), "should reject {h}");
        }
    }

    #[test]
    fn request_allowed_requires_both_origin_and_host() {
        // Loopback Host, no Origin (typical non-browser MCP client): allowed.
        assert!(request_allowed(&headers_with_host("127.0.0.1:9000")));

        // Loopback Host, foreign Origin: rejected by the origin gate.
        let mut h = headers_with_host("127.0.0.1:9000");
        h.insert(ORIGIN, HeaderValue::from_static("http://evil.example"));
        assert!(!request_allowed(&h));

        // No Origin, foreign Host (the rebinding gap): rejected by the host gate.
        assert!(!request_allowed(&headers_with_host("evil.example")));
    }

    #[test]
    fn resumption_and_protocol_headers_pass_through_to_upstream() {
        // MCP 2025-11-25 resumption (SEP-1699) resumes a stream with a GET carrying
        // `Last-Event-ID`; the transport also requires `MCP-Protocol-Version` on every
        // post-handshake request. Both must reach the upstream verbatim (not stripped),
        // or resumption and version negotiation break.
        let mut h = HeaderMap::new();
        h.insert("last-event-id", HeaderValue::from_static("evt-42"));
        h.insert("mcp-protocol-version", HeaderValue::from_static("2025-11-25"));
        let out = filter_request_headers(&h);
        assert_eq!(out.get("last-event-id").unwrap(), "evt-42");
        assert_eq!(out.get("mcp-protocol-version").unwrap(), "2025-11-25");
    }

    #[test]
    fn connection_named_headers_are_stripped_from_requests() {
        let mut h = HeaderMap::new();
        h.insert("connection", HeaderValue::from_static("x-hop, Keep-Alive"));
        h.insert("x-hop", HeaderValue::from_static("secret"));
        h.insert("authorization", HeaderValue::from_static("Bearer t"));
        let out = filter_request_headers(&h);
        assert!(out.get("x-hop").is_none(), "Connection-named header must be stripped");
        assert_eq!(out.get("authorization").unwrap(), "Bearer t");
    }
}
