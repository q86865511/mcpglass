//! `dashboard` subcommand: serve the local HTTP dashboard over the sessions DB.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use dashboard::{ReplayError, ReplayFn, ReplayOutcome};

use crate::replay;

/// Time budget for a dashboard-initiated replay. The CLI exposes `--timeout-secs`;
/// the dashboard has no such control, so it uses the same 30s default.
const DASHBOARD_REPLAY_TIMEOUT: Duration = Duration::from_secs(30);

/// Run the dashboard server until killed, printing its URL and (unless
/// `no_open`) opening it in a browser tab.
///
/// The URL is printed and the browser opened from `dashboard::serve`'s
/// `on_ready` callback, i.e. only after the listener has actually bound. That
/// way a port conflict surfaces as a bind error instead of a browser tab
/// pointed at whatever else is already listening on that port.
pub async fn run(db: Option<PathBuf>, port: u16, no_open: bool) -> i32 {
    let db_path = db
        .or_else(|| crate::default_data_dir().map(|d| d.join("sessions.db")))
        .unwrap_or_else(|| std::env::temp_dir().join("mcpglass").join("sessions.db"));

    let result = dashboard::serve(db_path.clone(), port, Some(replay_backend(db_path)), |addr| {
        let url = format!("http://{addr}");
        println!("Dashboard: {url}");
        if !no_open {
            if let Err(e) = opener::open(&url) {
                eprintln!("could not open browser: {e}");
            }
        }
    })
    .await;

    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("dashboard error: {e:#}");
            1
        }
    }
}

/// Build the boxed async closure the dashboard calls to replay a message. `dashboard`
/// can't depend on `cli`, so the concrete `replay::run_replay` is injected here; each
/// call reopens the db (cheap, read-only) so no rusqlite handle crosses the `!Sync`
/// boundary.
fn replay_backend(db_path: PathBuf) -> ReplayFn {
    Arc::new(move |id: i64| {
        let db = db_path.clone();
        Box::pin(async move {
            match replay::run_replay(db, id, DASHBOARD_REPLAY_TIMEOUT).await {
                Ok(r) => Ok(ReplayOutcome {
                    transport: r.transport.to_owned(),
                    response_raw: r.response_raw,
                    note: r.note,
                }),
                Err(e) => Err(map_replay_error(e)),
            }
        }) as Pin<Box<dyn Future<Output = Result<ReplayOutcome, ReplayError>> + Send>>
    })
}

/// Translate the cli-side replay error into the dashboard's status-carrying variant.
fn map_replay_error(e: replay::ReplayError) -> ReplayError {
    match e {
        replay::ReplayError::NotReplayable(m) => ReplayError::NotReplayable(m),
        replay::ReplayError::Timeout => ReplayError::Timeout,
        replay::ReplayError::Upstream(m) => ReplayError::Upstream(m),
        replay::ReplayError::Internal(m) => ReplayError::Internal(m),
    }
}
