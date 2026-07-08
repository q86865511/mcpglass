//! `dashboard` subcommand: serve the local HTTP dashboard over the sessions DB.

use std::path::PathBuf;

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

    let result = dashboard::serve(db_path, port, |addr| {
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
