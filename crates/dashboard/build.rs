//! Ensures `frontend/dist/` exists before `rust-embed` tries to embed it.
//!
//! The real bundle is built separately (`pnpm install && pnpm build` in
//! `frontend/`) and `dist/` is gitignored, so a clean checkout has no
//! `frontend/dist/` and `cargo build` would otherwise fail with a
//! folder-not-found error from the `#[derive(RustEmbed)]` in `src/lib.rs`.
//! Drop in a placeholder `index.html` only when the real bundle is missing;
//! an existing dist (real or previously placeholdered) is never touched.

use std::path::Path;

fn main() {
    let dist = Path::new("frontend/dist");
    let index = dist.join("index.html");
    if !index.exists() {
        std::fs::create_dir_all(dist).expect("creating frontend/dist placeholder dir");
        std::fs::write(
            &index,
            "Frontend not built. Run \"pnpm install && pnpm build\" in crates/dashboard/frontend, then rebuild.",
        )
        .expect("writing frontend/dist placeholder index.html");
    }
    println!("cargo:rerun-if-changed=frontend/dist");
}
