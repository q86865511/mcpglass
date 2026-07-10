//! Ensures `frontend/dist/` exists before `rust-embed` tries to embed it.
//!
//! The real bundle is built separately (`pnpm install && pnpm build` in
//! `frontend/`) and `dist/` is gitignored, so a clean checkout has no
//! `frontend/dist/` and `cargo build` would otherwise fail with a
//! folder-not-found error from the `#[derive(RustEmbed)]` in `src/lib.rs`.
//! Drop in a placeholder `index.html` only when the real bundle is missing;
//! an existing dist (real or previously placeholdered) is never touched.
//!
//! `MCPGLASS_REQUIRE_FRONTEND=1` flips this from "placeholder" to "panic":
//! release builds (see `.github/workflows/release.yml`) must never ship a
//! binary with the placeholder page silently embedded.

use std::path::Path;

fn main() {
    let dist = Path::new("frontend/dist");
    let index = dist.join("index.html");
    if !index.exists() {
        if std::env::var_os("MCPGLASS_REQUIRE_FRONTEND").is_some() {
            panic!(
                "frontend/dist/index.html is missing and MCPGLASS_REQUIRE_FRONTEND is set. \
                 Run \"pnpm install && pnpm build\" in crates/dashboard/frontend, then rebuild."
            );
        }
        std::fs::create_dir_all(dist).expect("creating frontend/dist placeholder dir");
        std::fs::write(
            &index,
            "Frontend not built. Run \"pnpm install && pnpm build\" in crates/dashboard/frontend, then rebuild.",
        )
        .expect("writing frontend/dist placeholder index.html");
    }
    println!("cargo:rerun-if-changed=frontend/dist");
    println!("cargo:rerun-if-env-changed=MCPGLASS_REQUIRE_FRONTEND");
}
