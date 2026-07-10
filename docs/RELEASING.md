# Releasing mcpglass

This is the checklist for cutting a new mcpglass release. The `.github/workflows/release.yml`
workflow builds four platform binaries, packages them, generates checksums + an SBOM + build
provenance attestation, and publishes a GitHub Release whenever a `v*` tag is pushed.

## Checklist

1. **Bump the version in three places** (they are not currently linked by tooling, so all three
   must be edited by hand):
   - `Cargo.toml` — `[workspace.package].version`
   - `crates/dashboard/frontend/package.json` — `"version"`
   - `README.md` — the `Rust` badge line is unaffected, but the `**Status**: vX.Y.Z — ...` line
     near the top of the file
2. **Finalize `CHANGELOG.md`** — move the `[Unreleased]` entries under a new `## [X.Y.Z] - YYYY-MM-DD`
   heading (Keep a Changelog format) and add the comparison link at the bottom of the file.
3. **Dry-run with a release-candidate tag first** — push `vX.Y.Z-rc1` and let the workflow run end
   to end. A `-rc`/`-pre` suffix makes the workflow mark the GitHub Release as a prerelease
   (`gh release create --prerelease`), so an rc tag is safe to publish without it being picked up
   as the "latest" release.
4. **Smoke-test each downloaded artifact**:
   - Download the platform-appropriate archive from the draft/rc release.
   - Extract it and run `./mcpglass dashboard --no-open` (or `mcpglass.exe dashboard --no-open`
     on Windows); confirm the process starts and prints the loopback dashboard URL. Then open that
     URL in a browser and confirm the real React dashboard renders — **not** the
     "Frontend not built..." placeholder page (this is exactly what
     `MCPGLASS_REQUIRE_FRONTEND=1` in the release workflow is meant to prevent from ever shipping;
     the manual check here is a belt-and-suspenders confirmation against the actual binary).
   - On macOS, first clear the quarantine attribute or Gatekeeper will refuse to run the binary:
     `xattr -d com.apple.quarantine ./mcpglass`.
5. **Verify supply-chain artifacts**:
   - `sha256sum -c SHA256SUMS` (or `shasum -a 256 -c SHA256SUMS` on macOS) against the downloaded
     archive.
   - `gh attestation verify <downloaded-archive> --owner q86865511` to confirm the build
     provenance attestation validates.
6. **Run the manual cross-client compatibility pass** described in `docs/compat.md` and record the
   results in its table.
7. **Check for new upstream MCP conformance releases** — mcpglass's spec alignment is pinned to a
   specific MCP schema version (see the version constants in `proxy-core`); confirm there is no
   newer official conformance test suite release that should be picked up before cutting a stable
   tag.
8. **Push the real tag** — once the rc has been smoke-tested, tag the finalized commit `vX.Y.Z` and
   push it. The workflow republishes under the real tag as a full (non-prerelease) release.

## What the workflow does

- Builds `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `aarch64-apple-darwin`, and
  `x86_64-apple-darwin` in a matrix, each building the frontend first (same steps as `ci.yml`)
  then `cargo build --release --target <t> -p cli` with `MCPGLASS_REQUIRE_FRONTEND=1` set.
- Packages each binary with `LICENSE` and `README.md` into
  `mcpglass-v<version>-<target>.tar.gz` (Windows: `.zip`).
- A second job downloads all artifacts, generates `SHA256SUMS`, generates an SPDX SBOM via
  `anchore/sbom-action` (syft), attests build provenance via
  `actions/attest-build-provenance`, and publishes everything with `gh release create`.

## Version bump reference

| File | Field |
| --- | --- |
| `Cargo.toml` | `[workspace.package].version` |
| `crates/dashboard/frontend/package.json` | `version` |
| `README.md` | `**Status**: vX.Y.Z — ...` line |
