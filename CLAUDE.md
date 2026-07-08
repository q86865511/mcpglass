# mcpglass — 專案層 CLAUDE.md

MCP 流量的 Wireshark＋防火牆：Rust 單一 binary 透明代理，坐在 AI client 與 MCP server 之間，
提供除錯、觀測、稽核與安全防護，資料全留本機。open-core，客群為全球開發者。

## 常用指令

- Build：`cargo build --workspace`
- Test：`cargo test --workspace`
- Lint：`cargo clippy --workspace -- -D warnings`
- 前端（Phase 1 起）：TODO（dashboard/frontend 建立後補：pnpm dev / pnpm build）

## 架構約定

- Workspace crates：`proxy-core`（JSON-RPC 解析、轉發、hook 點）／`storage`（rusqlite）／
  `policy`（規則引擎，Phase 2）／`cli`（clap 入口）／`dashboard`（axum＋rust-embed，Phase 1）。
- **fail-open 是鐵律**：代理自身任何錯誤（解析失敗、DB 寫入失敗）都不得阻斷 client↔server 流量；
  未知 JSON-RPC 欄位一律直通不擋。
- 訊息紀錄為旁路（tap）而非串接（filter）：先轉發、後解析入庫。
- 對外文件（README、docs/）英文；PROGRESS.md 與內部筆記中文。
- MCP spec 對齊官方 schema 版本，版本常數集中在 proxy-core。
