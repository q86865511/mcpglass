# mcpglass — 專案層 CLAUDE.md

MCP 流量的 Wireshark＋防火牆：Rust 單一 binary 透明代理，坐在 AI client 與 MCP server 之間，
提供除錯、觀測、稽核與安全防護，資料全留本機。open-core，客群為全球開發者。

## 常用指令

- Build：`cargo build --workspace`
- Test：`cargo test --workspace`
- Lint：`cargo clippy --workspace -- -D warnings`
- 前端（`crates/dashboard/frontend/`，pnpm）：`pnpm build`（tsc strict＋vite，產 dist 供 rust-embed）；`pnpm mock`＋`pnpm dev` 本地開發
- 前端要先 build 過，`cargo build` 才會內嵌真 UI（否則 build.rs 生佔位頁）

## 架構約定

- Workspace crates：`proxy-core`（JSON-RPC 解析、轉發、框架化）／`storage`（rusqlite，schema v3）／
  `policy`（純邏輯：政策/secret/指紋/決策，無 IO）／`cli`（clap 入口＋熱路徑）／`dashboard`（axum＋rust-embed）。
- **fail-open 是鐵律**：代理自身任何錯誤（解析失敗、DB 寫入失敗、policy panic）都不得阻斷或延遲
  client↔server 流量；未知 JSON-RPC 欄位一律直通不擋。**唯二例外**：政策檔啟動期載入失敗（尚未轉發任何 byte，中止安全）、
  enforce 模式政策明確命中（協定內合法拒絕，合成 -32001 回 client，非斷線）。
- 安全層職責分離：c2s（client→server）為**可攔阻的同步純函式決策**（`policy::evaluate_request`）；
  s2c（server→client）維持**旁路 tap**，指紋比對在 storage thread 做（只告警不阻擋）。
- 熱路徑日誌節流：channel 滿導致的 tap-drop 每 pump 只同步寫檔一次（避免故障態同步 I/O 回壓 wire）。
- 訊息紀錄為旁路（tap）：s2c 先轉發後記錄；c2s 逐幀決策（Forward 先轉發、Block 才不送），記錄一律在 wire 動作之後。
- 對外文件（README、docs/）英文；PROGRESS.md 與內部筆記中文。
- MCP spec 對齊官方 schema 版本，版本常數集中在 proxy-core。
