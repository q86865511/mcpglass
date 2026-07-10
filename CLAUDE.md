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

- Workspace crates：`proxy-core`（JSON-RPC 解析、轉發、框架化、SSE 切分、MCP 版本常數、bloat 分析）／`storage`（rusqlite，schema v6）／
  `policy`（純邏輯：政策/secret/指紋/決策/inject 規則，無 IO）／`cli`（clap 入口＋stdio 熱路徑＋HTTP gateway＋replay/bloat 子指令）／`dashboard`（axum＋rust-embed）。
- 兩種 transport 共用同一 tap/storage/指紋管線（`cli/src/tap.rs`）：stdio＝`wrap`（client spawn）；
  HTTP＝`gateway` 長駐反向代理（`/u/{route}`，gateway.toml 記 route→upstream，只綁 127.0.0.1，Origin＋Host 驗 loopback）。
  HTTP 下的 fail-open 對應：上游連不上誠實回 502（不合成 JSON-RPC 假冒 server）；tap/policy 故障絕不改變或延遲已在流動的回應 bytes。
- **fail-open 是鐵律**：代理自身任何錯誤（解析失敗、DB 寫入失敗、policy panic）都不得阻斷或延遲
  client↔server 流量；未知 JSON-RPC 欄位一律直通不擋。**例外**：政策/inject 檔啟動期載入失敗（尚未轉發任何 byte，中止安全）、
  enforce 模式政策明確命中（協定內合法拒絕，合成 -32001 回 client，非斷線）、`--inject` 明確設定的模擬故障
  （使用者要求的協定內干預,同 enforce 例外類）。注入層自身仍 fail-open：Injector lock poison/panic/事件入庫失敗一律照常轉發。
  順序：policy 先決策,只有 Forward 的幀才進注入層。
- 帶外工具（`replay`/`bloat`）不碰活體 wire、唯讀開庫、不落庫,不受 fail-open 約束；replay 會重啟 server/重送請求（可能有副作用,前端確認框標示）。
- dashboard 有變異端點（`POST /replay`）後,所有路由經 loopback middleware 驗 Origin＋Host（防 DNS rebinding/CSRF-to-localhost）。
- 安全層職責分離：c2s（client→server）為**可攔阻的同步純函式決策**（`policy::evaluate_request`）；
  s2c（server→client）維持**旁路 tap**，指紋比對在 storage thread 做（只告警不阻擋）。
- 熱路徑日誌節流：channel 滿導致的 tap-drop 每 pump 只同步寫檔一次（避免故障態同步 I/O 回壓 wire）。
- 訊息紀錄為旁路（tap）：s2c 先轉發後記錄；c2s 逐幀決策（Forward 先轉發、Block 才不送），記錄一律在 wire 動作之後。
- 對外文件（README、docs/）英文；PROGRESS.md 與內部筆記中文。
- MCP spec 對齊官方 schema 版本，版本常數集中在 proxy-core。
- 注入規則純邏輯在 `policy::inject`（`decide` 純函式,IO 只在 `InjectConfig::load`）；注入事件另立 `inject_events` 表（schema v5 新增,不動 security_events.kind 的 CHECK constraint）。
- 協定版本為被動觀測：storage_loop 旁路解析 initialize 往返（PendingInitialize）、gateway 以 ProtocolHint 傳 header 備援（initialize 優先、header 只記一次）,存 sessions 三欄（schema v6）；replay 用 session 記錄版本,NULL 回落 proxy-core 常數（legacy fallback）。指紋 FP_VERSION=3（v2＋outputSchema,排除 icons）,舊列 hash 命中靜默重釘。
