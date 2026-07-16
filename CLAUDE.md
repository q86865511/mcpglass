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

- Workspace crates：`proxy-core`（JSON-RPC 解析、轉發、框架化、SSE 切分、MCP 版本常數、bloat 分析）／`storage`（rusqlite，schema v7）／
  `policy`（純邏輯：政策/secret/指紋/決策/inject 規則/mask_secrets，無 IO）／`cli`（clap 入口＋stdio 熱路徑＋HTTP gateway＋replay/bloat/prune/export 子指令）／`dashboard`（axum＋rust-embed）。
- 兩種 transport 共用同一 tap/storage/指紋管線（`cli/src/tap.rs`）：stdio＝`wrap`（client spawn）；
  HTTP＝`gateway` 長駐反向代理（`/u/{route}`，gateway.toml 記 route→upstream，只綁 127.0.0.1，Origin＋Host 驗 loopback）。
  HTTP 下的 fail-open 對應：上游連不上誠實回 502（不合成 JSON-RPC 假冒 server）；tap/policy 故障絕不改變或延遲已在流動的回應 bytes。
- **fail-open 是鐵律**：代理自身任何錯誤（解析失敗、DB 寫入失敗、policy panic）都不得阻斷或延遲
  client↔server 流量；未知 JSON-RPC 欄位一律直通不擋。**例外**：政策/inject 檔啟動期載入失敗（尚未轉發任何 byte，中止安全）、
  enforce 模式政策明確命中（協定內合法拒絕，合成 -32001 回 client，非斷線）、`--inject` 明確設定的模擬故障
  （使用者要求的協定內干預,同 enforce 例外類）。注入層自身仍 fail-open：Injector lock poison/panic/事件入庫失敗一律照常轉發。
  順序：policy 先決策,只有 Forward 的幀才進注入層。
- 診斷類帶外工具（`replay`/`bloat`/`export`）不碰活體 wire、唯讀開庫、不落庫,不受 fail-open 約束；replay 會重啟 server/重送請求（可能有副作用,前端確認框標示）。`export` 一律遮罩（`policy::mask_secrets` 純函式跑內建 secret patterns,body 逐幀、argv 逐 token）,無不遮罩旗標。
- 資料生命週期（WF4）：`prune` 是生命週期管理指令,天生 writer（讀寫開庫、單交易刪除,非帶外唯讀）,一樣不碰活體 wire;刪除（prune／dashboard `DELETE /api/sessions/{id}`）永遠保留 tool_fingerprints（跨 session rug-pull 信任基線,session_id 懸空可接受）,故刪除交易以 `delete_with_fk_disabled` 暫時關 foreign_keys 容許懸空參照。`--max-size` 用 db_used_bytes（freelist 調整）迴圈刪最舊 session 至達標後自動 VACUUM;`--older-than` 單獨用不自動 VACUUM（WAL 頁面重用）,`--vacuum` 顯式要。
- 錄製模式 `--record full|metadata|off`（wrap／gateway,啟動旗標不可執行期切換）:off 在 pump 端就不 enqueue tap（零旁路成本,仍 begin_session,security/inject 照記）;metadata 在 storage_loop 丟棄 raw **之前**先做完 tools/list 指紋與 PendingInitialize 解析,raw 存空字串、原 byte 長度寫入 messages.raw_len。security/inject 事件不受 --record 影響（安全承諾獨立於錄製）。
- 磁碟落地敏感檔（sessions.db、mcpglass.log）Unix 下 best-effort 設 0600（-wal/-shm 繼承主檔）,Windows 靠 %LOCALAPPDATA% ACL 不動。
- dashboard 有變異端點（`POST /replay`、`DELETE /api/sessions/{id}`、`POST /api/prune`）後,所有路由經 loopback middleware 驗 Origin＋Host（防 DNS rebinding/CSRF-to-localhost）。`GET /api/sessions/{id}/export` 與 CLI export 共用 `dashboard::build_export_bundle`（單一遮罩路徑,經 `serve` 的 policy 參數）;`GET /api/health` 回 capabilities（replay 可用性),前端 replay 按鈕據此 gating。dashboard 前端為 CSS token 雙主題（Oscilloscope 儀器風,`styles/` 五檔）＋hash 深連結（`#/s/{id}/{view}?msg=`）。
- 安全層職責分離：c2s（client→server）為**可攔阻的同步純函式決策**（`policy::evaluate_request`）；
  s2c（server→client）維持**旁路 tap**，指紋比對在 storage thread 做（只告警不阻擋）。
- 熱路徑日誌節流：channel 滿導致的 tap-drop 每 pump 只同步寫檔一次（避免故障態同步 I/O 回壓 wire）。
- 訊息紀錄為旁路（tap）：s2c 先轉發後記錄；c2s 逐幀決策（Forward 先轉發、Block 才不送），記錄一律在 wire 動作之後。
- 對外文件（README、docs/）英文；PROGRESS.md 與內部筆記中文。
- MCP spec 對齊官方 schema 版本，版本常數集中在 proxy-core。
- 注入規則純邏輯在 `policy::inject`（`decide` 純函式,IO 只在 `InjectConfig::load`）；注入事件另立 `inject_events` 表（schema v5 新增,不動 security_events.kind 的 CHECK constraint）。
- 協定版本為被動觀測：storage_loop 旁路解析 initialize 往返（PendingInitialize）、gateway 以 ProtocolHint 傳 header 備援（initialize 優先、header 只記一次）,存 sessions 三欄（schema v6）；replay 用 session 記錄版本,NULL 回落 proxy-core 常數（legacy fallback）。指紋 FP_VERSION=3（v2＋outputSchema,排除 icons）,舊列 hash 命中靜默重釘。
- server identity 為結構化（schema v7,sessions 新增 program/argv_json/transport/server_id 四欄＋messages.raw_len 佔位欄）：`policy::ServerIdentity`（Stdio{argv}／Http{url},無 env 欄→env 不可能進 identity）,hash 純函式 `policy::server_identity_hash`＝sha256(canonical JSON)。指紋 scope key 改用 server_id;升級不歸零基線靠 record_fingerprint 的 lazy re-key（server_id 無列但 legacy_key（＝pre-v7 的 argv.join(" ")／url,即 command_line）有列時,同一 `BEGIN IMMEDIATE` 交易內整批重鍵）。replay 優先讀 argv_json 無損還原 argv、transport 欄取代 URL 嗅探,兩者皆有 legacy NULL 回落（split_command 僅適用 v7 以前）。
