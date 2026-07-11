# PROGRESS — mcpglass

## 目前狀態
v0.1.1 已正式發佈（四平台 binaries＋SBOM＋attestation）；v0.2.0 全部五個 PR（#5 fail-open 措辭、#6 schema v7 identity、#7 資料生命週期、#9 benchmark＋fail-open 迴歸）皆 merge 進 master，253 測試全綠。剩：docs/compat.md 手動 client 清單（使用者自跑）、v0.2.0 正式 tag 時機、收集真實使用者回饋。

## 已完成
- [2026-07-11] 🧬 v0.2.0 全數 merge（#5/#6/#7/#9，各經「agent 實作→主對話獨立重跑→reviewer 獨立審查→發現逐條裁決修正」流程）：
  - **fail-open 承諾收斂**（#5）：security-model/README 措辭改「程序存活時 tap 不施加 backpressure；程序級故障（OOM/kill/host crash）明確除外」——把不可證的絕對宣稱改成可驗證範圍。
  - **schema v7 結構化 server identity**（#6）：sessions 四欄（program/argv_json/transport/server_id）＋messages.raw_len；policy::ServerIdentity（型別上無 env 欄）＋sha256 canonical hash；指紋 scope 改 server_id，**lazy re-key 讓升級不歸零 rug-pull 基線**（BEGIN IMMEDIATE 同交易整批重鍵，「升級後首錄零告警」整合測試釘住）；replay 由 argv_json 無損還原。237 測試；reviewer 一條低嚴重度（COMMIT 洩漏交易毒化偵測）已修。
  - **資料生命週期**（#7）：`prune --older-than/--max-size`（fingerprints 永不刪、max-size 用 freelist 調整 used bytes＋自動 VACUUM）；dashboard DELETE session；`--record full|metadata|off`（off pump 端零旁路成本、metadata 先解析後丟 body 存 raw_len，安全事件不受錄製影響）；Unix db/log 0600；`export --policy` 遮罩診斷包（reviewer 中嚴重度：custom_secret_patterns 遮罩缺口——已修並測試釘住；label 遮罩補上）。251 測試。
  - **benchmark＋fail-open 證明**（#9）：criterion micro＋端到端四模式實測（**代理加成 p50 約 100µs/往返，off/metadata/full/enforce 差距在幾個百分點內**，docs/benchmarks.md）；channel 飽和與 DB 不可寫兩條迴歸測試進 CI（wire byte 級不變＋drop 節流），測試 hook 全 cfg(debug_assertions) 閘控、release 熱路徑零成本。253 測試。
- [2026-07-10] 🚀 v0.1.1 正式發佈：v0.1.1-rc1 演練→Windows artifact 實測（sha256sum -c、gh attestation verify=SLSA v1、dashboard 真 React bundle 非 placeholder）→正式 tag，Release 含四平台＋SHA256SUMS＋SPDX SBOM。
- [2026-07-10] 🚢 v0.1.1 產品化四 PR 全數 merge（#1 CI/MSRV、#3 協定升級、#4 conformance、#2 release，rebase 線性歷史）：
  - **MCP 2025-11-25＋被動版本觀測**（PR #3）：schema v6（sessions 三欄）、PendingInitialize 旁路解析握手、gateway ProtocolHint header 備援（一次性閘門）、replay 用 session 記錄版本、2025-11-25 全套 wire 形狀 passthrough 測試、**指紋 v3＝v2＋outputSchema**（排除 icons，舊列靜默重釘零誤報）。229 測試（+22）、reviewer 獨立審查無正確性發現。設計已預留 2026-07-28 移除 initialize 握手的退化路徑（header 自動升為 HTTP 主要來源）。
  - **差分 conformance CI**（PR #4）：官方套件對 server-everything 裸連 vs 經 gateway 各跑 2025-06-18/2025-11-25，斷言「代理失敗 ⊆ 裸連失敗」＋protocol_version 端到端斷言；真 ubuntu runner 實跑綠。**意外發現：dns-rebinding-protection 情境裸連失敗、經 mcpglass 反而通過**（gateway loopback gate 補了裸 server 的防護）。
  - **預編譯 binary release workflow**（PR #2）：四平台（linux/win/macOS arm+intel）＋SHA256SUMS＋SPDX SBOM＋GitHub provenance attestation；build.rs 防呆 MCPGLASS_REQUIRE_FRONTEND（release 永不內嵌 placeholder）；[profile.release] lto/strip（保 unwind）；docs/RELEASING.md 完整 checklist；README 安裝節改 binary 優先。
  - 版本定版 0.1.1（Cargo.toml/frontend package.json/README Status/CHANGELOG 定版＋比較連結）。
- [2026-07-10] 🔧 WF2C CI 補強＋MSRV 修正（分支 ci/macos-msrv）：CI 矩陣加 macOS；新增 msrv job（`cargo check --workspace --locked`，不建前端走 placeholder）。**MSRV 宣稱 1.80 實測證偽**——鎖檔中 reqwest http3 殘留（chacha20 需 edition2024）連 manifest 都解析不了、idna/icu 需 1.86；1.80/1.85/1.86 三版實測後修正宣稱為 1.86（Cargo.toml/README badge/CONTRIBUTING/CHANGELOG 同步）。另新增 docs/compat.md 手動 client 相容驗證清單（WF2B）。
- [2026-07-09] 📦 R7 Phase 4 發佈準備（/pipeline 兩波六任務＋雙重審查＋十項修正）：
  - **發佈基礎**：全 crate 升 0.1.0（workspace 繼承 metadata,各 crate 英文 description）；GitHub Actions CI（ubuntu＋windows 矩陣,pnpm build 先於 cargo build/test/clippy）；README 徽章/Install/Quickstart/截圖；docs/（cli.md、configuration.md、security-model.md,旗標與欄位逐一對過 clap/serde 定義）；CHANGELOG（0.1.0）/CONTRIBUTING/SECURITY.md。
  - **hardening**：attach/detach 顯式單一目標遇損毀 JSON 回 exit 1（all 模式跳過仍 0）；inject fault 未知欄位啟動期拒絕（deny_unknown_fields 實測與 internally-tagged enum 相容）；inject_events 儀表板（storage 分頁查詢＋counts、`GET /api/sessions/{id}/inject[/counts]` 掛 loopback middleware 內、前端 Inject tab＋徽章＋dev-mock）。
  - **demo 素材**：scripts/demo.ps1（實測,兩輪流量:乾淨＋注入,25 訊息＋2 注入事件入庫）＋demo.sh（未實測,已標注）＋demo-assets（自製 MCP client、inject.toml）；docs/demo.md（GIF 工具鏈＋七幕劇本）；docs/assets/dashboard-overview.png（headless Edge 實截）。
  - **發文草稿**：docs/launch/ Show HN＋r/mcp（各 3 候選標題,DRAFT 標注,平台支援度留一處待補實）。
  - **審查與修正**：reviewer（Opus）4 條＋Codex 7 條＋主對話截圖自查 1 條,合併 10 條經使用者裁決全修——含 README/草稿「masked in storage」誤述（實為僅稽核視圖遮罩）、allow 清單被誤寫成支援萬用（實為精確比對）、detach 誤寫 from backup、前端把 JSON-RPC 回應標成 (notification)（發佈截圖可見,修為 (response)）、demo client 500ms 就 kill 改為等正常退出＋5s 保底等。
  - **驗證**：207 Rust 測試全綠、clippy 零警告、前端 build 綠、demo 修後重跑成功、修後截圖重擷確認 (response) 標籤。
  - **首輪 CI 上線**（push 後三修至兩 OS 全綠）：pnpm 9→11（pnpm-workspace.yaml 是 config-only 用法,pnpm 9 拒收）；Node 20→22（pnpm 11 依賴 node:sqlite）；gateway 整合測試 port 競態根治（free_port 先占先放改 `--port 0` 由 OS 配＋解析啟動 banner,Linux 限定 flake）。
- [2026-07-09] 🔬 R6 Phase 3 下半（/pipeline：storage 地基→A/B/C 三線序列派工→雙重審查→五項修正→復審）：
  - **context bloat 分析**：proxy-core `bloat.rs` 啟發式估算（`chars/4`,一律標 approximate,`estimate_tokens`/`analyze_tools_list_response→BloatReport`,fat tool 門檻 description>100 token）；資料源為 session 最新 tools/list 回應（storage `latest_tools_list_raw`,rpc_id 配對）。CLI `mcpglass bloat [--session --top]` 文字報告；dashboard `GET /api/sessions/{id}/context`＋前端 Context tab（總估算、Top-N 佔比 bar、裁剪建議）。
  - **請求 replay**：CLI `mcpglass replay <message-id>`＋dashboard DetailPanel Replay 按鈕（確認框、`POST /api/messages/{id}/replay`,ReplayFn 注入使 dashboard 不依賴 cli）。stdio session 重 spawn server 走 initialize/initialized 握手後重送；HTTP session 重新 initialize 取新 Mcp-Session-Id 後重送。**完全不落庫**（帶外探針,唯讀開庫、不跨 await 持有）；僅允許 c2s request（守門拒 notification/response/s2c）。
  - **錯誤注入**：policy `inject.rs`（獨立 TOML `--inject`,`[[rules]]` direction/method 萬用/probability/max_triggers/fault,自帶 xorshift RNG,`decide` 純函式,載入失敗啟動期中止）；wrap 雙向 pump 與 gateway handle_post/relay_response 接線（policy 先決策,只有 Forward 才注入）；fault=delay/error/drop/truncate；被注入的原始幀照原樣入 messages,另記 `inject_events`（storage schema v5）。注入屬「使用者明確要求的模擬故障」（同 enforce 例外）,注入層自身仍 fail-open。
  - **審查與修正**：reviewer（Opus）＋Codex 雙審 9 條合併裁決,修 5 條（dashboard 變異端點缺 Origin/Host 防護＝高、replay DELETE 併入 timeout 把成功變 504、HTTP status 未檢查、SSE 讀到 EOF 無界累積、command 引號切分）＋復審通過；其餘 3 條列已知問題。
  - **驗證**：clippy 零警告、202 Rust 測試全綠（新增 56）、前端 build 綠。
- [2026-07-09] 🌐 R5 Phase 3 上半（/pipeline 四波派工＋雙重審查＋九項修正＋二輪復審）：
  - **HTTP（streamable）transport**：`mcpglass gateway` 長駐反向代理（axum，`POST|GET|DELETE /u/{name}`，預設埠 7412）——對齊 MCP spec 2025-06-18（版本常數落 proxy-core）；c2s 同步決策重用 `decide_c2s_frame`（Block＋id→200/-32001、Block 無 id→202）；reqwest 透傳剝 hop-by-hop（含 `Connection` 點名標頭）；SSE 以 `Body::from_stream` 逐 chunk 直通＋`SseSplitter` 旁路 tap；非 SSE 回應緩衝上限 256MB、超限直通不 tap；上游連不上→502；Origin＋Host 雙重 loopback 驗證防 DNS rebinding。
  - **attach url 型 entry**：改寫指向本機 gateway，原始 url 記 `gateway.toml`（唯一真相，先存表才寫 client 檔、失敗即中止）；route 名 sanitize＋`~n` 唯一化解同名不同 upstream；detach 由 url 反解 route 還原；client 檔寫入失敗以非零 exit code 回報。
  - **安全層增強**：指紋 v2 納入 annotations（storage v4 additive 遷移＋雙雜湊過渡——v1 匹配靜默改釘 v2，無誤報無空窗）；A→B→A 震盪回 `Reverted` 並發 fingerprint_change（detail 標 oscillation）；tools/list 關聯改 `HashMap<id,ts>`（真 request 才 invalidate、真 response 才消耗、error response 不指紋、容量 1024 淘汰最舊）。
  - **遺留清理**：attach 涵蓋 `~/.claude.json` 的 `projects.*.mcpServers`（報表標 scope）；dashboard 連線快取 `Arc<Mutex<Store>>`（legacy v0 檔退回每請求重開避免釘死空庫）；文案三處（方向徽章、搜尋 placeholder、launcher 的 program_label 推導）。
  - **前置重構**：main.rs 抽出 `tap.rs`（StorageMsg/storage_loop/record_fingerprints/Logger），stdio wrap 與 gateway 共用同一 tap/storage/指紋管線；storage 並發強化（busy_timeout、schema fast-path）支撐 gateway 多 writer。
  - **審查與修正**：reviewer（Opus）＋Codex 雙審 16 條合併裁決，修 9 條（gateway.toml 同名覆蓋、tools/list 關聯方向性誤判 ×2、Host 驗證缺口、寫入順序、回應緩衝無上限、legacy v0 釘死、route 字元、Connection 標頭）＋復審追修 exit code 1 條;其餘列已知問題。
  - **驗證**：clippy 零警告、146 Rust 測試全綠（新增 55）、前端 build 綠。
- [2026-07-08] 🛡️ R4 Phase 2 安全層（/pipeline 兩波派工＋雙重審查＋修正）：
  - **policy crate**（純邏輯核心）：TOML 政策載入（mode monitor/enforce、allow/deny 清單含 `*` 萬用、自訂 secret regex）、secret 偵測（AWS/GitHub/OpenAI/Anthropic/Slack/Google/私鑰/JWT 等內建 pattern，preview 遮罩）、tool 指紋（自實作 canonical JSON key-sort→SHA-256，防 workspace `preserve_order` feature 統一造成指紋失穩）、純函式 `evaluate_request→{Forward|Block, events}`。
  - **storage v3**：additive 升級新增 `security_events`（append-only）＋`tool_fingerprints`（帶 `server_key` 以 server 啟動指令為身分、跨 session 比對）表；`record_fingerprint` 回 New/Unchanged/Changed。
  - **wrap 熱路徑安全整合**：c2s 改逐幀決策——monitor 只記 flagged、enforce 命中則不送 server 改往 client 合成合法 -32001 error（協定內拒絕，非斷線）；s2c 與 c2s 共享 stdout 鎖確保幀不撕裂；tools/list 回應（僅比對到對應 request 者）記指紋、跨 session 變化→fingerprint_change 告警。**預設 monitor（不阻擋），enforce 為 opt-in**。fail-open 鐵律嚴格分層（政策啟動期失敗才中止、其餘一律放行）。
  - **儀表板**：新增 `/api/sessions/{id}/security`＋`/security/counts` 端點＋前端 Security tab（告警徽章、事件表、blocked 紅點提示）。
  - **審查與修正**：reviewer（Opus）＋Codex 雙審 8+ 條，逐條讀碼裁決；修 4 條（跨 session rug-pull 漏偵測＝規劃時把指紋綁 session_id 的疏漏、channel 滿時同步 log 回壓、enforce 被超大幀繞過、決策 catch_unwind 保底）＋只對匹配 tools/list request 記指紋；其餘列已知限制。
  - **驗證**：clippy 零警告、91 Rust 測試全綠、前端 build 綠、真實 smoke——enforce deny 命中 client 收 -32001 且 server 沒收到、secret_leak flagged 遮罩、跨 session 同 server 指紋去重（14 筆非 28）不誤報。
- [2026-07-08] 🚀 R3 Phase 1 MVP（/pipeline 分層派工＋雙重審查）：
  - **儲存層 v2**：sessions 表＋messages 歸屬 session／is_error、v0 檔遷移（僅 writer 路徑執行，唯讀 open 不動檔）、查詢 API（分頁篩選、rpc_id 配對 latency 的 stats）。
  - **attach/detach**：一鍵改寫 Claude Code（含 `--project`）／Claude Desktop／Cursor 設定檔把 stdio server 導入 `mcpglass wrap`；原子寫入（temp＋rename）、備份、逆轉換還原、冪等、非陣列 args 等奇形設定跳過不動。
  - **儀表板**：`mcpglass dashboard`——axum REST（5 端點）＋rust-embed 內嵌 React 前端（session 側欄、訊息時間軸分頁篩選、詳情、stats、2 秒輪詢），bind 成功才印 URL 開瀏覽器；build.rs 佔位 dist 讓乾淨 checkout 可編譯。
  - **審查與修正**：reviewer（Opus）＋Codex 雙審共 11 條實質意見，裁決後修 9 條（前端 null latency 崩潰、設定檔半份寫入、非陣列 args 丟參數、`cmd /c` shell 注入面改 PATHEXT 解析、gitignored dist 斷 build、唯讀遷移隱患、stale response、stats 輪詢、bind 時序），2 條列待辦。
  - **驗證**：clippy 零警告、36 Rust 測試全綠、前端 tsc strict＋build 綠、真實 client/server 端到端 smoke 通過。
- [2026-07-08] ⚙️ R2 Phase 0 尖刺通過：Cargo workspace（proxy-core／storage／cli）＋ `mcpglass wrap` 透明代理——newline JSON-RPC 旁路 tap 落 SQLite（WAL）、fail-open（try_send 不施加背壓、超長行只限記錄緩衝不限轉發）、診斷只寫 log 檔絕不污染 stdout/stderr、Windows `.cmd` shim 以 `cmd /c` 退回。驗證：clippy 零警告、9 測試全綠（含 bytes 完全一致的 passthrough 整合測試）；真實端到端——Claude Code CLI 經代理呼叫官方 filesystem server，11 筆訊息完整入庫（initialize／tools/list／tools/call×2，含 server→client 的 roots/list 反向 RPC）。
- [2026-07-08] 📄 R1 專案初始化：市調（兩個研究 agent 查證 MCP 生態縫隙）→ 選題「MCP 本機觀測／安全代理」→ 10 週計劃核准（計劃檔：`~/.claude/plans/godot-aivtuber-functional-toucan.md`）→ 建基礎文件與 git repo。

## 進行中
（無——v0.1.1/v0.2.0 計劃全部落地；等待真實使用者回饋決定下一步。）

## 待辦
- 真實 client 的手動相容清單（docs/compat.md）——使用者自跑，結果記回該檔表格。
- v0.2.0 正式 tag（照 docs/RELEASING.md：版本 bump 三處→CHANGELOG 定版→rc 演練→正式）。
- 審查遺留（低優先）：帶外工具的 Store::open 改真正 read-only 開庫（現況：不記錄流量但對舊版 DB 會做 additive schema 升級，docs/cli.md 已如實揭露）；bloat 對 metadata-only session 印 parse error 而非「no tools/list captured」（metadata 模式已知限制，可更友善）。
- 指紋 v4 觀察名單：icons（2025-11-25 新欄位，URL 高頻誤報故 v3 排除）。追蹤 2026-07-28 spec（移除 initialize 握手/Mcp-Session-Id、Tasks 畢業 extension）——版本觀測已預留退化路徑，發布後驗證。
- （Phase 4 已全部收尾：push、repo public、demo GIF、README 重排、作品集 notable 上架〔portfolio commit 538448e〕。使用者裁決**不發** Show HN / r/mcp 文，docs/launch/ 草稿保留備用。）

## 已知問題
- 本機 SQLite 會存**原始流量全文**（含任何流經的密鑰）——這是「流量 Wireshark」的核心設計，資料不出本機；secret 過濾只在 `security_events.detail` 遮罩並告警/阻擋外流。已在 README 明示。
- s2c 超大單幀（>64MB 單行 server 回應）分段寫出期間，enforce 的 c2s 拒絕回應理論上可插入撕裂該幀——需 64MB 單行＋並發命中，屬病理邊界，已註解為已知取捨。
- JSON-RPC id 正規化成文字後數字 `1` 與字串 `"1"` 同鍵——tools/list 關聯在跨型別 id 撞號的病態 client 下可能誤配（既有 parse_line 行為，影響僅告警面）。
- 同毫秒內的指紋震盪（A→B→A 全在 1ms 內）tie-break 依 row id，可能對同一回退重複發 Reverted 告警（僅告警面誤報，需惡意 server 毫秒級連改才觸發）。
- gateway 對 >64MB 的 monitor 模式請求 body 採緩衝轉發（上限 256MB，超限 413）而非零拷貝串流；正常 MCP 訊息（<64MB）不受影響。
- gateway 要求請求帶 loopback Host（防 DNS rebinding）；HTTP/1.0 或 h2c 等不帶 Host 的 client 會被 403——MCP client 實務皆走 HTTP/1.1（hyper 對無 Host 的 1.1 請求本就 400），影響面可忽略。
- 指紋 v1→v2 改釘在「legacy v1 列時間戳晚於既有 v2 同值列」的理論情境下可撞 UNIQUE——單調時鐘下幾乎不可達，fail-open 僅 log 丟該次 outcome。
- gateway c2s 注入路徑在 wire 動作**之前**先 tap 原始請求（為保 c2s<s2c 指紋配對順序,異於 handle_post 於 send_upstream 後才記錄）；delay 期間程序被殺則 DB 顯示發生過但上游未收——try_send 非阻塞不延遲 wire,屬一致性存疑非危害。
- gateway 對「無 id 通知」注入 error 會合成 id:null 的 200 錯誤,stdio 對應路徑則不送任何東西——兩 transport 對通知注入 error 的行為不對稱。
- stdio replay 以引號感知切分還原 `argv.join(" ")` 存下的 command,含嵌入引號/shell 元字元的 command 仍可能失真；根治需 storage 改存 argv 陣列（未來工作）。stdio replay 會重新啟動 server 程序、重送請求可能有副作用（前端確認框與 CLI 說明已標示）。gateway s2c error 注入與 replay 均不注入/處理 SSE 串流（v1 限制）。

## 重要決策紀錄
- [2026-07-08] 選題依據市調：企業級 MCP gateway 紅海、registry 被官方卡死，空窗在「個人開發者本機觀測層」（Inspector 看不到真實流量、競品 2026-07 才出現）；Invariant Labs 被 Snyk 收購證明出口存在。
- [2026-07-08] 技術選型：Rust workspace（proxy-core / storage / policy / cli / dashboard）＋ React/TS 前端以 rust-embed 嵌入 → 單一執行檔。理由：單 binary 是差異化武器，前端沿用既有強項。
- [2026-07-08] 授權 Apache-2.0（對商業採用友善，利於 open-core）；README/docs 英文優先（全球客群），PROGRESS.md 維持中文。
- [2026-07-08] Phase 2 安全層定位：**預設 monitor（只觀測告警不阻擋），enforce 為 opt-in**（使用者拍板）。攔阻採「協定內合法拒絕」——enforce 命中時不斷線，改合成 -32001 error response 回 client，其餘流量零影響；與 fail-open 嚴格區分（代理自身故障永遠放行，只有政策明確命中才擋）。rug-pull 指紋以 server 啟動指令為身分**跨 session** 比對（同 session 內偵測對真實攻擊無意義）。
- [2026-07-08] 定名 **mcpglass**（原暫名 mcp-lens）：mcp-lens 在 GitHub 至少 6 個同名 repo（含一個 MCP proxy）、npm 已占用；mcptap 被 jondot/mcptap（15★，「wireshark but for MCP」，直接競品，需持續關注）占用；mcpglass 查證 GitHub 全文／crates.io／npm／PyPI 四處全空。
- [2026-07-08] 硬需求：透明直通零破壞，代理內部錯誤一律 fail-open 直通。
- [2026-07-09] HTTP transport 行程模型（使用者拍板）：**長駐 `mcpglass gateway` 反向代理**（非 stdio 橋接）——attach 把 url 型 entry 改指 `http://127.0.0.1:{port}/u/{route}`，原始 url 存 gateway.toml；OAuth 等標頭由 client 發、gateway 透傳。stdio 橋接因破壞 client 端 OAuth 流程而否決。
- [2026-07-09] fail-open 鐵律的 HTTP 詮釋（使用者拍板）：上游連不上/逾時**誠實回 502**（純文字，不合成 JSON-RPC、不假冒 server 發言）；鐵律在 HTTP 下定義為「代理自身 tap/解析/policy 故障絕不改變、延遲或中斷已在流動的回應 bytes」。enforce 攔無 id notification 回 202（spec 內合法）。
- [2026-07-09] 指紋演算法升版策略：**雙雜湊過渡**——v2（含 annotations）與 v1 同時計算，既有 v1 記錄匹配即靜默改釘 v2；否決「首次重釘」（會漏掉恰在升級時發生的 rug-pull）。
- [2026-07-09] Phase 3 下半三取捨（使用者拍板）：bloat token 估算走**啟發式零依賴**（chars/4,標 approximate,不引 tokenizer）；replay 介面 **CLI＋儀表板按鈕都做**（按鈕確認框、CLI 直接執行）；錯誤注入**雙向 c2s/s2c、獨立 TOML**（與 policy 分離、預設不啟用）。
- [2026-07-09] replay **完全不落庫**：帶外除錯探針,結果只回 CLI stdout / 儀表板面板；寫回會污染 session 列表且 stdio replay 的 tools/list 會動到同 server_key 指紋基線。注入事件另立 `inject_events` 表（schema v5,避免改 security_events.kind 的 CHECK constraint）；注入純邏輯放 policy crate（複用 TOML/萬用字元機制,proxy-core 保持只依賴 serde_json）。
- [2026-07-10] **MSRV 宣稱 1.80→1.86**：實測 1.80 連鎖檔 manifest 都解析不了（reqwest http3 殘留 chacha20 需 edition2024）、1.85 差 icu/idna；否決釘住十幾個不編譯的傳遞依賴保 1.80（每次 cargo update 再破），宣稱對齊實測值並以 msrv CI job（cargo check --locked）釘住。
- [2026-07-10] **conformance 採差分模型**：透明代理的正確判準是「經代理不得比裸連多任何失敗」而非絕對通過（參考 server 自身有 conformance 缺口）；否決官方 GitHub Action（只有絕對通過模型）。套件 exact pin，第三方起不來 soft-skip、代理獨有失敗硬紅。
- [2026-07-10] **指紋 v3 納 outputSchema、排除 icons**：outputSchema 是行為契約（rug-pull 真面向）；icons 是遠端 URL（CDN 換址高頻誤報）記 v4 觀察名單。沿雙雜湊過渡樣板，v1/v2 舊列命中靜默重釘 v3。
- [2026-07-10] **版本觀測為被動旁路**：代理不參與協商，只記錄——initialize 優先、HTTP header 備援一次；2026-07-28 spec 移除握手後 header 自動升為主要來源，stdio 顯示 unknown（誠實優於猜測）。replay 常數保持 2025-06-18 不動（語意＝legacy session fallback）。
