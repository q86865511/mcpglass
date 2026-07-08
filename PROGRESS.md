# PROGRESS — mcpglass

## 目前狀態
Phase 3 上半完成：HTTP（streamable）transport 長駐 gateway 反向代理、安全層增強三項（指紋納入 annotations＋雙雜湊過渡、A→B→A 震盪告警、tools/list 關聯嚴格化）、Phase 2 遺留三項清理，皆過雙重審查＋修正＋二輪復審，146 Rust 測試＋前端 build 全綠。下一步 Phase 3 下半（context bloat 分析、請求 replay、錯誤注入）。

## 已完成
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
（無）

## 待辦
- Phase 3 下半：context bloat 分析、請求 replay、錯誤注入。
- 審查遺留（低優先）：顯式單一目標的 attach/detach 遇 `Unreadable`（損毀 JSON）仍 exit 0，可評估納入非零 exit（`all` 模式的跳過屬預期，需區分 explicit）；指紋 v3 候選納入 `outputSchema`；真實 streamable HTTP server 的手動 smoke（gateway 端到端已有整合測試，真實 client 對接未跑）。
- Phase 4（發佈）：英文 docs＋demo GIF、GitHub 開源、Show HN / r/mcp 發文、收進 terrychou.com 作品集。

## 已知問題
- 本機 SQLite 會存**原始流量全文**（含任何流經的密鑰）——這是「流量 Wireshark」的核心設計，資料不出本機；secret 過濾只在 `security_events.detail` 遮罩並告警/阻擋外流。已在 README 明示。
- s2c 超大單幀（>64MB 單行 server 回應）分段寫出期間，enforce 的 c2s 拒絕回應理論上可插入撕裂該幀——需 64MB 單行＋並發命中，屬病理邊界，已註解為已知取捨。
- JSON-RPC id 正規化成文字後數字 `1` 與字串 `"1"` 同鍵——tools/list 關聯在跨型別 id 撞號的病態 client 下可能誤配（既有 parse_line 行為，影響僅告警面）。
- 同毫秒內的指紋震盪（A→B→A 全在 1ms 內）tie-break 依 row id，可能對同一回退重複發 Reverted 告警（僅告警面誤報，需惡意 server 毫秒級連改才觸發）。
- gateway 對 >64MB 的 monitor 模式請求 body 採緩衝轉發（上限 256MB，超限 413）而非零拷貝串流；正常 MCP 訊息（<64MB）不受影響。
- gateway 要求請求帶 loopback Host（防 DNS rebinding）；HTTP/1.0 或 h2c 等不帶 Host 的 client 會被 403——MCP client 實務皆走 HTTP/1.1（hyper 對無 Host 的 1.1 請求本就 400），影響面可忽略。
- 指紋 v1→v2 改釘在「legacy v1 列時間戳晚於既有 v2 同值列」的理論情境下可撞 UNIQUE——單調時鐘下幾乎不可達，fail-open 僅 log 丟該次 outcome。

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
