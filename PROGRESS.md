# PROGRESS — mcpglass

## 目前狀態
Phase 2 安全層完成：policy 引擎（TOML、monitor/enforce）、c2s 決策式攔阻（enforce 下命中 deny/secret 合成 -32001 拒絕）、跨 session tool 指紋防 rug-pull、append-only 稽核日誌、儀表板 Security tab，皆過雙重審查與修正，91 Rust 測試＋前端 build 全綠。下一步 Phase 3 補完。

## 已完成
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
- 審查遺留（低優先）：`attach claude-code` 涵蓋 `~/.claude.json` 的 `projects.<path>.mcpServers`（project-local scope）；dashboard 連線快取（現為每請求開 Store，MVP 可接受）；文案微調（s2c 徽章、搜尋 placeholder、npx 手動 wrap 的預設 label）。
- Phase 3（補完）：HTTP（streamable）transport、context bloat 分析、請求 replay、錯誤注入；安全層增強（指紋納入 annotations 欄位、A→B→A 震盪告警、指紋比對關聯 request 的更嚴格化）。
- Phase 4（發佈）：英文 docs＋demo GIF、GitHub 開源、Show HN / r/mcp 發文、收進 terrychou.com 作品集。

## 已知問題
- 本機 SQLite 會存**原始流量全文**（含任何流經的密鑰）——這是「流量 Wireshark」的核心設計，資料不出本機；secret 過濾只在 `security_events.detail` 遮罩並告警/阻擋外流。已在 README 明示。
- s2c 超大單幀（>64MB 單行 server 回應）分段寫出期間，enforce 的 c2s 拒絕回應理論上可插入撕裂該幀——需 64MB 單行＋並發命中，屬病理邊界，已註解為已知取捨。
- 指紋僅涵蓋 tool 的 name/description/inputSchema；server 若只改 annotations（readOnlyHint 等次要欄位）不觸發告警（列 Phase 3 增強）。

## 重要決策紀錄
- [2026-07-08] 選題依據市調：企業級 MCP gateway 紅海、registry 被官方卡死，空窗在「個人開發者本機觀測層」（Inspector 看不到真實流量、競品 2026-07 才出現）；Invariant Labs 被 Snyk 收購證明出口存在。
- [2026-07-08] 技術選型：Rust workspace（proxy-core / storage / policy / cli / dashboard）＋ React/TS 前端以 rust-embed 嵌入 → 單一執行檔。理由：單 binary 是差異化武器，前端沿用既有強項。
- [2026-07-08] 授權 Apache-2.0（對商業採用友善，利於 open-core）；README/docs 英文優先（全球客群），PROGRESS.md 維持中文。
- [2026-07-08] Phase 2 安全層定位：**預設 monitor（只觀測告警不阻擋），enforce 為 opt-in**（使用者拍板）。攔阻採「協定內合法拒絕」——enforce 命中時不斷線，改合成 -32001 error response 回 client，其餘流量零影響；與 fail-open 嚴格區分（代理自身故障永遠放行，只有政策明確命中才擋）。rug-pull 指紋以 server 啟動指令為身分**跨 session** 比對（同 session 內偵測對真實攻擊無意義）。
- [2026-07-08] 定名 **mcpglass**（原暫名 mcp-lens）：mcp-lens 在 GitHub 至少 6 個同名 repo（含一個 MCP proxy）、npm 已占用；mcptap 被 jondot/mcptap（15★，「wireshark but for MCP」，直接競品，需持續關注）占用；mcpglass 查證 GitHub 全文／crates.io／npm／PyPI 四處全空。
- [2026-07-08] 硬需求：透明直通零破壞，代理內部錯誤一律 fail-open 直通。
