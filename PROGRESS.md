# PROGRESS — mcp-lens

## 目前狀態
專案剛初始化：計劃已定（MCP 本機觀測／安全代理，Rust 單一 binary），進入 Phase 0 風險尖刺。

## 已完成
- [2026-07-08] 📄 R1 專案初始化：市調（兩個研究 agent 查證 MCP 生態縫隙）→ 選題「MCP 本機觀測／安全代理」→ 10 週計劃核准（計劃檔：`~/.claude/plans/godot-aivtuber-functional-toucan.md`）→ 建基礎文件與 git repo。

## 進行中
- Phase 0 風險尖刺：最小 stdio wrapper 透明攔截（spawn 真 server 為子行程、雙向轉發、JSON-RPC 解析落 SQLite），用官方 filesystem server ＋真實 client 端到端驗證零破壞。失敗＝重估題目。

## 待辦
- Phase 1（MVP）：CLI（wrap/unwrap/dashboard）＋ client 設定檔一鍵接管與還原 ＋ 本機儀表板（axum 內嵌 React 前端）。
- Phase 2（安全層）：tool schema 指紋釘選（防 rug-pull）、secrets 外洩過濾、per-tool allow/deny 政策、append-only 稽核日誌。
- Phase 3（補完）：HTTP（streamable）transport、context bloat 分析、請求 replay、錯誤注入。
- Phase 4（發佈）：英文 docs＋demo GIF、GitHub 開源、Show HN / r/mcp 發文、收進 terrychou.com 作品集。
- 正式命名（暫名 mcp-lens，需查名稱衝突）與 GitHub repo 建立。

## 已知問題
（無）

## 重要決策紀錄
- [2026-07-08] 選題依據市調：企業級 MCP gateway 紅海、registry 被官方卡死，空窗在「個人開發者本機觀測層」（Inspector 看不到真實流量、競品 2026-07 才出現）；Invariant Labs 被 Snyk 收購證明出口存在。
- [2026-07-08] 技術選型：Rust workspace（proxy-core / storage / policy / cli / dashboard）＋ React/TS 前端以 rust-embed 嵌入 → 單一執行檔。理由：單 binary 是差異化武器，前端沿用既有強項。
- [2026-07-08] 授權 Apache-2.0（對商業採用友善，利於 open-core）；README/docs 英文優先（全球客群），PROGRESS.md 維持中文。
- [2026-07-08] 硬需求：透明直通零破壞，代理內部錯誤一律 fail-open 直通。
