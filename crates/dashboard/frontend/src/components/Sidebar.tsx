import type { SessionSummary } from "../api";
import { formatDateTime } from "../format";

interface SidebarProps {
  sessions: SessionSummary[];
  selectedId: number | null;
  onSelect: (id: number) => void;
}

export function Sidebar({ sessions, selectedId, onSelect }: SidebarProps) {
  return (
    <aside className="sidebar">
      <div className="sidebar-header">Sessions</div>
      <ul className="session-list">
        {sessions.map((s) => {
          const live = s.ended_at_ms === null;
          return (
            <li key={s.id}>
              <button
                className={
                  "session-item" + (s.id === selectedId ? " session-item-active" : "")
                }
                onClick={() => onSelect(s.id)}
              >
                <div className="session-item-top">
                  {live && <span className="live-dot" title="in progress" />}
                  <span className="session-label">{s.label}</span>
                </div>
                <div className="session-item-meta">
                  <span>{formatDateTime(s.started_at_ms)}</span>
                  <span>{s.message_count} msgs</span>
                </div>
              </button>
            </li>
          );
        })}
      </ul>
    </aside>
  );
}
