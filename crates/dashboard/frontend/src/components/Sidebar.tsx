import type { SessionSummary } from "../api";
import { formatDateTime } from "../format";

interface SidebarProps {
  sessions: SessionSummary[];
  selectedId: number | null;
  onSelect: (id: number) => void;
  onDelete: (id: number) => void;
  // Opens the data-lifecycle (prune) dialog from the pinned footer button.
  onPrune: () => void;
  // Drawer state — applied as an open class at the <=900px off-canvas breakpoint;
  // ignored (sidebar is always in-flow) on wider viewports.
  open: boolean;
}

export function Sidebar({ sessions, selectedId, onSelect, onDelete, onPrune, open }: SidebarProps) {
  return (
    <aside className={"sidebar" + (open ? " sidebar-open" : "")}>
      <div className="sidebar-header tick-label">Sessions</div>
      <ul className="session-list">
        {sessions.map((s) => {
          const live = s.ended_at_ms === null;
          return (
            <li key={s.id} className="session-row">
              <button
                className={
                  "session-item" + (s.id === selectedId ? " session-item-active" : "")
                }
                onClick={() => onSelect(s.id)}
              >
                <div className="session-item-top">
                  {/* Status LED: green trace while live, otherwise a faint idle dot.
                      (No red — a blocked-session signal would need a count the
                      sessions list endpoint doesn't carry.) */}
                  <span
                    className={"status-led" + (live ? " status-led-live" : "")}
                    title={live ? "in progress" : undefined}
                    aria-hidden="true"
                  />
                  <span className="session-label">{s.label}</span>
                </div>
                <div className="session-item-meta">
                  <span>{formatDateTime(s.started_at_ms)}</span>
                  <span>{s.message_count} msgs</span>
                </div>
                {s.protocol_version && (
                  <div className="session-item-proto">
                    <span
                      className="badge badge-proto"
                      title={
                        "MCP protocol " +
                        s.protocol_version +
                        (s.protocol_version_source ? ` (via ${s.protocol_version_source})` : "")
                      }
                    >
                      MCP {s.protocol_version}
                    </span>
                  </div>
                )}
              </button>
              <button
                className="session-delete"
                title="Delete this session"
                aria-label={`Delete session ${s.label}`}
                onClick={() => onDelete(s.id)}
              >
                ×
              </button>
            </li>
          );
        })}
      </ul>
      <div className="sidebar-footer">
        <button
          type="button"
          className="sidebar-prune tick-label"
          onClick={onPrune}
          title="Delete recorded sessions by age or size (tool fingerprints kept)"
        >
          Prune data
        </button>
      </div>
    </aside>
  );
}
