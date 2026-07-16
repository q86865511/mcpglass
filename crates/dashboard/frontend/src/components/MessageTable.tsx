import { useEffect, useRef } from "react";
import type { MessageSummary } from "../api";
import { formatClock, formatSize } from "../format";
import { TableSkeleton } from "./Skeleton";

interface MessageTableProps {
  messages: MessageSummary[];
  selectedId: number | null;
  onSelect: (id: number) => void;
  // First-load flag: show a skeleton only when loading with no prior rows.
  loading: boolean;
}

function DirectionBadge({ msg }: { msg: MessageSummary }) {
  if (msg.is_error) {
    return <span className="badge badge-error">ERR</span>;
  }
  // CH1 = c2s (client → server), CH2 = s2c (server → client).
  if (msg.direction === "c2s") {
    return (
      <span className="badge badge-c2s" title="c2s (client → server)">
        ▲ C1
      </span>
    );
  }
  return (
    <span className="badge badge-s2c" title="s2c (server → client)">
      ▼ C2
    </span>
  );
}

export function MessageTable({ messages, selectedId, onSelect, loading }: MessageTableProps) {
  const activeRowRef = useRef<HTMLTableRowElement>(null);

  // Keep the selected row in view — a no-op when it is already fully visible, so
  // mouse clicks on visible rows don't jump, but j/k onto an off-screen row scrolls.
  useEffect(() => {
    activeRowRef.current?.scrollIntoView({ block: "nearest" });
  }, [selectedId]);

  if (messages.length === 0) {
    if (loading) return <TableSkeleton rows={8} />;
    return <div className="empty-hint">No messages match the current filters.</div>;
  }

  return (
    <table className="message-table">
      <thead>
        <tr>
          <th>time</th>
          <th>direction</th>
          <th>method</th>
          <th>rpc_id</th>
          <th>size</th>
        </tr>
      </thead>
      <tbody>
        {messages.map((m) => {
          const active = m.id === selectedId;
          return (
            <tr
              key={m.id}
              ref={active ? activeRowRef : undefined}
              tabIndex={0}
              aria-selected={active}
              className={
                "message-row" +
                (active ? " message-row-active" : "") +
                (!m.is_valid_json ? " message-row-invalid" : "")
              }
              onClick={() => onSelect(m.id)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onSelect(m.id);
                }
              }}
            >
              <td className="mono">{formatClock(m.ts_ms)}</td>
              <td>
                <DirectionBadge msg={m} />
              </td>
              <td className="mono">
                {m.method ?? (
                  <span className="dim">{m.rpc_id != null ? "(response)" : "(notification)"}</span>
                )}
              </td>
              <td className="mono">{m.rpc_id ?? <span className="dim">—</span>}</td>
              <td className="mono">{formatSize(m.size)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
