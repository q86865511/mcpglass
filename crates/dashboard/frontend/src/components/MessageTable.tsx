import type { MessageSummary } from "../api";
import { formatClock, formatSize } from "../format";

interface MessageTableProps {
  messages: MessageSummary[];
  selectedId: number | null;
  onSelect: (id: number) => void;
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

export function MessageTable({ messages, selectedId, onSelect }: MessageTableProps) {
  if (messages.length === 0) {
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
        {messages.map((m) => (
          <tr
            key={m.id}
            className={
              "message-row" +
              (m.id === selectedId ? " message-row-active" : "") +
              (!m.is_valid_json ? " message-row-invalid" : "")
            }
            onClick={() => onSelect(m.id)}
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
        ))}
      </tbody>
    </table>
  );
}
