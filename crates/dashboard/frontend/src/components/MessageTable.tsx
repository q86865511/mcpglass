import type { MessageSummary } from "../api";
import { formatClock, formatSize } from "../format";

interface MessageTableProps {
  messages: MessageSummary[];
  selectedId: number | null;
  onSelect: (id: number) => void;
}

function DirectionBadge({ msg }: { msg: MessageSummary }) {
  if (msg.is_error) {
    return <span className="badge badge-error">error</span>;
  }
  if (msg.direction === "c2s") {
    return <span className="badge badge-c2s">client &rarr; server</span>;
  }
  return <span className="badge badge-s2c">server &rarr; client</span>;
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
            <td className="mono">{m.method ?? <span className="dim">(notification)</span>}</td>
            <td className="mono">{m.rpc_id ?? <span className="dim">—</span>}</td>
            <td className="mono">{formatSize(m.size)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
