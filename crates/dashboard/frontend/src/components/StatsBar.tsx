import { useState } from "react";
import type { SessionStats } from "../api";
import { sessionExportUrl } from "../api";
import { formatLatency } from "../format";

interface StatsBarProps {
  stats: SessionStats | null;
  // The selected session, so the export link can target it. Null hides the button.
  sessionId: number | null;
}

export function StatsBar({ stats, sessionId }: StatsBarProps) {
  const [expanded, setExpanded] = useState(false);

  if (!stats) {
    return <div className="stats-bar dim">no stats yet</div>;
  }

  return (
    <div className="stats-bar">
      <div className="stats-readouts">
        <div className="readout">
          <div className="readout-label">messages</div>
          <div className="readout-value">{stats.totals.messages}</div>
        </div>
        <div className="readout">
          <div className="readout-label">invalid</div>
          <div className={"readout-value" + (stats.totals.invalid > 0 ? " readout-value-error" : "")}>
            {stats.totals.invalid}
          </div>
        </div>
        <div className="readout">
          <div className="readout-label">errors</div>
          <div className={"readout-value" + (stats.totals.errors > 0 ? " readout-value-error" : "")}>
            {stats.totals.errors}
          </div>
        </div>
        <div className="stats-actions">
          <button className="stats-toggle" onClick={() => setExpanded((v) => !v)}>
            {expanded ? "hide per-method latency ▲" : "show per-method latency ▼"}
          </button>
          {sessionId !== null && (
            <a
              className="btn stats-export"
              href={sessionExportUrl(sessionId)}
              download
              title="download masked session bundle (secrets redacted)"
            >
              EXPORT
            </a>
          )}
        </div>
      </div>
      {expanded && (
        <table className="stats-table">
          <thead>
            <tr>
              <th>method</th>
              <th>count</th>
              <th>avg latency</th>
              <th>max latency</th>
            </tr>
          </thead>
          <tbody>
            {stats.per_method.map((m) => (
              <tr key={m.method}>
                <td className="mono">{m.method}</td>
                <td className="mono">{m.count}</td>
                <td className="mono">{formatLatency(m.avg_latency_ms)}</td>
                <td className="mono">{formatLatency(m.max_latency_ms)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
