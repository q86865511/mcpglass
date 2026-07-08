import { useState } from "react";
import type { SessionStats } from "../api";
import { formatLatency } from "../format";

interface StatsBarProps {
  stats: SessionStats | null;
}

export function StatsBar({ stats }: StatsBarProps) {
  const [expanded, setExpanded] = useState(false);

  if (!stats) {
    return <div className="stats-bar dim">no stats yet</div>;
  }

  return (
    <div className="stats-bar">
      <div className="stats-totals">
        <span>
          messages: <b className="mono">{stats.totals.messages}</b>
        </span>
        <span>
          invalid: <b className="mono">{stats.totals.invalid}</b>
        </span>
        <span>
          errors: <b className="mono">{stats.totals.errors}</b>
        </span>
        <button className="stats-toggle" onClick={() => setExpanded((v) => !v)}>
          {expanded ? "hide per-method latency ▲" : "show per-method latency ▼"}
        </button>
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
