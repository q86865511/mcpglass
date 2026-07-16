import type { ContextReport } from "../api";

interface ContextViewProps {
  report: ContextReport | null;
}

// How many of the heaviest tools to show in the table. The backend already
// sorts `tools` heaviest-first over the full catalog; this is a display cap
// only — the totals above the table always reflect every tool.
const TOP_N = 10;

export function ContextView({ report }: ContextViewProps) {
  if (!report) {
    return <div className="empty-hint dim">no context data yet</div>;
  }

  if (report.tool_count === 0) {
    return (
      <div className="security-view">
        <div className="empty-hint">
          No tools/list captured for this session yet.
          <br />
          <span className="dim">
            (context-bloat analysis needs a recorded tools/list request paired with its response.)
          </span>
        </div>
      </div>
    );
  }

  const top = report.tools.slice(0, TOP_N);

  return (
    <div className="security-view">
      <div className="context-total">
        <span className="context-total-value">
          ~{report.est_total_tokens.toLocaleString()}
        </span>
        <span className="dim">
          estimated tokens — approximate (chars/4), not a real tokenizer count
        </span>
      </div>

      <div className="security-badges">
        <span className="count-badge">
          tools <b className="mono">{report.tool_count}</b>
        </span>
        <span className="count-badge">
          total chars <b className="mono">{report.total_chars.toLocaleString()}</b>
        </span>
        <span className={"count-badge" + (report.fat_tools.length > 0 ? " count-badge-blocked" : "")}>
          fat tools <b className="mono">{report.fat_tools.length}</b>
        </span>
      </div>

      <table className="security-table context-table">
        <thead>
          <tr>
            <th>tool</th>
            <th>est. tokens</th>
            <th>chars</th>
            <th>share of total</th>
          </tr>
        </thead>
        <tbody>
          {top.map((t) => (
            <tr key={t.name} className="security-row">
              <td className="mono">{t.name}</td>
              <td className="mono">{t.est_tokens.toLocaleString()}</td>
              <td className="mono">{t.total_chars.toLocaleString()}</td>
              <td>
                <div className="context-bar-cell">
                  <div className="context-bar-track">
                    <div
                      className="context-bar-fill"
                      style={{ width: `${Math.min(100, t.pct)}%` }}
                    />
                  </div>
                  <span className="mono dim">{t.pct.toFixed(1)}%</span>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {report.fat_tools.length > 0 && (
        <div className="context-trim">
          <div className="dim">
            Trim candidates — description alone estimates over the fat threshold:
          </div>
          <ul>
            {report.fat_tools.map((name) => (
              <li key={name} className="mono">
                {name}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
