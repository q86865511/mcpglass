import type { Direction, InjectCounts, InjectEvent, InjectFault } from "../api";
import { formatClock } from "../format";
import { Pagination } from "./Pagination";

interface InjectViewProps {
  counts: InjectCounts | null;
  events: InjectEvent[];
  total: number;
  offset: number;
  limit: number;
  onOffsetChange: (offset: number) => void;
}

const FAULT_LABEL: Record<InjectFault, string> = {
  delay: "delay",
  error: "error",
  drop: "drop",
  truncate: "truncate",
};

const DIRECTION_LABEL: Record<Direction, string> = {
  c2s: "c2s",
  s2c: "s2c",
};

function FaultBadge({ fault }: { fault: InjectFault }) {
  return <span className={`badge badge-fault-${fault}`}>{FAULT_LABEL[fault]}</span>;
}

function CountBadges({ counts }: { counts: InjectCounts | null }) {
  if (!counts) {
    return <div className="inject-badges dim">no counts yet</div>;
  }
  const { delay, error, drop, truncate } = counts;
  return (
    <div className="inject-badges">
      <span className={"count-badge" + (delay > 0 ? " count-badge-delay" : "")}>
        delay <b className="mono">{delay}</b>
      </span>
      <span className={"count-badge" + (error > 0 ? " count-badge-error" : "")}>
        error <b className="mono">{error}</b>
      </span>
      <span className={"count-badge" + (drop > 0 ? " count-badge-drop" : "")}>
        drop <b className="mono">{drop}</b>
      </span>
      <span className={"count-badge" + (truncate > 0 ? " count-badge-truncate" : "")}>
        truncate <b className="mono">{truncate}</b>
      </span>
    </div>
  );
}

export function InjectView({ counts, events, total, offset, limit, onOffsetChange }: InjectViewProps) {
  return (
    <div className="inject-view">
      <CountBadges counts={counts} />
      {events.length === 0 ? (
        <div className="empty-hint">
          No fault-injection events — nothing simulated for this session.
          <br />
          <span className="dim">
            (mcpglass only injects faults when `--inject` rules are configured on `wrap`/`gateway`.)
          </span>
        </div>
      ) : (
        <>
          <table className="inject-table">
            <thead>
              <tr>
                <th>time</th>
                <th>direction</th>
                <th>fault</th>
                <th>rule</th>
                <th>method</th>
                <th>detail</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} className="inject-row">
                  <td className="mono">{formatClock(e.ts_ms)}</td>
                  <td className="mono">{DIRECTION_LABEL[e.direction]}</td>
                  <td>
                    <FaultBadge fault={e.fault} />
                  </td>
                  <td className="mono">{e.rule}</td>
                  <td className="mono">{e.method ?? <span className="dim">—</span>}</td>
                  <td className="inject-detail">{e.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination offset={offset} limit={limit} total={total} onOffsetChange={onOffsetChange} />
        </>
      )}
    </div>
  );
}
