import type { ActionTaken, SecurityCounts, SecurityEvent, SecurityEventKind } from "../api";
import { formatClock } from "../format";
import { Pagination } from "./Pagination";

interface SecurityViewProps {
  counts: SecurityCounts | null;
  events: SecurityEvent[];
  total: number;
  offset: number;
  limit: number;
  onOffsetChange: (offset: number) => void;
}

const KIND_LABEL: Record<SecurityEventKind, string> = {
  policy_deny: "policy deny",
  secret_leak: "secret leak",
  fingerprint_change: "fingerprint change",
};

function KindBadge({ kind }: { kind: SecurityEventKind }) {
  return <span className={`badge badge-kind-${kind}`}>{KIND_LABEL[kind]}</span>;
}

function ActionBadge({ action }: { action: ActionTaken }) {
  return <span className={`badge badge-action-${action}`}>{action}</span>;
}

function CountBadges({ counts }: { counts: SecurityCounts | null }) {
  if (!counts) {
    return <div className="security-badges dim">no counts yet</div>;
  }
  const { policy_deny, secret_leak, fingerprint_change, blocked } = counts;
  return (
    <div className="security-badges">
      <span className={"count-badge" + (policy_deny > 0 ? " count-badge-policy_deny" : "")}>
        policy deny <b className="mono">{policy_deny}</b>
      </span>
      <span className={"count-badge" + (secret_leak > 0 ? " count-badge-secret_leak" : "")}>
        secret leak <b className="mono">{secret_leak}</b>
      </span>
      <span
        className={"count-badge" + (fingerprint_change > 0 ? " count-badge-fingerprint_change" : "")}
      >
        fingerprint change <b className="mono">{fingerprint_change}</b>
      </span>
      <span className={"count-badge" + (blocked > 0 ? " count-badge-blocked" : "")}>
        blocked <b className="mono">{blocked}</b>
      </span>
    </div>
  );
}

export function SecurityView({ counts, events, total, offset, limit, onOffsetChange }: SecurityViewProps) {
  return (
    <div className="security-view">
      <CountBadges counts={counts} />
      {events.length === 0 ? (
        <div className="empty-hint">
          No security events — traffic looks clean.
          <br />
          <span className="dim">
            (mcpglass only flags in monitor mode; enable enforce mode to also block.)
          </span>
        </div>
      ) : (
        <>
          <table className="security-table">
            <thead>
              <tr>
                <th>time</th>
                <th>kind</th>
                <th>rule</th>
                <th>tool</th>
                <th>action</th>
                <th>detail</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} className="security-row">
                  <td className="mono">{formatClock(e.ts_ms)}</td>
                  <td>
                    <KindBadge kind={e.kind} />
                  </td>
                  <td className="mono">{e.rule}</td>
                  <td className="mono">{e.tool_name ?? <span className="dim">—</span>}</td>
                  <td>
                    <ActionBadge action={e.action_taken} />
                  </td>
                  <td className="security-detail">{e.detail}</td>
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
