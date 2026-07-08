import { useEffect, useState } from "react";
import type { MessageDetail } from "../api";
import { fetchMessageDetail } from "../api";
import { formatClock, formatSize, tryPrettyJson } from "../format";

interface DetailPanelProps {
  messageId: number | null;
}

export function DetailPanel({ messageId }: DetailPanelProps) {
  const [detail, setDetail] = useState<MessageDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setCopied(false);
    if (messageId === null) {
      setDetail(null);
      setError(null);
      return;
    }
    let cancelled = false;
    fetchMessageDetail(messageId)
      .then((d) => {
        if (!cancelled) {
          setDetail(d);
          setError(null);
        }
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [messageId]);

  if (messageId === null) {
    return (
      <aside className="detail-panel detail-panel-empty">
        <div className="empty-hint">Select a message to see its detail.</div>
      </aside>
    );
  }

  if (error) {
    return (
      <aside className="detail-panel">
        <div className="empty-hint error-text">Failed to load message {messageId}: {error}</div>
      </aside>
    );
  }

  if (!detail) {
    return (
      <aside className="detail-panel">
        <div className="empty-hint">Loading…</div>
      </aside>
    );
  }

  const { pretty, ok } = tryPrettyJson(detail.raw);

  const copy = () => {
    void navigator.clipboard.writeText(detail.raw).then(() => setCopied(true));
  };

  return (
    <aside className="detail-panel">
      <div className="detail-header">Message #{detail.id}</div>
      <dl className="detail-fields">
        <dt>time</dt>
        <dd className="mono">{formatClock(detail.ts_ms)}</dd>
        <dt>direction</dt>
        <dd className="mono">{detail.direction}</dd>
        <dt>method</dt>
        <dd className="mono">{detail.method ?? "(notification)"}</dd>
        <dt>rpc_id</dt>
        <dd className="mono">{detail.rpc_id ?? "—"}</dd>
        <dt>size</dt>
        <dd className="mono">{formatSize(detail.size)}</dd>
        <dt>valid json</dt>
        <dd className="mono">{detail.is_valid_json ? "yes" : "no"}</dd>
        <dt>error</dt>
        <dd className="mono">{detail.is_error ? "yes" : "no"}</dd>
        <dt>session</dt>
        <dd className="mono">{detail.session_id}</dd>
      </dl>
      <div className="detail-raw-header">
        <span>raw{!ok && " (not valid JSON, showing as-is)"}</span>
        <button className="copy-btn" onClick={copy}>
          {copied ? "Copied!" : "Copy"}
        </button>
      </div>
      <pre className="detail-raw mono">{pretty}</pre>
    </aside>
  );
}
