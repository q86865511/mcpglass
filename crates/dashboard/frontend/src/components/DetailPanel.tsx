import { useEffect, useState } from "react";
import type { MessageDetail, ReplayResult } from "../api";
import { fetchMessageDetail, postReplay } from "../api";
import { formatClock, formatSize, tryPrettyJson } from "../format";

interface DetailPanelProps {
  messageId: number | null;
}

export function DetailPanel({ messageId }: DetailPanelProps) {
  const [detail, setDetail] = useState<MessageDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [replaying, setReplaying] = useState(false);
  const [replayResult, setReplayResult] = useState<ReplayResult | null>(null);
  const [replayError, setReplayError] = useState<string | null>(null);

  useEffect(() => {
    setCopied(false);
    // Any pending replay result belongs to the previously selected message.
    setReplaying(false);
    setReplayResult(null);
    setReplayError(null);
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

  // A metadata-only recording (`--record metadata`): the body was deliberately not
  // stored, so `raw` is empty and `raw_len` carries the original byte length.
  const metadataOnly = detail.raw === "" && detail.raw_len !== null;

  const copy = () => {
    void navigator.clipboard.writeText(detail.raw).then(() => setCopied(true));
  };

  // Only a client->server request (has a method and an id) can be replayed; a
  // response, a notification, or an s2c frame has nothing to re-send — and a
  // metadata-only recording has no body to send at all.
  const canReplay =
    detail.direction === "c2s" &&
    detail.method !== null &&
    detail.rpc_id !== null &&
    !metadataOnly;

  const doReplay = () => {
    if (!window.confirm("Re-send this request to the server? Side effects may occur.")) {
      return;
    }
    setReplaying(true);
    setReplayResult(null);
    setReplayError(null);
    postReplay(detail.id)
      .then((r) => setReplayResult(r))
      .catch((e: unknown) => setReplayError(e instanceof Error ? e.message : String(e)))
      .finally(() => setReplaying(false));
  };

  return (
    <aside className="detail-panel">
      <div className="detail-header">Message #{detail.id}</div>
      <dl className="detail-fields">
        <dt>time</dt>
        <dd className="mono">{formatClock(detail.ts_ms)}</dd>
        <dt>direction</dt>
        <dd className={"mono channel-" + detail.direction}>{detail.direction}</dd>
        <dt>method</dt>
        <dd className="mono">
          {detail.method ?? (detail.rpc_id != null ? "(response)" : "(notification)")}
        </dd>
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
        <span>
          raw
          {metadataOnly
            ? " (metadata-only, body not recorded)"
            : !ok && " (not valid JSON, showing as-is)"}
        </span>
        {!metadataOnly && (
          <button className="copy-btn" onClick={copy}>
            {copied ? "Copied!" : "Copy"}
          </button>
        )}
      </div>
      {metadataOnly ? (
        <div className="empty-hint">
          This message was recorded in metadata-only mode. Its body was not stored
          (original size {formatSize(detail.size)}).
        </div>
      ) : (
        <pre className="detail-raw mono">{pretty}</pre>
      )}
      {canReplay && (
        <div className="detail-raw-header">
          <span>replay</span>
          <button className="copy-btn btn-primary" onClick={doReplay} disabled={replaying}>
            {replaying ? "Replaying…" : "Replay"}
          </button>
        </div>
      )}
      {replayError && (
        <div className="empty-hint error-text">Replay failed: {replayError}</div>
      )}
      {replayResult && (
        <>
          <div className="detail-raw-header">
            <span>replay response · {replayResult.transport}</span>
          </div>
          <pre className="detail-raw mono">
            {replayResult.response_raw === null
              ? "(no response captured)"
              : tryPrettyJson(replayResult.response_raw).pretty}
          </pre>
          <div className="empty-hint">{replayResult.note}</div>
        </>
      )}
    </aside>
  );
}
