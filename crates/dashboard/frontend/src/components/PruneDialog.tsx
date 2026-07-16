import { useEffect, useRef, useState } from "react";
import type { PruneRequest, PruneResponse } from "../api";
import { postPrune } from "../api";
import { formatSize } from "../format";
import { useToast } from "./Toast";

interface PruneDialogProps {
  open: boolean;
  onCancel: () => void;
  // Called after a successful (non-dry-run) prune, so the caller can refresh the
  // session list. The dialog closes itself first.
  onPruned: () => void;
}

const MS_PER_DAY = 86_400_000;
const BYTES_PER_MB = 1024 * 1024;

// Parse a positive number from a text input; returns null for empty / non-positive
// (which the form treats as "condition not set").
function positive(raw: string): number | null {
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : null;
}

/**
 * Data-lifecycle maintenance: preview then confirm a prune of recorded sessions.
 *
 * A form modal (ConfirmDialog is message-only, so it can't carry the two inputs),
 * sharing the same scrim/dialog chrome and focus behaviour. The flow is two-step:
 * Preview sends dry_run:true and shows the estimate, which unlocks a red Confirm
 * that sends dry_run:false. Editing any input invalidates a shown preview, so the
 * user can never confirm against a stale estimate.
 */
export function PruneDialog({ open, onCancel, onPruned }: PruneDialogProps) {
  const toast = useToast();
  const [olderDays, setOlderDays] = useState("");
  const [maxMb, setMaxMb] = useState("");
  const [vacuum, setVacuum] = useState(false);
  const [preview, setPreview] = useState<PruneResponse | null>(null);
  const [busy, setBusy] = useState(false);

  const dialogRef = useRef<HTMLDivElement>(null);
  const firstFieldRef = useRef<HTMLInputElement>(null);
  const prevFocus = useRef<Element | null>(null);

  // Reset the form each time the dialog opens, and manage focus in/out.
  useEffect(() => {
    if (!open) return;
    setOlderDays("");
    setMaxMb("");
    setVacuum(false);
    setPreview(null);
    setBusy(false);
    prevFocus.current = document.activeElement;
    firstFieldRef.current?.focus();
    return () => {
      if (prevFocus.current instanceof HTMLElement) prevFocus.current.focus();
    };
  }, [open]);

  // Esc cancels; Tab is trapped within the dialog's focusable controls.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onCancel();
      } else if (e.key === "Tab") {
        const focusables = dialogRef.current?.querySelectorAll<HTMLElement>(
          "input, button",
        );
        if (!focusables || focusables.length === 0) return;
        const list = Array.from(focusables).filter((el) => !el.hasAttribute("disabled"));
        if (list.length === 0) return;
        const first = list[0];
        const last = list[list.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onCancel]);

  if (!open) return null;

  const olderMs = positive(olderDays);
  const maxBytes = positive(maxMb);
  // At least one condition is required (matches the backend's 400).
  const canPreview = olderMs !== null || maxBytes !== null;

  const buildBody = (dryRun: boolean): PruneRequest => ({
    ...(olderMs !== null ? { older_than_ms: Math.round(olderMs * MS_PER_DAY) } : {}),
    ...(maxBytes !== null ? { max_size_bytes: Math.round(maxBytes * BYTES_PER_MB) } : {}),
    dry_run: dryRun,
    vacuum,
  });

  // Editing any input invalidates a shown preview — the estimate no longer matches
  // the form, so the confirm step must be re-armed with a fresh Preview.
  const invalidate = () => setPreview(null);

  const runPreview = () => {
    if (!canPreview || busy) return;
    setBusy(true);
    postPrune(buildBody(true))
      .then((r) => setPreview(r))
      .catch((e: unknown) =>
        toast(`Preview failed: ${e instanceof Error ? e.message : String(e)}`, "error"),
      )
      .finally(() => setBusy(false));
  };

  const runPrune = () => {
    if (preview === null || busy) return;
    setBusy(true);
    postPrune(buildBody(false))
      .then((r) => {
        const { sessions, messages } = r.stats;
        toast(
          `Pruned ${sessions} session(s), ${messages} message(s) · ` +
            `${formatSize(r.db_size_before)} → ${formatSize(r.db_size_after)}`,
          "success",
        );
        onPruned();
        onCancel();
      })
      .catch((e: unknown) => {
        toast(`Prune failed: ${e instanceof Error ? e.message : String(e)}`, "error");
        setBusy(false);
      });
  };

  return (
    <div className="modal-scrim" onClick={onCancel}>
      <div
        className="modal-dialog"
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label="Prune recorded data"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-title tick-label">Prune recorded data</div>
        <div className="modal-body">
          <p className="prune-intro">
            Delete recorded sessions by age and/or to a size target.{" "}
            <span className="prune-keep">Tool fingerprints are always kept</span> (the
            cross-session rug-pull baseline).
          </p>
          <div className="prune-form">
            <label className="prune-field">
              <span className="tick-label">older than (days)</span>
              <input
                ref={firstFieldRef}
                type="number"
                min="0"
                step="1"
                inputMode="decimal"
                placeholder="e.g. 30"
                value={olderDays}
                onChange={(e) => {
                  setOlderDays(e.target.value);
                  invalidate();
                }}
              />
            </label>
            <label className="prune-field">
              <span className="tick-label">max size (MB)</span>
              <input
                type="number"
                min="0"
                step="1"
                inputMode="decimal"
                placeholder="e.g. 200"
                value={maxMb}
                onChange={(e) => {
                  setMaxMb(e.target.value);
                  invalidate();
                }}
              />
            </label>
          </div>
          <label className="prune-vacuum">
            <input
              type="checkbox"
              checked={vacuum}
              onChange={(e) => {
                setVacuum(e.target.checked);
                invalidate();
              }}
            />
            <span>
              VACUUM to return freed pages to the OS. A max-size target always
              vacuums; for an age-only prune it is optional.
            </span>
          </label>
          {!canPreview && (
            <p className="prune-hint dim">Set at least one condition to preview.</p>
          )}
          {preview && (
            <div className="prune-preview">
              <div className="tick-label">estimated removal</div>
              <dl className="prune-preview-grid">
                <dt>sessions</dt>
                <dd className="mono">{preview.stats.sessions}</dd>
                <dt>messages</dt>
                <dd className="mono">{preview.stats.messages}</dd>
                <dt>security events</dt>
                <dd className="mono">{preview.stats.security_events}</dd>
                <dt>inject events</dt>
                <dd className="mono">{preview.stats.inject_events}</dd>
                <dt>current DB size</dt>
                <dd className="mono">{formatSize(preview.db_size_before)}</dd>
              </dl>
            </div>
          )}
        </div>
        <div className="modal-actions">
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
          {preview ? (
            <button type="button" className="btn btn-danger" onClick={runPrune} disabled={busy}>
              {busy ? "Pruning…" : "Confirm prune"}
            </button>
          ) : (
            <button
              type="button"
              className="btn btn-primary"
              onClick={runPreview}
              disabled={!canPreview || busy}
            >
              {busy ? "Previewing…" : "Preview"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
