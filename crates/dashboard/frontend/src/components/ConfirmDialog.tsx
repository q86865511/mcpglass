import { useEffect, useRef, type ReactNode } from "react";

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  // Which trace colour the confirm button rides: danger = alarm red (delete),
  // primary = CH1 phosphor (replay and other affirmative actions).
  variant?: "danger" | "primary";
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * A single reusable modal confirmation, replacing native window.confirm.
 *
 * Behaviour: Esc cancels, Enter confirms, focus lands on the cancel button on
 * open and returns to the triggering element on close, and Tab is trapped inside
 * the dialog. A backdrop click cancels. role="dialog" + aria-modal for AT.
 */
export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  variant = "primary",
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const prevFocus = useRef<Element | null>(null);

  // Move focus in on open, restore it on close.
  useEffect(() => {
    if (!open) return;
    prevFocus.current = document.activeElement;
    cancelRef.current?.focus();
    return () => {
      if (prevFocus.current instanceof HTMLElement) prevFocus.current.focus();
    };
  }, [open]);

  // Keyboard: Esc = cancel, Enter = confirm (preventDefault stops a focused
  // button self-activating), Tab = wrap within the dialog's buttons.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onCancel();
      } else if (e.key === "Enter") {
        e.preventDefault();
        onConfirm();
      } else if (e.key === "Tab") {
        const focusables = dialogRef.current?.querySelectorAll<HTMLElement>("button");
        if (!focusables || focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
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
  }, [open, onCancel, onConfirm]);

  if (!open) return null;

  return (
    <div className="modal-scrim" onClick={onCancel}>
      <div
        className="modal-dialog"
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-title tick-label">{title}</div>
        <div className="modal-body">{message}</div>
        <div className="modal-actions">
          <button type="button" className="btn" ref={cancelRef} onClick={onCancel}>
            {cancelLabel}
          </button>
          <button
            type="button"
            className={"btn " + (variant === "danger" ? "btn-danger" : "btn-primary")}
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
