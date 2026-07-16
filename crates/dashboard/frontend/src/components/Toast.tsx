import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";

// Semantic classes map to the left edge-bar colour: success = CH1 phosphor,
// error = alarm red, info = a neutral dim rail.
export type ToastVariant = "success" | "error" | "info";

interface Toast {
  id: number;
  message: string;
  variant: ToastVariant;
}

// A single push(message, variant?) function is all consumers need.
type PushToast = (message: string, variant?: ToastVariant) => void;

const ToastContext = createContext<PushToast>(() => {
  // No provider mounted — pushes are silently dropped rather than throwing, so a
  // component can call useToast() defensively without a hard dependency.
});

export function useToast(): PushToast {
  return useContext(ToastContext);
}

let toastSeq = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const remove = useCallback((id: number) => {
    setToasts((ts) => ts.filter((t) => t.id !== id));
  }, []);

  const push = useCallback<PushToast>((message, variant = "info") => {
    setToasts((ts) => [...ts, { id: toastSeq++, message, variant }]);
  }, []);

  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toast-stack" aria-live="polite" aria-atomic="false">
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} onClose={() => remove(t.id)} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

const DISMISS_MS = 4000;
const EXIT_MS = 120; // matches the fade-out transition in components.css

function ToastItem({ toast, onClose }: { toast: Toast; onClose: () => void }) {
  const [leaving, setLeaving] = useState(false);
  const dismissTimer = useRef<number | undefined>(undefined);
  const exitTimer = useRef<number | undefined>(undefined);

  // Begin the fade-out, then actually unmount after the transition window.
  const close = useCallback(() => {
    if (exitTimer.current !== undefined) return; // already leaving
    setLeaving(true);
    exitTimer.current = window.setTimeout(onClose, EXIT_MS);
  }, [onClose]);

  const startDismiss = useCallback(() => {
    window.clearTimeout(dismissTimer.current);
    dismissTimer.current = window.setTimeout(close, DISMISS_MS);
  }, [close]);

  useEffect(() => {
    startDismiss();
    return () => {
      window.clearTimeout(dismissTimer.current);
      window.clearTimeout(exitTimer.current);
    };
  }, [startDismiss]);

  // Hover pauses the auto-dismiss countdown; leaving restarts it.
  const pause = () => window.clearTimeout(dismissTimer.current);
  const resume = () => {
    if (!leaving) startDismiss();
  };

  return (
    <div
      className={"toast toast-" + toast.variant + (leaving ? " toast-leaving" : "")}
      onMouseEnter={pause}
      onMouseLeave={resume}
      role="status"
    >
      <span className="toast-msg">{toast.message}</span>
      <button type="button" className="toast-close" onClick={close} aria-label="Dismiss">
        ×
      </button>
    </div>
  );
}
