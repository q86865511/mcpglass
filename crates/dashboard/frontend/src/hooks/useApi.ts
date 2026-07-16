import { useCallback, useEffect, useRef, useState, type DependencyList } from "react";

export interface ApiResult<T> {
  // The last successfully fetched value, or null before the first success / while
  // no request is active. A failed refetch keeps the previous data (the error is
  // surfaced alongside it) — matching the old per-view behaviour.
  data: T | null;
  loading: boolean;
  error: string | null;
  // Force a refetch with the current inputs (e.g. after a mutation).
  retry: () => void;
}

/**
 * Declarative data fetching with automatic race protection.
 *
 * Pass a `fetcher` that performs one request honouring the given `AbortSignal`, plus
 * the `deps` that determine *what* to fetch. Whenever `deps` change (or `retry()` is
 * called) the previous request is aborted before a new one starts, so a slow, stale
 * response can never clobber a newer one — this replaces the hand-rolled monotonic
 * sequence counters the dashboard used to keep per resource.
 *
 * Pass `fetcher = null` to represent "no request right now" (e.g. no session selected);
 * the hook then clears its state and issues nothing.
 */
export function useApi<T>(
  fetcher: ((signal: AbortSignal) => Promise<T>) | null,
  deps: DependencyList,
): ApiResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);

  // The fetcher closure is re-created every render; keep it in a ref so it is not part
  // of the effect deps (the caller-supplied `deps` are the real trigger).
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const retry = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    const run = fetcherRef.current;
    if (!run) {
      setData(null);
      setLoading(false);
      setError(null);
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    run(controller.signal)
      .then((d) => {
        if (controller.signal.aborted) return;
        setData(d);
        setError(null);
        setLoading(false);
      })
      .catch((e: unknown) => {
        if (controller.signal.aborted) return;
        // A cancelled request is not a real error.
        if (e instanceof DOMException && e.name === "AbortError") return;
        setError(e instanceof Error ? e.message : String(e));
        setLoading(false);
      });
    return () => controller.abort();
    // deps are the caller's contract for "what to fetch"; nonce drives retry().
  }, [...deps, nonce]);

  return { data, loading, error, retry };
}
