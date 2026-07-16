import { useEffect, useState, type RefObject } from "react";
import type { Direction } from "../api";

interface ToolbarProps {
  direction: Direction | "";
  onDirectionChange: (v: Direction | "") => void;
  method: string;
  onMethodChange: (v: string) => void;
  query: string;
  onQueryChange: (v: string) => void;
  autoRefresh: boolean;
  onAutoRefreshChange: (v: boolean) => void;
  // Lets the `/` shortcut in App focus the raw-JSON search box.
  searchInputRef: RefObject<HTMLInputElement>;
}

// The raw-JSON search debounces so typing doesn't fire a fetch per keystroke.
const SEARCH_DEBOUNCE_MS = 250;

export function Toolbar({
  direction,
  onDirectionChange,
  method,
  onMethodChange,
  query,
  onQueryChange,
  autoRefresh,
  onAutoRefreshChange,
  searchInputRef,
}: ToolbarProps) {
  // Local mirror of the search box so keystrokes stay responsive while the
  // committed `query` (a fetch dep) updates on a debounce.
  const [localQuery, setLocalQuery] = useState(query);

  // Keep in sync when the committed query changes from outside (e.g. a filter
  // reset). No-op when it already matches after a debounced commit.
  useEffect(() => {
    setLocalQuery(query);
  }, [query]);

  useEffect(() => {
    if (localQuery === query) return; // nothing pending
    if (localQuery === "") {
      onQueryChange(""); // clearing the box takes effect immediately
      return;
    }
    const id = window.setTimeout(() => onQueryChange(localQuery), SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(id);
  }, [localQuery, query, onQueryChange]);

  return (
    <div className="toolbar">
      <select
        value={direction}
        onChange={(e) => onDirectionChange(e.target.value as Direction | "")}
        title="Filter by direction"
      >
        <option value="">all directions</option>
        <option value="c2s">c2s (client → server)</option>
        <option value="s2c">s2c (server → client)</option>
      </select>
      <input
        type="text"
        placeholder="method (exact)"
        value={method}
        onChange={(e) => onMethodChange(e.target.value)}
      />
      <input
        ref={searchInputRef}
        type="text"
        placeholder="search raw JSON... ( / )"
        value={localQuery}
        onChange={(e) => setLocalQuery(e.target.value)}
        className="toolbar-search"
      />
      <label className="toolbar-toggle">
        <input
          type="checkbox"
          checked={autoRefresh}
          onChange={(e) => onAutoRefreshChange(e.target.checked)}
        />
        auto-refresh (3s)
      </label>
    </div>
  );
}
