import type { Direction } from "../api";
import type { Theme } from "../hooks/useTheme";

interface ToolbarProps {
  direction: Direction | "";
  onDirectionChange: (v: Direction | "") => void;
  method: string;
  onMethodChange: (v: string) => void;
  query: string;
  onQueryChange: (v: string) => void;
  autoRefresh: boolean;
  onAutoRefreshChange: (v: boolean) => void;
  theme: Theme;
  onToggleTheme: () => void;
}

export function Toolbar({
  direction,
  onDirectionChange,
  method,
  onMethodChange,
  query,
  onQueryChange,
  autoRefresh,
  onAutoRefreshChange,
  theme,
  onToggleTheme,
}: ToolbarProps) {
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
        type="text"
        placeholder="search raw JSON..."
        value={query}
        onChange={(e) => onQueryChange(e.target.value)}
        className="toolbar-search"
      />
      <label className="toolbar-toggle">
        <input
          type="checkbox"
          checked={autoRefresh}
          onChange={(e) => onAutoRefreshChange(e.target.checked)}
        />
        auto-refresh (2s)
      </label>
      <button
        type="button"
        className="theme-toggle"
        onClick={onToggleTheme}
        title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
        aria-label="Toggle colour theme"
      >
        {theme === "dark" ? "☀" : "☾"}
      </button>
    </div>
  );
}
