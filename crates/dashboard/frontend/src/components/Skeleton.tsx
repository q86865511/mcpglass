// Loading placeholders — shown only on a first load (no prior data). Refetches
// that already have data keep showing it, so these never flash on a poll tick.
// The pulse is a very light animation, disabled under prefers-reduced-motion by
// the global rule in base.css.

// A stack of shimmer rows for tables (messages / security / inject).
export function TableSkeleton({ rows = 8 }: { rows?: number }) {
  return (
    <div className="skeleton-table" aria-hidden="true">
      {Array.from({ length: rows }).map((_, i) => (
        <div className="skeleton-row" key={i}>
          <span className="skeleton-bar" />
        </div>
      ))}
    </div>
  );
}

// A field-list + raw-well placeholder for the detail panel.
export function DetailSkeleton() {
  return (
    <div className="skeleton-detail" aria-hidden="true">
      <span className="skeleton-bar skeleton-bar-title" />
      {Array.from({ length: 6 }).map((_, i) => (
        <span className="skeleton-bar skeleton-bar-field" key={i} />
      ))}
      <span className="skeleton-bar skeleton-bar-block" />
    </div>
  );
}
