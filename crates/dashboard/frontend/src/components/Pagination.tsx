interface PaginationProps {
  offset: number;
  limit: number;
  total: number;
  onOffsetChange: (offset: number) => void;
}

export function Pagination({ offset, limit, total, onOffsetChange }: PaginationProps) {
  const page = Math.floor(offset / limit) + 1;
  const pageCount = Math.max(1, Math.ceil(total / limit));
  const canPrev = offset > 0;
  const canNext = offset + limit < total;

  return (
    <div className="pagination">
      <button disabled={!canPrev} onClick={() => onOffsetChange(Math.max(0, offset - limit))}>
        ← prev
      </button>
      <span className="mono">
        page {page} / {pageCount} · {total} total
      </span>
      <button disabled={!canNext} onClick={() => onOffsetChange(offset + limit)}>
        next →
      </button>
    </div>
  );
}
