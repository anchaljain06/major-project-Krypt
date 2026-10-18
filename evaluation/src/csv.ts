// CSV writer shared by the result scripts (aggregate, E7). Node-only callers, but no Node imports.

/**
 * Rows to CSV with the first row's keys as columns. Non-finite numbers, null and
 * undefined become empty cells (pandas reads them as NaN). `digits` rounds numbers.
 */
export function toCsv(rows: readonly Record<string, unknown>[], digits?: number): string {
  if (!rows.length) return '';
  const cols = Object.keys(rows[0]);
  const cell = (v: unknown) => {
    if (v === undefined || v === null || (typeof v === 'number' && !Number.isFinite(v))) return '';
    const s = typeof v === 'number' && digits !== undefined ? String(Number(v.toFixed(digits))) : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [cols.join(','), ...rows.map((r) => cols.map((c) => cell(r[c])).join(','))].join('\n') + '\n';
}
