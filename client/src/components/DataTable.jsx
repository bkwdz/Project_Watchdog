function resolveCell(row, column) {
  if (typeof column.render === 'function') {
    return column.render(row);
  }

  return row[column.key] ?? '-';
}

export default function DataTable({
  columns,
  rows,
  emptyMessage = 'No records found.',
  rowKey = 'id',
  onRowClick,
}) {
  const hasRows = Array.isArray(rows) && rows.length > 0;

  return (
    <div className="table-wrapper">
      <table className="ui-table">
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key || column.header} className={column.align ? `align-${column.align}` : ''}>
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {!hasRows && (
            <tr>
              <td colSpan={columns.length} className="table-empty">
                {emptyMessage}
              </td>
            </tr>
          )}

          {hasRows &&
            rows.map((row, idx) => (
              <tr
                key={row[rowKey] ?? `${idx}`}
                className={onRowClick ? 'table-row-clickable' : ''}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
              >
                {columns.map((column) => (
                  <td key={`${column.key || column.header}-${row[rowKey] ?? idx}`} className={column.align ? `align-${column.align}` : ''}>
                    {resolveCell(row, column)}
                  </td>
                ))}
              </tr>
            ))}
        </tbody>
      </table>
    </div>
  );
}
