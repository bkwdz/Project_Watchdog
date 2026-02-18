function toColorStops(segments, total) {
  if (!Array.isArray(segments) || total <= 0) {
    return 'conic-gradient(rgba(148, 163, 184, 0.28) 0deg 360deg)';
  }

  let consumed = 0;
  const stops = [];

  segments.forEach((segment) => {
    const value = Number(segment?.value || 0);

    if (value <= 0) {
      return;
    }

    const start = (consumed / total) * 360;
    consumed += value;
    const end = (consumed / total) * 360;
    const color = segment.color || 'rgba(148, 163, 184, 0.55)';
    stops.push(`${color} ${start}deg ${end}deg`);
  });

  if (stops.length === 0) {
    return 'conic-gradient(rgba(148, 163, 184, 0.28) 0deg 360deg)';
  }

  return `conic-gradient(${stops.join(', ')})`;
}

export default function PieChart({ title = '', segments = [], totalLabel = '' }) {
  const total = segments.reduce((sum, segment) => sum + Number(segment?.value || 0), 0);
  const gradient = toColorStops(segments, total);

  return (
    <div className="pie-chart-wrap">
      <div className="pie-chart-shell">
        <div className="pie-chart-graphic" style={{ backgroundImage: gradient }}>
          <div className="pie-chart-center">
            <span className="pie-total">{totalLabel || total}</span>
            {title && <span className="pie-title">{title}</span>}
          </div>
        </div>
      </div>

      <div className="pie-legend">
        {segments.map((segment) => (
          <div key={segment.key || segment.label} className="pie-legend-row">
            <span className="pie-legend-dot" style={{ background: segment.color || 'rgba(148, 163, 184, 0.55)' }} />
            <span className="pie-legend-label">{segment.label}</span>
            <span className="pie-legend-value">{Number(segment.value || 0)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
