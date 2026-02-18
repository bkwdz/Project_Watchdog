import Card from './Card';

export default function StatCard({ label, value, secondary = '', tone = 'neutral' }) {
  return (
    <Card className={`stat-card stat-${tone}`}>
      <p className="stat-label">{label}</p>
      <p className="stat-value">{value}</p>
      {secondary ? <p className="stat-secondary">{secondary}</p> : null}
    </Card>
  );
}
