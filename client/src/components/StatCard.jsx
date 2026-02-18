import Card from './Card';

export default function StatCard({ label, value, tone = 'neutral' }) {
  return (
    <Card className={`stat-card stat-${tone}`}>
      <p className="stat-label">{label}</p>
      <p className="stat-value">{value}</p>
    </Card>
  );
}
