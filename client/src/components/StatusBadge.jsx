const STATUS_CLASS = {
  queued: 'status-queued',
  running: 'status-running',
  completed: 'status-completed',
  failed: 'status-failed',
  open: 'status-completed',
  closed: 'status-queued',
  filtered: 'status-failed',
};

export default function StatusBadge({ status }) {
  const normalized = (status || 'unknown').toLowerCase();
  const badgeClass = STATUS_CLASS[normalized] || 'status-queued';

  return <span className={`status-badge ${badgeClass}`}>{normalized}</span>;
}
