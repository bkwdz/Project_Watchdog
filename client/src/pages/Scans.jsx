import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { createScan } from '../api/endpoints';
import Card from '../components/Card';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ToastStack from '../components/ToastStack';
import useScansFeed from '../hooks/useScansFeed';
import useToast from '../hooks/useToast';
import { isCidr, isIpv4 } from '../utils/ip';
import { formatDateTime } from '../utils/time';

function isValidTarget(target) {
  return isIpv4(target) || isCidr(target);
}

export default function Scans() {
  const navigate = useNavigate();
  const { toasts, pushToast, removeToast } = useToast();

  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('standard');
  const [submitting, setSubmitting] = useState(false);

  const {
    scans,
    loading,
    error,
    listUnavailable,
    loadScans,
    registerScan,
  } = useScansFeed();

  const hasActiveScans = useMemo(
    () => scans.some((scan) => scan.status === 'running' || scan.status === 'queued'),
    [scans],
  );

  useEffect(() => {
    if (!hasActiveScans) {
      return undefined;
    }

    const timer = window.setInterval(() => {
      void loadScans();
    }, 5000);

    return () => {
      window.clearInterval(timer);
    };
  }, [hasActiveScans, loadScans]);

  useEffect(() => {
    const onScanCreated = () => {
      void loadScans();
    };

    window.addEventListener('watchdog:scan-created', onScanCreated);

    return () => {
      window.removeEventListener('watchdog:scan-created', onScanCreated);
    };
  }, [loadScans]);

  const submitScan = async (event) => {
    event.preventDefault();
    const normalizedTarget = target.trim();

    if (!isValidTarget(normalizedTarget)) {
      pushToast('Target must be a valid IPv4 address or CIDR range.', 'error');
      return;
    }

    setSubmitting(true);

    try {
      const scan = await createScan({ target: normalizedTarget, scan_type: scanType });
      registerScan(scan);
      pushToast(`Scan #${scan.id} queued.`, 'success');
      window.dispatchEvent(new CustomEvent('watchdog:scan-created', { detail: scan }));
      setTarget('');
    } catch (err) {
      pushToast(err?.response?.data?.error || 'Failed to create scan.', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const rows = useMemo(() => [...scans].sort((a, b) => b.id - a.id), [scans]);

  const columns = useMemo(
    () => [
      { key: 'id', header: 'ID' },
      { key: 'target', header: 'Target' },
      { key: 'scan_type', header: 'Type' },
      {
        key: 'status',
        header: 'Status',
        render: (scan) => <StatusBadge status={scan.status} />,
      },
      {
        key: 'progress_percent',
        header: 'Progress %',
        align: 'right',
        render: (scan) => (scan.progress_percent ?? 0),
      },
      {
        key: 'started_at',
        header: 'Started',
        render: (scan) => formatDateTime(scan.started_at),
      },
      {
        key: 'completed_at',
        header: 'Completed',
        render: (scan) => formatDateTime(scan.completed_at),
      },
      {
        key: 'view',
        header: 'View',
        align: 'right',
        render: (scan) => (
          <button
            type="button"
            className="small-button"
            onClick={(event) => {
              event.stopPropagation();
              navigate(`/scans/${scan.id}`);
            }}
          >
            View
          </button>
        ),
      },
    ],
    [navigate],
  );

  return (
    <div className="page-stack">
      <Card title="Run Scan" subtitle="Create a single-host or range scan job.">
        <form className="inline-form" onSubmit={submitScan}>
          <div className="field-stack">
            <label htmlFor="scanTarget">Target (IPv4 or CIDR)</label>
            <input
              id="scanTarget"
              type="text"
              placeholder="192.168.1.5 or 192.168.1.0/24"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
            />
          </div>

          <div className="field-stack">
            <label htmlFor="scanType">Scan Type</label>
            <select id="scanType" value={scanType} onChange={(event) => setScanType(event.target.value)}>
              <option value="discovery">discovery</option>
              <option value="quick">quick</option>
              <option value="standard">standard</option>
              <option value="aggressive">aggressive</option>
              <option value="full">full</option>
            </select>
          </div>

          <div className="field-stack inline-form-action">
            <button type="submit" className="primary-button" disabled={submitting}>
              {submitting ? 'Submitting...' : 'Start Scan'}
            </button>
          </div>
        </form>
      </Card>

      <Card
        title="Scans"
        subtitle={hasActiveScans ? 'Auto-refreshing every 5 seconds while scans are active.' : 'Scan execution history.'}
      >
        {loading && <p className="muted">Loading scans...</p>}
        {error && <p className="error-text">{error}</p>}
        {listUnavailable && (
          <p className="muted">
            Scan list endpoint is unavailable. Showing scans known to this browser session.
          </p>
        )}

        <DataTable
          columns={columns}
          rows={rows}
          emptyMessage="No scans found yet."
          onRowClick={(scan) => navigate(`/scans/${scan.id}`)}
        />
      </Card>

      <ToastStack toasts={toasts} onDismiss={removeToast} />
    </div>
  );
}
