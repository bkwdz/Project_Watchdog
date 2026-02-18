import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getDevices } from '../api/endpoints';
import Card from '../components/Card';
import DataTable from '../components/DataTable';
import StatCard from '../components/StatCard';
import StatusBadge from '../components/StatusBadge';
import useScansFeed from '../hooks/useScansFeed';
import { formatDateTime } from '../utils/time';

function toRecentScanRows(scans) {
  return [...scans]
    .sort((a, b) => {
      const left = a.started_at ? new Date(a.started_at).getTime() : 0;
      const right = b.started_at ? new Date(b.started_at).getTime() : 0;
      return right - left || b.id - a.id;
    })
    .slice(0, 5);
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [devices, setDevices] = useState([]);
  const [devicesLoading, setDevicesLoading] = useState(true);
  const [devicesError, setDevicesError] = useState('');

  const {
    scans,
    loading: scansLoading,
    error: scansError,
    listUnavailable,
    loadScans,
  } = useScansFeed();

  const loadDevices = useCallback(async () => {
    setDevicesError('');

    try {
      const data = await getDevices();
      setDevices(Array.isArray(data) ? data : []);
    } catch (err) {
      setDevicesError(err?.response?.data?.error || 'Unable to load devices');
    } finally {
      setDevicesLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDevices();
  }, [loadDevices]);

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
      void loadDevices();
    }, 5000);

    return () => {
      window.clearInterval(timer);
    };
  }, [hasActiveScans, loadDevices, loadScans]);

  useEffect(() => {
    const onScanCreated = () => {
      void loadScans();
      void loadDevices();
    };

    window.addEventListener('watchdog:scan-created', onScanCreated);

    return () => {
      window.removeEventListener('watchdog:scan-created', onScanCreated);
    };
  }, [loadDevices, loadScans]);

  const totals = useMemo(() => {
    const totalDevices = devices.length;
    const runningScans = scans.filter((scan) => scan.status === 'running').length;
    const totalScans = scans.length;
    const totalOpenPorts = devices.reduce((sum, device) => sum + Number(device.open_ports || 0), 0);

    return {
      totalDevices,
      runningScans,
      totalScans,
      totalOpenPorts,
    };
  }, [devices, scans]);

  const recentScans = useMemo(() => toRecentScanRows(scans), [scans]);

  const recentColumns = useMemo(
    () => [
      { key: 'target', header: 'Target' },
      { key: 'scan_type', header: 'Type' },
      {
        key: 'status',
        header: 'Status',
        render: (scan) => <StatusBadge status={scan.status} />,
      },
      {
        key: 'started_at',
        header: 'Started',
        render: (scan) => formatDateTime(scan.started_at),
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
      <section className="stats-grid">
        <StatCard label="Total Devices" value={totals.totalDevices} tone="neutral" />
        <StatCard label="Running Scans" value={totals.runningScans} tone="info" />
        <StatCard label="Total Open Ports" value={totals.totalOpenPorts} tone="warning" />
        <StatCard label="Total Scans" value={totals.totalScans} tone="success" />
      </section>

      <Card
        title="Recent Scans"
        subtitle={hasActiveScans ? 'Auto-refreshing every 5 seconds while scans are active.' : 'Latest five scans.'}
      >
        {(devicesLoading || scansLoading) && <p className="muted">Loading dashboard data...</p>}
        {devicesError && <p className="error-text">{devicesError}</p>}
        {scansError && <p className="error-text">{scansError}</p>}
        {listUnavailable && (
          <p className="muted">
            Scan list endpoint is unavailable. Showing scans known to this browser session.
          </p>
        )}

        <DataTable columns={recentColumns} rows={recentScans} emptyMessage="No scans found yet." />
      </Card>
    </div>
  );
}
