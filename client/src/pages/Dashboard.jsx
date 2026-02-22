import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getDevices, getDevicesSummary } from '../api/endpoints';
import Card from '../components/Card';
import DataTable from '../components/DataTable';
import PieChart from '../components/PieChart';
import ProgressBar from '../components/ProgressBar';
import StatCard from '../components/StatCard';
import StatusBadge from '../components/StatusBadge';
import useScansFeed from '../hooks/useScansFeed';
import { formatDateTime } from '../utils/time';

export default function Dashboard() {
  const navigate = useNavigate();
  const [devices, setDevices] = useState([]);
  const [devicesLoading, setDevicesLoading] = useState(true);
  const [devicesError, setDevicesError] = useState('');
  const [summary, setSummary] = useState(null);
  const [summaryError, setSummaryError] = useState('');

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

  const loadSummary = useCallback(async () => {
    setSummaryError('');

    try {
      const data = await getDevicesSummary();
      setSummary(data || null);
    } catch (err) {
      setSummaryError(err?.response?.data?.error || 'Unable to load dashboard summary');
    }
  }, []);

  useEffect(() => {
    void loadDevices();
    void loadSummary();
  }, [loadDevices, loadSummary]);

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
      void loadSummary();
    }, 5000);

    return () => {
      window.clearInterval(timer);
    };
  }, [hasActiveScans, loadDevices, loadScans, loadSummary]);

  useEffect(() => {
    const onScanCreated = () => {
      void loadScans();
      void loadDevices();
      void loadSummary();
    };

    window.addEventListener('watchdog:scan-created', onScanCreated);

    return () => {
      window.removeEventListener('watchdog:scan-created', onScanCreated);
    };
  }, [loadDevices, loadScans, loadSummary]);

  const totals = useMemo(() => {
    const fromSummary = summary?.totals || {};
    const totalDevices = Number(fromSummary.total_devices ?? devices.length);
    const onlineDevices = Number(
      fromSummary.online_devices ?? devices.filter((device) => device.online_status === true || device.online === true).length,
    );
    const offlineDevices = Number(fromSummary.offline_devices ?? Math.max(0, totalDevices - onlineDevices));
    const runningScans = Number(fromSummary.running_scans ?? scans.filter((scan) => scan.status === 'running').length);
    const queuedScans = Number(fromSummary.queued_scans ?? scans.filter((scan) => scan.status === 'queued').length);
    const totalScans = Number(fromSummary.total_scans ?? scans.length);
    const totalOpenPorts = Number(fromSummary.total_open_ports ?? devices.reduce((sum, device) => sum + Number(device.open_ports || 0), 0));
    const vulnerabilitiesTotal = Number(fromSummary.vulnerabilities_total ?? 0);
    const vulnerableDevices = Number(fromSummary.vulnerable_devices ?? 0);
    const criticalCount = Number(fromSummary.critical_count ?? 0);
    const highCount = Number(fromSummary.high_count ?? 0);
    const mediumCount = Number(fromSummary.medium_count ?? 0);
    const lowCount = Number(fromSummary.low_count ?? 0);
    const failedScans = Number(fromSummary.failed_scans ?? scans.filter((scan) => scan.status === 'failed').length);

    return {
      totalDevices,
      onlineDevices,
      offlineDevices,
      runningScans,
      queuedScans,
      totalScans,
      totalOpenPorts,
      vulnerabilitiesTotal,
      vulnerableDevices,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      failedScans,
    };
  }, [devices, scans, summary]);

  const severityRows = useMemo(
    () => [
      { key: 'critical', label: 'Critical', count: totals.criticalCount, color: '#ff5d5d' },
      { key: 'high', label: 'High', count: totals.highCount, color: '#ff8a80' },
      { key: 'medium', label: 'Medium', count: totals.mediumCount, color: '#ff8f43' },
      { key: 'low', label: 'Low', count: totals.lowCount, color: '#5ad68a' },
    ],
    [totals],
  );

  const activeScans = useMemo(() => {
    const rows = Array.isArray(summary?.active_scans) ? summary.active_scans : [];

    if (rows.length > 0) {
      return rows;
    }

    return scans
      .filter((scan) => scan.status === 'running' || scan.status === 'queued')
      .slice(0, 12);
  }, [scans, summary]);

  const topPorts = useMemo(
    () => (Array.isArray(summary?.top_ports) ? summary.top_ports : []),
    [summary],
  );

  const topServices = useMemo(
    () => (Array.isArray(summary?.top_services) ? summary.top_services : []),
    [summary],
  );

  const topRiskyDevices = useMemo(
    () => (Array.isArray(summary?.top_risky_devices) ? summary.top_risky_devices : []),
    [summary],
  );

  const topRiskyDeviceColumns = useMemo(
    () => [
      {
        key: 'device_name',
        header: 'Device Name',
        render: (row) => row.device_name || '-',
      },
      { key: 'ip_address', header: 'IP' },
      {
        key: 'os',
        header: 'OS',
        render: (row) => row.os || '-',
      },
      {
        key: 'critical_vulns',
        header: 'Critical Vulns',
        align: 'right',
      },
      {
        key: 'high_vulns',
        header: 'High Vulns',
        align: 'right',
      },
    ],
    [],
  );

  return (
    <div className="page-stack">
      <section className="stats-grid dashboard-stats-grid">
        <StatCard
          label="Devices Online"
          value={totals.onlineDevices}
          secondary={`Offline: ${totals.offlineDevices}`}
          tone="info"
        />
        <StatCard label="Running Scans" value={totals.runningScans} tone="info" />
        <StatCard label="Queued Scans" value={totals.queuedScans} tone="warning" />
        <StatCard label="Failed Scans" value={totals.failedScans} tone="danger" />
        <StatCard label="Open Ports" value={totals.totalOpenPorts} tone="warning" />
        <StatCard label="Vulnerabilities" value={totals.vulnerabilitiesTotal} tone="danger" />
        <StatCard label="Vulnerable Devices" value={totals.vulnerableDevices} tone="info" />
        <StatCard label="Total Scans" value={totals.totalScans} tone="success" />
      </section>

      <Card
        title="Active Scan Operations"
        subtitle={hasActiveScans ? 'Auto-refreshing every 5 seconds while scans are active.' : 'No active scans right now.'}
      >
        {(devicesLoading || scansLoading) && <p className="muted">Loading dashboard data...</p>}
        {devicesError && <p className="error-text">{devicesError}</p>}
        {summaryError && <p className="error-text">{summaryError}</p>}
        {scansError && <p className="error-text">{scansError}</p>}
        {listUnavailable && (
          <p className="muted">
            Scan list endpoint is unavailable. Showing scans known to this browser session.
          </p>
        )}

        {activeScans.length === 0 && <p className="muted">No running or queued scans.</p>}
        {activeScans.length > 0 && (
          <div className="active-scan-list">
            {activeScans.map((scan) => (
              <article key={scan.id} className="active-scan-item">
                <div className="active-scan-main">
                  <p className="active-scan-title">
                    #{scan.id} {scan.target}
                  </p>
                  <p className="active-scan-meta">
                    {(scan.scanner_type || 'nmap') === 'greenbone' ? 'vulnerability' : scan.scan_type}
                    {' | '}
                    {scan.scanner_type || 'nmap'}
                    {' | '}
                    {formatDateTime(scan.started_at)}
                  </p>
                </div>
                <div className="active-scan-status">
                  <StatusBadge status={scan.status} />
                  <span>{scan.progress_percent ?? (scan.status === 'running' ? 10 : 0)}%</span>
                </div>
                <ProgressBar value={scan.progress_percent ?? (scan.status === 'running' ? 10 : 0)} />
              </article>
            ))}
          </div>
        )}
      </Card>

      <section className="dashboard-split-grid">
        <Card title="Vulnerability Posture" subtitle="Distribution across discovered findings.">
          <div className="vuln-posture-grid">
            <PieChart title="Severity" segments={severityRows.map((row) => ({ ...row, value: row.count }))} />
          </div>
        </Card>

        <Card title="Exposure Hotspots" subtitle="Most common open ports and services.">
          <div className="hotspot-grid">
            <div>
              <p className="hotspot-title">Top Ports</p>
              {topPorts.length === 0 && <p className="muted">No open port data yet.</p>}
              {topPorts.length > 0 && (
                <div className="service-bars">
                  {topPorts.map((row) => {
                    const maxCount = topPorts[0].count || 1;
                    const width = Math.round((row.count / maxCount) * 100);

                    return (
                      <div key={`${row.protocol}-${row.port}`} className="service-bar-row">
                        <span className="service-name">
                          {row.protocol}/{row.port}
                        </span>
                        <div className="service-bar-track">
                          <div className="service-bar-fill" style={{ width: `${width}%` }} />
                        </div>
                        <span className="service-count">{row.count}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            <div>
              <p className="hotspot-title">Top Services</p>
              {topServices.length === 0 && <p className="muted">No service data yet.</p>}
              {topServices.length > 0 && (
                <div className="service-bars">
                  {topServices.map((row) => {
                    const maxCount = topServices[0].count || 1;
                    const width = Math.round((row.count / maxCount) * 100);

                    return (
                      <div key={row.service} className="service-bar-row">
                        <span className="service-name">{row.service}</span>
                        <div className="service-bar-track">
                          <div className="service-bar-fill" style={{ width: `${width}%` }} />
                        </div>
                        <span className="service-count">{row.count}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </Card>
      </section>

      <Card
        title="Top Risky Devices"
        subtitle="Hosts with the highest critical/high vulnerability counts."
      >
        <DataTable
          columns={topRiskyDeviceColumns}
          rows={topRiskyDevices}
          emptyMessage="No high-risk devices identified yet."
          onRowClick={(row) => navigate(`/devices/${row.id}`)}
        />
      </Card>
    </div>
  );
}
