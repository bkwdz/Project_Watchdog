import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { getDevices, getScanById } from '../api/endpoints';
import Card from '../components/Card';
import DataTable from '../components/DataTable';
import ProgressBar from '../components/ProgressBar';
import StatusBadge from '../components/StatusBadge';
import { cidrContains, isCidr, isIpv4 } from '../utils/ip';
import { formatDateTime } from '../utils/time';

function scanIncludesDevice(scanTarget, deviceIp) {
  if (!scanTarget || !deviceIp) {
    return false;
  }

  if (isIpv4(scanTarget)) {
    return scanTarget === deviceIp;
  }

  if (isCidr(scanTarget)) {
    return cidrContains(scanTarget, deviceIp);
  }

  return false;
}

function severityClass(severity) {
  const normalized = String(severity || '').toLowerCase();

  if (normalized === 'critical') {
    return 'severity-critical';
  }

  if (normalized === 'high') {
    return 'severity-high';
  }

  if (normalized === 'medium') {
    return 'severity-medium';
  }

  return 'severity-low';
}

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [devices, setDevices] = useState([]);
  const [devicesError, setDevicesError] = useState('');

  const loadScan = useCallback(async () => {
    setError('');

    try {
      const data = await getScanById(id);
      setScan(data);
      return data;
    } catch (err) {
      if (err?.response?.status === 503) {
        setError('Vulnerability scanner is not active.');
      } else {
        setError(err?.response?.data?.error || 'Unable to load scan');
      }
      return null;
    } finally {
      setLoading(false);
    }
  }, [id]);

  const loadDevices = useCallback(async () => {
    setDevicesError('');

    try {
      const data = await getDevices();
      setDevices(Array.isArray(data) ? data : []);
    } catch (err) {
      setDevicesError(err?.response?.data?.error || 'Unable to load devices');
    }
  }, []);

  useEffect(() => {
    void loadScan();
  }, [loadScan]);

  const isActive = scan?.status === 'running' || scan?.status === 'queued';

  useEffect(() => {
    if (!isActive) {
      return undefined;
    }

    const timer = window.setInterval(() => {
      void loadScan();
    }, 3000);

    return () => {
      window.clearInterval(timer);
    };
  }, [isActive, loadScan]);

  useEffect(() => {
    if (!scan || (scan.status !== 'completed' && scan.status !== 'failed')) {
      return;
    }

    void loadDevices();
  }, [loadDevices, scan]);

  const discoveredDevices = useMemo(() => {
    if (!scan?.target) {
      return [];
    }

    return devices.filter((device) => scanIncludesDevice(scan.target, device.ip_address || device.ip));
  }, [devices, scan]);

  const summary = scan?.summary || {};
  const vulnerabilities = useMemo(
    () => (Array.isArray(scan?.vulnerabilities) ? scan.vulnerabilities : []),
    [scan?.vulnerabilities],
  );

  const vulnerabilityColumns = useMemo(
    () => [
      { key: 'cve', header: 'CVE' },
      { key: 'name', header: 'Name' },
      {
        key: 'cvss_severity',
        header: 'Severity',
        render: (row) => {
          const label = row.cvss_severity || row.severity || 'Low';
          return <span className={`severity-chip ${severityClass(label)}`}>{label}</span>;
        },
      },
      {
        key: 'cvss_score',
        header: 'CVSS',
        align: 'right',
        render: (row) => {
          const score = Number.parseFloat(row.cvss_score);
          return Number.isFinite(score) ? score.toFixed(1) : '-';
        },
      },
      {
        key: 'port',
        header: 'Port',
        align: 'right',
        render: (row) => row.port ?? '-',
      },
      {
        key: 'description',
        header: 'Description',
        render: (row) => row.description || '-',
      },
    ],
    [],
  );

  return (
    <div className="page-stack">
      <Card title={`Scan #${id}`} subtitle="Asynchronous scan job details.">
        {loading && <p className="muted">Loading scan...</p>}
        {error && <p className="error-text">{error}</p>}

        {!loading && !error && scan && (
          <dl className="detail-grid">
            <div>
              <dt>Target</dt>
              <dd>{scan.target}</dd>
            </div>
            <div>
              <dt>Type</dt>
              <dd>{scan.scan_type}</dd>
            </div>
            <div>
              <dt>Scanner</dt>
              <dd>{scan.scanner_type || 'nmap'}</dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>
                <StatusBadge status={scan.status} />
              </dd>
            </div>
            <div>
              <dt>Progress</dt>
              <dd>{scan.progress_percent ?? 0}%</dd>
            </div>
            <div>
              <dt>Started</dt>
              <dd>{formatDateTime(scan.started_at)}</dd>
            </div>
            <div>
              <dt>Completed</dt>
              <dd>{formatDateTime(scan.completed_at)}</dd>
            </div>
          </dl>
        )}

        {scan && isActive && (
          <div className="scan-progress">
            <p className="muted">Scan in progress...</p>
            <ProgressBar value={scan.progress_percent ?? 10} />
          </div>
        )}
      </Card>

      <Card title="Summary" subtitle="Scan output summary from backend aggregation.">
        {scan && (scan.status === 'completed' || scan.status === 'failed') && (
          <ul className="summary-list">
            {scan.scanner_type === 'greenbone' ? (
              <>
                <li>
                  Vulnerabilities:
                  {' '}
                  <strong>{summary.vulnerabilities_total ?? 0}</strong>
                </li>
                <li>
                  Critical:
                  {' '}
                  <strong>{summary.critical_count ?? 0}</strong>
                </li>
                <li>
                  High:
                  {' '}
                  <strong>{summary.high_count ?? 0}</strong>
                </li>
                <li>
                  Affected Devices:
                  {' '}
                  <strong>{summary.affected_devices ?? 0}</strong>
                </li>
              </>
            ) : (
              <>
                <li>
                  Hosts up:
                  {' '}
                  <strong>{summary.hosts_up ?? 0}</strong>
                </li>
                <li>
                  Ports observed:
                  {' '}
                  <strong>{summary.ports_observed ?? 0}</strong>
                </li>
              </>
            )}
          </ul>
        )}

        {scan && scan.status !== 'completed' && scan.status !== 'failed' && (
          <p className="muted">Summary will be available after completion.</p>
        )}
      </Card>

      {scan?.scanner_type === 'greenbone' && (
        <Card title="Vulnerabilities" subtitle="Findings reported by Greenbone for this scan.">
          <DataTable
            columns={vulnerabilityColumns}
            rows={vulnerabilities}
            emptyMessage="No vulnerabilities reported for this scan."
          />
        </Card>
      )}

      <Card title="Discovered Devices" subtitle="Devices that match this scan target.">
        {devicesError && <p className="error-text">{devicesError}</p>}

        {discoveredDevices.length === 0 && <p className="muted">No matching devices yet.</p>}

        {discoveredDevices.length > 0 && (
          <ul className="link-list">
            {discoveredDevices.map((device) => (
              <li key={device.id}>
                <Link to={`/devices/${device.id}`}>
                  {device.hostname || device.ip_address || device.ip || `Device ${device.id}`}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
