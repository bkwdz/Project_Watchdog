import { Fragment, useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { getScanById } from '../api/endpoints';
import Card from '../components/Card';
import DataTable from '../components/DataTable';
import ProgressBar from '../components/ProgressBar';
import StatusBadge from '../components/StatusBadge';
import { formatDateTime } from '../utils/time';

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }

  return value;
}

function normalizeSeverityBucket(severity, score) {
  const normalized = String(severity || '').toLowerCase().trim();
  const numericScore = Number.parseFloat(score);

  if (
    normalized.includes('log') ||
    normalized.includes('info') ||
    normalized.includes('informational') ||
    normalized === 'none' ||
    (Number.isFinite(numericScore) && numericScore <= 0)
  ) {
    return 'log';
  }

  if (normalized.includes('critical')) {
    return 'critical';
  }

  if (normalized.includes('high')) {
    return 'high';
  }

  if (normalized.includes('medium')) {
    return 'medium';
  }

  return 'low';
}

function severityLabel(bucket) {
  if (bucket === 'critical') {
    return 'Critical';
  }

  if (bucket === 'high') {
    return 'High';
  }

  if (bucket === 'medium') {
    return 'Medium';
  }

  if (bucket === 'log') {
    return 'Log';
  }

  return 'Low';
}

function severityClass(bucket) {
  if (bucket === 'critical') {
    return 'severity-critical';
  }

  if (bucket === 'high') {
    return 'severity-high';
  }

  if (bucket === 'medium') {
    return 'severity-medium';
  }

  if (bucket === 'log') {
    return 'severity-log';
  }

  return 'severity-low';
}

function normalizeQod(value) {
  const parsed = Number.parseFloat(value);

  if (!Number.isFinite(parsed)) {
    return null;
  }

  if (parsed > 1 && parsed <= 100) {
    return parsed / 100;
  }

  return parsed;
}

function formatQod(value) {
  const normalized = normalizeQod(value);

  if (!Number.isFinite(normalized)) {
    return '-';
  }

  return `${Math.round(normalized * 100)}%`;
}

function formatCvss(value) {
  const parsed = Number.parseFloat(value);

  if (!Number.isFinite(parsed)) {
    return '-';
  }

  return parsed.toFixed(1);
}

function toCveArray(row) {
  const values = new Set();

  (Array.isArray(row?.cve_list) ? row.cve_list : []).forEach((entry) => {
    const normalized = String(entry || '').trim().toUpperCase();

    if (/^CVE-\d{4}-\d{4,}$/.test(normalized)) {
      values.add(normalized);
    }
  });

  const fallback = String(row?.cve || '').trim().toUpperCase();

  if (/^CVE-\d{4}-\d{4,}$/.test(fallback)) {
    values.add(fallback);
  }

  return [...values];
}

function summarizeCves(cves) {
  if (!Array.isArray(cves) || cves.length === 0) {
    return '-';
  }

  if (cves.length <= 3) {
    return cves.join(', ');
  }

  return `${cves.slice(0, 3).join(', ')} +${cves.length - 3}`;
}

function vulnerabilityRowKey(row, index) {
  const parts = [
    row.id ?? `v-${index}`,
    row.device_id ?? 'd',
    row.nvt_oid || row.name || 'finding',
    row.port ?? 'p',
    row.cvss_score ?? 's',
  ];

  return parts.map((value) => String(value)).join('|');
}

function nmapPortRowKey(row, index) {
  const parts = [
    row.id ?? `p-${index}`,
    row.device_id ?? 'd',
    row.port ?? 'port',
    row.protocol || 'proto',
  ];

  return parts.map((value) => String(value)).join('|');
}

function parseDateToMillis(value) {
  if (!value) {
    return 0;
  }

  const parsed = new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed : 0;
}

function buildTopServicesFallback(rows, limit = 8) {
  const counts = new Map();

  (Array.isArray(rows) ? rows : []).forEach((row) => {
    const key = String(row?.service || 'unknown').trim().toLowerCase() || 'unknown';
    counts.set(key, (counts.get(key) || 0) + 1);
  });

  return [...counts.entries()]
    .map(([service, count]) => ({ service, count }))
    .sort((left, right) => right.count - left.count || left.service.localeCompare(right.service))
    .slice(0, limit);
}

function isGreenboneScan(scan) {
  const scannerType = String(scan?.scanner_type || '').trim().toLowerCase();
  const scanType = String(scan?.scan_type || '').trim().toLowerCase();
  return scannerType === 'greenbone' || scanType === 'vulnerability';
}

function toOnlineStatusLabel(value) {
  if (typeof value === 'boolean') {
    return value ? 'online' : 'offline';
  }

  const normalized = String(value || '').trim().toLowerCase();

  if (normalized === 'true' || normalized === '1') {
    return 'online';
  }

  if (normalized === 'false' || normalized === '0') {
    return 'offline';
  }

  return normalized || 'unknown';
}

function formatGreenboneLocation(row) {
  if (Number.isInteger(row?.port) && row.port > 0) {
    const protocol = String(row?.port_protocol || '').trim().toLowerCase() || 'tcp';
    return `${row.port}/${protocol}`;
  }

  return '-';
}

const GREENBONE_SCAN_TABS = [
  { key: 'information', label: 'Information' },
  { key: 'results', label: 'Results' },
  { key: 'hosts', label: 'Hosts' },
  { key: 'ports', label: 'Ports' },
  { key: 'cves', label: 'CVEs' },
  { key: 'logs', label: 'Logs' },
];

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [findingSearch, setFindingSearch] = useState('');
  const [expandedVulnerabilities, setExpandedVulnerabilities] = useState({});
  const [expandedPorts, setExpandedPorts] = useState({});
  const [activeGreenboneTab, setActiveGreenboneTab] = useState('information');

  const loadScan = useCallback(async () => {
    setError('');

    try {
      const data = await getScanById(id);
      setScan(data);
    } catch (err) {
      if (err?.response?.status === 503) {
        setError('Vulnerability scanner is not active.');
      } else {
        setError(err?.response?.data?.error || 'Unable to load scan');
      }
    } finally {
      setLoading(false);
    }
  }, [id]);

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

  const isGreenbone = isGreenboneScan(scan);
  const summary = toObject(scan?.summary);

  useEffect(() => {
    if (!isGreenbone && activeGreenboneTab !== 'information') {
      setActiveGreenboneTab('information');
    }
  }, [activeGreenboneTab, isGreenbone]);

  const vulnerabilities = useMemo(
    () => (Array.isArray(scan?.vulnerabilities) ? scan.vulnerabilities : []),
    [scan?.vulnerabilities],
  );

  const discoveredDevices = useMemo(
    () => (Array.isArray(scan?.discovered_devices) ? scan.discovered_devices : []),
    [scan?.discovered_devices],
  );

  const nmapOpenPorts = useMemo(
    () => (Array.isArray(scan?.nmap_open_ports) ? scan.nmap_open_ports : []),
    [scan?.nmap_open_ports],
  );

  const logFindings = useMemo(
    () => vulnerabilities.filter((row) => normalizeSeverityBucket(row.cvss_severity || row.severity, row.cvss_score) === 'log'),
    [vulnerabilities],
  );

  const greenbonePortRows = useMemo(() => {
    const map = new Map();

    vulnerabilities.forEach((row) => {
      const location = formatGreenboneLocation(row);
      const key = `${location}|${row.port ?? '-'}`;
      const bucket = normalizeSeverityBucket(row.cvss_severity || row.severity, row.cvss_score);
      const score = Number.parseFloat(row.cvss_score);

      if (!map.has(key)) {
        map.set(key, {
          row_key: key,
          location,
          findings_count: 0,
          critical_count: 0,
          high_count: 0,
          medium_count: 0,
          low_count: 0,
          log_count: 0,
          top_cvss: Number.isFinite(score) ? score : null,
        });
      }

      const entry = map.get(key);
      entry.findings_count += 1;

      if (bucket === 'critical') {
        entry.critical_count += 1;
      } else if (bucket === 'high') {
        entry.high_count += 1;
      } else if (bucket === 'medium') {
        entry.medium_count += 1;
      } else if (bucket === 'log') {
        entry.log_count += 1;
      } else {
        entry.low_count += 1;
      }

      if (Number.isFinite(score)) {
        entry.top_cvss = entry.top_cvss === null ? score : Math.max(entry.top_cvss, score);
      }
    });

    return [...map.values()]
      .sort((left, right) => right.findings_count - left.findings_count || left.location.localeCompare(right.location));
  }, [vulnerabilities]);

  const greenboneCveRows = useMemo(() => {
    const groups = new Map();

    vulnerabilities.forEach((row) => {
      const cves = toCveArray(row);
      if (cves.length === 0) {
        return;
      }

      const nvtName = String(row.name || '').trim() || (row.nvt_oid ? `NVT ${row.nvt_oid}` : 'Unknown NVT');
      const groupKey = String(row.nvt_oid || nvtName).trim().toLowerCase();
      const score = Number.parseFloat(row.cvss_score);
      const bucket = normalizeSeverityBucket(row.cvss_severity || row.severity, row.cvss_score);

      if (!groups.has(groupKey)) {
        groups.set(groupKey, {
          row_key: groupKey,
          nvt_name: nvtName,
          cves: new Set(),
          top_cvss: Number.isFinite(score) ? score : null,
          highest_bucket: bucket,
        });
      }

      const entry = groups.get(groupKey);
      cves.forEach((cve) => entry.cves.add(cve));
      if (Number.isFinite(score)) {
        entry.top_cvss = entry.top_cvss === null ? score : Math.max(entry.top_cvss, score);
      }

      const rank = { log: 0, low: 1, medium: 2, high: 3, critical: 4 };
      if ((rank[bucket] ?? 0) > (rank[entry.highest_bucket] ?? 0)) {
        entry.highest_bucket = bucket;
      }
    });

    return [...groups.values()]
      .map((entry) => ({
        row_key: entry.row_key,
        nvt_name: entry.nvt_name,
        cves: [...entry.cves].sort(),
        highest_severity: severityLabel(entry.highest_bucket),
        highest_bucket: entry.highest_bucket,
        top_cvss: entry.top_cvss,
      }))
      .sort((left, right) => {
        const severityRank = { Critical: 4, High: 3, Medium: 2, Low: 1, Log: 0 };
        return (severityRank[right.highest_severity] ?? -1) - (severityRank[left.highest_severity] ?? -1)
          || (right.cves.length - left.cves.length)
          || left.nvt_name.localeCompare(right.nvt_name);
      });
  }, [vulnerabilities]);

  const topServices = useMemo(() => {
    const fromSummary = Array.isArray(summary.top_services) ? summary.top_services : [];

    if (fromSummary.length > 0) {
      return fromSummary;
    }

    return buildTopServicesFallback(nmapOpenPorts);
  }, [nmapOpenPorts, summary.top_services]);

  const calculatedGreenboneSummary = useMemo(() => {
    const metrics = {
      vulnerabilities_total: 0,
      actionable_count: 0,
      informational_count: 0,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      log_count: 0,
      affected_ports: new Set(),
      unique_findings: new Set(),
      unique_cves: new Set(),
      qod_values: [],
    };

    vulnerabilities.forEach((row) => {
      const bucket = normalizeSeverityBucket(row.cvss_severity || row.severity, row.cvss_score);
      metrics.vulnerabilities_total += 1;

      if (bucket === 'critical') {
        metrics.critical_count += 1;
      } else if (bucket === 'high') {
        metrics.high_count += 1;
      } else if (bucket === 'medium') {
        metrics.medium_count += 1;
      } else if (bucket === 'log') {
        metrics.log_count += 1;
      } else {
        metrics.low_count += 1;
      }

      if (bucket === 'log') {
        metrics.informational_count += 1;
      } else {
        metrics.actionable_count += 1;
      }

      if (Number.isInteger(row.port) && row.port > 0) {
        metrics.affected_ports.add(row.port);
      }

      const findingKey = String(row.nvt_oid || row.name || '').trim().toLowerCase();
      if (findingKey) {
        metrics.unique_findings.add(findingKey);
      }

      toCveArray(row).forEach((cve) => metrics.unique_cves.add(cve));

      const normalizedQod = normalizeQod(row.qod);
      if (Number.isFinite(normalizedQod)) {
        metrics.qod_values.push(normalizedQod);
      }
    });

    const avgQod = metrics.qod_values.length > 0
      ? Math.round(
        (metrics.qod_values.reduce((total, value) => total + value, 0) / metrics.qod_values.length) * 1000,
      ) / 10
      : null;

    return {
      vulnerabilities_total: metrics.vulnerabilities_total,
      actionable_count: metrics.actionable_count,
      informational_count: metrics.informational_count,
      critical_count: metrics.critical_count,
      high_count: metrics.high_count,
      medium_count: metrics.medium_count,
      low_count: metrics.low_count,
      log_count: metrics.log_count,
      affected_devices: discoveredDevices.length,
      affected_ports: metrics.affected_ports.size,
      unique_findings: metrics.unique_findings.size,
      unique_cves: metrics.unique_cves.size,
      avg_qod_percent: avgQod,
    };
  }, [discoveredDevices.length, vulnerabilities]);

  const greenboneSummary = isGreenbone
    ? {
      vulnerabilities_total: Number.isFinite(Number(summary.vulnerabilities_total))
        ? Number(summary.vulnerabilities_total)
        : calculatedGreenboneSummary.vulnerabilities_total,
      actionable_count: Number.isFinite(Number(summary.actionable_count))
        ? Number(summary.actionable_count)
        : calculatedGreenboneSummary.actionable_count,
      informational_count: Number.isFinite(Number(summary.informational_count))
        ? Number(summary.informational_count)
        : calculatedGreenboneSummary.informational_count,
      critical_count: Number.isFinite(Number(summary.critical_count))
        ? Number(summary.critical_count)
        : calculatedGreenboneSummary.critical_count,
      high_count: Number.isFinite(Number(summary.high_count))
        ? Number(summary.high_count)
        : calculatedGreenboneSummary.high_count,
      medium_count: Number.isFinite(Number(summary.medium_count))
        ? Number(summary.medium_count)
        : calculatedGreenboneSummary.medium_count,
      low_count: Number.isFinite(Number(summary.low_count))
        ? Number(summary.low_count)
        : calculatedGreenboneSummary.low_count,
      log_count: Number.isFinite(Number(summary.log_count))
        ? Number(summary.log_count)
        : calculatedGreenboneSummary.log_count,
      affected_devices: Number.isFinite(Number(summary.affected_devices))
        ? Number(summary.affected_devices)
        : calculatedGreenboneSummary.affected_devices,
      affected_ports: Number.isFinite(Number(summary.affected_ports))
        ? Number(summary.affected_ports)
        : calculatedGreenboneSummary.affected_ports,
      unique_findings: Number.isFinite(Number(summary.unique_findings))
        ? Number(summary.unique_findings)
        : calculatedGreenboneSummary.unique_findings,
      unique_cves: Number.isFinite(Number(summary.unique_cves))
        ? Number(summary.unique_cves)
        : calculatedGreenboneSummary.unique_cves,
      avg_qod_percent: Number.isFinite(Number(summary.avg_qod_percent))
        ? Number(summary.avg_qod_percent)
        : calculatedGreenboneSummary.avg_qod_percent,
    }
    : null;

  const filteredVulnerabilities = useMemo(() => {
    const search = String(findingSearch || '').trim().toLowerCase();

    return vulnerabilities.filter((row) => {
      const bucket = normalizeSeverityBucket(row.cvss_severity || row.severity, row.cvss_score);

      if (severityFilter !== 'all' && bucket !== severityFilter) {
        return false;
      }

      if (!search) {
        return true;
      }

      const cves = toCveArray(row).join(' ');
      const fields = [
        row.name,
        row.nvt_oid,
        row.description,
        row.solution,
        cves,
      ]
        .map((value) => String(value || '').toLowerCase())
        .join(' ');

      return fields.includes(search);
    });
  }, [findingSearch, severityFilter, vulnerabilities]);

  const vulnerabilitiesWithKeys = useMemo(
    () => filteredVulnerabilities.map((row, index) => ({
      ...row,
      _row_key: vulnerabilityRowKey(row, index),
    })),
    [filteredVulnerabilities],
  );

  const logFindingsWithKeys = useMemo(
    () => logFindings.map((row, index) => ({
      ...row,
      _row_key: vulnerabilityRowKey(row, index),
    })),
    [logFindings],
  );

  const nmapOpenPortsWithKeys = useMemo(
    () => nmapOpenPorts.map((row, index) => ({
      ...row,
      _row_key: nmapPortRowKey(row, index),
    })),
    [nmapOpenPorts],
  );

  const toggleVulnerability = (rowKey) => {
    setExpandedVulnerabilities((current) => ({
      ...current,
      [rowKey]: !current[rowKey],
    }));
  };

  const togglePort = (rowKey) => {
    setExpandedPorts((current) => ({
      ...current,
      [rowKey]: !current[rowKey],
    }));
  };

  const greenboneDeviceColumns = useMemo(
    () => [
      {
        key: 'name',
        header: 'Device',
        render: (row) => (
          <Link to={`/devices/${row.id}`}>
            {row.display_name || row.hostname || row.ip_address || `Device ${row.id}`}
          </Link>
        ),
      },
      { key: 'ip_address', header: 'IP' },
      {
        key: 'os_guess',
        header: 'OS',
        render: (row) => row.os_guess || '-',
      },
      {
        key: 'findings_total',
        header: 'Findings',
        align: 'right',
      },
      {
        key: 'actionable_count',
        header: 'Actionable',
        align: 'right',
      },
      {
        key: 'critical_count',
        header: 'Critical',
        align: 'right',
      },
      {
        key: 'high_count',
        header: 'High',
        align: 'right',
      },
    ],
    [],
  );

  const nmapDeviceColumns = useMemo(
    () => [
      {
        key: 'name',
        header: 'Device',
        render: (row) => (
          <Link to={`/devices/${row.id}`}>
            {row.display_name || row.hostname || row.ip_address || `Device ${row.id}`}
          </Link>
        ),
      },
      { key: 'ip_address', header: 'IP' },
      {
        key: 'os_guess',
        header: 'OS',
        render: (row) => row.os_guess || '-',
      },
      {
        key: 'open_ports',
        header: 'Open Ports',
        align: 'right',
      },
      {
        key: 'tcp_open_ports',
        header: 'TCP',
        align: 'right',
      },
      {
        key: 'udp_open_ports',
        header: 'UDP',
        align: 'right',
      },
      {
        key: 'online_status',
        header: 'Status',
        render: (row) => <StatusBadge status={toOnlineStatusLabel(row.online_status)} />,
      },
      {
        key: 'last_seen',
        header: 'Last Seen',
        render: (row) => formatDateTime(row.last_seen),
      },
    ],
    [],
  );

  const sortedDiscoveredDevices = useMemo(() => {
    const copy = [...discoveredDevices];

    if (isGreenbone) {
      copy.sort((left, right) => {
        const leftCount = Number(left.findings_total || 0);
        const rightCount = Number(right.findings_total || 0);
        return rightCount - leftCount || Number(left.id || 0) - Number(right.id || 0);
      });
    } else {
      copy.sort((left, right) => {
        const leftCount = Number(left.open_ports || 0);
        const rightCount = Number(right.open_ports || 0);
        return rightCount - leftCount || parseDateToMillis(right.last_seen) - parseDateToMillis(left.last_seen);
      });
    }

    return copy;
  }, [discoveredDevices, isGreenbone]);

  const maxServiceCount = useMemo(
    () => topServices.reduce((highest, entry) => Math.max(highest, Number(entry?.count || 0)), 0),
    [topServices],
  );

  const nmapSummaryScope = String(summary.scope || '').trim().toLowerCase();
  const displayedGreenboneRows = activeGreenboneTab === 'logs' ? logFindingsWithKeys : vulnerabilitiesWithKeys;


  return (
    <div className="page-stack">
      <Card
        title={`Scan #${id}`}
        subtitle={isGreenbone ? 'Greenbone vulnerability task detail.' : 'Nmap host/port discovery detail.'}
      >
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
            {isGreenbone && (
              <div>
                <dt>Greenbone Task</dt>
                <dd>{scan.external_task_id || '-'}</dd>
              </div>
            )}
            {isGreenbone && (
              <div>
                <dt>SSH Credential ID</dt>
                <dd>{scan.ssh_credential_id ?? '-'}</dd>
              </div>
            )}
            {isGreenbone && (
              <div>
                <dt>SMB Credential ID</dt>
                <dd>{scan.smb_credential_id ?? '-'}</dd>
              </div>
            )}
          </dl>
        )}

        {scan && isActive && (
          <div className="scan-progress">
            <p className="muted">Scan is active. Refreshing every 3 seconds.</p>
            <ProgressBar value={scan.progress_percent ?? 10} />
          </div>
        )}
      </Card>

      {isGreenbone && (
        <Card title="Report Sections" subtitle="GSA-style view for this Greenbone report.">
          <div className="device-tab-list">
            {GREENBONE_SCAN_TABS.map((tab) => (
              <button
                key={tab.key}
                type="button"
                className={`device-tab-button ${activeGreenboneTab === tab.key ? 'active' : ''}`}
                onClick={() => setActiveGreenboneTab(tab.key)}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </Card>
      )}

      {(!isGreenbone || activeGreenboneTab === 'information') && (
      <Card title="Summary" subtitle="Scanner-specific aggregation for this scan.">
        {scan
          && (scan.status === 'completed' || scan.status === 'failed')
          && isGreenbone
          && activeGreenboneTab === 'information'
          && greenboneSummary && (
          <div className="device-kpi-grid">
            <div className="kpi-tile">
              <p className="kpi-label">Findings</p>
              <p className="kpi-value">{greenboneSummary.vulnerabilities_total}</p>
            </div>
            <div className="kpi-tile">
              <p className="kpi-label">Actionable</p>
              <p className="kpi-value">{greenboneSummary.actionable_count}</p>
            </div>
            <div className="kpi-tile">
              <p className="kpi-label">Informational</p>
              <p className="kpi-value">{greenboneSummary.informational_count}</p>
            </div>
            <div className="kpi-tile">
              <p className="kpi-label">Unique CVEs</p>
              <p className="kpi-value">{greenboneSummary.unique_cves}</p>
            </div>
            <div className="kpi-tile">
              <p className="kpi-label">Critical</p>
              <p className="kpi-value">{greenboneSummary.critical_count}</p>
            </div>
            <div className="kpi-tile">
              <p className="kpi-label">High</p>
              <p className="kpi-value">{greenboneSummary.high_count}</p>
            </div>
            <div className="kpi-tile">
              <p className="kpi-label">Medium</p>
              <p className="kpi-value">{greenboneSummary.medium_count}</p>
            </div>
            <div className="kpi-tile">
              <p className="kpi-label">Low</p>
              <p className="kpi-value">{greenboneSummary.low_count}</p>
            </div>
            <div className="kpi-tile">
              <p className="kpi-label">Log</p>
              <p className="kpi-value">{greenboneSummary.log_count}</p>
            </div>
            <div className="kpi-tile">
              <p className="kpi-label">Affected Devices</p>
              <p className="kpi-value">{greenboneSummary.affected_devices}</p>
            </div>
            <div className="kpi-tile">
              <p className="kpi-label">Affected Ports</p>
              <p className="kpi-value">{greenboneSummary.affected_ports}</p>
            </div>
            <div className="kpi-tile">
              <p className="kpi-label">Avg QoD</p>
              <p className="kpi-value">
                {Number.isFinite(greenboneSummary.avg_qod_percent)
                  ? `${greenboneSummary.avg_qod_percent.toFixed(1)}%`
                  : '-'}
              </p>
            </div>
          </div>
        )}

        {scan && (scan.status === 'completed' || scan.status === 'failed') && !isGreenbone && (
          <div className="dashboard-split-grid">
            <div className="device-kpi-grid scan-kpi-compact">
              <div className="kpi-tile">
                <p className="kpi-label">Hosts Up</p>
                <p className="kpi-value">{summary.hosts_up ?? discoveredDevices.length}</p>
              </div>
              <div className="kpi-tile">
                <p className="kpi-label">Open Ports</p>
                <p className="kpi-value">{summary.ports_observed ?? nmapOpenPorts.length}</p>
              </div>
              <div className="kpi-tile">
                <p className="kpi-label">TCP Open</p>
                <p className="kpi-value">
                  {summary.tcp_open_ports
                    ?? nmapOpenPorts.filter(
                      (row) => String(row.state || '').toLowerCase() === 'open'
                        && String(row.protocol || '').toLowerCase() === 'tcp',
                    ).length}
                </p>
              </div>
              <div className="kpi-tile">
                <p className="kpi-label">UDP Open</p>
                <p className="kpi-value">
                  {summary.udp_open_ports
                    ?? nmapOpenPorts.filter(
                      (row) => String(row.state || '').toLowerCase() === 'open'
                        && String(row.protocol || '').toLowerCase() === 'udp',
                    ).length}
                </p>
              </div>
            </div>

            <article className="insight-panel">
              <h4>Top Services</h4>
              {topServices.length === 0 && <p className="muted">No open service data captured for this scan yet.</p>}
              {topServices.length > 0 && (
                <div className="service-bars">
                  {topServices.map((entry) => {
                    const count = Number(entry.count || 0);
                    const width = maxServiceCount > 0 ? (count / maxServiceCount) * 100 : 0;
                    return (
                      <div className="service-bar-row" key={entry.service}>
                        <span className="service-name">{entry.service || 'unknown'}</span>
                        <span className="service-bar-track">
                          <span className="service-bar-fill" style={{ width: `${width}%` }} />
                        </span>
                        <span className="service-count">{count}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </article>
          </div>
        )}

        {scan && (scan.status === 'completed' || scan.status === 'failed') && !isGreenbone && (
          <p className="muted scan-summary-note">
            Scope:
            {' '}
            <strong>
              {nmapSummaryScope === 'target_snapshot' ? 'Target Snapshot' : 'Scan Window'}
            </strong>
            {' '}
            {summary.scope_note ? `- ${summary.scope_note}` : ''}
          </p>
        )}

        {scan && scan.status !== 'completed' && scan.status !== 'failed' && (
          <p className="muted">Summary will continue to update while the scan is running.</p>
        )}
      </Card>
      )}

      {isGreenbone && (activeGreenboneTab === 'results' || activeGreenboneTab === 'logs') && (
        <Card
          title={activeGreenboneTab === 'logs' ? 'Log Findings' : 'Findings'}
          subtitle={activeGreenboneTab === 'logs'
            ? 'Informational/Log findings from this Greenbone report.'
            : 'Greenbone results for this scan with expanded remediation and evidence details.'}
        >
          {activeGreenboneTab === 'results' && (
          <div className="settings-form-grid">
            <div className="field-stack">
              <label htmlFor="scanFindingSeverity">Severity</label>
              <select
                id="scanFindingSeverity"
                value={severityFilter}
                onChange={(event) => setSeverityFilter(event.target.value)}
              >
                <option value="all">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="log">Log/Informational</option>
              </select>
            </div>

            <div className="field-stack">
              <label htmlFor="scanFindingSearch">Search</label>
              <input
                id="scanFindingSearch"
                type="text"
                placeholder="Search by finding name, CVE, OID, description"
                value={findingSearch}
                onChange={(event) => setFindingSearch(event.target.value)}
              />
            </div>
          </div>
          )}

          <div className="table-wrapper table-wrapper-compact">
            <table className="ui-table ui-table-compact">
              <thead>
                <tr>
                  <th>Vulnerability</th>
                  <th>Severity</th>
                  <th>QoD</th>
                  <th>Host</th>
                  <th>Location</th>
                  <th>CVEs</th>
                  <th className="align-right">Details</th>
                </tr>
              </thead>
              <tbody>
                {displayedGreenboneRows.length === 0 && (
                  <tr>
                    <td colSpan={7} className="table-empty">
                      {activeGreenboneTab === 'logs'
                        ? 'No informational/log findings in this report.'
                        : 'No findings match the current filters.'}
                    </td>
                  </tr>
                )}

                {displayedGreenboneRows.map((row) => {
                  const bucket = normalizeSeverityBucket(row.cvss_severity || row.severity, row.cvss_score);
                  const cves = toCveArray(row);
                  const hasDetails = Boolean(row.description || row.solution || row.cvss_vector || row.nvt_oid || cves.length > 0);
                  const isExpanded = Boolean(expandedVulnerabilities[row._row_key]);

                  return (
                    <Fragment key={row._row_key}>
                      <tr>
                        <td>{String(row.name || '').trim() || (row.nvt_oid ? `NVT ${row.nvt_oid}` : 'Unnamed finding')}</td>
                        <td>
                          <span className={`severity-chip ${severityClass(bucket)}`}>
                            {bucket === 'log'
                              ? 'Log'
                              : formatCvss(row.cvss_score) !== '-'
                                ? `${formatCvss(row.cvss_score)} (${severityLabel(bucket)})`
                                : severityLabel(bucket)}
                          </span>
                        </td>
                        <td>{formatQod(row.qod)}</td>
                        <td>{row.device_ip || scan?.target || '-'}</td>
                        <td>{formatGreenboneLocation(row)}</td>
                        <td>{summarizeCves(cves)}</td>
                        <td className="align-right">
                          <button
                            type="button"
                            className="small-button"
                            disabled={!hasDetails}
                            onClick={() => toggleVulnerability(row._row_key)}
                          >
                            {isExpanded ? 'Hide' : 'Expand'}
                          </button>
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr className="port-detail-row">
                          <td colSpan={7}>
                            <div className="port-detail-panel">
                              {row.nvt_oid && (
                                <section className="port-detail-section">
                                  <h5>NVT OID</h5>
                                  <article className="port-detail-card">
                                    <p className="port-detail-text">{row.nvt_oid}</p>
                                  </article>
                                </section>
                              )}

                              {cves.length > 0 && (
                                <section className="port-detail-section">
                                  <h5>CVEs</h5>
                                  <article className="port-detail-card">
                                    <p className="port-detail-text">{cves.join(', ')}</p>
                                  </article>
                                </section>
                              )}

                              {row.solution && (
                                <section className="port-detail-section">
                                  <h5>Solution</h5>
                                  <article className="port-detail-card">
                                    <p className="port-detail-text">{row.solution}</p>
                                  </article>
                                </section>
                              )}

                              {row.cvss_vector && (
                                <section className="port-detail-section">
                                  <h5>CVSS Vector</h5>
                                  <article className="port-detail-card">
                                    <p className="port-detail-text">{row.cvss_vector}</p>
                                  </article>
                                </section>
                              )}

                              {row.description && (
                                <section className="port-detail-section">
                                  <h5>Description</h5>
                                  <article className="port-detail-card">
                                    <p className="port-detail-text">{row.description}</p>
                                  </article>
                                </section>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {isGreenbone && activeGreenboneTab === 'hosts' && (
        <Card title="Hosts" subtitle="Affected hosts from this Greenbone report.">
          <DataTable
            columns={greenboneDeviceColumns}
            rows={sortedDiscoveredDevices}
            emptyMessage="No affected hosts mapped for this report."
          />
        </Card>
      )}

      {isGreenbone && activeGreenboneTab === 'ports' && (
        <Card title="Ports" subtitle="Location summary based on Greenbone findings for this report.">
          <DataTable
            columns={[
              { key: 'location', header: 'Location' },
              { key: 'findings_count', header: 'Findings', align: 'right' },
              { key: 'critical_count', header: 'Critical', align: 'right' },
              { key: 'high_count', header: 'High', align: 'right' },
              { key: 'medium_count', header: 'Medium', align: 'right' },
              { key: 'low_count', header: 'Low', align: 'right' },
              { key: 'log_count', header: 'Log', align: 'right' },
              {
                key: 'top_cvss',
                header: 'Top CVSS',
                align: 'right',
                render: (row) => (Number.isFinite(row.top_cvss) ? Number(row.top_cvss).toFixed(1) : '-'),
              },
            ]}
            rows={greenbonePortRows}
            rowKey="row_key"
            emptyMessage="No location/port evidence in this report."
          />
        </Card>
      )}

      {isGreenbone && activeGreenboneTab === 'cves' && (
        <Card title="CVEs" subtitle="CVE evidence grouped by NVT for this Greenbone report.">
          <DataTable
            columns={[
              {
                key: 'cves',
                header: 'CVEs',
                render: (row) => (row.cves.length > 0 ? row.cves.join(', ') : '-'),
              },
              { key: 'nvt_name', header: 'NVT Name' },
              {
                key: 'highest_severity',
                header: 'Highest Severity',
                render: (row) => (
                  <span className={`severity-chip ${severityClass(row.highest_bucket)}`}>
                    {row.highest_severity}
                  </span>
                ),
              },
              {
                key: 'top_cvss',
                header: 'Top CVSS',
                align: 'right',
                render: (row) => (Number.isFinite(row.top_cvss) ? Number(row.top_cvss).toFixed(1) : '-'),
              },
            ]}
            rows={greenboneCveRows}
            rowKey="row_key"
            emptyMessage="No CVE evidence in this report."
          />
        </Card>
      )}

      {!isGreenbone && (
        <Card title="Observed Ports" subtitle="All recorded Nmap port evidence for this scan target.">
          <div className="table-wrapper table-wrapper-compact">
            <table className="ui-table ui-table-compact">
              <thead>
                <tr>
                  <th>Device</th>
                  <th>IP</th>
                  <th>Port</th>
                  <th>Protocol</th>
                  <th>State</th>
                  <th>Service</th>
                  <th>Version</th>
                  <th>Source</th>
                  <th>Confidence</th>
                  <th className="align-right">Details</th>
                </tr>
              </thead>
              <tbody>
                {nmapOpenPortsWithKeys.length === 0 && (
                  <tr>
                    <td colSpan={10} className="table-empty">No port records captured for this scan target.</td>
                  </tr>
                )}

                {nmapOpenPortsWithKeys.map((row) => {
                  const metadata = toObject(row.metadata);
                  const scriptResults = toObject(row.script_results);
                  const metadataEntries = Object.entries(metadata);
                  const hasDetails = metadataEntries.length > 0 || Object.keys(scriptResults).length > 0;
                  const isExpanded = Boolean(expandedPorts[row._row_key]);
                  const confidence = Number.parseFloat(row.source_confidence);
                  const normalizedConfidence = Number.isFinite(confidence)
                    ? confidence > 1 ? confidence / 100 : confidence
                    : null;

                  return (
                    <Fragment key={row._row_key}>
                      <tr>
                        <td>{row.device_name || '-'}</td>
                        <td>{row.ip_address || '-'}</td>
                        <td>{Number.isInteger(row.port) ? row.port : '-'}</td>
                        <td>{row.protocol || '-'}</td>
                        <td><StatusBadge status={row.state || 'unknown'} /></td>
                        <td>{row.service || '-'}</td>
                        <td>{row.version || '-'}</td>
                        <td>{row.last_source || '-'}</td>
                        <td>{Number.isFinite(normalizedConfidence) ? `${Math.round(normalizedConfidence * 100)}%` : '-'}</td>
                        <td className="align-right">
                          <button
                            type="button"
                            className="small-button"
                            disabled={!hasDetails}
                            onClick={() => togglePort(row._row_key)}
                          >
                            {isExpanded ? 'Hide' : 'Expand'}
                          </button>
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr className="port-detail-row">
                          <td colSpan={10}>
                            <div className="port-detail-panel">
                              {Object.keys(scriptResults).length > 0 && (
                                <section className="port-detail-section">
                                  <h5>Script Results</h5>
                                  {Object.entries(scriptResults).map(([scriptId, payload]) => {
                                    const payloadObject = toObject(payload);
                                    const output = typeof payload === 'string'
                                      ? payload
                                      : payloadObject.output || '';
                                    const detailPayload = payloadObject.details || payloadObject;
                                    return (
                                      <article className="port-detail-card" key={`${row._row_key}-${scriptId}`}>
                                        <p className="port-detail-title">{scriptId}</p>
                                        {output && <p className="port-detail-text">{output}</p>}
                                        {detailPayload && Object.keys(toObject(detailPayload)).length > 0 && (
                                          <pre className="port-detail-pre">{JSON.stringify(detailPayload, null, 2)}</pre>
                                        )}
                                      </article>
                                    );
                                  })}
                                </section>
                              )}

                              {metadataEntries.length > 0 && (
                                <section className="port-detail-section">
                                  <h5>Metadata</h5>
                                  {metadataEntries.map(([key, value]) => (
                                    <article className="port-detail-card" key={`${row._row_key}-${key}`}>
                                      <p className="port-detail-title">{key}</p>
                                      <pre className="port-detail-pre">{JSON.stringify(value, null, 2)}</pre>
                                    </article>
                                  ))}
                                </section>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {!isGreenbone && (
        <Card
          title="Discovered Devices"
          subtitle="Target hosts correlated to this Nmap scan context."
        >
          <DataTable
            columns={nmapDeviceColumns}
            rows={sortedDiscoveredDevices}
            emptyMessage="No discovered devices mapped for this scan."
          />
        </Card>
      )}

      {!isGreenbone && (
        <Card title="Host Evidence" subtitle="Host-level metadata and script results captured by Nmap parsing.">
          <div className="table-wrapper table-wrapper-compact">
            <table className="ui-table ui-table-compact">
              <thead>
                <tr>
                  <th>Device</th>
                  <th>IP</th>
                  <th>Status</th>
                  <th>Last Seen</th>
                  <th className="align-right">Details</th>
                </tr>
              </thead>
              <tbody>
                {sortedDiscoveredDevices.length === 0 && (
                  <tr>
                    <td colSpan={5} className="table-empty">No host-level evidence for this scan.</td>
                  </tr>
                )}

                {sortedDiscoveredDevices.map((row, index) => {
                  const metadata = toObject(row.metadata);
                  const scriptResults = toObject(row.script_results);
                  const metadataEntries = Object.entries(metadata);
                  const hasDetails = metadataEntries.length > 0 || Object.keys(scriptResults).length > 0;
                  const rowKey = `host-${row.id || index}`;
                  const isExpanded = Boolean(expandedPorts[rowKey]);

                  return (
                    <Fragment key={rowKey}>
                      <tr>
                        <td>{row.display_name || row.hostname || row.ip_address || '-'}</td>
                        <td>{row.ip_address || '-'}</td>
                        <td><StatusBadge status={toOnlineStatusLabel(row.online_status)} /></td>
                        <td>{formatDateTime(row.last_seen)}</td>
                        <td className="align-right">
                          <button
                            type="button"
                            className="small-button"
                            disabled={!hasDetails}
                            onClick={() => togglePort(rowKey)}
                          >
                            {isExpanded ? 'Hide' : 'Expand'}
                          </button>
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr className="port-detail-row">
                          <td colSpan={5}>
                            <div className="port-detail-panel">
                              {Object.keys(scriptResults).length > 0 && (
                                <section className="port-detail-section">
                                  <h5>Host Script Results</h5>
                                  {Object.entries(scriptResults).map(([scriptId, payload]) => {
                                    const payloadObject = toObject(payload);
                                    const output = typeof payload === 'string'
                                      ? payload
                                      : payloadObject.output || '';
                                    const detailPayload = payloadObject.details || payloadObject;
                                    return (
                                      <article className="port-detail-card" key={`${rowKey}-${scriptId}`}>
                                        <p className="port-detail-title">{scriptId}</p>
                                        {output && <p className="port-detail-text">{output}</p>}
                                        {detailPayload && Object.keys(toObject(detailPayload)).length > 0 && (
                                          <pre className="port-detail-pre">{JSON.stringify(detailPayload, null, 2)}</pre>
                                        )}
                                      </article>
                                    );
                                  })}
                                </section>
                              )}

                              {metadataEntries.length > 0 && (
                                <section className="port-detail-section">
                                  <h5>Host Metadata</h5>
                                  {metadataEntries.map(([key, value]) => (
                                    <article className="port-detail-card" key={`${rowKey}-${key}`}>
                                      <p className="port-detail-title">{key}</p>
                                      <pre className="port-detail-pre">{JSON.stringify(value, null, 2)}</pre>
                                    </article>
                                  ))}
                                </section>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
