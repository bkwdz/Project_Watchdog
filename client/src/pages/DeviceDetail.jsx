import { Fragment, useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  createScan,
  createVulnerabilityScan,
  getDeviceById,
  getScanById,
  getVulnerabilityCredentials,
  updateDevice,
  getVulnerabilityScanConfigs,
  getVulnerabilityScannerStatus,
} from '../api/endpoints';
import Card from '../components/Card';
import CredentialFields from '../components/CredentialFields';
import DataTable from '../components/DataTable';
import HoverProfileSelect from '../components/HoverProfileSelect';
import PieChart from '../components/PieChart';
import ProgressBar from '../components/ProgressBar';
import StatusBadge from '../components/StatusBadge';
import ToastStack from '../components/ToastStack';
import useScansFeed from '../hooks/useScansFeed';
import useToast from '../hooks/useToast';
import { cidrContains, isCidr } from '../utils/ip';
import { formatDateTime } from '../utils/time';

const DEVICE_TABS = [
  { key: 'overview', label: 'Overview' },
  { key: 'scan-console', label: 'Scan Console' },
  { key: 'vulnerabilities', label: 'Vulnerabilities' },
  { key: 'ports', label: 'Ports & Services' },
  { key: 'certificates', label: 'Certificates & Keys' },
  { key: 'cves', label: 'CVEs' },
];

function scanRelatesToDevice(scan, deviceIp) {
  if (!scan?.target || !deviceIp) {
    return false;
  }

  if (scan.target === deviceIp) {
    return true;
  }

  if (isCidr(scan.target)) {
    return cidrContains(scan.target, deviceIp);
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

function normalizeSeverityBucket(value) {
  const normalized = String(value || '').toLowerCase().trim();

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

function severityRank(value) {
  const bucket = normalizeSeverityBucket(value);

  if (bucket === 'critical') {
    return 4;
  }

  if (bucket === 'high') {
    return 3;
  }

  if (bucket === 'medium') {
    return 2;
  }

  return 1;
}

function isInformationalFinding(row) {
  const score = Number.parseFloat(row?.cvss_score);
  const severity = String(row?.cvss_severity || row?.severity || '').toLowerCase();

  if (Number.isFinite(score) && score <= 0) {
    return true;
  }

  return severity.includes('log') || severity.includes('none') || severity.includes('info');
}

function toObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }

  return value;
}

function toCveArray(row) {
  const cves = new Set();

  (Array.isArray(row?.cve_list) ? row.cve_list : []).forEach((entry) => {
    const normalized = String(entry || '').trim().toUpperCase();

    if (/^CVE-\d{4}-\d{4,}$/.test(normalized)) {
      cves.add(normalized);
    }
  });

  const fallback = String(row?.cve || '').trim().toUpperCase();

  if (/^CVE-\d{4}-\d{4,}$/.test(fallback)) {
    cves.add(fallback);
  }

  return [...cves];
}

function portKey(row) {
  return `${row?.port ?? 'unknown'}-${row?.protocol ?? 'proto'}-${row?.id ?? 'row'}`;
}

function vulnerabilityKey(row) {
  return `${row?.id ?? 'vuln'}-${row?.nvt_oid ?? 'oid'}-${row?.port ?? 'port'}`;
}

export default function DeviceDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { toasts, pushToast, removeToast } = useToast();

  const [device, setDevice] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [triggeringType, setTriggeringType] = useState('');
  const [activeScan, setActiveScan] = useState(null);

  const [vulnEnabled, setVulnEnabled] = useState(false);
  const [vulnStatusLoaded, setVulnStatusLoaded] = useState(false);
  const [vulnTriggering, setVulnTriggering] = useState(false);
  const [vulnStatusMessage, setVulnStatusMessage] = useState('');
  const [vulnConfigs, setVulnConfigs] = useState([]);
  const [vulnConfigId, setVulnConfigId] = useState('');
  const [vulnConfigsLoaded, setVulnConfigsLoaded] = useState(false);
  const [vulnTcpPorts, setVulnTcpPorts] = useState('1-1000');
  const [vulnUdpPorts, setVulnUdpPorts] = useState('');
  const [useCredentials, setUseCredentials] = useState(false);
  const [credentialMode, setCredentialMode] = useState('existing');
  const [credentialType, setCredentialType] = useState('ssh');
  const [credentialOptions, setCredentialOptions] = useState([]);
  const [credentialsLoading, setCredentialsLoading] = useState(false);
  const [credentialId, setCredentialId] = useState('');
  const [credentialName, setCredentialName] = useState('');
  const [credentialUsername, setCredentialUsername] = useState('');
  const [credentialPassword, setCredentialPassword] = useState('');

  const [hostnameEditing, setHostnameEditing] = useState(false);
  const [hostnameDraft, setHostnameDraft] = useState('');
  const [hostnameSaving, setHostnameSaving] = useState(false);

  const [activeTab, setActiveTab] = useState('overview');
  const [expandedPorts, setExpandedPorts] = useState({});
  const [expandedVulnerabilities, setExpandedVulnerabilities] = useState({});

  const {
    scans,
    loading: scansLoading,
    error: scansError,
    listUnavailable,
    loadScans,
    registerScan,
  } = useScansFeed();

  const loadDevice = useCallback(async () => {
    setError('');

    try {
      const data = await getDeviceById(id);
      setDevice(data);
    } catch (err) {
      setError(err?.response?.data?.error || 'Unable to load device');
    } finally {
      setLoading(false);
    }
  }, [id]);

  const loadVulnerabilityStatus = useCallback(async () => {
    setVulnStatusLoaded(false);
    setVulnStatusMessage('');

    try {
      await getVulnerabilityScannerStatus();
      setVulnEnabled(true);
    } catch (err) {
      if (err?.response?.status === 503) {
        setVulnEnabled(false);
        setVulnStatusMessage('Vulnerability scanner is not active.');
      } else {
        setVulnEnabled(false);
        setVulnStatusMessage('Unable to reach vulnerability scanner.');
      }
    } finally {
      setVulnStatusLoaded(true);
    }
  }, []);

  const loadVulnerabilityConfigs = useCallback(async () => {
    setVulnConfigsLoaded(false);

    try {
      const data = await getVulnerabilityScanConfigs();
      const configs = Array.isArray(data?.configs) ? data.configs : [];
      const defaultConfigId = String(data?.default_scan_config_id || '').trim();

      setVulnConfigs(configs);

      if (configs.length === 0) {
        setVulnConfigId('');
        setVulnStatusMessage('No vulnerability scan configurations are available in Greenbone yet.');
      } else {
        const selectedId = defaultConfigId && configs.some((config) => config.id === defaultConfigId)
          ? defaultConfigId
          : configs[0].id;
        setVulnConfigId(selectedId);
        setVulnStatusMessage('');
      }
    } catch (err) {
      setVulnConfigs([]);
      setVulnConfigId('');
      setVulnStatusMessage(err?.response?.data?.error || 'Unable to load vulnerability scan configurations.');
    } finally {
      setVulnConfigsLoaded(true);
    }
  }, []);

  const loadVulnerabilityCredentials = useCallback(async (type) => {
    setCredentialsLoading(true);

    try {
      const data = await getVulnerabilityCredentials(type);
      const entries = Array.isArray(data?.credentials) ? data.credentials : [];
      setCredentialOptions(entries);
      setCredentialId((current) => {
        if (current && entries.some((entry) => String(entry.id) === String(current))) {
          return current;
        }

        return entries[0]?.id ? String(entries[0].id) : '';
      });
    } catch (err) {
      setCredentialOptions([]);
      setCredentialId('');
      pushToast(err?.response?.data?.error || 'Unable to load saved credentials.', 'error');
    } finally {
      setCredentialsLoading(false);
    }
  }, [pushToast]);

  useEffect(() => {
    void loadDevice();
    void loadVulnerabilityStatus();
  }, [loadDevice, loadVulnerabilityStatus]);

  useEffect(() => {
    if (!vulnStatusLoaded) {
      return;
    }

    if (!vulnEnabled) {
      setVulnConfigs([]);
      setVulnConfigId('');
      setVulnConfigsLoaded(true);
      return;
    }

    void loadVulnerabilityConfigs();
  }, [loadVulnerabilityConfigs, vulnEnabled, vulnStatusLoaded]);

  useEffect(() => {
    if (!useCredentials || credentialMode !== 'existing' || !vulnEnabled || !vulnStatusLoaded) {
      return;
    }

    void loadVulnerabilityCredentials(credentialType);
  }, [
    credentialMode,
    credentialType,
    loadVulnerabilityCredentials,
    useCredentials,
    vulnEnabled,
    vulnStatusLoaded,
  ]);

  useEffect(() => {
    if (!activeScan?.id) {
      return undefined;
    }

    const timer = window.setInterval(async () => {
      try {
        const next = await getScanById(activeScan.id);
        registerScan(next);
        setActiveScan(next);

        if (next.status === 'completed' || next.status === 'failed') {
          window.clearInterval(timer);
          pushToast(`Scan #${next.id} ${next.status}.`, next.status === 'completed' ? 'success' : 'error');
          setActiveScan(null);
          void loadDevice();
          void loadScans();
        }
      } catch (pollError) {
        window.clearInterval(timer);
        setActiveScan(null);
        pushToast(pollError?.response?.data?.error || 'Scan polling failed.', 'error');
      }
    }, 3000);

    return () => {
      window.clearInterval(timer);
    };
  }, [activeScan, loadDevice, loadScans, pushToast, registerScan]);

  useEffect(() => {
    if (!device || hostnameEditing) {
      return;
    }

    setHostnameDraft(device.display_name || device.displayName || '');
  }, [device, hostnameEditing]);

  const startProfileScan = async (scanType) => {
    const targetIp = device?.ip_address || device?.ip;

    if (!targetIp) {
      pushToast('Device IP is not available for scanning.', 'error');
      return;
    }

    setTriggeringType(scanType);

    try {
      const scan = await createScan({ target: targetIp, scan_type: scanType });
      registerScan(scan);
      setActiveScan(scan);
      pushToast(`Scan #${scan.id} queued (${scanType}).`, 'success');
      window.dispatchEvent(new CustomEvent('watchdog:scan-created', { detail: scan }));
    } catch (err) {
      pushToast(err?.response?.data?.error || 'Unable to start scan.', 'error');
    } finally {
      setTriggeringType('');
    }
  };

  const startVulnScan = async () => {
    const targetIp = device?.ip_address || device?.ip;

    if (!targetIp) {
      pushToast('Device IP is not available for vulnerability scanning.', 'error');
      return;
    }

    if (!vulnConfigId) {
      pushToast('No vulnerability scan configuration is available yet.', 'error');
      return;
    }

    setVulnTriggering(true);

    try {
      let credentials = { mode: 'none' };

      if (useCredentials) {
        if (credentialMode === 'existing') {
          const parsedCredentialId = Number(credentialId);

          if (!Number.isInteger(parsedCredentialId) || parsedCredentialId < 1) {
            throw new Error('Select a saved credential before starting the scan.');
          }

          credentials = {
            mode: 'existing',
            type: credentialType,
            credential_id: parsedCredentialId,
          };
        } else {
          const username = credentialUsername.trim();
          const password = credentialPassword.trim();

          if (!username || !password) {
            throw new Error('Credential username and password are required.');
          }

          credentials = {
            mode: 'new',
            type: credentialType,
            name: credentialName.trim(),
            username,
            password,
          };
        }
      }

      const scan = await createVulnerabilityScan(targetIp, vulnConfigId, {
        tcpPorts: vulnTcpPorts,
        udpPorts: vulnUdpPorts,
        credentials,
      });
      registerScan(scan);
      pushToast(`Vulnerability scan #${scan.id} started.`, 'success');
      window.dispatchEvent(new CustomEvent('watchdog:scan-created', { detail: scan }));
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      const apiMessage = err?.response?.data?.error;

      if (err?.response?.status === 503) {
        setVulnEnabled(false);
        setVulnStatusMessage('Vulnerability scanner is not active.');
      }

      pushToast(apiMessage || 'Unable to start vulnerability scan.', 'error');
    } finally {
      setVulnTriggering(false);
    }
  };
  const relatedScans = useMemo(() => {
    if (!device?.ip_address) {
      return [];
    }

    return scans
      .filter((scan) => scanRelatesToDevice(scan, device.ip_address))
      .sort((a, b) => {
        const left = a.started_at ? new Date(a.started_at).getTime() : 0;
        const right = b.started_at ? new Date(b.started_at).getTime() : 0;
        return right - left || b.id - a.id;
      });
  }, [device?.ip_address, scans]);

  const portRows = useMemo(() => (Array.isArray(device?.ports) ? device.ports : []), [device]);
  const vulnerabilityRows = useMemo(
    () => (Array.isArray(device?.vulnerabilities) ? device.vulnerabilities.filter((row) => !isInformationalFinding(row)) : []),
    [device],
  );
  const tlsCertificateRows = useMemo(
    () => (Array.isArray(device?.tls_certificates) ? device.tls_certificates : []),
    [device],
  );
  const sshHostKeyRows = useMemo(
    () => (Array.isArray(device?.ssh_host_keys) ? device.ssh_host_keys : []),
    [device],
  );

  useEffect(() => {
    setExpandedPorts({});
  }, [portRows.length]);

  useEffect(() => {
    setExpandedVulnerabilities({});
  }, [vulnerabilityRows.length]);

  const cveRows = useMemo(() => {
    const map = new Map();

    vulnerabilityRows.forEach((row) => {
      const cves = toCveArray(row);

      cves.forEach((cve) => {
        const score = Number.parseFloat(row.cvss_score);
        const severity = row.cvss_severity || row.severity || 'Low';
        const existing = map.get(cve);

        if (!existing) {
          map.set(cve, {
            cve,
            severity,
            cvss_score: Number.isFinite(score) ? score : null,
            ports: row.port != null ? [row.port] : [],
            findings: 1,
          });
          return;
        }

        existing.findings += 1;

        if (row.port != null && !existing.ports.includes(row.port)) {
          existing.ports.push(row.port);
        }

        if (severityRank(severity) > severityRank(existing.severity)) {
          existing.severity = severity;
        }

        if (Number.isFinite(score) && (!Number.isFinite(existing.cvss_score) || score > existing.cvss_score)) {
          existing.cvss_score = score;
        }
      });
    });

    return [...map.values()]
      .map((row) => ({
        ...row,
        ports: row.ports.sort((left, right) => left - right),
      }))
      .sort((left, right) => {
        const severityDiff = severityRank(right.severity) - severityRank(left.severity);

        if (severityDiff !== 0) {
          return severityDiff;
        }

        const leftScore = Number.isFinite(left.cvss_score) ? left.cvss_score : -1;
        const rightScore = Number.isFinite(right.cvss_score) ? right.cvss_score : -1;

        if (rightScore !== leftScore) {
          return rightScore - leftScore;
        }

        return left.cve.localeCompare(right.cve);
      });
  }, [vulnerabilityRows]);

  const deviceSnapshot = useMemo(() => {
    const openPorts = portRows.filter((row) => String(row.state || '').toLowerCase() === 'open');
    const tcpOpen = openPorts.filter((row) => String(row.protocol || '').toLowerCase() === 'tcp').length;
    const udpOpen = openPorts.filter((row) => String(row.protocol || '').toLowerCase() === 'udp').length;

    const severityCounts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    vulnerabilityRows.forEach((row) => {
      const bucket = normalizeSeverityBucket(row.cvss_severity || row.severity);
      severityCounts[bucket] += 1;
    });

    const serviceCounts = new Map();
    openPorts.forEach((row) => {
      const key = String(row.service || 'unknown').toLowerCase();
      serviceCounts.set(key, (serviceCounts.get(key) || 0) + 1);
    });

    const topServices = [...serviceCounts.entries()]
      .map(([service, count]) => ({ service, count }))
      .sort((a, b) => b.count - a.count || a.service.localeCompare(b.service))
      .slice(0, 5);

    return {
      totalOpenPorts: openPorts.length,
      tcpOpen,
      udpOpen,
      vulnerabilityTotal: vulnerabilityRows.length,
      severityCounts,
      topServices,
    };
  }, [portRows, vulnerabilityRows]);

  const historyColumns = useMemo(
    () => [
      { key: 'id', header: 'ID' },
      { key: 'target', header: 'Target' },
      {
        key: 'scan_type',
        header: 'Type',
        render: (scan) => (scan.scanner_type === 'greenbone' ? 'vulnerability' : scan.scan_type),
      },
      { key: 'status', header: 'Status', render: (scan) => <StatusBadge status={scan.status} /> },
      { key: 'started_at', header: 'Started', render: (scan) => formatDateTime(scan.started_at) },
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

  const tlsColumns = useMemo(
    () => [
      {
        key: 'port',
        header: 'Port',
        render: (row) => (Number.isInteger(row.port) ? `${row.port}/${row.protocol || 'tcp'}` : '-'),
      },
      { key: 'subject', header: 'Subject' },
      { key: 'issuer', header: 'Issuer' },
      { key: 'fingerprint_sha256', header: 'SHA-256 Fingerprint' },
      {
        key: 'not_after',
        header: 'Valid Until',
        render: (row) => formatDateTime(row.not_after),
      },
    ],
    [],
  );

  const sshColumns = useMemo(
    () => [
      {
        key: 'port',
        header: 'Port',
        render: (row) => (Number.isInteger(row.port) ? `${row.port}/${row.protocol || 'tcp'}` : '-'),
      },
      { key: 'key_type', header: 'Key Type' },
      { key: 'fingerprint', header: 'Fingerprint' },
      {
        key: 'key_bits',
        header: 'Bits',
        align: 'right',
        render: (row) => row.key_bits ?? '-',
      },
    ],
    [],
  );

  const cveColumns = useMemo(
    () => [
      {
        key: 'cve',
        header: 'CVE',
        render: (row) => (
          <a href={`https://nvd.nist.gov/vuln/detail/${row.cve}`} target="_blank" rel="noreferrer">
            {row.cve}
          </a>
        ),
      },
      {
        key: 'severity',
        header: 'Highest Severity',
        render: (row) => <span className={`severity-chip ${severityClass(row.severity)}`}>{row.severity}</span>,
      },
      {
        key: 'cvss_score',
        header: 'Top CVSS',
        align: 'right',
        render: (row) => (Number.isFinite(row.cvss_score) ? row.cvss_score.toFixed(1) : '-'),
      },
      {
        key: 'ports',
        header: 'Ports',
        render: (row) => (row.ports.length > 0 ? row.ports.join(', ') : '-'),
      },
      {
        key: 'findings',
        header: 'Finding Count',
        align: 'right',
      },
    ],
    [],
  );

  const severitySegments = useMemo(
    () => [
      {
        key: 'critical',
        label: 'Critical',
        value: deviceSnapshot.severityCounts.critical,
        color: '#ff5d5d',
      },
      {
        key: 'high',
        label: 'High',
        value: deviceSnapshot.severityCounts.high,
        color: '#ff8a80',
      },
      {
        key: 'medium',
        label: 'Medium',
        value: deviceSnapshot.severityCounts.medium,
        color: '#ff8f43',
      },
      {
        key: 'low',
        label: 'Low',
        value: deviceSnapshot.severityCounts.low,
        color: '#5ad68a',
      },
    ],
    [deviceSnapshot.severityCounts],
  );

  const bestOsLabel = useMemo(() => {
    if (!device?.os_guess) {
      return '-';
    }

    const source = String(device.os_guess_source || '').trim();
    const confidence = Number.parseFloat(device.os_guess_confidence);
    const confidenceLabel = Number.isFinite(confidence) ? `${Math.round(confidence * 100)}%` : '';
    const meta = [source, confidenceLabel].filter(Boolean).join(', ');

    return meta ? `${device.os_guess} (${meta})` : device.os_guess;
  }, [device]);

  const saveHostname = async () => {
    if (!device?.id) {
      return;
    }

    const nextDisplayName = hostnameDraft.trim();
    const currentDisplayName = String(device.display_name || device.displayName || '').trim();

    if (nextDisplayName === currentDisplayName) {
      setHostnameEditing(false);
      return;
    }

    setHostnameSaving(true);

    try {
      const updated = await updateDevice(device.id, { display_name: nextDisplayName });
      setDevice((prev) => {
        if (!prev) {
          return updated;
        }

        return {
          ...prev,
          ...updated,
          ports: prev.ports,
          vulnerabilities: prev.vulnerabilities,
          tls_certificates: prev.tls_certificates,
          ssh_host_keys: prev.ssh_host_keys,
        };
      });
      setHostnameEditing(false);
      pushToast('Device display name updated.', 'success');
    } catch (err) {
      pushToast(err?.response?.data?.error || 'Unable to update device display name.', 'error');
    } finally {
      setHostnameSaving(false);
    }
  };

  const togglePortExpansion = (key) => {
    setExpandedPorts((current) => ({
      ...current,
      [key]: !current[key],
    }));
  };

  const toggleVulnerabilityExpansion = (key) => {
    setExpandedVulnerabilities((current) => ({
      ...current,
      [key]: !current[key],
    }));
  };

  return (
    <div className="page-stack">
      <Card title="Device Detail" subtitle={device?.ip_address || device?.ip || 'Host record'}>
        {loading && <p className="muted">Loading device...</p>}
        {error && <p className="error-text">{error}</p>}

        {!loading && !error && device && (
          <>
            <div className="device-identity-row">
              <div className="device-identity-main">
                <p className="device-identity-label">Display Name</p>
                <h4 className="device-identity-value">
                  {device.display_name || device.displayName || device.hostname || device.ip_address || device.ip || '-'}
                </h4>
              </div>
              {!hostnameEditing && (
                <button
                  type="button"
                  className="icon-button"
                  aria-label="Edit device display name"
                  onClick={() => setHostnameEditing(true)}
                >
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path
                      d="M4 17.25V20h2.75L17.81 8.94l-2.75-2.75L4 17.25zm15.71-9.04a1.003 1.003 0 000-1.42l-2.5-2.5a1.003 1.003 0 00-1.42 0l-1.96 1.96 3.92 3.92 1.96-1.96z"
                      fill="currentColor"
                    />
                  </svg>
                </button>
              )}
            </div>

            {hostnameEditing && (
              <div className="hostname-edit-row">
                <div className="field-stack hostname-field">
                  <label htmlFor="hostname-edit-input">Display Name</label>
                  <input
                    id="hostname-edit-input"
                    type="text"
                    placeholder="Set custom display name (blank clears)"
                    value={hostnameDraft}
                    disabled={hostnameSaving}
                    onChange={(event) => setHostnameDraft(event.target.value)}
                  />
                </div>
                <div className="hostname-edit-actions">
                  <button
                    type="button"
                    className="primary-button"
                    disabled={hostnameSaving}
                    onClick={saveHostname}
                  >
                    {hostnameSaving ? 'Saving...' : 'Save'}
                  </button>
                  <button
                    type="button"
                    className="ghost-button"
                    disabled={hostnameSaving}
                    onClick={() => {
                      setHostnameEditing(false);
                      setHostnameDraft(device.display_name || device.displayName || '');
                    }}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            <dl className="detail-grid">
              <div>
                <dt>IP</dt>
                <dd>{device.ip_address || device.ip || '-'}</dd>
              </div>
              <div>
                <dt>Hostname</dt>
                <dd>{device.hostname || '-'}</dd>
              </div>
              <div>
                <dt>MAC</dt>
                <dd>{device.mac_address || device.mac || '-'}</dd>
              </div>
              <div>
                <dt>OS</dt>
                <dd>{bestOsLabel}</dd>
              </div>
              <div>
                <dt>Status</dt>
                <dd>{device.online || device.online_status ? 'Online' : 'Offline'}</dd>
              </div>
              <div>
                <dt>Last Health Check</dt>
                <dd>{formatDateTime(device.last_healthcheck_at)}</dd>
              </div>
            </dl>
          </>
        )}
      </Card>

      <Card title="Device Console" subtitle="Detailed host intelligence with reconciled Nmap and Greenbone data.">
        {loading && <p className="muted">Loading console data...</p>}
        {error && <p className="error-text">{error}</p>}

        {!loading && !error && device && (
          <>
            <div className="device-tab-list" role="tablist" aria-label="Device detail tabs">
              {DEVICE_TABS.map((tab) => (
                <button
                  key={tab.key}
                  type="button"
                  role="tab"
                  aria-selected={activeTab === tab.key}
                  className={`device-tab-button ${activeTab === tab.key ? 'active' : ''}`}
                  onClick={() => setActiveTab(tab.key)}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="device-tab-panel">
              {activeTab === 'overview' && (
                <>
                  <div className="device-kpi-grid">
                    <article className="kpi-tile">
                      <p className="kpi-label">Open Ports</p>
                      <p className="kpi-value">{deviceSnapshot.totalOpenPorts}</p>
                    </article>
                    <article className="kpi-tile">
                      <p className="kpi-label">TCP Open</p>
                      <p className="kpi-value">{deviceSnapshot.tcpOpen}</p>
                    </article>
                    <article className="kpi-tile">
                      <p className="kpi-label">UDP Open</p>
                      <p className="kpi-value">{deviceSnapshot.udpOpen}</p>
                    </article>
                    <article className="kpi-tile">
                      <p className="kpi-label">Vulnerabilities</p>
                      <p className="kpi-value">{deviceSnapshot.vulnerabilityTotal}</p>
                    </article>
                  </div>

                  <div className="device-insight-grid">
                    <article className="insight-panel">
                      <h4>Severity Distribution</h4>
                      <div className="device-severity-layout">
                        <div className="severity-bars">
                          {['critical', 'high', 'medium', 'low'].map((bucket) => {
                            const count = deviceSnapshot.severityCounts[bucket];
                            const denominator = deviceSnapshot.vulnerabilityTotal || 1;
                            const width = Math.round((count / denominator) * 100);

                            return (
                              <div key={bucket} className="severity-bar-row">
                                <span className="severity-name">{bucket}</span>
                                <div className="severity-bar-track">
                                  <div className={`severity-bar-fill severity-${bucket}`} style={{ width: `${width}%` }} />
                                </div>
                                <span className="severity-count">{count}</span>
                              </div>
                            );
                          })}
                        </div>

                        <PieChart
                          title="Severity"
                          totalLabel={deviceSnapshot.vulnerabilityTotal}
                          segments={severitySegments}
                        />
                      </div>
                    </article>

                    <article className="insight-panel">
                      <h4>Top Open Services</h4>
                      {deviceSnapshot.topServices.length === 0 && <p className="muted">No open services observed yet.</p>}
                      {deviceSnapshot.topServices.length > 0 && (
                        <div className="service-bars">
                          {deviceSnapshot.topServices.map((row) => {
                            const maxCount = deviceSnapshot.topServices[0].count || 1;
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
                    </article>
                  </div>

                  <article className="insight-panel">
                    <h4>Scan History</h4>
                    {scansLoading && <p className="muted">Loading scan history...</p>}
                    {scansError && <p className="error-text">{scansError}</p>}
                    {listUnavailable && (
                      <p className="muted">
                        Scan list endpoint is unavailable. Showing scans known to this browser session.
                      </p>
                    )}
                    <DataTable columns={historyColumns} rows={relatedScans} emptyMessage="No related scans found." />
                  </article>
                </>
              )}

              {activeTab === 'scan-console' && (
                <>
                  <div className="device-actions-layout">
                    <section className="device-actions-nmap">
                      <p className="actions-group-title">Nmap Scan Profiles</p>
                      <div className="nmap-button-row">
                        {['quick', 'standard', 'aggressive', 'full'].map((scanType) => (
                          <button
                            key={scanType}
                            type="button"
                            className="primary-button nmap-action-button"
                            disabled={Boolean(triggeringType) || loading || !device}
                            onClick={() => startProfileScan(scanType)}
                          >
                            {triggeringType === scanType ? 'Starting...' : `${scanType[0].toUpperCase()}${scanType.slice(1)} Scan`}
                          </button>
                        ))}
                      </div>
                    </section>

                    <section className="device-actions-vuln">
                      <p className="actions-group-title">Vulnerability Scan (Greenbone)</p>
                      <div className="vuln-action-inline">
                        <button
                          type="button"
                          className="danger-button"
                          disabled={!vulnEnabled || !vulnStatusLoaded || !vulnConfigsLoaded || !vulnConfigId || vulnTriggering || loading || !device}
                          title={vulnEnabled ? 'Run Greenbone vulnerability scan' : 'Vulnerability scanner not enabled'}
                          onClick={startVulnScan}
                        >
                          {vulnTriggering ? 'Starting...' : 'Vulnerability Scan'}
                        </button>

                        <HoverProfileSelect
                          id="vuln-config-select"
                          className="vuln-profile-select"
                          ariaLabel="Vulnerability Scan Profile"
                          value={vulnConfigId}
                          options={vulnConfigs}
                          disabled={!vulnEnabled || !vulnStatusLoaded || !vulnConfigsLoaded || vulnTriggering || loading || !device}
                          onChange={setVulnConfigId}
                        />

                        <div className="vuln-port-row">
                          <div className="field-stack vuln-port-field">
                            <label htmlFor="vuln-tcp-ports">TCP Ports</label>
                            <input
                              id="vuln-tcp-ports"
                              type="text"
                              placeholder="1-1000"
                              value={vulnTcpPorts}
                              disabled={!vulnEnabled || !vulnStatusLoaded || vulnTriggering || loading || !device}
                              onChange={(event) => setVulnTcpPorts(event.target.value)}
                            />
                          </div>
                          <div className="field-stack vuln-port-field">
                            <label htmlFor="vuln-udp-ports">UDP Ports</label>
                            <input
                              id="vuln-udp-ports"
                              type="text"
                              placeholder="blank or 0 = disabled"
                              value={vulnUdpPorts}
                              disabled={!vulnEnabled || !vulnStatusLoaded || vulnTriggering || loading || !device}
                              onChange={(event) => setVulnUdpPorts(event.target.value)}
                            />
                          </div>
                        </div>

                        <CredentialFields
                          useCredentials={useCredentials}
                          setUseCredentials={setUseCredentials}
                          credentialMode={credentialMode}
                          setCredentialMode={setCredentialMode}
                          credentialType={credentialType}
                          setCredentialType={setCredentialType}
                          credentialId={credentialId}
                          setCredentialId={setCredentialId}
                          credentialName={credentialName}
                          setCredentialName={setCredentialName}
                          credentialUsername={credentialUsername}
                          setCredentialUsername={setCredentialUsername}
                          credentialPassword={credentialPassword}
                          setCredentialPassword={setCredentialPassword}
                          credentialOptions={credentialOptions}
                          credentialsLoading={credentialsLoading}
                          disabled={vulnTriggering || loading || !device}
                        />

                        {!vulnConfigsLoaded && vulnEnabled && (
                          <p className="muted vuln-status-inline">Loading vulnerability scan profiles...</p>
                        )}
                        {vulnStatusLoaded && vulnStatusMessage && (
                          <p className="warning-text vuln-status-inline">{vulnStatusMessage}</p>
                        )}
                      </div>
                    </section>
                  </div>

                  {activeScan && (
                    <div className="scan-inline-status">
                      <p>
                        Scan #{activeScan.id}: <StatusBadge status={activeScan.status} />
                      </p>
                      {(activeScan.status === 'running' || activeScan.status === 'queued') && (
                        <ProgressBar value={activeScan.progress_percent || 10} />
                      )}
                    </div>
                  )}
                </>
              )}

              {activeTab === 'vulnerabilities' && (
                <>
                  <p className="muted">Actionable Greenbone findings only. Informational logs are excluded.</p>
                  <div className="table-wrapper table-wrapper-compact">
                    <table className="ui-table ui-table-compact">
                      <thead>
                        <tr>
                          <th>Severity</th>
                          <th>Name</th>
                          <th>QoD</th>
                          <th>CVSS</th>
                          <th>Port</th>
                          <th className="align-right">Details</th>
                        </tr>
                      </thead>
                      <tbody>
                        {vulnerabilityRows.length === 0 && (
                          <tr>
                            <td colSpan={6} className="table-empty">No vulnerabilities reported for this device yet.</td>
                          </tr>
                        )}

                        {vulnerabilityRows.map((row) => {
                          const rowKey = vulnerabilityKey(row);
                          const qod = Number.parseFloat(row.qod);
                          const normalizedQod = Number.isFinite(qod)
                            ? (qod > 1 && qod <= 100 ? qod / 100 : qod)
                            : null;
                          const score = Number.parseFloat(row.cvss_score);
                          const label = row.cvss_severity || row.severity || 'Low';
                          const isExpanded = Boolean(expandedVulnerabilities[rowKey]);
                          const hasDetails = Boolean(row.solution || row.description || row.cvss_vector);

                          return (
                            <Fragment key={rowKey}>
                              <tr>
                                <td><span className={`severity-chip ${severityClass(label)}`}>{label}</span></td>
                                <td>{row.name || '-'}</td>
                                <td>{Number.isFinite(normalizedQod) ? `${Math.round(normalizedQod * 100)}%` : '-'}</td>
                                <td>{Number.isFinite(score) ? score.toFixed(1) : '-'}</td>
                                <td>{row.port ?? '-'}</td>
                                <td className="align-right">
                                  <button
                                    type="button"
                                    className="small-button"
                                    disabled={!hasDetails}
                                    onClick={() => toggleVulnerabilityExpansion(rowKey)}
                                  >
                                    {isExpanded ? 'Hide' : 'Expand'}
                                  </button>
                                </td>
                              </tr>
                              {isExpanded && (
                                <tr className="port-detail-row">
                                  <td colSpan={6}>
                                    <div className="port-detail-panel">
                                      {row.solution && (
                                        <section className="port-detail-section">
                                          <h5>Remediation</h5>
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
                </>
              )}

              {activeTab === 'ports' && (
                <>
                  <p className="muted">Merged Nmap and Greenbone service data. Expand rows for deep metadata.</p>
                  <div className="table-wrapper table-wrapper-compact">
                    <table className="ui-table ui-table-compact">
                      <thead>
                        <tr>
                          <th>Port</th>
                          <th>Protocol</th>
                          <th>Service</th>
                          <th>Version</th>
                          <th>State</th>
                          <th className="align-right">Details</th>
                        </tr>
                      </thead>
                      <tbody>
                        {portRows.length === 0 && (
                          <tr>
                            <td colSpan={6} className="table-empty">No port data for this device yet.</td>
                          </tr>
                        )}

                        {portRows.map((row) => {
                          const rowKey = portKey(row);
                          const metadata = toObject(row.metadata);
                          const scriptResults = toObject(row.script_results);
                          const serviceBanners = Array.isArray(metadata.service_banners)
                            ? metadata.service_banners
                            : [];
                          const greenboneLogs = Array.isArray(metadata.greenbone_logs)
                            ? metadata.greenbone_logs
                            : [];
                          const metadataEntries = Object.entries(metadata).filter(
                            ([key]) => key !== 'service_banners' && key !== 'greenbone_logs',
                          );
                          const hasDetails = Object.keys(metadata).length > 0 || Object.keys(scriptResults).length > 0;
                          const isExpanded = Boolean(expandedPorts[rowKey]);

                          return (
                            <Fragment key={rowKey}>
                              <tr>
                                <td>{row.port ?? '-'}</td>
                                <td>{row.protocol || '-'}</td>
                                <td>{row.service || '-'}</td>
                                <td>{row.version || '-'}</td>
                                <td><StatusBadge status={row.state} /></td>
                                <td className="align-right">
                                  <button
                                    type="button"
                                    className="small-button"
                                    disabled={!hasDetails}
                                    onClick={() => togglePortExpansion(rowKey)}
                                  >
                                    {isExpanded ? 'Hide' : 'Expand'}
                                  </button>
                                </td>
                              </tr>
                              {isExpanded && (
                                <tr className="port-detail-row">
                                  <td colSpan={6}>
                                    <div className="port-detail-panel">
                                      {Object.keys(scriptResults).length > 0 && (
                                        <section className="port-detail-section">
                                          <h5>Nmap Script Results</h5>
                                          {Object.entries(scriptResults).map(([scriptId, payload]) => (
                                            <article className="port-detail-card" key={scriptId}>
                                              <p className="port-detail-title">{scriptId}</p>
                                              {payload?.output && <p className="port-detail-text">{payload.output}</p>}
                                              {payload?.details && <pre className="port-detail-pre">{JSON.stringify(payload.details, null, 2)}</pre>}
                                            </article>
                                          ))}
                                        </section>
                                      )}

                                      {Object.keys(metadata).length > 0 && (
                                        <section className="port-detail-section">
                                          <h5>Reconciled Metadata</h5>

                                          {serviceBanners.length > 0 && (
                                            <article className="port-detail-card">
                                              <p className="port-detail-title">Service Banners</p>
                                              <ul className="summary-list">
                                                {serviceBanners.map((entry, index) => (
                                                  <li key={`${rowKey}-banner-${index}`}>{String(entry)}</li>
                                                ))}
                                              </ul>
                                            </article>
                                          )}

                                          {greenboneLogs.length > 0 && (
                                            <article className="port-detail-card">
                                              <p className="port-detail-title">Greenbone Log Evidence</p>
                                              {greenboneLogs.map((entry, index) => (
                                                <p className="port-detail-text" key={`${rowKey}-log-${index}`}>
                                                  {typeof entry === 'string'
                                                    ? entry
                                                    : JSON.stringify(entry)}
                                                </p>
                                              ))}
                                            </article>
                                          )}

                                          {metadataEntries.map(([key, value]) => (
                                            <article className="port-detail-card" key={key}>
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
                </>
              )}

              {activeTab === 'certificates' && (
                <section className="device-data-grid">
                  <article className="insight-panel">
                    <h4>TLS Certificates</h4>
                    <DataTable
                      columns={tlsColumns}
                      rows={tlsCertificateRows}
                      emptyMessage="No TLS certificates captured for this host."
                      wrapperClassName="table-wrapper-compact"
                      tableClassName="ui-table-compact"
                    />
                  </article>

                  <article className="insight-panel">
                    <h4>SSH Host Keys</h4>
                    <DataTable
                      columns={sshColumns}
                      rows={sshHostKeyRows}
                      emptyMessage="No SSH host keys captured for this host."
                      wrapperClassName="table-wrapper-compact"
                      tableClassName="ui-table-compact"
                    />
                  </article>
                </section>
              )}

              {activeTab === 'cves' && (
                <>
                  <p className="muted">Deduplicated CVEs with direct NVD links.</p>
                  <DataTable
                    columns={cveColumns}
                    rows={cveRows}
                    emptyMessage="No CVEs associated with this host."
                    wrapperClassName="table-wrapper-compact"
                    tableClassName="ui-table-compact"
                  />
                </>
              )}
            </div>
          </>
        )}
      </Card>

      <ToastStack toasts={toasts} onDismiss={removeToast} />
    </div>
  );
}
