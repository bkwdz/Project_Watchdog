import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  createScan,
  createVulnerabilityScan,
  getDeviceById,
  getScanById,
  updateDevice,
  getVulnerabilityScanConfigs,
  getVulnerabilityScannerStatus,
} from '../api/endpoints';
import Card from '../components/Card';
import DataTable from '../components/DataTable';
import PieChart from '../components/PieChart';
import ProgressBar from '../components/ProgressBar';
import StatusBadge from '../components/StatusBadge';
import ToastStack from '../components/ToastStack';
import useScansFeed from '../hooks/useScansFeed';
import useToast from '../hooks/useToast';
import { cidrContains, isCidr } from '../utils/ip';
import { formatDateTime } from '../utils/time';

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
  const [hostnameEditing, setHostnameEditing] = useState(false);
  const [hostnameDraft, setHostnameDraft] = useState('');
  const [hostnameSaving, setHostnameSaving] = useState(false);
  const [portsVisibleCount, setPortsVisibleCount] = useState(10);
  const [vulnsVisibleCount, setVulnsVisibleCount] = useState(10);

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

    setHostnameDraft(device.hostname || '');
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
      const scan = await createVulnerabilityScan(targetIp, vulnConfigId, {
        tcpPorts: vulnTcpPorts,
        udpPorts: vulnUdpPorts,
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
    () => (Array.isArray(device?.vulnerabilities) ? device.vulnerabilities : []),
    [device],
  );

  const visiblePortRows = useMemo(
    () => portRows.slice(0, portsVisibleCount),
    [portRows, portsVisibleCount],
  );

  const visibleVulnerabilityRows = useMemo(
    () => vulnerabilityRows.slice(0, vulnsVisibleCount),
    [vulnerabilityRows, vulnsVisibleCount],
  );

  const hasMorePorts = portRows.length > portsVisibleCount;
  const hasMoreVulnerabilities = vulnerabilityRows.length > vulnsVisibleCount;

  useEffect(() => {
    setPortsVisibleCount(10);
  }, [portRows.length]);

  useEffect(() => {
    setVulnsVisibleCount(10);
  }, [vulnerabilityRows.length]);

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

  const portsColumns = useMemo(
    () => [
      { key: 'port', header: 'Port' },
      { key: 'protocol', header: 'Protocol' },
      { key: 'service', header: 'Service' },
      { key: 'version', header: 'Version' },
      {
        key: 'state',
        header: 'State',
        render: (row) => <StatusBadge status={row.state} />,
      },
    ],
    [],
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
        color: '#ffb454',
      },
      {
        key: 'low',
        label: 'Low',
        value: deviceSnapshot.severityCounts.low,
        color: '#f5c451',
      },
    ],
    [deviceSnapshot.severityCounts],
  );

  const saveHostname = async () => {
    if (!device?.id) {
      return;
    }

    const nextHostname = hostnameDraft.trim();
    const currentHostname = String(device.hostname || '').trim();

    if (nextHostname === currentHostname) {
      setHostnameEditing(false);
      return;
    }

    setHostnameSaving(true);

    try {
      const updated = await updateDevice(device.id, { hostname: nextHostname });
      setDevice((prev) => {
        if (!prev) {
          return updated;
        }

        return {
          ...prev,
          ...updated,
          ports: prev.ports,
          vulnerabilities: prev.vulnerabilities,
        };
      });
      setHostnameEditing(false);
      pushToast('Device hostname updated.', 'success');
    } catch (err) {
      pushToast(err?.response?.data?.error || 'Unable to update device hostname.', 'error');
    } finally {
      setHostnameSaving(false);
    }
  };

  return (
    <div className="page-stack">
      <Card title="Device Detail" subtitle={device?.ip_address || device?.ip || 'Host record'}>
        {loading && <p className="muted">Loading device...</p>}
        {error && <p className="error-text">{error}</p>}

        {!loading && !error && device && (
          <>
            <div className="device-identity-row">
              <div>
                <p className="device-identity-label">Display Name</p>
                <h4 className="device-identity-value">
                  {device.hostname || device.name || device.ip_address || device.ip || '-'}
                </h4>
              </div>
              {!hostnameEditing && (
                <button
                  type="button"
                  className="icon-button"
                  aria-label="Edit device hostname"
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
                  <label htmlFor="hostname-edit-input">Hostname</label>
                  <input
                    id="hostname-edit-input"
                    type="text"
                    placeholder="Set custom hostname (blank clears)"
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
                      setHostnameDraft(device.hostname || '');
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
                <dd>{device.os_guess || '-'}</dd>
              </div>
              <div>
                <dt>Status</dt>
                <dd>{device.online || device.online_status ? 'Online' : 'Offline'}</dd>
              </div>
              <div>
                <dt>Last Health Check</dt>
                <dd>{formatDateTime(device.last_healthcheck_at)}</dd>
              </div>
              <div>
                <dt>First Seen</dt>
                <dd>{formatDateTime(device.first_seen)}</dd>
              </div>
              <div>
                <dt>Last Seen</dt>
                <dd>{formatDateTime(device.last_seen)}</dd>
              </div>
            </dl>
          </>
        )}
      </Card>

      <Card title="Actions" subtitle="Start targeted discovery and vulnerability scans for this host.">
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

              <select
                id="vuln-config-select"
                className="vuln-profile-select"
                aria-label="Vulnerability Scan Profile"
                value={vulnConfigId}
                disabled={!vulnEnabled || !vulnStatusLoaded || !vulnConfigsLoaded || vulnTriggering || loading || !device}
                onChange={(event) => setVulnConfigId(event.target.value)}
              >
                {vulnConfigs.length === 0 && <option value="">No scan profiles available</option>}
                {vulnConfigs.map((config) => (
                  <option key={config.id} value={config.id}>
                    {config.name || config.id}
                  </option>
                ))}
              </select>

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
            </div>
          </section>
        </div>

        {!vulnConfigsLoaded && vulnEnabled && <p className="muted">Loading vulnerability scan profiles...</p>}
        {vulnStatusLoaded && vulnStatusMessage && <p className="warning-text">{vulnStatusMessage}</p>}

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
      </Card>

      <Card title="Security Snapshot" subtitle="Current exposure and vulnerability posture for this host.">
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
      </Card>

      <section className="device-data-grid">
        <Card title="Ports" subtitle="Observed service exposure by protocol and state." className="device-panel-card">
          <DataTable
            columns={portsColumns}
            rows={visiblePortRows}
            emptyMessage="No port data for this device yet."
            wrapperClassName="table-wrapper-compact"
            tableClassName="ui-table-compact"
          />
          {portRows.length > 10 && (
            <div className="table-expand-row">
              <button
                type="button"
                className="small-button"
                onClick={() => {
                  if (hasMorePorts) {
                    setPortsVisibleCount((current) => Math.min(current + 10, portRows.length));
                    return;
                  }

                  setPortsVisibleCount(10);
                }}
              >
                {hasMorePorts ? `Show More (${portRows.length - portsVisibleCount} remaining)` : 'Show Less'}
              </button>
            </div>
          )}
        </Card>

        <Card
          title="Vulnerabilities"
          subtitle="Known findings from Greenbone reports for this host."
          className="device-panel-card"
        >
          <DataTable
            columns={vulnerabilityColumns}
            rows={visibleVulnerabilityRows}
            emptyMessage="No vulnerabilities reported for this device yet."
            wrapperClassName="table-wrapper-compact"
            tableClassName="ui-table-compact"
          />
          {vulnerabilityRows.length > 10 && (
            <div className="table-expand-row">
              <button
                type="button"
                className="small-button"
                onClick={() => {
                  if (hasMoreVulnerabilities) {
                    setVulnsVisibleCount((current) => Math.min(current + 10, vulnerabilityRows.length));
                    return;
                  }

                  setVulnsVisibleCount(10);
                }}
              >
                {hasMoreVulnerabilities
                  ? `Show More (${vulnerabilityRows.length - vulnsVisibleCount} remaining)`
                  : 'Show Less'}
              </button>
            </div>
          )}
        </Card>
      </section>

      <Card title="Scan History" subtitle="Scans whose target includes this host.">
        {scansLoading && <p className="muted">Loading scan history...</p>}
        {scansError && <p className="error-text">{scansError}</p>}
        {listUnavailable && (
          <p className="muted">
            Scan list endpoint is unavailable. Showing scans known to this browser session.
          </p>
        )}
        <DataTable columns={historyColumns} rows={relatedScans} emptyMessage="No related scans found." />
      </Card>

      <ToastStack toasts={toasts} onDismiss={removeToast} />
    </div>
  );
}
