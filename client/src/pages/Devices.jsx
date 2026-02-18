import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  createScan,
  createVulnerabilityScan,
  getDevices,
  getVulnerabilityScanConfigs,
  getVulnerabilityScannerStatus,
} from '../api/endpoints';
import Card from '../components/Card';
import Modal from '../components/Modal';
import ToastStack from '../components/ToastStack';
import useToast from '../hooks/useToast';
import { formatDateTime, formatRelative } from '../utils/time';
import { isCidr } from '../utils/ip';

function riskTone(openPorts) {
  const count = Number(openPorts || 0);

  if (count >= 15) {
    return { label: 'High', className: 'risk-high' };
  }

  if (count >= 5) {
    return { label: 'Medium', className: 'risk-medium' };
  }

  return { label: 'Low', className: 'risk-low' };
}

export default function Devices() {
  const navigate = useNavigate();
  const { toasts, pushToast, removeToast } = useToast();

  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [modalOpen, setModalOpen] = useState(false);
  const [rangeTarget, setRangeTarget] = useState('');
  const [rangeScanner, setRangeScanner] = useState('nmap');
  const [rangeType, setRangeType] = useState('discovery');
  const [rangeTcpPorts, setRangeTcpPorts] = useState('1-1000');
  const [rangeUdpPorts, setRangeUdpPorts] = useState('');
  const [submittingScan, setSubmittingScan] = useState(false);
  const [vulnEnabled, setVulnEnabled] = useState(false);
  const [vulnStatusLoaded, setVulnStatusLoaded] = useState(false);
  const [vulnStatusMessage, setVulnStatusMessage] = useState('');
  const [vulnConfigs, setVulnConfigs] = useState([]);
  const [vulnConfigId, setVulnConfigId] = useState('');
  const [vulnConfigsLoaded, setVulnConfigsLoaded] = useState(false);

  const loadDevices = useCallback(async () => {
    setError('');

    try {
      const data = await getDevices();
      setDevices(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err?.response?.data?.error || 'Unable to load devices');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDevices();
  }, [loadDevices]);

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
    if (!modalOpen || rangeScanner !== 'greenbone') {
      return;
    }

    void loadVulnerabilityStatus();
  }, [loadVulnerabilityStatus, modalOpen, rangeScanner]);

  useEffect(() => {
    if (!modalOpen || rangeScanner !== 'greenbone' || !vulnStatusLoaded) {
      return;
    }

    if (!vulnEnabled) {
      setVulnConfigs([]);
      setVulnConfigId('');
      setVulnConfigsLoaded(true);
      return;
    }

    void loadVulnerabilityConfigs();
  }, [loadVulnerabilityConfigs, modalOpen, rangeScanner, vulnEnabled, vulnStatusLoaded]);

  const orderedDevices = useMemo(
    () =>
      [...devices].sort((a, b) => {
        const left = a.last_seen ? new Date(a.last_seen).getTime() : 0;
        const right = b.last_seen ? new Date(b.last_seen).getTime() : 0;
        return right - left;
      }),
    [devices],
  );

  const submitRangeScan = async () => {
    const target = rangeTarget.trim();

    if (!isCidr(target)) {
      pushToast('Please enter a valid CIDR range (example: 192.168.1.0/24).', 'error');
      return;
    }

    setSubmittingScan(true);

    try {
      let scan;

      if (rangeScanner === 'greenbone') {
        if (!vulnEnabled) {
          throw new Error(vulnStatusMessage || 'Vulnerability scanner is not active.');
        }

        if (!vulnConfigId) {
          throw new Error('No vulnerability scan profile is available.');
        }

        scan = await createVulnerabilityScan(target, vulnConfigId, {
          tcpPorts: rangeTcpPorts,
          udpPorts: rangeUdpPorts,
        });

        pushToast(`Vulnerability scan #${scan.id} queued for ${target}.`, 'success');
      } else {
        scan = await createScan({ target, scan_type: rangeType });
        pushToast(`Network scan #${scan.id} queued.`, 'success');
      }

      window.dispatchEvent(new CustomEvent('watchdog:scan-created', { detail: scan }));
      setModalOpen(false);
      setRangeTarget('');
      setRangeType('discovery');
      setRangeScanner('nmap');
      setRangeTcpPorts('1-1000');
      setRangeUdpPorts('');
    } catch (err) {
      pushToast(err?.response?.data?.error || err?.message || 'Unable to start range scan.', 'error');
    } finally {
      setSubmittingScan(false);
    }
  };

  return (
    <div className="page-stack">
      <Card
        title="Network Devices"
        subtitle="Asset inventory discovered by active and passive scans."
        actions={(
          <button type="button" className="primary-button" onClick={() => setModalOpen(true)}>
            Scan Network Range
          </button>
        )}
      >
        {loading && <p className="muted">Loading devices...</p>}
        {error && <p className="error-text">{error}</p>}

        {!loading && !error && (
          <div className="device-grid">
            {orderedDevices.length === 0 && <p className="muted">No devices discovered yet.</p>}

            {orderedDevices.map((device) => {
              const risk = riskTone(device.open_ports);
              const isOnline = device.online_status === true || device.online === true;

              return (
                <button
                  key={device.id}
                  type="button"
                  className="device-card"
                  onClick={() => navigate(`/devices/${device.id}`)}
                >
                  <div className="device-card-header">
                    <h3>{device.display_name || device.displayName || device.hostname || device.ip_address || device.ip || 'Unknown Device'}</h3>
                    <span className={`risk-pill ${risk.className}`}>{risk.label}</span>
                  </div>

                  <p className="device-meta">IP: {device.ip_address || device.ip || '-'}</p>
                  <p className="device-meta">OS: {device.os_guess || 'Unknown'}</p>
                  <p className="device-meta">
                    Status:{' '}
                    <span className={`health-pill ${isOnline ? 'health-online' : 'health-offline'}`}>
                      {isOnline ? 'Online' : 'Offline'}
                    </span>
                  </p>
                  <p className="device-meta">Open ports: {Number(device.open_ports || 0)}</p>
                  <p className="device-meta">
                    Last seen: {formatRelative(device.last_seen)} ({formatDateTime(device.last_seen)})
                  </p>
                </button>
              );
            })}
          </div>
        )}
      </Card>

      <Modal open={modalOpen} title="Scan Network Range" onClose={() => setModalOpen(false)}>
        <div className="field-stack">
          <label htmlFor="rangeTarget">CIDR Range</label>
          <input
            id="rangeTarget"
            type="text"
            placeholder="192.168.1.0/24"
            value={rangeTarget}
            onChange={(event) => setRangeTarget(event.target.value)}
          />
        </div>

        <div className="field-stack">
          <label htmlFor="rangeScanner">Scanner</label>
          <select id="rangeScanner" value={rangeScanner} onChange={(event) => setRangeScanner(event.target.value)}>
            <option value="nmap">nmap (host/port discovery)</option>
            <option value="greenbone">greenbone (vulnerability)</option>
          </select>
        </div>

        <div className="field-stack">
          <label htmlFor={rangeScanner === 'nmap' ? 'rangeType' : 'rangeVulnProfile'}>
            {rangeScanner === 'nmap' ? 'Scan Type' : 'Scan Profile'}
          </label>
          {rangeScanner === 'nmap' ? (
            <select id="rangeType" value={rangeType} onChange={(event) => setRangeType(event.target.value)}>
              <option value="discovery">discovery</option>
              <option value="standard">standard</option>
              <option value="aggressive">aggressive</option>
              <option value="full">full</option>
            </select>
          ) : (
            <>
              <select id="rangeVulnProfile" value={vulnConfigId} onChange={(event) => setVulnConfigId(event.target.value)}>
                {vulnConfigs.length === 0 && <option value="">No scan profiles available</option>}
                {vulnConfigs.map((config) => (
                  <option key={config.id} value={config.id}>
                    {config.name || config.id}
                  </option>
                ))}
              </select>
              {!vulnConfigsLoaded && vulnEnabled && <p className="muted">Loading vulnerability scan profiles...</p>}
              {vulnStatusLoaded && vulnStatusMessage && <p className="warning-text">{vulnStatusMessage}</p>}
            </>
          )}
        </div>

        {rangeScanner === 'greenbone' && (
          <>
            <div className="field-stack">
              <label htmlFor="rangeTcpPorts">TCP Ports</label>
              <input
                id="rangeTcpPorts"
                type="text"
                placeholder="1-1000"
                value={rangeTcpPorts}
                onChange={(event) => setRangeTcpPorts(event.target.value)}
              />
            </div>
            <div className="field-stack">
              <label htmlFor="rangeUdpPorts">UDP Ports</label>
              <input
                id="rangeUdpPorts"
                type="text"
                placeholder="blank or 0 = disabled"
                value={rangeUdpPorts}
                onChange={(event) => setRangeUdpPorts(event.target.value)}
              />
            </div>
          </>
        )}

        <div className="modal-actions">
          <button type="button" className="ghost-button" onClick={() => setModalOpen(false)}>
            Cancel
          </button>
          <button type="button" className="primary-button" disabled={submittingScan} onClick={submitRangeScan}>
            {submittingScan ? 'Submitting...' : 'Start Scan'}
          </button>
        </div>
      </Modal>

      <ToastStack toasts={toasts} onDismiss={removeToast} />
    </div>
  );
}
