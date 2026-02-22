import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  createScan,
  createVulnerabilityScan,
  getVulnerabilityCredentials,
  getVulnerabilityScanConfigs,
  getVulnerabilityScannerStatus,
} from '../api/endpoints';
import Card from '../components/Card';
import CredentialFields from '../components/CredentialFields';
import DataTable from '../components/DataTable';
import HoverProfileSelect from '../components/HoverProfileSelect';
import Modal from '../components/Modal';
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
  const [modalOpen, setModalOpen] = useState(false);

  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('standard');
  const [scanner, setScanner] = useState('nmap');
  const [submitting, setSubmitting] = useState(false);

  const [vulnEnabled, setVulnEnabled] = useState(false);
  const [vulnStatusLoaded, setVulnStatusLoaded] = useState(false);
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

  useEffect(() => {
    if (!modalOpen || scanner !== 'greenbone') {
      return;
    }

    void loadVulnerabilityStatus();
  }, [loadVulnerabilityStatus, modalOpen, scanner]);

  useEffect(() => {
    if (!modalOpen || scanner !== 'greenbone' || !vulnStatusLoaded) {
      return;
    }

    if (!vulnEnabled) {
      setVulnConfigs([]);
      setVulnConfigId('');
      setVulnConfigsLoaded(true);
      return;
    }

    void loadVulnerabilityConfigs();
  }, [loadVulnerabilityConfigs, modalOpen, scanner, vulnEnabled, vulnStatusLoaded]);

  useEffect(() => {
    if (!modalOpen || scanner !== 'greenbone' || !useCredentials || credentialMode !== 'existing') {
      return;
    }

    void loadVulnerabilityCredentials(credentialType);
  }, [
    credentialMode,
    credentialType,
    loadVulnerabilityCredentials,
    modalOpen,
    scanner,
    useCredentials,
  ]);

  useEffect(() => {
    if (scanner === 'greenbone') {
      return;
    }

    setUseCredentials(false);
  }, [scanner]);

  const resetModalState = () => {
    setTarget('');
    setScanType('standard');
    setScanner('nmap');
    setVulnTcpPorts('1-1000');
    setVulnUdpPorts('');
    setUseCredentials(false);
    setCredentialMode('existing');
    setCredentialType('ssh');
    setCredentialOptions([]);
    setCredentialsLoading(false);
    setCredentialId('');
    setCredentialName('');
    setCredentialUsername('');
    setCredentialPassword('');
  };

  const submitScan = async () => {
    const normalizedTarget = target.trim();

    if (!isValidTarget(normalizedTarget)) {
      pushToast('Target must be a valid IPv4 address or CIDR range.', 'error');
      return;
    }

    setSubmitting(true);

    try {
      let scan;

      if (scanner === 'greenbone') {
        if (!vulnEnabled) {
          throw new Error(vulnStatusMessage || 'Vulnerability scanner is not active.');
        }

        if (!vulnConfigId) {
          throw new Error('No vulnerability scan profile is available.');
        }

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

        scan = await createVulnerabilityScan(normalizedTarget, vulnConfigId, {
          tcpPorts: vulnTcpPorts,
          udpPorts: vulnUdpPorts,
          credentials,
        });
        pushToast(`Vulnerability scan #${scan.id} queued.`, 'success');
      } else {
        scan = await createScan({ target: normalizedTarget, scan_type: scanType });
        pushToast(`Scan #${scan.id} queued.`, 'success');
      }

      registerScan(scan);
      window.dispatchEvent(new CustomEvent('watchdog:scan-created', { detail: scan }));
      setModalOpen(false);
      resetModalState();
    } catch (err) {
      pushToast(err?.response?.data?.error || err?.message || 'Failed to create scan.', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const rows = useMemo(() => [...scans].sort((a, b) => b.id - a.id), [scans]);

  const columns = useMemo(
    () => [
      { key: 'id', header: 'ID' },
      { key: 'target', header: 'Target' },
      {
        key: 'scan_type',
        header: 'Type',
        render: (scan) => (scan.scanner_type === 'greenbone' ? 'vulnerability' : scan.scan_type),
      },
      { key: 'scanner_type', header: 'Scanner' },
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
      <Card
        title="Run Scan"
        subtitle="Create a single-host or range scan job."
        actions={(
          <button type="button" className="primary-button" onClick={() => setModalOpen(true)}>
            New Scan
          </button>
        )}
      >
        <p className="muted">Use scanner-aware modal controls for Nmap discovery or Greenbone vulnerability scans.</p>
      </Card>

      <Modal open={modalOpen} title="Create Scan" onClose={() => setModalOpen(false)}>
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
          <label htmlFor="scanScanner">Scanner</label>
          <select id="scanScanner" value={scanner} onChange={(event) => setScanner(event.target.value)}>
            <option value="nmap">nmap (host/port discovery)</option>
            <option value="greenbone">greenbone (vulnerability)</option>
          </select>
        </div>

        {scanner === 'nmap' ? (
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
        ) : (
          <>
            <div className="field-stack">
              <label htmlFor="scanVulnProfile">Scan Profile</label>
              <HoverProfileSelect
                id="scanVulnProfile"
                ariaLabel="Vulnerability Scan Profile"
                value={vulnConfigId}
                options={vulnConfigs}
                disabled={!vulnEnabled || !vulnStatusLoaded || !vulnConfigsLoaded || submitting}
                onChange={setVulnConfigId}
              />
            </div>

            {!vulnConfigsLoaded && vulnEnabled && <p className="muted">Loading vulnerability scan profiles...</p>}
            {vulnStatusLoaded && vulnStatusMessage && <p className="warning-text">{vulnStatusMessage}</p>}

            <div className="field-stack">
              <label htmlFor="scanVulnTcpPorts">TCP Ports</label>
              <input
                id="scanVulnTcpPorts"
                type="text"
                placeholder="1-1000"
                value={vulnTcpPorts}
                onChange={(event) => setVulnTcpPorts(event.target.value)}
              />
            </div>

            <div className="field-stack">
              <label htmlFor="scanVulnUdpPorts">UDP Ports</label>
              <input
                id="scanVulnUdpPorts"
                type="text"
                placeholder="blank or 0 = disabled"
                value={vulnUdpPorts}
                onChange={(event) => setVulnUdpPorts(event.target.value)}
              />
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
              disabled={submitting}
            />
          </>
        )}

        <div className="modal-actions">
          <button type="button" className="ghost-button" onClick={() => setModalOpen(false)}>
            Cancel
          </button>
          <button type="button" className="primary-button" disabled={submitting} onClick={submitScan}>
            {submitting ? 'Submitting...' : 'Start Scan'}
          </button>
        </div>
      </Modal>

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
