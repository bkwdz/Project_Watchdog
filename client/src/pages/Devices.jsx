import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { createScan, getDevices } from '../api/endpoints';
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
  const [rangeType, setRangeType] = useState('discovery');
  const [submittingScan, setSubmittingScan] = useState(false);

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
      const scan = await createScan({ target, scan_type: rangeType });
      pushToast(`Network scan #${scan.id} queued.`, 'success');
      window.dispatchEvent(new CustomEvent('watchdog:scan-created', { detail: scan }));
      setModalOpen(false);
      setRangeTarget('');
      setRangeType('discovery');
    } catch (err) {
      pushToast(err?.response?.data?.error || 'Unable to start range scan.', 'error');
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

              return (
                <button
                  key={device.id}
                  type="button"
                  className="device-card"
                  onClick={() => navigate(`/devices/${device.id}`)}
                >
                  <div className="device-card-header">
                    <h3>{device.hostname || device.ip_address || device.ip || 'Unknown Device'}</h3>
                    <span className={`risk-pill ${risk.className}`}>{risk.label}</span>
                  </div>

                  <p className="device-meta">IP: {device.ip_address || device.ip || '-'}</p>
                  <p className="device-meta">OS: {device.os_guess || 'Unknown'}</p>
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
          <label htmlFor="rangeType">Scan Type</label>
          <select id="rangeType" value={rangeType} onChange={(event) => setRangeType(event.target.value)}>
            <option value="discovery">discovery</option>
            <option value="standard">standard</option>
            <option value="aggressive">aggressive</option>
          </select>
        </div>

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
