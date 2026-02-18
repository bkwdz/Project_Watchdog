import { useCallback, useEffect, useState } from 'react';
import { getVulnerabilitySettings, updateVulnerabilitySettings } from '../api/endpoints';
import Card from '../components/Card';
import { formatDateTime } from '../utils/time';

export default function Settings() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [updatedAt, setUpdatedAt] = useState(null);
  const [maxChecks, setMaxChecks] = useState('4');
  const [maxHosts, setMaxHosts] = useState('1');

  const loadSettings = useCallback(async () => {
    setError('');

    try {
      const data = await getVulnerabilitySettings();
      setMaxChecks(String(data?.max_checks ?? 4));
      setMaxHosts(String(data?.max_hosts ?? 1));
      setUpdatedAt(data?.updated_at || null);
    } catch (err) {
      setError(err?.response?.data?.error || 'Unable to load scanner settings');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadSettings();
  }, [loadSettings]);

  const saveSettings = async () => {
    setSuccess('');
    setError('');

    const parsedMaxChecks = Number.parseInt(maxChecks, 10);
    const parsedMaxHosts = Number.parseInt(maxHosts, 10);

    if (!Number.isInteger(parsedMaxChecks) || parsedMaxChecks < 1 || parsedMaxChecks > 64) {
      setError('max checks must be an integer between 1 and 64');
      return;
    }

    if (!Number.isInteger(parsedMaxHosts) || parsedMaxHosts < 1 || parsedMaxHosts > 64) {
      setError('max hosts must be an integer between 1 and 64');
      return;
    }

    setSaving(true);

    try {
      const data = await updateVulnerabilitySettings({
        max_checks: parsedMaxChecks,
        max_hosts: parsedMaxHosts,
      });
      setMaxChecks(String(data?.max_checks ?? parsedMaxChecks));
      setMaxHosts(String(data?.max_hosts ?? parsedMaxHosts));
      setUpdatedAt(data?.updated_at || null);
      setSuccess('Scanner performance settings saved.');
    } catch (err) {
      setError(err?.response?.data?.error || 'Unable to save scanner settings');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="page-stack">
      <Card title="Settings" subtitle="Tune scanner behavior for your VM resources.">
        {loading && <p className="muted">Loading settings...</p>}

        {!loading && (
          <div className="settings-panel-grid">
            <div className="settings-heading-row">
              <h4>Greenbone Task Parallelism</h4>
              <span className="hover-tip" tabIndex={0} aria-label="Performance recommendations">
                i
                <span className="hover-tip-panel">
                  <strong>Recommended starting points</strong>
                  <br />
                  4 vCPU / 8 GB RAM: max checks 4, max hosts 1
                  <br />
                  5 vCPU / 10 GB RAM: max checks 6, max hosts 1
                  <br />
                  6-8 vCPU / 12-16 GB RAM: max checks 8-10, max hosts 1-2
                </span>
              </span>
            </div>

            <p className="muted">
              These values are applied to newly created vulnerability scan tasks.
            </p>

            <div className="settings-form-grid">
              <div className="field-stack">
                <label htmlFor="setting-max-checks">Max Checks (per host)</label>
                <input
                  id="setting-max-checks"
                  type="number"
                  min={1}
                  max={64}
                  value={maxChecks}
                  onChange={(event) => setMaxChecks(event.target.value)}
                />
              </div>

              <div className="field-stack">
                <label htmlFor="setting-max-hosts">Max Hosts (per task)</label>
                <input
                  id="setting-max-hosts"
                  type="number"
                  min={1}
                  max={64}
                  value={maxHosts}
                  onChange={(event) => setMaxHosts(event.target.value)}
                />
              </div>
            </div>

            <div className="settings-actions">
              <button type="button" className="primary-button" disabled={saving} onClick={saveSettings}>
                {saving ? 'Saving...' : 'Save Settings'}
              </button>
              <button type="button" className="ghost-button" disabled={saving} onClick={() => void loadSettings()}>
                Reload
              </button>
            </div>

            {updatedAt && <p className="muted">Last updated: {formatDateTime(updatedAt)}</p>}
            {success && <p className="success-text">{success}</p>}
            {error && <p className="error-text">{error}</p>}
          </div>
        )}
      </Card>
    </div>
  );
}
