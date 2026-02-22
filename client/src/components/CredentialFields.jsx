function optionLabel(entry) {
  const display = String(entry?.display_name || '').trim();
  const user = String(entry?.username || '').trim();
  const external = String(entry?.external_credential_id || '').trim();

  if (display && user) {
    return `${display} (${user})`;
  }

  if (display) {
    return display;
  }

  if (user && external) {
    return `${user} (${external})`;
  }

  if (user) {
    return user;
  }

  return `Credential ${entry?.id ?? '-'}`;
}

export default function CredentialFields({
  useCredentials,
  setUseCredentials,
  credentialMode,
  setCredentialMode,
  credentialType,
  setCredentialType,
  credentialId,
  setCredentialId,
  credentialName,
  setCredentialName,
  credentialUsername,
  setCredentialUsername,
  credentialPassword,
  setCredentialPassword,
  credentialOptions,
  credentialsLoading = false,
  disabled = false,
}) {
  return (
    <section className="credential-panel">
      <label className="checkbox-inline" htmlFor="useCredentialsToggle">
        <input
          id="useCredentialsToggle"
          type="checkbox"
          checked={useCredentials}
          disabled={disabled}
          onChange={(event) => setUseCredentials(event.target.checked)}
        />
        <span>Use Credentials</span>
      </label>

      {useCredentials && (
        <div className="credential-grid">
          <div className="field-stack">
            <label htmlFor="credentialType">Credential Type</label>
            <select
              id="credentialType"
              value={credentialType}
              disabled={disabled}
              onChange={(event) => setCredentialType(event.target.value)}
            >
              <option value="ssh">SSH</option>
              <option value="smb">SMB</option>
            </select>
          </div>

          <div className="field-stack">
            <label htmlFor="credentialMode">Credential Mode</label>
            <select
              id="credentialMode"
              value={credentialMode}
              disabled={disabled}
              onChange={(event) => setCredentialMode(event.target.value)}
            >
              <option value="existing">Select Existing</option>
              <option value="new">Create New</option>
            </select>
          </div>

          {credentialMode === 'existing' && (
            <div className="field-stack credential-span-all">
              <label htmlFor="credentialId">Saved Credential</label>
              <select
                id="credentialId"
                value={credentialId}
                disabled={disabled || credentialsLoading}
                onChange={(event) => setCredentialId(event.target.value)}
              >
                <option value="">{credentialsLoading ? 'Loading credentials...' : 'Select a credential'}</option>
                {(Array.isArray(credentialOptions) ? credentialOptions : []).map((entry) => (
                  <option key={entry.id} value={entry.id}>
                    {optionLabel(entry)}
                  </option>
                ))}
              </select>
            </div>
          )}

          {credentialMode === 'new' && (
            <>
              <div className="field-stack">
                <label htmlFor="credentialName">Credential Name</label>
                <input
                  id="credentialName"
                  type="text"
                  placeholder="Optional label"
                  value={credentialName}
                  disabled={disabled}
                  onChange={(event) => setCredentialName(event.target.value)}
                />
              </div>

              <div className="field-stack">
                <label htmlFor="credentialUsername">Username</label>
                <input
                  id="credentialUsername"
                  type="text"
                  placeholder="scanner-user"
                  value={credentialUsername}
                  disabled={disabled}
                  onChange={(event) => setCredentialUsername(event.target.value)}
                />
              </div>

              <div className="field-stack credential-span-all">
                <label htmlFor="credentialPassword">Password</label>
                <input
                  id="credentialPassword"
                  type="password"
                  placeholder="Credential password"
                  value={credentialPassword}
                  disabled={disabled}
                  onChange={(event) => setCredentialPassword(event.target.value)}
                />
              </div>
            </>
          )}
        </div>
      )}
    </section>
  );
}
