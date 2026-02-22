module.exports = [
  `
    CREATE TABLE IF NOT EXISTS scan_credentials (
      id SERIAL PRIMARY KEY,
      credential_type VARCHAR(8) NOT NULL CHECK (credential_type IN ('ssh', 'smb')),
      display_name TEXT,
      username TEXT NOT NULL,
      secret_ciphertext BYTEA NOT NULL,
      secret_iv BYTEA NOT NULL,
      secret_tag BYTEA NOT NULL,
      external_credential_id TEXT,
      source VARCHAR(16) NOT NULL DEFAULT 'greenbone',
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_used_at TIMESTAMPTZ
    );
  `,
  `ALTER TABLE scans ADD COLUMN IF NOT EXISTS ssh_credential_id INTEGER REFERENCES scan_credentials(id) ON DELETE SET NULL;`,
  `ALTER TABLE scans ADD COLUMN IF NOT EXISTS smb_credential_id INTEGER REFERENCES scan_credentials(id) ON DELETE SET NULL;`,
  `ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS solution TEXT;`,
  `ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS qod DOUBLE PRECISION;`,
  `ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cvss_vector TEXT;`,
  `CREATE INDEX IF NOT EXISTS idx_scan_credentials_type ON scan_credentials(credential_type);`,
  `CREATE INDEX IF NOT EXISTS idx_scan_credentials_last_used ON scan_credentials(last_used_at DESC);`,
  `CREATE INDEX IF NOT EXISTS idx_scans_ssh_credential_id ON scans(ssh_credential_id);`,
  `CREATE INDEX IF NOT EXISTS idx_scans_smb_credential_id ON scans(smb_credential_id);`,
];
