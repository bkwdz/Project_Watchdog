const { query } = require('../db');
const greenboneMigration = require('./migrations/002_greenbone');
const deviceHealthMigration = require('./migrations/003_device_health');
const deviceDisplayNameMigration = require('./migrations/004_device_display_name');

const SCHEMA_STATEMENTS = [
  `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(255) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      role VARCHAR(32) NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `,
  `
    CREATE TABLE IF NOT EXISTS devices (
      id SERIAL PRIMARY KEY,
      ip_address INET NOT NULL UNIQUE,
      display_name TEXT,
      hostname TEXT,
      mac_address TEXT,
      os_guess TEXT,
      first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `,
  `
    CREATE TABLE IF NOT EXISTS scans (
      id SERIAL PRIMARY KEY,
      target TEXT NOT NULL,
      scan_type VARCHAR(32) NOT NULL CHECK (scan_type IN ('discovery', 'quick', 'standard', 'aggressive', 'full', 'vulnerability')),
      scanner_type VARCHAR(16) NOT NULL DEFAULT 'nmap' CHECK (scanner_type IN ('nmap', 'greenbone')),
      status VARCHAR(16) NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
      progress_percent INTEGER CHECK (progress_percent BETWEEN 0 AND 100),
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      initiated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      external_task_id TEXT
    );
  `,
  `
    CREATE TABLE IF NOT EXISTS ports (
      id SERIAL PRIMARY KEY,
      device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      port INTEGER NOT NULL,
      protocol VARCHAR(16) NOT NULL,
      service TEXT,
      version TEXT,
      state VARCHAR(32) NOT NULL,
      CONSTRAINT ports_device_port_protocol_unique UNIQUE (device_id, port, protocol)
    );
  `,
  `
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id SERIAL PRIMARY KEY,
      device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
      port INTEGER,
      cve VARCHAR(64),
      name TEXT,
      severity VARCHAR(32),
      cvss_score DOUBLE PRECISION,
      cvss_severity VARCHAR(32),
      description TEXT,
      source VARCHAR(64)
    );
  `,
  `CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);`,
  `CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);`,
  `CREATE INDEX IF NOT EXISTS idx_scans_initiated_by ON scans(initiated_by);`,
  `CREATE INDEX IF NOT EXISTS idx_ports_device ON ports(device_id);`,
  `CREATE INDEX IF NOT EXISTS idx_ports_state ON ports(state);`,
  `CREATE INDEX IF NOT EXISTS idx_vulnerabilities_device ON vulnerabilities(device_id);`,
  `CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve);`,
  `CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);`,
  ...greenboneMigration,
  ...deviceHealthMigration,
  ...deviceDisplayNameMigration,
];

async function migrate() {
  for (const statement of SCHEMA_STATEMENTS) {
    await query(statement);
  }
}

module.exports = {
  migrate,
};
