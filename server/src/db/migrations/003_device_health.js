module.exports = [
  `ALTER TABLE devices ADD COLUMN IF NOT EXISTS online_status BOOLEAN NOT NULL DEFAULT false;`,
  `ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_healthcheck_at TIMESTAMPTZ;`,
  `CREATE INDEX IF NOT EXISTS idx_devices_online_status ON devices(online_status);`,
  `CREATE INDEX IF NOT EXISTS idx_devices_last_healthcheck ON devices(last_healthcheck_at DESC);`,
];
