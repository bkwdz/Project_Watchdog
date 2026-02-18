module.exports = [
  `ALTER TABLE devices ADD COLUMN IF NOT EXISTS display_name TEXT;`,
  `CREATE INDEX IF NOT EXISTS idx_devices_display_name ON devices(display_name);`,
];
