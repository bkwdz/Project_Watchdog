module.exports = [
  `
    CREATE TABLE IF NOT EXISTS scanner_settings (
      id SMALLINT PRIMARY KEY CHECK (id = 1),
      greenbone_max_checks INTEGER NOT NULL DEFAULT 4 CHECK (greenbone_max_checks BETWEEN 1 AND 64),
      greenbone_max_hosts INTEGER NOT NULL DEFAULT 1 CHECK (greenbone_max_hosts BETWEEN 1 AND 64),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `,
  `
    INSERT INTO scanner_settings (id, greenbone_max_checks, greenbone_max_hosts)
    VALUES (1, 4, 1)
    ON CONFLICT (id) DO NOTHING;
  `,
];
