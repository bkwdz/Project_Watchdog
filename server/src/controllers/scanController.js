const { query } = require('../db');
const { enqueueScan } = require('../services/scanWorker');
const { isValidScanType } = require('../services/scanProfiles');
const { isValidCidr, isValidTarget } = require('../utils/targetValidation');

function normalizeTarget(target) {
  return typeof target === 'string' ? target.trim() : '';
}

async function buildScanSummary(scan) {
  if (!scan.started_at) {
    return {
      hosts_up: 0,
      ports_observed: 0,
    };
  }

  const windowStart = scan.started_at;
  const windowEnd = scan.completed_at || new Date();

  if (isValidCidr(scan.target)) {
    const hostCountResult = await query(
      `
        SELECT COUNT(*)::int AS hosts_up
        FROM devices
        WHERE ip_address << $1::cidr
          AND last_seen >= $2
          AND last_seen <= $3
      `,
      [scan.target, windowStart, windowEnd],
    );

    const portCountResult = await query(
      `
        SELECT COUNT(p.id)::int AS ports_observed
        FROM ports p
        INNER JOIN devices d ON d.id = p.device_id
        WHERE d.ip_address << $1::cidr
          AND d.last_seen >= $2
          AND d.last_seen <= $3
      `,
      [scan.target, windowStart, windowEnd],
    );

    return {
      hosts_up: hostCountResult.rows[0].hosts_up,
      ports_observed: portCountResult.rows[0].ports_observed,
    };
  }

  const deviceResult = await query(
    `
      SELECT id, last_seen
      FROM devices
      WHERE ip_address = $1::inet
      LIMIT 1
    `,
    [scan.target],
  );

  const device = deviceResult.rows[0];

  if (!device || device.last_seen < windowStart || device.last_seen > windowEnd) {
    return {
      hosts_up: 0,
      ports_observed: 0,
    };
  }

  const portsResult = await query(
    `
      SELECT COUNT(*)::int AS ports_observed
      FROM ports
      WHERE device_id = $1
    `,
    [device.id],
  );

  return {
    hosts_up: 1,
    ports_observed: portsResult.rows[0].ports_observed,
  };
}

exports.createScan = async (req, res, next) => {
  try {
    const target = normalizeTarget(req.body.target);
    const scanType = typeof req.body.scan_type === 'string'
      ? req.body.scan_type.trim().toLowerCase()
      : 'standard';

    if (!isValidTarget(target)) {
      return res.status(400).json({ error: 'target must be a valid IPv4 address or CIDR range' });
    }

    if (!isValidScanType(scanType)) {
      return res.status(400).json({
        error: "scan_type must be one of: discovery, quick, standard, aggressive, full",
      });
    }

    const scanResult = await query(
      `
        INSERT INTO scans (target, scan_type, status, progress_percent, initiated_by)
        VALUES ($1, $2, 'queued', NULL, $3)
        RETURNING id, target, scan_type, status, progress_percent, started_at, completed_at, initiated_by
      `,
      [target, scanType, req.user?.id || null],
    );

    const scan = scanResult.rows[0];
    enqueueScan(scan.id);

    return res.status(202).json(scan);
  } catch (err) {
    return next(err);
  }
};

exports.getScan = async (req, res, next) => {
  try {
    const scanId = Number(req.params.id);

    if (!Number.isInteger(scanId)) {
      return res.status(400).json({ error: 'invalid scan id' });
    }

    const scanResult = await query(
      `
        SELECT id, target, scan_type, status, progress_percent, started_at, completed_at, initiated_by
        FROM scans
        WHERE id = $1
        LIMIT 1
      `,
      [scanId],
    );

    const scan = scanResult.rows[0];

    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    const summary = await buildScanSummary(scan);

    return res.json({
      ...scan,
      summary,
    });
  } catch (err) {
    return next(err);
  }
};

exports.startScan = async (req, res, next) => {
  req.body = {
    target: req.body?.ip,
    scan_type: req.body?.scan_type || 'standard',
  };

  return exports.createScan(req, res, next);
};
