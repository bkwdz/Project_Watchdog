const { query, withTransaction } = require('../db');
const { enqueueScan } = require('../services/scanWorker');
const { isValidScanType } = require('../services/scanProfiles');
const {
  GreenboneServiceError,
  getConfig: getGreenboneConfig,
  isGreenboneEnabled,
  startScan: startGreenboneScan,
  getTaskStatus,
  fetchAndParseReport,
} = require('../services/greenboneService');
const { isValidCidr, isValidTarget, isValidIPv4 } = require('../utils/targetValidation');

const GREENBONE_DISABLED_MESSAGE = 'Vulnerability scanner not enabled';

const SCAN_COLUMNS = `
  id,
  target,
  scan_type,
  COALESCE(scanner_type, 'nmap') AS scanner_type,
  status,
  progress_percent,
  started_at,
  completed_at,
  initiated_by,
  external_task_id
`;

function normalizeTarget(target) {
  return typeof target === 'string' ? target.trim() : '';
}

function normalizeScanType(scanType) {
  if (typeof scanType !== 'string') {
    return 'standard';
  }

  return scanType.trim().toLowerCase();
}

function isTerminalStatus(status) {
  return status === 'completed' || status === 'failed';
}

function toControllerError(error, fallbackMessage) {
  if (error instanceof GreenboneServiceError) {
    return {
      statusCode: error.statusCode || 502,
      payload: {
        error: error.message,
        code: error.code,
        details: error.details,
      },
    };
  }

  return {
    statusCode: 502,
    payload: {
      error: fallbackMessage,
    },
  };
}

async function findScanById(scanId) {
  const scanResult = await query(
    `
      SELECT ${SCAN_COLUMNS}
      FROM scans
      WHERE id = $1
      LIMIT 1
    `,
    [scanId],
  );

  return scanResult.rows[0] || null;
}

async function updateScan(scanId, fields) {
  const entries = Object.entries(fields).filter(([, value]) => value !== undefined);

  if (entries.length === 0) {
    return findScanById(scanId);
  }

  const setClauses = [];
  const values = [scanId];

  entries.forEach(([key, value], index) => {
    setClauses.push(`${key} = $${index + 2}`);
    values.push(value);
  });

  const updateResult = await query(
    `
      UPDATE scans
      SET ${setClauses.join(', ')}
      WHERE id = $1
      RETURNING ${SCAN_COLUMNS}
    `,
    values,
  );

  return updateResult.rows[0] || null;
}

async function upsertDeviceByIp(client, ipAddress) {
  const deviceResult = await client.query(
    `
      INSERT INTO devices (ip_address, first_seen, last_seen)
      VALUES ($1::inet, NOW(), NOW())
      ON CONFLICT (ip_address)
      DO UPDATE SET last_seen = NOW()
      RETURNING id
    `,
    [ipAddress],
  );

  return deviceResult.rows[0].id;
}

async function storeGreenboneVulnerabilities(scan, vulnerabilities) {
  if (!Array.isArray(vulnerabilities) || vulnerabilities.length === 0) {
    return 0;
  }

  return withTransaction(async (client) => {
    const existingCountResult = await client.query(
      `
        SELECT COUNT(*)::int AS count
        FROM vulnerabilities
        WHERE scan_id = $1
      `,
      [scan.id],
    );

    if (existingCountResult.rows[0].count > 0) {
      return existingCountResult.rows[0].count;
    }

    let inserted = 0;

    for (const vulnerability of vulnerabilities) {
      const hostIp = isValidIPv4(vulnerability.host) ? vulnerability.host : null;
      const fallbackIp = isValidIPv4(scan.target) ? scan.target : null;
      const deviceIp = hostIp || fallbackIp;

      if (!deviceIp) {
        continue;
      }

      const deviceId = await upsertDeviceByIp(client, deviceIp);

      await client.query(
        `
          INSERT INTO vulnerabilities (
            device_id,
            scan_id,
            cve,
            name,
            severity,
            cvss_score,
            cvss_severity,
            port,
            description,
            source
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        `,
        [
          deviceId,
          scan.id,
          vulnerability.cve || null,
          vulnerability.name || null,
          vulnerability.severity || null,
          Number.isFinite(vulnerability.cvss_score) ? vulnerability.cvss_score : null,
          vulnerability.cvss_severity || null,
          Number.isInteger(vulnerability.port) ? vulnerability.port : null,
          vulnerability.description || null,
          vulnerability.source || 'greenbone',
        ],
      );

      inserted += 1;
    }

    return inserted;
  });
}

async function getScanVulnerabilities(scanId) {
  const vulnerabilityResult = await query(
    `
      SELECT
        id,
        device_id,
        scan_id,
        cve,
        name,
        severity,
        cvss_score,
        cvss_severity,
        port,
        description,
        source
      FROM vulnerabilities
      WHERE scan_id = $1
      ORDER BY cvss_score DESC NULLS LAST, id DESC
    `,
    [scanId],
  );

  return vulnerabilityResult.rows;
}

async function buildNmapSummary(scan) {
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

async function buildGreenboneSummary(scan) {
  const summaryResult = await query(
    `
      SELECT
        COUNT(*)::int AS vulnerabilities_total,
        COUNT(*) FILTER (WHERE COALESCE(cvss_severity, severity) ILIKE 'critical')::int AS critical_count,
        COUNT(*) FILTER (WHERE COALESCE(cvss_severity, severity) ILIKE 'high')::int AS high_count,
        COUNT(*) FILTER (WHERE COALESCE(cvss_severity, severity) ILIKE 'medium')::int AS medium_count,
        COUNT(*) FILTER (WHERE COALESCE(cvss_severity, severity) ILIKE 'low')::int AS low_count,
        COUNT(DISTINCT device_id)::int AS affected_devices
      FROM vulnerabilities
      WHERE scan_id = $1
    `,
    [scan.id],
  );

  const row = summaryResult.rows[0];

  return {
    vulnerabilities_total: row.vulnerabilities_total,
    critical_count: row.critical_count,
    high_count: row.high_count,
    medium_count: row.medium_count,
    low_count: row.low_count,
    affected_devices: row.affected_devices,
  };
}

async function syncGreenboneScan(scan) {
  if (scan.scanner_type !== 'greenbone') {
    return scan;
  }

  if (!isGreenboneEnabled()) {
    throw new GreenboneServiceError(GREENBONE_DISABLED_MESSAGE, {
      statusCode: 503,
      code: 'GREENBONE_DISABLED',
    });
  }

  if (!scan.external_task_id) {
    return updateScan(scan.id, {
      status: 'failed',
      completed_at: scan.completed_at || new Date(),
    });
  }

  if (isTerminalStatus(scan.status)) {
    return scan;
  }

  const taskStatus = await getTaskStatus(scan.external_task_id);

  const updates = {
    status: taskStatus.status,
    progress_percent: taskStatus.progress_percent,
  };

  if (!scan.started_at && (taskStatus.status === 'running' || taskStatus.status === 'completed')) {
    updates.started_at = new Date();
  }

  if (taskStatus.status === 'completed') {
    updates.progress_percent = 100;
    updates.completed_at = scan.completed_at || new Date();
  }

  if (taskStatus.status === 'failed') {
    updates.completed_at = scan.completed_at || new Date();
  }

  let updatedScan = await updateScan(scan.id, updates);

  if (taskStatus.status === 'completed') {
    const existingCountResult = await query(
      `
        SELECT COUNT(*)::int AS count
        FROM vulnerabilities
        WHERE scan_id = $1
      `,
      [scan.id],
    );

    if (existingCountResult.rows[0].count === 0) {
      const reportData = await fetchAndParseReport(scan.external_task_id, taskStatus.report_id);
      await storeGreenboneVulnerabilities(scan, reportData.vulnerabilities);
      updatedScan = await findScanById(scan.id);
    }
  }

  return updatedScan;
}

exports.listScans = async (req, res, next) => {
  try {
    const scansResult = await query(
      `
        SELECT ${SCAN_COLUMNS}
        FROM scans
        ORDER BY id DESC
        LIMIT 200
      `,
    );

    const scans = scansResult.rows;

    if (isGreenboneEnabled()) {
      const runningGreenboneScans = scans.filter(
        (scan) => scan.scanner_type === 'greenbone' && !isTerminalStatus(scan.status),
      );

      await Promise.all(
        runningGreenboneScans.map(async (scan) => {
          try {
            await syncGreenboneScan(scan);
          } catch (error) {
            console.error(`Failed syncing Greenbone scan ${scan.id}`, error);
          }
        }),
      );

      const refreshedResult = await query(
        `
          SELECT ${SCAN_COLUMNS}
          FROM scans
          ORDER BY id DESC
          LIMIT 200
        `,
      );

      return res.json(refreshedResult.rows);
    }

    return res.json(scans);
  } catch (err) {
    return next(err);
  }
};

exports.createScan = async (req, res, next) => {
  try {
    const target = normalizeTarget(req.body.target);
    const scanType = normalizeScanType(req.body.scan_type);

    if (!isValidTarget(target)) {
      return res.status(400).json({ error: 'target must be a valid IPv4 address or CIDR range' });
    }

    if (!isValidScanType(scanType)) {
      return res.status(400).json({
        error: 'scan_type must be one of: discovery, quick, standard, aggressive, full',
      });
    }

    const scanResult = await query(
      `
        INSERT INTO scans (target, scan_type, scanner_type, status, progress_percent, initiated_by)
        VALUES ($1, $2, 'nmap', 'queued', NULL, $3)
        RETURNING ${SCAN_COLUMNS}
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

exports.createVulnerabilityScan = async (req, res, next) => {
  try {
    if (!isGreenboneEnabled()) {
      return res.status(503).json({ error: GREENBONE_DISABLED_MESSAGE });
    }

    const target = normalizeTarget(req.body.target);

    if (!isValidIPv4(target)) {
      return res.status(400).json({ error: 'target must be a valid IPv4 address' });
    }

    const queuedResult = await query(
      `
        INSERT INTO scans (target, scan_type, scanner_type, status, progress_percent, initiated_by)
        VALUES ($1, 'vulnerability', 'greenbone', 'queued', 0, $2)
        RETURNING ${SCAN_COLUMNS}
      `,
      [target, req.user?.id || null],
    );

    const queuedScan = queuedResult.rows[0];

    try {
      const job = await startGreenboneScan(target);

      const runningScan = await updateScan(queuedScan.id, {
        status: 'running',
        started_at: new Date(),
        progress_percent: 10,
        external_task_id: job.externalTaskId,
      });

      return res.status(202).json(runningScan);
    } catch (error) {
      await updateScan(queuedScan.id, {
        status: 'failed',
        completed_at: new Date(),
      });

      const mappedError = toControllerError(error, 'Unable to start vulnerability scan');
      return res.status(mappedError.statusCode).json(mappedError.payload);
    }
  } catch (err) {
    return next(err);
  }
};

exports.getVulnerabilityStatus = (req, res) => {
  if (!isGreenboneEnabled()) {
    return res.status(503).json({ error: GREENBONE_DISABLED_MESSAGE });
  }

  const config = getGreenboneConfig();

  return res.json({
    enabled: true,
    host: config.host,
    port: config.port,
  });
};

exports.getScan = async (req, res, next) => {
  try {
    const scanId = Number(req.params.id);

    if (!Number.isInteger(scanId)) {
      return res.status(400).json({ error: 'invalid scan id' });
    }

    let scan = await findScanById(scanId);

    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    let summary;
    let vulnerabilities = [];

    if (scan.scanner_type === 'greenbone') {
      if (!isGreenboneEnabled()) {
        return res.status(503).json({ error: GREENBONE_DISABLED_MESSAGE });
      }

      if (!isTerminalStatus(scan.status)) {
        try {
          scan = await syncGreenboneScan(scan);
        } catch (error) {
          const mappedError = toControllerError(error, 'Unable to check vulnerability scan status');
          return res.status(mappedError.statusCode).json(mappedError.payload);
        }
      }

      summary = await buildGreenboneSummary(scan);
      vulnerabilities = await getScanVulnerabilities(scan.id);
    } else {
      summary = await buildNmapSummary(scan);
    }

    return res.json({
      ...scan,
      summary,
      vulnerabilities,
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