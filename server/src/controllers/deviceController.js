const { query } = require('../db');

exports.summary = async (req, res, next) => {
  try {
    const totalsResult = await query(
      `
        SELECT
          (SELECT COUNT(*)::int FROM devices) AS total_devices,
          (SELECT COUNT(*)::int FROM scans) AS total_scans,
          (SELECT COUNT(*)::int FROM scans WHERE status = 'running') AS running_scans,
          (SELECT COUNT(*)::int FROM scans WHERE status = 'queued') AS queued_scans,
          (SELECT COUNT(*)::int FROM scans WHERE status = 'failed') AS failed_scans,
          (SELECT COUNT(*)::int FROM scans WHERE status = 'completed') AS completed_scans,
          (SELECT COUNT(*)::int FROM ports WHERE state = 'open') AS total_open_ports,
          (SELECT COUNT(*)::int FROM vulnerabilities) AS vulnerabilities_total,
          (SELECT COUNT(DISTINCT device_id)::int FROM vulnerabilities) AS vulnerable_devices,
          (SELECT COUNT(*)::int FROM vulnerabilities WHERE COALESCE(cvss_severity, severity) ILIKE 'critical') AS critical_count,
          (SELECT COUNT(*)::int FROM vulnerabilities WHERE COALESCE(cvss_severity, severity) ILIKE 'high') AS high_count,
          (SELECT COUNT(*)::int FROM vulnerabilities WHERE COALESCE(cvss_severity, severity) ILIKE 'medium') AS medium_count,
          (SELECT COUNT(*)::int FROM vulnerabilities WHERE COALESCE(cvss_severity, severity) ILIKE 'low') AS low_count
      `,
    );

    const topPortsResult = await query(
      `
        SELECT
          port,
          protocol,
          COUNT(*)::int AS count
        FROM ports
        WHERE state = 'open'
        GROUP BY port, protocol
        ORDER BY count DESC, port ASC
        LIMIT 10
      `,
    );

    const topServicesResult = await query(
      `
        SELECT
          COALESCE(NULLIF(service, ''), 'unknown') AS service,
          COUNT(*)::int AS count
        FROM ports
        WHERE state = 'open'
        GROUP BY COALESCE(NULLIF(service, ''), 'unknown')
        ORDER BY count DESC, service ASC
        LIMIT 10
      `,
    );

    const activeScansResult = await query(
      `
        SELECT
          id,
          target,
          scan_type,
          COALESCE(scanner_type, 'nmap') AS scanner_type,
          status,
          progress_percent,
          started_at
        FROM scans
        WHERE status IN ('queued', 'running')
        ORDER BY started_at DESC NULLS LAST, id DESC
        LIMIT 12
      `,
    );

    return res.json({
      totals: totalsResult.rows[0],
      top_ports: topPortsResult.rows,
      top_services: topServicesResult.rows,
      active_scans: activeScansResult.rows,
    });
  } catch (err) {
    return next(err);
  }
};

exports.list = async (req, res, next) => {
  try {
    const result = await query(
      `
        SELECT
          d.id,
          d.ip_address,
          d.hostname,
          d.mac_address,
          d.os_guess,
          d.first_seen,
          d.last_seen,
          COALESCE(COUNT(p.id) FILTER (WHERE p.state = 'open'), 0)::int AS open_ports
        FROM devices d
        LEFT JOIN ports p ON p.device_id = d.id
        GROUP BY d.id
        ORDER BY d.last_seen DESC
      `,
    );

    const devices = result.rows.map((device) => ({
      ...device,
      ip: device.ip_address,
      name: device.hostname,
      mac: device.mac_address,
      lastSeen: device.last_seen,
    }));

    return res.json(devices);
  } catch (err) {
    return next(err);
  }
};

exports.get = async (req, res, next) => {
  try {
    const deviceId = Number(req.params.id);

    if (!Number.isInteger(deviceId)) {
      return res.status(400).json({ error: 'invalid device id' });
    }

    const deviceResult = await query(
      `
        SELECT id, ip_address, hostname, mac_address, os_guess, first_seen, last_seen
        FROM devices
        WHERE id = $1
        LIMIT 1
      `,
      [deviceId],
    );

    const device = deviceResult.rows[0];

    if (!device) {
      return res.status(404).json({ error: 'Not found' });
    }

    const portsResult = await query(
      `
        SELECT id, port, protocol, service, version, state
        FROM ports
        WHERE device_id = $1
        ORDER BY port ASC, protocol ASC
      `,
      [deviceId],
    );

    const vulnerabilitiesResult = await query(
      `
        SELECT
          id,
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
        WHERE device_id = $1
        ORDER BY cvss_score DESC NULLS LAST, id DESC
      `,
      [deviceId],
    );

    return res.json({
      ...device,
      ip: device.ip_address,
      name: device.hostname,
      mac: device.mac_address,
      lastSeen: device.last_seen,
      ports: portsResult.rows,
      vulnerabilities: vulnerabilitiesResult.rows,
    });
  } catch (err) {
    return next(err);
  }
};
