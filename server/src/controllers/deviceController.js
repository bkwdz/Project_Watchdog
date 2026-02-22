const { query } = require('../db');

function normalizeOptionalText(value) {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function sanitizeOsName(value) {
  const normalized = normalizeOptionalText(value);

  if (!normalized) {
    return null;
  }

  if (/^\/a:|^cpe:\/a:|^cpe:2\.3:a:/i.test(normalized)) {
    return null;
  }

  return normalized;
}

function resolveRequestedDisplayName(body) {
  if (!body || typeof body !== 'object') {
    return { provided: false, value: null };
  }

  if (Object.prototype.hasOwnProperty.call(body, 'display_name')) {
    return {
      provided: true,
      value: normalizeOptionalText(body.display_name),
    };
  }

  // Backward compatibility for clients still sending hostname in the edit form.
  if (Object.prototype.hasOwnProperty.call(body, 'hostname')) {
    return {
      provided: true,
      value: normalizeOptionalText(body.hostname),
    };
  }

  return { provided: false, value: null };
}

exports.summary = async (req, res, next) => {
  try {
    const totalsResult = await query(
      `
        SELECT
          (SELECT COUNT(*)::int FROM devices) AS total_devices,
          (SELECT COUNT(*)::int FROM devices WHERE online_status = true) AS online_devices,
          (SELECT COUNT(*)::int FROM devices WHERE online_status = false) AS offline_devices,
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

    const topRiskyDevicesResult = await query(
      `
        SELECT
          d.id,
          d.ip_address,
          COALESCE(NULLIF(d.display_name, ''), NULLIF(d.hostname, ''), d.ip_address::text) AS device_name,
          d.os_guess AS os,
          COUNT(*) FILTER (
            WHERE LOWER(COALESCE(v.cvss_severity, v.severity)) = 'critical'
          )::int AS critical_vulns,
          COUNT(*) FILTER (
            WHERE LOWER(COALESCE(v.cvss_severity, v.severity)) = 'high'
          )::int AS high_vulns
        FROM devices d
        INNER JOIN vulnerabilities v ON v.device_id = d.id
        WHERE LOWER(COALESCE(v.cvss_severity, v.severity)) IN ('critical', 'high')
        GROUP BY d.id, d.ip_address, d.display_name, d.hostname, d.os_guess
        ORDER BY critical_vulns DESC, high_vulns DESC, d.id ASC
        LIMIT 10
      `,
    );

    return res.json({
      totals: totalsResult.rows[0],
      top_ports: topPortsResult.rows,
      top_services: topServicesResult.rows,
      active_scans: activeScansResult.rows,
      top_risky_devices: topRiskyDevicesResult.rows,
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
          d.display_name,
          d.hostname,
          d.mac_address,
          d.os_guess,
          d.os_guess_source,
          d.os_guess_confidence,
          d.online_status,
          d.last_healthcheck_at,
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
      name: device.display_name || device.hostname,
      mac: device.mac_address,
      online: Boolean(device.online_status),
      lastSeen: device.last_seen,
      displayName: device.display_name,
      os: {
        name: sanitizeOsName(device.os_guess),
        source: device.os_guess_source || null,
        confidence: Number.isFinite(Number(device.os_guess_confidence))
          ? Number(device.os_guess_confidence)
          : null,
      },
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
        SELECT
          id,
          ip_address,
          display_name,
          hostname,
          mac_address,
          os_guess,
          os_guess_source,
          os_guess_confidence,
          os_detections,
          script_results,
          metadata,
          online_status,
          last_healthcheck_at,
          first_seen,
          last_seen
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
        SELECT
          id,
          port,
          protocol,
          service,
          version,
          state,
          metadata,
          script_results,
          last_source,
          source_confidence
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
          cve_list,
          nvt_oid,
          name,
          severity,
          cvss_score,
          cvss_severity,
          qod,
          cvss_vector,
          solution,
          port,
          description,
          source
        FROM vulnerabilities
        WHERE device_id = $1
        ORDER BY cvss_score DESC NULLS LAST, id DESC
      `,
      [deviceId],
    );

    const tlsCertificatesResult = await query(
      `
        SELECT
          id,
          port,
          protocol,
          subject,
          issuer,
          serial_number,
          fingerprint_sha256,
          not_before,
          not_after,
          raw_text,
          metadata,
          source,
          first_seen,
          last_seen
        FROM tls_certificates
        WHERE device_id = $1
        ORDER BY port ASC NULLS LAST, id DESC
      `,
      [deviceId],
    );

    const sshHostKeysResult = await query(
      `
        SELECT
          id,
          port,
          protocol,
          key_type,
          fingerprint,
          key_bits,
          raw_text,
          metadata,
          source,
          first_seen,
          last_seen
        FROM ssh_host_keys
        WHERE device_id = $1
        ORDER BY port ASC NULLS LAST, id DESC
      `,
      [deviceId],
    );

    return res.json({
      ...device,
      ip: device.ip_address,
      name: device.display_name || device.hostname,
      mac: device.mac_address,
      online: Boolean(device.online_status),
      lastSeen: device.last_seen,
      displayName: device.display_name,
      os: {
        name: sanitizeOsName(device.os_guess),
        source: device.os_guess_source || null,
        confidence: Number.isFinite(Number(device.os_guess_confidence))
          ? Number(device.os_guess_confidence)
          : null,
        detections: Array.isArray(device.os_detections) ? device.os_detections : [],
      },
      ports: portsResult.rows,
      vulnerabilities: vulnerabilitiesResult.rows,
      tls_certificates: tlsCertificatesResult.rows,
      ssh_host_keys: sshHostKeysResult.rows,
    });
  } catch (err) {
    return next(err);
  }
};

exports.update = async (req, res, next) => {
  try {
    const deviceId = Number(req.params.id);

    if (!Number.isInteger(deviceId)) {
      return res.status(400).json({ error: 'invalid device id' });
    }

    const requestedDisplayName = resolveRequestedDisplayName(req.body);

    if (!requestedDisplayName.provided) {
      return res.status(400).json({ error: 'display_name is required' });
    }

    const displayName = requestedDisplayName.value;
    const shouldPopulateHostname = displayName !== null;

    const updateResult = await query(
      `
        UPDATE devices
        SET
          display_name = $2,
          hostname = CASE
            WHEN $3::boolean = true AND (hostname IS NULL OR BTRIM(hostname) = '') THEN $2
            ELSE hostname
          END
        WHERE id = $1
        RETURNING id, ip_address, display_name, hostname, mac_address, os_guess, online_status, last_healthcheck_at, first_seen, last_seen
      `,
      [deviceId, displayName, shouldPopulateHostname],
    );

    const updated = updateResult.rows[0];

    if (!updated) {
      return res.status(404).json({ error: 'Not found' });
    }

    return res.json({
      ...updated,
      ip: updated.ip_address,
      name: updated.display_name || updated.hostname,
      mac: updated.mac_address,
      online: Boolean(updated.online_status),
      lastSeen: updated.last_seen,
      displayName: updated.display_name,
    });
  } catch (err) {
    return next(err);
  }
};
