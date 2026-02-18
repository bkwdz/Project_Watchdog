const { query } = require('../db');

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
