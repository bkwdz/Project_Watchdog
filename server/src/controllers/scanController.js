const { query, withTransaction } = require('../db');
const { enqueueScan } = require('../services/scanWorker');
const { isValidScanType } = require('../services/scanProfiles');
const {
  GreenboneServiceError,
  getConfig: getGreenboneConfig,
  isGreenboneEnabled,
  listScanConfigs: listGreenboneScanConfigs,
  createCredential: createGreenboneCredential,
  startScan: startGreenboneScan,
  getTaskStatus,
  fetchAndParseReport,
} = require('../services/greenboneService');
const {
  upsertDeviceRecord,
  upsertPortRecord,
  buildAssetHash,
} = require('../services/dataReconciliation');
const {
  normalizeCredentialType,
  createCredentialRecord,
  listCredentialSummaries,
  resolveCredentialWithSecret,
  markCredentialUsed,
  updateCredentialExternalId,
  sanitizeCredentialRow,
} = require('../services/scanCredentialService');
const { isValidCidr, isValidTarget, isValidIPv4 } = require('../utils/targetValidation');

const GREENBONE_DISABLED_MESSAGE = 'Vulnerability scanner not enabled';

const DEFAULT_GREENBONE_MAX_CHECKS = Number.parseInt(process.env.GREENBONE_MAX_CHECKS || '4', 10) || 4;
const DEFAULT_GREENBONE_MAX_HOSTS = Number.parseInt(process.env.GREENBONE_MAX_HOSTS || '1', 10) || 1;

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
  external_task_id,
  ssh_credential_id,
  smb_credential_id
`;

function normalizeTarget(target) {
  return typeof target === 'string' ? target.trim() : '';
}

function normalizeOptionalText(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function hasOwn(body, key) {
  return Object.prototype.hasOwnProperty.call(body || {}, key);
}

function parsePositiveInteger(value, fieldName, { min = 1, max = 64 } = {}) {
  const parsed = Number.parseInt(String(value).trim(), 10);

  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${fieldName} must be an integer between ${min} and ${max}`);
  }

  return parsed;
}

async function getStoredVulnerabilitySettings() {
  await query(
    `
      INSERT INTO scanner_settings (id, greenbone_max_checks, greenbone_max_hosts)
      VALUES (1, $1, $2)
      ON CONFLICT (id) DO NOTHING
    `,
    [DEFAULT_GREENBONE_MAX_CHECKS, DEFAULT_GREENBONE_MAX_HOSTS],
  );

  const settingsResult = await query(
    `
      SELECT greenbone_max_checks, greenbone_max_hosts, updated_at
      FROM scanner_settings
      WHERE id = 1
      LIMIT 1
    `,
  );

  const settings = settingsResult.rows[0];

  if (!settings) {
    return {
      greenbone_max_checks: DEFAULT_GREENBONE_MAX_CHECKS,
      greenbone_max_hosts: DEFAULT_GREENBONE_MAX_HOSTS,
      updated_at: null,
    };
  }

  return settings;
}

function parsePortSpec(spec, fieldName) {
  const normalized = normalizeOptionalText(spec);

  if (!normalized) {
    return '';
  }

  if (fieldName === 'udp_ports' && normalized === '0') {
    return '';
  }

  const tokens = normalized
    .split(',')
    .map((token) => token.trim())
    .filter(Boolean);

  if (tokens.length === 0) {
    return '';
  }

  const validatedTokens = tokens.map((token) => {
    const singleMatch = token.match(/^(\d{1,5})$/);

    if (singleMatch) {
      const port = Number(singleMatch[1]);

      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`${fieldName} contains an out-of-range port: ${token}`);
      }

      return `${port}`;
    }

    const rangeMatch = token.match(/^(\d{1,5})-(\d{1,5})$/);

    if (!rangeMatch) {
      throw new Error(`${fieldName} contains an invalid token: ${token}`);
    }

    const start = Number(rangeMatch[1]);
    const end = Number(rangeMatch[2]);

    if (
      !Number.isInteger(start)
      || !Number.isInteger(end)
      || start < 1
      || end < 1
      || start > 65535
      || end > 65535
      || start > end
    ) {
      throw new Error(`${fieldName} contains an invalid range: ${token}`);
    }

    return `${start}-${end}`;
  });

  return validatedTokens.join(',');
}

function buildGreenbonePortRange(tcpPortsRaw, udpPortsRaw) {
  const tcpPorts = parsePortSpec(tcpPortsRaw, 'tcp_ports');
  const udpPorts = parsePortSpec(udpPortsRaw, 'udp_ports');

  if (!tcpPorts && !udpPorts) {
    return null;
  }

  const sections = [];

  if (tcpPorts) {
    sections.push(`T:${tcpPorts}`);
  }

  if (udpPorts) {
    sections.push(`U:${udpPorts}`);
  }

  return sections.join(',');
}

function parseCredentialMode(value) {
  const normalized = String(value || 'none').trim().toLowerCase();
  return ['none', 'existing', 'new'].includes(normalized) ? normalized : null;
}

function parseVulnerabilityCredentialRequest(value) {
  if (!value || typeof value !== 'object') {
    return {
      mode: 'none',
      type: null,
      credential_id: null,
      name: null,
      username: null,
      password: null,
    };
  }

  const mode = parseCredentialMode(value.mode);

  if (!mode) {
    throw new Error('credentials.mode must be one of: none, existing, new');
  }

  if (mode === 'none') {
    return {
      mode,
      type: null,
      credential_id: null,
      name: null,
      username: null,
      password: null,
    };
  }

  const type = normalizeCredentialType(value.type);

  if (!type) {
    throw new Error('credentials.type must be ssh or smb');
  }

  if (mode === 'existing') {
    const credentialId = Number(value.credential_id);

    if (!Number.isInteger(credentialId) || credentialId < 1) {
      throw new Error('credentials.credential_id must be a positive integer');
    }

    return {
      mode,
      type,
      credential_id: credentialId,
      name: null,
      username: null,
      password: null,
    };
  }

  const username = normalizeOptionalText(value.username);
  const password = normalizeOptionalText(value.password);

  if (!username || !password) {
    throw new Error('credentials.username and credentials.password are required');
  }

  return {
    mode,
    type,
    credential_id: null,
    name: normalizeOptionalText(value.name),
    username,
    password,
  };
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

function buildCredentialDisplayName({ mode, type, target, username, explicitName }) {
  const provided = normalizeOptionalText(explicitName);

  if (provided) {
    return provided;
  }

  const safeTarget = normalizeOptionalText(target) || 'target';
  const safeUser = normalizeOptionalText(username) || 'user';
  const suffix = mode === 'new' ? 'new' : 'reuse';

  return `Watchdog ${type.toUpperCase()} ${safeUser}@${safeTarget} (${suffix})`;
}

async function ensureCredentialExternalId(binding, { target }) {
  if (!binding) {
    return null;
  }

  if (binding.external_credential_id) {
    return binding.external_credential_id;
  }

  const displayName = buildCredentialDisplayName({
    mode: binding.mode,
    type: binding.type,
    target,
    username: binding.username,
    explicitName: binding.display_name,
  });
  const created = await createGreenboneCredential({
    credentialType: binding.type,
    name: displayName,
    username: binding.username,
    password: binding.password,
  });

  binding.external_credential_id = created.credentialId;

  if (binding.row?.id) {
    await updateCredentialExternalId(binding.row.id, created.credentialId);
  }

  return created.credentialId;
}

async function resolveVulnerabilityCredentialBinding(credentialRequest, { userId, target }) {
  if (!credentialRequest || credentialRequest.mode === 'none') {
    return null;
  }

  if (credentialRequest.mode === 'existing') {
    const existing = await resolveCredentialWithSecret(
      credentialRequest.credential_id,
      credentialRequest.type,
    );
    const binding = {
      mode: 'existing',
      type: credentialRequest.type,
      row: existing.row,
      display_name: existing.row.display_name,
      username: existing.username,
      password: existing.password,
      external_credential_id: existing.external_credential_id,
    };

    await ensureCredentialExternalId(binding, { target });
    return binding;
  }

  const createdExternal = await createGreenboneCredential({
    credentialType: credentialRequest.type,
    name: buildCredentialDisplayName({
      mode: 'new',
      type: credentialRequest.type,
      target,
      username: credentialRequest.username,
      explicitName: credentialRequest.name,
    }),
    username: credentialRequest.username,
    password: credentialRequest.password,
  });

  const localRecord = await createCredentialRecord({
    credentialType: credentialRequest.type,
    displayName: credentialRequest.name || null,
    username: credentialRequest.username,
    password: credentialRequest.password,
    source: 'greenbone',
    createdBy: userId,
    externalCredentialId: createdExternal.credentialId,
  });

  return {
    mode: 'new',
    type: credentialRequest.type,
    row: localRecord,
    display_name: localRecord.display_name,
    username: localRecord.username,
    password: credentialRequest.password,
    external_credential_id: createdExternal.credentialId,
  };
}

async function retryCredentialIfRejected(error, binding, target) {
  if (
    !binding
    || !(error instanceof GreenboneServiceError)
    || error.code !== 'GREENBONE_CREDENTIAL_REJECTED'
  ) {
    throw error;
  }

  const recreated = await createGreenboneCredential({
    credentialType: binding.type,
    name: buildCredentialDisplayName({
      mode: binding.mode,
      type: binding.type,
      target,
      username: binding.username,
      explicitName: binding.display_name,
    }),
    username: binding.username,
    password: binding.password,
  });

  binding.external_credential_id = recreated.credentialId;

  if (binding.row?.id) {
    await updateCredentialExternalId(binding.row.id, recreated.credentialId);
  }

  return binding;
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

async function findLatestCompletedGreenboneScanForDeviceIp(ipAddress) {
  const safeIp = String(ipAddress || '').trim();

  if (!isValidIPv4(safeIp)) {
    return null;
  }

  const result = await query(
    `
      SELECT ${SCAN_COLUMNS}
      FROM scans
      WHERE COALESCE(scanner_type, 'nmap') = 'greenbone'
        AND status = 'completed'
        AND external_task_id IS NOT NULL
        AND (
          target = $1
          OR (
            POSITION('/' IN target) > 0
            AND $1::inet << target::cidr
          )
        )
      ORDER BY completed_at DESC NULLS LAST, started_at DESC NULLS LAST, id DESC
      LIMIT 1
    `,
    [safeIp],
  );

  return result.rows[0] || null;
}

async function findCompletedGreenboneScanByIdForDeviceIp(scanId, ipAddress) {
  const parsedScanId = Number(scanId);
  const safeIp = String(ipAddress || '').trim();

  if (!Number.isInteger(parsedScanId) || parsedScanId < 1 || !isValidIPv4(safeIp)) {
    return null;
  }

  const result = await query(
    `
      SELECT ${SCAN_COLUMNS}
      FROM scans
      WHERE id = $1
        AND COALESCE(scanner_type, 'nmap') = 'greenbone'
        AND status = 'completed'
        AND external_task_id IS NOT NULL
        AND (
          target = $2
          OR (
            POSITION('/' IN target) > 0
            AND $2::inet << target::cidr
          )
        )
      LIMIT 1
    `,
    [parsedScanId, safeIp],
  );

  return result.rows[0] || null;
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

function extractHostIp(value) {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();

  if (!trimmed) {
    return null;
  }

  if (isValidIPv4(trimmed)) {
    return trimmed;
  }

  const match = trimmed.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);

  if (!match) {
    return null;
  }

  return isValidIPv4(match[0]) ? match[0] : null;
}

function asJsonObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }

  return value;
}

function normalizeCveList(value) {
  const set = new Set();

  (Array.isArray(value) ? value : [value]).forEach((entry) => {
    String(entry || '')
      .split(/[,\s;]+/)
      .map((token) => token.trim().toUpperCase())
      .filter((token) => /^CVE-\d{4}-\d{4,}$/i.test(token))
      .forEach((token) => set.add(token));
  });

  return [...set];
}

async function upsertTlsCertificate(client, deviceId, entry) {
  const assetHash = buildAssetHash([
    entry.fingerprint_sha256,
    entry.serial_number,
    entry.subject,
    entry.port,
    entry.protocol,
  ]);

  await client.query(
    `
      INSERT INTO tls_certificates (
        device_id,
        asset_hash,
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
        source
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13)
      ON CONFLICT (device_id, asset_hash)
      DO UPDATE SET
        port = COALESCE(EXCLUDED.port, tls_certificates.port),
        protocol = COALESCE(EXCLUDED.protocol, tls_certificates.protocol),
        subject = COALESCE(EXCLUDED.subject, tls_certificates.subject),
        issuer = COALESCE(EXCLUDED.issuer, tls_certificates.issuer),
        serial_number = COALESCE(EXCLUDED.serial_number, tls_certificates.serial_number),
        fingerprint_sha256 = COALESCE(EXCLUDED.fingerprint_sha256, tls_certificates.fingerprint_sha256),
        not_before = COALESCE(EXCLUDED.not_before, tls_certificates.not_before),
        not_after = COALESCE(EXCLUDED.not_after, tls_certificates.not_after),
        raw_text = COALESCE(EXCLUDED.raw_text, tls_certificates.raw_text),
        metadata = COALESCE(tls_certificates.metadata, '{}'::jsonb) || COALESCE(EXCLUDED.metadata, '{}'::jsonb),
        source = EXCLUDED.source,
        last_seen = NOW()
    `,
    [
      deviceId,
      assetHash,
      Number.isInteger(entry.port) ? entry.port : null,
      entry.protocol || null,
      entry.subject || null,
      entry.issuer || null,
      entry.serial_number || null,
      entry.fingerprint_sha256 || null,
      entry.not_before || null,
      entry.not_after || null,
      entry.raw_text || null,
      JSON.stringify(asJsonObject(entry.metadata)),
      entry.source || 'greenbone',
    ],
  );
}

async function upsertSshHostKey(client, deviceId, entry) {
  const assetHash = buildAssetHash([
    entry.fingerprint,
    entry.key_type,
    entry.port,
    entry.protocol,
  ]);

  await client.query(
    `
      INSERT INTO ssh_host_keys (
        device_id,
        asset_hash,
        port,
        protocol,
        key_type,
        fingerprint,
        key_bits,
        raw_text,
        metadata,
        source
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)
      ON CONFLICT (device_id, asset_hash)
      DO UPDATE SET
        port = COALESCE(EXCLUDED.port, ssh_host_keys.port),
        protocol = COALESCE(EXCLUDED.protocol, ssh_host_keys.protocol),
        key_type = COALESCE(EXCLUDED.key_type, ssh_host_keys.key_type),
        fingerprint = COALESCE(EXCLUDED.fingerprint, ssh_host_keys.fingerprint),
        key_bits = COALESCE(EXCLUDED.key_bits, ssh_host_keys.key_bits),
        raw_text = COALESCE(EXCLUDED.raw_text, ssh_host_keys.raw_text),
        metadata = COALESCE(ssh_host_keys.metadata, '{}'::jsonb) || COALESCE(EXCLUDED.metadata, '{}'::jsonb),
        source = EXCLUDED.source,
        last_seen = NOW()
    `,
    [
      deviceId,
      assetHash,
      Number.isInteger(entry.port) ? entry.port : null,
      entry.protocol || null,
      entry.key_type || null,
      entry.fingerprint || null,
      Number.isInteger(entry.key_bits) ? entry.key_bits : null,
      entry.raw_text || null,
      JSON.stringify(asJsonObject(entry.metadata)),
      entry.source || 'greenbone',
    ],
  );
}

async function storeGreenboneReportData(scan, reportData, { replaceExisting = false } = {}) {
  const vulnerabilities = Array.isArray(reportData?.vulnerabilities) ? reportData.vulnerabilities : [];
  const ports = Array.isArray(reportData?.ports) ? reportData.ports : [];
  const osDetections = Array.isArray(reportData?.osDetections) ? reportData.osDetections : [];
  const tlsCertificates = Array.isArray(reportData?.tlsCertificates) ? reportData.tlsCertificates : [];
  const sshHostKeys = Array.isArray(reportData?.sshHostKeys) ? reportData.sshHostKeys : [];
  const hostMetadata = Array.isArray(reportData?.hostMetadata) ? reportData.hostMetadata : [];

  if (
    vulnerabilities.length === 0
    && ports.length === 0
    && osDetections.length === 0
    && tlsCertificates.length === 0
    && sshHostKeys.length === 0
    && hostMetadata.length === 0
  ) {
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

    if (!replaceExisting && existingCountResult.rows[0].count > 0) {
      return existingCountResult.rows[0].count;
    }

    if (replaceExisting && existingCountResult.rows[0].count > 0) {
      await client.query(
        `
          DELETE FROM vulnerabilities
          WHERE scan_id = $1
        `,
        [scan.id],
      );
    }

    const fallbackIp = isValidIPv4(scan.target) ? scan.target : null;
    const cachedDeviceIds = new Map();
    const cleanedDeviceIps = new Set();

    const ensureDeviceId = async (hostValue, patch = null) => {
      const ipAddress = extractHostIp(hostValue) || fallbackIp;

      if (!ipAddress) {
        return null;
      }

      if (replaceExisting && !cleanedDeviceIps.has(ipAddress)) {
        await client.query(
          `
            UPDATE devices
            SET metadata = (
              COALESCE(metadata, '{}'::jsonb)
              - 'applications'
              - 'greenbone_logs'
              - 'greenbone_host_details'
              - 'service_banners'
            )
            WHERE ip_address = $1::inet
          `,
          [ipAddress],
        );
        cleanedDeviceIps.add(ipAddress);
      }

      if (!patch && cachedDeviceIds.has(ipAddress)) {
        return cachedDeviceIds.get(ipAddress);
      }

      const payload = patch && typeof patch === 'object' ? patch : {};
      const device = await upsertDeviceRecord(client, {
        ipAddress,
        source: 'greenbone',
        touchLastSeen: true,
        ...payload,
      });

      cachedDeviceIds.set(ipAddress, device.id);
      return device.id;
    };

    for (const detail of hostMetadata) {
      await ensureDeviceId(detail.host, {
        metadata: asJsonObject(detail.metadata),
      });
    }

    for (const detection of osDetections) {
      await ensureDeviceId(detection.host, {
        osDetection: {
          name: detection.name,
          source: detection.source || 'greenbone',
          confidence: detection.confidence,
          evidence: detection.evidence || null,
        },
      });
    }

    for (const portObservation of ports) {
      const deviceId = await ensureDeviceId(portObservation.host);

      if (!deviceId) {
        continue;
      }

      await upsertPortRecord(client, {
        deviceId,
        port: portObservation.port,
        protocol: portObservation.protocol || 'tcp',
        service: portObservation.service || null,
        version: portObservation.version || null,
        state: portObservation.state || 'open',
        metadata: asJsonObject(portObservation.metadata),
        source: portObservation.source || 'greenbone',
        confidence: Number.isFinite(portObservation.confidence) ? portObservation.confidence : 0.95,
      });
    }

    for (const certificate of tlsCertificates) {
      const deviceId = await ensureDeviceId(certificate.host);

      if (!deviceId) {
        continue;
      }

      await upsertTlsCertificate(client, deviceId, certificate);

      if (Number.isInteger(certificate.port)) {
        await upsertPortRecord(client, {
          deviceId,
          port: certificate.port,
          protocol: certificate.protocol || 'tcp',
          state: 'open',
          metadata: {
            tls_certificates: [
              {
                subject: certificate.subject || null,
                issuer: certificate.issuer || null,
                fingerprint_sha256: certificate.fingerprint_sha256 || null,
                not_after: certificate.not_after || null,
              },
            ],
          },
          source: 'greenbone',
          confidence: 0.95,
        });
      }
    }

    for (const hostKey of sshHostKeys) {
      const deviceId = await ensureDeviceId(hostKey.host);

      if (!deviceId) {
        continue;
      }

      await upsertSshHostKey(client, deviceId, hostKey);

      if (Number.isInteger(hostKey.port)) {
        await upsertPortRecord(client, {
          deviceId,
          port: hostKey.port,
          protocol: hostKey.protocol || 'tcp',
          state: 'open',
          metadata: {
            ssh_host_keys: [
              {
                key_type: hostKey.key_type || null,
                fingerprint: hostKey.fingerprint || null,
                key_bits: Number.isInteger(hostKey.key_bits) ? hostKey.key_bits : null,
              },
            ],
          },
          source: 'greenbone',
          confidence: 0.95,
        });
      }
    }

    let inserted = 0;

    for (const vulnerability of vulnerabilities) {
      const cveList = normalizeCveList(vulnerability.cve_list || vulnerability.cve);
      const deviceId = await ensureDeviceId(vulnerability.host);

      if (!deviceId) {
        continue;
      }

      if (Number.isInteger(vulnerability.port)) {
        await upsertPortRecord(client, {
          deviceId,
          port: vulnerability.port,
          protocol: 'tcp',
          state: 'open',
          metadata: {
            vulnerability_refs: [
              {
                cve: vulnerability.cve || cveList[0] || null,
                cve_list: cveList,
                nvt_oid: vulnerability.nvt_oid || null,
                severity: vulnerability.cvss_severity || vulnerability.severity || null,
                qod: Number.isFinite(vulnerability.qod) ? vulnerability.qod : null,
                cvss_vector: vulnerability.cvss_vector || null,
                solution: vulnerability.solution || null,
              },
            ],
          },
          source: 'greenbone',
          confidence: 0.95,
        });
      }

      await client.query(
        `
          INSERT INTO vulnerabilities (
            device_id,
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
          )
          VALUES ($1, $2, $3, $4::text[], $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        `,
        [
          deviceId,
          scan.id,
          vulnerability.cve || cveList[0] || null,
          cveList,
          vulnerability.nvt_oid || null,
          vulnerability.name || null,
          vulnerability.severity || null,
          Number.isFinite(vulnerability.cvss_score) ? vulnerability.cvss_score : null,
          vulnerability.cvss_severity || null,
          Number.isFinite(vulnerability.qod) ? vulnerability.qod : null,
          vulnerability.cvss_vector || null,
          vulnerability.solution || null,
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
      await storeGreenboneReportData(scan, reportData);
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
    const scanConfigId = normalizeOptionalText(req.body.scan_config_id);
    let credentialRequest;
    let portRange = null;

    try {
      portRange = buildGreenbonePortRange(req.body.tcp_ports, req.body.udp_ports);
      credentialRequest = parseVulnerabilityCredentialRequest(req.body.credentials);
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }

    if (!isValidTarget(target)) {
      return res.status(400).json({ error: 'target must be a valid IPv4 address or CIDR range' });
    }

    const runtimeSettings = await getStoredVulnerabilitySettings();
    let credentialBinding;

    try {
      credentialBinding = await resolveVulnerabilityCredentialBinding(credentialRequest, {
        userId: req.user?.id || null,
        target,
      });
    } catch (error) {
      if (error instanceof GreenboneServiceError) {
        const mappedError = toControllerError(error, 'Unable to prepare vulnerability credentials');
        return res.status(mappedError.statusCode).json(mappedError.payload);
      }

      return res.status(400).json({ error: error.message || 'Invalid credentials payload' });
    }

    const scanCredentialIds = {
      ssh_credential_id: credentialBinding?.type === 'ssh' ? credentialBinding.row?.id || null : null,
      smb_credential_id: credentialBinding?.type === 'smb' ? credentialBinding.row?.id || null : null,
    };

    const queuedResult = await query(
      `
        INSERT INTO scans (
          target,
          scan_type,
          scanner_type,
          status,
          progress_percent,
          initiated_by,
          ssh_credential_id,
          smb_credential_id
        )
        VALUES ($1, 'vulnerability', 'greenbone', 'queued', 0, $2, $3, $4)
        RETURNING ${SCAN_COLUMNS}
      `,
      [
        target,
        req.user?.id || null,
        scanCredentialIds.ssh_credential_id,
        scanCredentialIds.smb_credential_id,
      ],
    );

    const queuedScan = queuedResult.rows[0];

    try {
      const startScanPayload = {
        scanConfigId: scanConfigId || undefined,
        portRange: portRange || undefined,
        maxChecks: runtimeSettings.greenbone_max_checks,
        maxHosts: runtimeSettings.greenbone_max_hosts,
        sshCredentialId: credentialBinding?.type === 'ssh'
          ? credentialBinding.external_credential_id || undefined
          : undefined,
        smbCredentialId: credentialBinding?.type === 'smb'
          ? credentialBinding.external_credential_id || undefined
          : undefined,
      };

      let job;

      try {
        job = await startGreenboneScan(target, startScanPayload);
      } catch (error) {
        const retriedBinding = await retryCredentialIfRejected(error, credentialBinding, target);

        if (!retriedBinding) {
          throw error;
        }

        job = await startGreenboneScan(target, {
          ...startScanPayload,
          sshCredentialId: retriedBinding.type === 'ssh'
            ? retriedBinding.external_credential_id || undefined
            : undefined,
          smbCredentialId: retriedBinding.type === 'smb'
            ? retriedBinding.external_credential_id || undefined
            : undefined,
        });
      }

      const runningScan = await updateScan(queuedScan.id, {
        status: 'running',
        started_at: new Date(),
        progress_percent: 10,
        external_task_id: job.externalTaskId,
      });

      if (credentialBinding?.row?.id) {
        await markCredentialUsed(credentialBinding.row.id);
      }

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

exports.refreshDeviceFromGreenboneHistory = async (req, res, next) => {
  try {
    if (!isGreenboneEnabled()) {
      return res.status(503).json({ error: GREENBONE_DISABLED_MESSAGE });
    }

    const deviceId = Number(req.params.deviceId);

    if (!Number.isInteger(deviceId) || deviceId < 1) {
      return res.status(400).json({ error: 'invalid device id' });
    }

    const deviceResult = await query(
      `
        SELECT id, ip_address
        FROM devices
        WHERE id = $1
        LIMIT 1
      `,
      [deviceId],
    );
    const device = deviceResult.rows[0];

    if (!device?.ip_address) {
      return res.status(404).json({ error: 'Device not found' });
    }

    const requestedScanId = Number(req.body?.scan_id);
    const scan = Number.isInteger(requestedScanId) && requestedScanId > 0
      ? await findCompletedGreenboneScanByIdForDeviceIp(requestedScanId, device.ip_address)
      : await findLatestCompletedGreenboneScanForDeviceIp(device.ip_address);

    if (!scan) {
      return res.status(404).json({
        error: Number.isInteger(requestedScanId) && requestedScanId > 0
          ? 'Requested completed Greenbone scan was not found for this device'
          : 'No completed vulnerability scan history found for this device',
      });
    }

    try {
      const reportData = await fetchAndParseReport(scan.external_task_id, null);
      const inserted = await storeGreenboneReportData(scan, reportData, {
        replaceExisting: true,
      });

      return res.json({
        refreshed: true,
        device_id: deviceId,
        scan_id: scan.id,
        external_task_id: scan.external_task_id,
        report_id: reportData.reportId,
        vulnerabilities_imported: inserted,
      });
    } catch (error) {
      const mappedError = toControllerError(error, 'Unable to refresh device data from Greenbone history');
      return res.status(mappedError.statusCode).json(mappedError.payload);
    }
  } catch (err) {
    return next(err);
  }
};

exports.getVulnerabilityCredentials = async (req, res, next) => {
  try {
    const type = normalizeCredentialType(req.query.type);

    if (!type) {
      return res.status(400).json({ error: 'type must be ssh or smb' });
    }

    const credentials = await listCredentialSummaries(type);
    return res.json({
      type,
      credentials: credentials.map(sanitizeCredentialRow),
    });
  } catch (err) {
    return next(err);
  }
};

exports.getVulnerabilitySettings = async (req, res, next) => {
  try {
    const settings = await getStoredVulnerabilitySettings();

    return res.json({
      max_checks: settings.greenbone_max_checks,
      max_hosts: settings.greenbone_max_hosts,
      updated_at: settings.updated_at,
    });
  } catch (err) {
    return next(err);
  }
};

exports.updateVulnerabilitySettings = async (req, res, next) => {
  try {
    const body = req.body || {};
    const hasMaxChecks = hasOwn(body, 'max_checks');
    const hasMaxHosts = hasOwn(body, 'max_hosts');

    if (!hasMaxChecks && !hasMaxHosts) {
      return res.status(400).json({ error: 'Provide max_checks or max_hosts' });
    }

    const current = await getStoredVulnerabilitySettings();

    let maxChecks = current.greenbone_max_checks;
    let maxHosts = current.greenbone_max_hosts;

    if (hasMaxChecks) {
      try {
        maxChecks = parsePositiveInteger(body.max_checks, 'max_checks', { min: 1, max: 64 });
      } catch (error) {
        return res.status(400).json({ error: error.message });
      }
    }

    if (hasMaxHosts) {
      try {
        maxHosts = parsePositiveInteger(body.max_hosts, 'max_hosts', { min: 1, max: 64 });
      } catch (error) {
        return res.status(400).json({ error: error.message });
      }
    }

    const updateResult = await query(
      `
        INSERT INTO scanner_settings (id, greenbone_max_checks, greenbone_max_hosts, updated_at)
        VALUES (1, $1, $2, NOW())
        ON CONFLICT (id)
        DO UPDATE SET
          greenbone_max_checks = EXCLUDED.greenbone_max_checks,
          greenbone_max_hosts = EXCLUDED.greenbone_max_hosts,
          updated_at = NOW()
        RETURNING greenbone_max_checks, greenbone_max_hosts, updated_at
      `,
      [maxChecks, maxHosts],
    );

    const updated = updateResult.rows[0];

    return res.json({
      max_checks: updated.greenbone_max_checks,
      max_hosts: updated.greenbone_max_hosts,
      updated_at: updated.updated_at,
    });
  } catch (err) {
    return next(err);
  }
};

exports.getVulnerabilityScanConfigs = async (req, res) => {
  if (!isGreenboneEnabled()) {
    return res.status(503).json({ error: GREENBONE_DISABLED_MESSAGE });
  }

  try {
    const { configs, defaultScanConfigId } = await listGreenboneScanConfigs();
    return res.json({
      configs,
      default_scan_config_id: defaultScanConfigId,
    });
  } catch (error) {
    const mappedError = toControllerError(error, 'Unable to load vulnerability scan configurations');
    return res.status(mappedError.statusCode).json(mappedError.payload);
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
