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

function isGreenboneScanRecord(scan) {
  const scannerType = String(scan?.scanner_type || '').trim().toLowerCase();
  const scanType = String(scan?.scan_type || '').trim().toLowerCase();
  return scannerType === 'greenbone' || scanType === 'vulnerability';
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

async function findCompletedGreenboneScansForDeviceIp(ipAddress) {
  const safeIp = String(ipAddress || '').trim();

  if (!isValidIPv4(safeIp)) {
    return [];
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
    `,
    [safeIp],
  );

  return result.rows;
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

async function storeGreenboneReportData(
  scan,
  reportData,
  {
    replaceExisting = false,
    skipExistingScanCheck = false,
    dedupeKeys = null,
  } = {},
) {
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

    if (!replaceExisting && !skipExistingScanCheck && existingCountResult.rows[0].count > 0) {
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
    const seenVulnerabilityKeys = dedupeKeys instanceof Set ? dedupeKeys : new Set();

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

      const normalizedOid = String(vulnerability.nvt_oid || '').trim().toLowerCase();
      const normalizedName = String(vulnerability.name || '').trim().toLowerCase();
      const normalizedPort = Number.isInteger(vulnerability.port) ? vulnerability.port : 'none';
      const identityKey = normalizedOid || normalizedName || (cveList[0] || '').toLowerCase();

      if (!identityKey) {
        continue;
      }

      const vulnerabilityKey = [
        deviceId,
        identityKey,
        normalizedPort,
      ].join('|');

      if (seenVulnerabilityKeys.has(vulnerabilityKey)) {
        continue;
      }

      seenVulnerabilityKeys.add(vulnerabilityKey);

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
          String(vulnerability.name || '').trim() || (normalizedOid ? `NVT ${normalizedOid}` : null),
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
        v.id,
        v.device_id,
        v.scan_id,
        d.ip_address::text AS device_ip,
        COALESCE(NULLIF(d.display_name, ''), NULLIF(d.hostname, ''), d.ip_address::text) AS device_name,
        v.cve,
        v.cve_list,
        v.nvt_oid,
        v.name,
        v.severity,
        v.cvss_score,
        v.cvss_severity,
        v.qod,
        v.cvss_vector,
        v.solution,
        v.port,
        v.description,
        v.source,
        port_match.protocol AS port_protocol,
        port_match.state AS port_state,
        port_match.service AS port_service,
        port_match.version AS port_version
      FROM vulnerabilities v
      INNER JOIN devices d ON d.id = v.device_id
      LEFT JOIN LATERAL (
        SELECT p.protocol, p.state, p.service, p.version
        FROM ports p
        WHERE p.device_id = v.device_id
          AND v.port IS NOT NULL
          AND p.port = v.port
        ORDER BY
          CASE WHEN LOWER(COALESCE(p.state, '')) = 'open' THEN 0 ELSE 1 END,
          CASE WHEN LOWER(COALESCE(p.protocol, '')) = 'tcp' THEN 0 ELSE 1 END,
          p.id DESC
        LIMIT 1
      ) AS port_match ON TRUE
      WHERE v.scan_id = $1
      ORDER BY v.cvss_score DESC NULLS LAST, v.id DESC
    `,
    [scanId],
  );

  return vulnerabilityResult.rows;
}

async function getScanVulnerabilitiesLegacy(scanId) {
  const result = await query(
    `
      SELECT
        v.id,
        v.device_id,
        v.scan_id,
        d.ip_address::text AS device_ip,
        COALESCE(NULLIF(d.hostname, ''), d.ip_address::text) AS device_name,
        v.cve,
        ARRAY[]::text[] AS cve_list,
        NULL::text AS nvt_oid,
        v.name,
        v.severity,
        v.cvss_score,
        v.cvss_severity,
        NULL::double precision AS qod,
        NULL::text AS cvss_vector,
        NULL::text AS solution,
        v.port,
        v.description,
        v.source,
        NULL::text AS port_protocol,
        NULL::text AS port_state,
        NULL::text AS port_service,
        NULL::text AS port_version
      FROM vulnerabilities v
      INNER JOIN devices d ON d.id = v.device_id
      WHERE v.scan_id = $1
      ORDER BY v.cvss_score DESC NULLS LAST, v.id DESC
    `,
    [scanId],
  );

  return result.rows;
}

function buildTargetPredicate(target, columnRef, paramPosition = 1) {
  const safeTarget = normalizeTarget(target);

  if (isValidCidr(safeTarget)) {
    return {
      clause: `${columnRef} << $${paramPosition}::cidr`,
      params: [safeTarget],
    };
  }

  if (isValidIPv4(safeTarget)) {
    return {
      clause: `${columnRef} = $${paramPosition}::inet`,
      params: [safeTarget],
    };
  }

  return null;
}

function summarizeTopServices(portRows, limit = 8) {
  const counts = new Map();

  (Array.isArray(portRows) ? portRows : []).forEach((row) => {
    const key = String(row?.service || 'unknown').trim().toLowerCase() || 'unknown';
    counts.set(key, (counts.get(key) || 0) + 1);
  });

  return [...counts.entries()]
    .map(([service, count]) => ({ service, count }))
    .sort((left, right) => right.count - left.count || left.service.localeCompare(right.service))
    .slice(0, limit);
}

async function getNmapTargetDevices(scan, { enforceWindow = true } = {}) {
  const targetPredicate = buildTargetPredicate(scan.target, 'd.ip_address', 1);

  if (!targetPredicate) {
    return [];
  }

  const params = [...targetPredicate.params];
  let windowClause = '';

  if (enforceWindow && scan.started_at) {
    params.push(scan.started_at);
    params.push(scan.completed_at || new Date());
    windowClause = `AND d.last_seen >= $${params.length - 1} AND d.last_seen <= $${params.length}`;
  }

  const result = await query(
    `
      SELECT
        d.id,
        d.ip_address,
        d.display_name,
        d.hostname,
        d.os_guess,
        d.online_status,
        d.script_results,
        d.metadata,
        d.last_seen,
        COALESCE(COUNT(p.id) FILTER (WHERE p.state = 'open'), 0)::int AS open_ports,
        COALESCE(COUNT(p.id) FILTER (WHERE p.state = 'open' AND p.protocol = 'tcp'), 0)::int AS tcp_open_ports,
        COALESCE(COUNT(p.id) FILTER (WHERE p.state = 'open' AND p.protocol = 'udp'), 0)::int AS udp_open_ports
      FROM devices d
      LEFT JOIN ports p ON p.device_id = d.id
      WHERE ${targetPredicate.clause}
      ${windowClause}
      GROUP BY d.id
      ORDER BY open_ports DESC, d.last_seen DESC NULLS LAST, d.id ASC
    `,
    params,
  );

  return result.rows;
}

async function getNmapTargetOpenPorts(scan, { enforceWindow = true, limit = 500 } = {}) {
  const targetPredicate = buildTargetPredicate(scan.target, 'd.ip_address', 1);

  if (!targetPredicate) {
    return [];
  }

  const params = [...targetPredicate.params];
  let windowClause = '';

  if (enforceWindow && scan.started_at) {
    params.push(scan.started_at);
    params.push(scan.completed_at || new Date());
    windowClause = `AND d.last_seen >= $${params.length - 1} AND d.last_seen <= $${params.length}`;
  }

  params.push(limit);

  const result = await query(
    `
      SELECT
        p.id,
        p.device_id,
        d.ip_address,
        COALESCE(NULLIF(d.display_name, ''), NULLIF(d.hostname, ''), d.ip_address::text) AS device_name,
        p.port,
        p.protocol,
        p.service,
        p.version,
        p.state,
        p.script_results,
        p.metadata,
        p.last_source,
        p.source_confidence
      FROM ports p
      INNER JOIN devices d ON d.id = p.device_id
      WHERE ${targetPredicate.clause}
        ${windowClause}
      ORDER BY
        d.ip_address ASC,
        CASE WHEN LOWER(COALESCE(p.state, '')) = 'open' THEN 0 ELSE 1 END,
        p.port ASC,
        p.protocol ASC
      LIMIT $${params.length}
    `,
    params,
  );

  return result.rows;
}

async function buildNmapSummary(scan) {
  const hasWindow = Boolean(scan.started_at);
  let scope = hasWindow ? 'scan_window' : 'target_snapshot';

  let discoveredDevices = await getNmapTargetDevices(scan, { enforceWindow: hasWindow });
  let observedPorts = await getNmapTargetOpenPorts(scan, { enforceWindow: hasWindow });

  if (hasWindow && discoveredDevices.length === 0 && observedPorts.length === 0) {
    discoveredDevices = await getNmapTargetDevices(scan, { enforceWindow: false });
    observedPorts = await getNmapTargetOpenPorts(scan, { enforceWindow: false });
    scope = 'target_snapshot';
  }

  const openPorts = observedPorts.filter((row) => String(row.state || '').toLowerCase() === 'open');

  return {
    summary: {
      hosts_up: discoveredDevices.length,
      ports_observed: observedPorts.length,
      tcp_open_ports: openPorts.filter((row) => String(row.protocol || '').toLowerCase() === 'tcp').length,
      udp_open_ports: openPorts.filter((row) => String(row.protocol || '').toLowerCase() === 'udp').length,
      top_services: summarizeTopServices(openPorts),
      scope,
      scope_note: scope === 'scan_window'
        ? 'Derived from device updates captured during this scan window.'
        : 'No device updates were recorded in the scan window; showing latest target snapshot.',
    },
    discovered_devices: discoveredDevices,
    open_ports: observedPorts,
  };
}

async function getGreenboneAffectedDevices(scanId) {
  const result = await query(
    `
      SELECT
        d.id,
        d.ip_address,
        d.display_name,
        d.hostname,
        d.os_guess,
        COUNT(v.id)::int AS findings_total,
        COUNT(v.id) FILTER (
          WHERE (
            LOWER(COALESCE(v.cvss_severity, v.severity, '')) IN ('log', 'info', 'informational', 'none')
            OR COALESCE(v.cvss_score, 0) <= 0
          )
        )::int AS informational_count,
        COUNT(v.id) FILTER (
          WHERE NOT (
            LOWER(COALESCE(v.cvss_severity, v.severity, '')) IN ('log', 'info', 'informational', 'none')
            OR COALESCE(v.cvss_score, 0) <= 0
          )
        )::int AS actionable_count,
        COUNT(v.id) FILTER (WHERE LOWER(COALESCE(v.cvss_severity, v.severity, '')) = 'critical')::int AS critical_count,
        COUNT(v.id) FILTER (WHERE LOWER(COALESCE(v.cvss_severity, v.severity, '')) = 'high')::int AS high_count
      FROM vulnerabilities v
      INNER JOIN devices d ON d.id = v.device_id
      WHERE v.scan_id = $1
      GROUP BY d.id
      ORDER BY findings_total DESC, d.id ASC
    `,
    [scanId],
  );

  return result.rows;
}

async function getGreenboneAffectedDevicesLegacy(scanId) {
  const result = await query(
    `
      SELECT
        d.id,
        d.ip_address,
        NULL::text AS display_name,
        d.hostname,
        d.os_guess,
        COUNT(v.id)::int AS findings_total,
        0::int AS informational_count,
        COUNT(v.id)::int AS actionable_count,
        COUNT(v.id) FILTER (WHERE LOWER(COALESCE(v.cvss_severity, v.severity, '')) = 'critical')::int AS critical_count,
        COUNT(v.id) FILTER (WHERE LOWER(COALESCE(v.cvss_severity, v.severity, '')) = 'high')::int AS high_count
      FROM vulnerabilities v
      INNER JOIN devices d ON d.id = v.device_id
      WHERE v.scan_id = $1
      GROUP BY d.id
      ORDER BY findings_total DESC, d.id ASC
    `,
    [scanId],
  );

  return result.rows;
}

async function buildGreenboneSummary(scan) {
  const summaryResult = await query(
    `
      WITH vuln AS (
        SELECT
          device_id,
          port,
          nvt_oid,
          name,
          cvss_score,
          qod,
          cve,
          cve_list,
          LOWER(COALESCE(cvss_severity, severity, '')) AS normalized_severity
        FROM vulnerabilities
        WHERE scan_id = $1
      ),
      cve_tokens AS (
        SELECT UNNEST(COALESCE(v.cve_list, ARRAY[]::text[])) AS token
        FROM vuln v
        UNION ALL
        SELECT v.cve AS token
        FROM vuln v
        WHERE v.cve IS NOT NULL
      )
      SELECT
        COUNT(*)::int AS vulnerabilities_total,
        COUNT(*) FILTER (
          WHERE (
            normalized_severity IN ('log', 'info', 'informational', 'none')
            OR COALESCE(cvss_score, 0) <= 0
          )
        )::int AS informational_count,
        COUNT(*) FILTER (
          WHERE NOT (
            normalized_severity IN ('log', 'info', 'informational', 'none')
            OR COALESCE(cvss_score, 0) <= 0
          )
        )::int AS actionable_count,
        COUNT(*) FILTER (WHERE normalized_severity = 'critical')::int AS critical_count,
        COUNT(*) FILTER (WHERE normalized_severity = 'high')::int AS high_count,
        COUNT(*) FILTER (WHERE normalized_severity = 'medium')::int AS medium_count,
        COUNT(*) FILTER (WHERE normalized_severity = 'low')::int AS low_count,
        COUNT(*) FILTER (WHERE normalized_severity IN ('log', 'info', 'informational', 'none'))::int AS log_count,
        COUNT(DISTINCT device_id)::int AS affected_devices,
        COUNT(DISTINCT port) FILTER (WHERE port IS NOT NULL)::int AS affected_ports,
        COUNT(DISTINCT COALESCE(NULLIF(nvt_oid, ''), LOWER(name)))::int AS unique_findings,
        (
          SELECT COUNT(DISTINCT UPPER(TRIM(token)))::int
          FROM cve_tokens
          WHERE token ~* '^CVE-\\d{4}-\\d{4,}$'
        ) AS unique_cves,
        ROUND(AVG(qod) FILTER (WHERE qod IS NOT NULL) * 100, 1) AS avg_qod_percent
      FROM vuln
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
    log_count: row.log_count,
    actionable_count: row.actionable_count,
    informational_count: row.informational_count,
    affected_devices: row.affected_devices,
    affected_ports: row.affected_ports,
    unique_findings: row.unique_findings,
    unique_cves: row.unique_cves,
    avg_qod_percent: Number.isFinite(Number.parseFloat(row.avg_qod_percent))
      ? Number.parseFloat(row.avg_qod_percent)
      : null,
  };
}

async function buildGreenboneSummaryLegacy(scan) {
  const result = await query(
    `
      SELECT
        COUNT(*)::int AS vulnerabilities_total,
        COUNT(*) FILTER (WHERE LOWER(COALESCE(cvss_severity, severity, '')) = 'critical')::int AS critical_count,
        COUNT(*) FILTER (WHERE LOWER(COALESCE(cvss_severity, severity, '')) = 'high')::int AS high_count,
        COUNT(*) FILTER (WHERE LOWER(COALESCE(cvss_severity, severity, '')) = 'medium')::int AS medium_count,
        COUNT(*) FILTER (WHERE LOWER(COALESCE(cvss_severity, severity, '')) = 'low')::int AS low_count,
        COUNT(*) FILTER (WHERE LOWER(COALESCE(cvss_severity, severity, '')) IN ('log', 'info', 'informational', 'none'))::int AS log_count,
        COUNT(DISTINCT device_id)::int AS affected_devices
      FROM vulnerabilities
      WHERE scan_id = $1
    `,
    [scan.id],
  );

  const row = result.rows[0] || {};

  return {
    vulnerabilities_total: Number(row.vulnerabilities_total || 0),
    critical_count: Number(row.critical_count || 0),
    high_count: Number(row.high_count || 0),
    medium_count: Number(row.medium_count || 0),
    low_count: Number(row.low_count || 0),
    log_count: Number(row.log_count || 0),
    actionable_count: Number(row.vulnerabilities_total || 0) - Number(row.log_count || 0),
    informational_count: Number(row.log_count || 0),
    affected_devices: Number(row.affected_devices || 0),
    affected_ports: 0,
    unique_findings: 0,
    unique_cves: 0,
    avg_qod_percent: null,
  };
}

async function syncGreenboneScan(scan) {
  if (!isGreenboneScanRecord(scan)) {
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
        (scan) => isGreenboneScanRecord(scan) && !isTerminalStatus(scan.status),
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
    const refreshMode = String(req.body?.mode || 'selected').trim().toLowerCase();

    if (refreshMode !== 'selected' && refreshMode !== 'all') {
      return res.status(400).json({ error: 'mode must be selected or all' });
    }

    const pullAllScans = refreshMode === 'all';
    let selectedScans = [];

    if (pullAllScans) {
      const scans = await findCompletedGreenboneScansForDeviceIp(device.ip_address);

      if (scans.length === 0) {
        return res.status(404).json({
          error: 'No completed vulnerability scan history found for this device',
        });
      }

      selectedScans = [...scans].sort((left, right) => {
        const leftTime = left.completed_at ? new Date(left.completed_at).getTime() : 0;
        const rightTime = right.completed_at ? new Date(right.completed_at).getTime() : 0;
        return rightTime - leftTime || right.id - left.id;
      });
    } else {
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

      selectedScans = [scan];
    }

    try {
      await query(
        `
          DELETE FROM vulnerabilities
          WHERE device_id = $1
        `,
        [deviceId],
      );

      let insertedTotal = 0;
      const importedReports = [];
      const dedupeKeys = new Set();

      for (let index = 0; index < selectedScans.length; index += 1) {
        const scan = selectedScans[index];
        const reportData = await fetchAndParseReport(scan.external_task_id, null);
        const inserted = await storeGreenboneReportData(scan, reportData, {
          replaceExisting: index === 0,
          skipExistingScanCheck: true,
          dedupeKeys,
        });

        insertedTotal += inserted;
        importedReports.push({
          scan_id: scan.id,
          external_task_id: scan.external_task_id,
          report_id: reportData.reportId,
          completed_at: scan.completed_at,
          vulnerabilities_imported: inserted,
        });
      }

      const latest = selectedScans[0];

      return res.json({
        refreshed: true,
        mode: pullAllScans ? 'all' : 'selected',
        device_id: deviceId,
        scan_id: latest.id,
        external_task_id: latest.external_task_id,
        report_id: importedReports[importedReports.length - 1]?.report_id || null,
        completed_at: latest.completed_at || null,
        vulnerabilities_imported: insertedTotal,
        reports_imported: importedReports,
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
    let discoveredDevices = [];
    let nmapOpenPorts = [];

    if (isGreenboneScanRecord(scan)) {
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

      try {
        summary = await buildGreenboneSummary(scan);
      } catch (error) {
        console.error(`Failed to build enriched Greenbone summary for scan ${scan.id}`, error);
        summary = await buildGreenboneSummaryLegacy(scan);
      }

      try {
        vulnerabilities = await getScanVulnerabilities(scan.id);
      } catch (error) {
        console.error(`Failed to load enriched vulnerabilities for scan ${scan.id}`, error);
        vulnerabilities = await getScanVulnerabilitiesLegacy(scan.id);
      }

      try {
        discoveredDevices = await getGreenboneAffectedDevices(scan.id);
      } catch (error) {
        console.error(`Failed to load enriched affected devices for scan ${scan.id}`, error);
        discoveredDevices = await getGreenboneAffectedDevicesLegacy(scan.id);
      }
    } else {
      const nmapResult = await buildNmapSummary(scan);
      summary = nmapResult.summary;
      discoveredDevices = nmapResult.discovered_devices;
      nmapOpenPorts = nmapResult.open_ports;
    }

    const resolvedScannerType = isGreenboneScanRecord(scan) ? 'greenbone' : 'nmap';

    return res.json({
      ...scan,
      scanner_type: resolvedScannerType,
      summary,
      vulnerabilities,
      discovered_devices: discoveredDevices,
      nmap_open_ports: nmapOpenPorts,
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
