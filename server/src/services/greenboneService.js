const net = require('net');
const tls = require('tls');
const { parseStringPromise } = require('xml2js');
const { mergeJsonValues } = require('./dataReconciliation');

class GreenboneServiceError extends Error {
  constructor(message, { statusCode = 502, code = 'GREENBONE_ERROR', details = null } = {}) {
    super(message);
    this.name = 'GreenboneServiceError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

function isGreenboneEnabled() {
  return (process.env.GREENBONE_ENABLED || 'false').toLowerCase() === 'true';
}

function ensureEnabled() {
  if (!isGreenboneEnabled()) {
    throw new GreenboneServiceError('Vulnerability scanner not enabled', {
      statusCode: 503,
      code: 'GREENBONE_DISABLED',
    });
  }
}

function getConfig() {
  const socketPath = String(process.env.GREENBONE_SOCKET_PATH || '').trim();
  const envMaxChecks = Number.parseInt(String(process.env.GREENBONE_MAX_CHECKS || '').trim(), 10);
  const envMaxHosts = Number.parseInt(String(process.env.GREENBONE_MAX_HOSTS || '').trim(), 10);

  return {
    host: process.env.GREENBONE_HOST || 'greenbone',
    port: Number(process.env.GREENBONE_PORT || 9390),
    username: process.env.GREENBONE_USERNAME || 'admin',
    password: process.env.GREENBONE_PASSWORD || 'admin',
    socketPath: socketPath || null,
    useTls: !socketPath && (process.env.GREENBONE_TLS || 'true').toLowerCase() !== 'false',
    timeoutMs: Number(process.env.GREENBONE_TIMEOUT_MS || 20_000),
    // Default to full TCP only. Full UDP adds very long runtime and is rarely needed for routine scans.
    portRange: process.env.GREENBONE_PORT_RANGE || 'T:1-65535',
    scanConfigId: process.env.GREENBONE_SCAN_CONFIG_ID || 'daba56c8-73ec-11df-a475-002264764cea',
    scannerId: process.env.GREENBONE_SCANNER_ID || '08b69003-5fc2-4037-a479-93b440211c73',
    maxChecks: Number.isInteger(envMaxChecks) && envMaxChecks > 0 ? envMaxChecks : null,
    maxHosts: Number.isInteger(envMaxHosts) && envMaxHosts > 0 ? envMaxHosts : null,
  };
}

function toArray(value) {
  if (!value) {
    return [];
  }

  return Array.isArray(value) ? value : [value];
}

function xmlEscape(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function extractText(node) {
  if (node === null || node === undefined) {
    return '';
  }

  if (typeof node === 'string' || typeof node === 'number' || typeof node === 'boolean') {
    return String(node);
  }

  if (Array.isArray(node)) {
    return extractText(node[0]);
  }

  if (typeof node === 'object') {
    if (typeof node._ === 'string') {
      return node._;
    }

    const values = Object.values(node);

    for (const value of values) {
      const text = extractText(value);

      if (text) {
        return text;
      }
    }
  }

  return '';
}

function normalizeSeverityLabel(value) {
  const normalized = String(value || '').trim().toLowerCase();

  if (!normalized) {
    return null;
  }

  if (normalized.includes('critical')) {
    return 'Critical';
  }

  if (normalized.includes('high')) {
    return 'High';
  }

  if (normalized.includes('medium')) {
    return 'Medium';
  }

  if (normalized.includes('low')) {
    return 'Low';
  }

  if (normalized.includes('log') || normalized.includes('none')) {
    return 'Low';
  }

  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function severityFromScore(score) {
  if (!Number.isFinite(score)) {
    return null;
  }

  if (score >= 9) {
    return 'Critical';
  }

  if (score >= 7) {
    return 'High';
  }

  if (score >= 4) {
    return 'Medium';
  }

  return 'Low';
}

function normalizeText(value) {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function parsePort(portText) {
  const match = String(portText || '').match(/(\d{1,5})/);

  if (!match) {
    return null;
  }

  const port = Number(match[1]);

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return null;
  }

  return port;
}

function parsePortDescriptor(portText) {
  const raw = String(portText || '').trim();

  if (!raw) {
    return {
      port: null,
      protocol: null,
      service: null,
      raw: '',
    };
  }

  const detailedMatch = raw.match(/(\d{1,5})\/([a-zA-Z]+)/);
  const port = detailedMatch ? Number(detailedMatch[1]) : parsePort(raw);
  const protocol = detailedMatch ? detailedMatch[2].toLowerCase() : null;
  const serviceHint = raw.match(/\((?:[^:]+:\s*)?([^)]+)\)/);
  const service = normalizeText(serviceHint?.[1]);

  return {
    port: Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null,
    protocol,
    service,
    raw,
  };
}

function parseCvssScore(...values) {
  for (const value of values) {
    const numeric = Number.parseFloat(String(value || '').trim());

    if (Number.isFinite(numeric)) {
      return numeric;
    }
  }

  return null;
}

function parseCveList(value) {
  const raw = String(value || '').trim();

  if (!raw || raw.toLowerCase() === 'nocve') {
    return [];
  }

  const deduped = [...new Set(
    raw
    .split(/[,\s;]+/)
    .map((entry) => entry.trim())
    .filter((entry) => /^CVE-\d{4}-\d{4,}$/i.test(entry))
    .map((entry) => entry.toUpperCase()),
  )];

  return deduped;
}

function parseCve(value) {
  return parseCveList(value)[0] || null;
}

function parseDateValue(value) {
  const normalized = normalizeText(value);

  if (!normalized) {
    return null;
  }

  const parsed = Date.parse(normalized);

  if (Number.isNaN(parsed)) {
    return null;
  }

  return new Date(parsed).toISOString();
}

function extractIpv4Candidate(value) {
  const match = String(value || '').match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  return match ? match[0] : null;
}

function summarizeText(value, maxLength = 800) {
  const normalized = String(value || '').trim();

  if (!normalized) {
    return '';
  }

  if (normalized.length <= maxLength) {
    return normalized;
  }

  return `${normalized.slice(0, maxLength)}...`;
}

function parseLabelValuePairs(value) {
  const text = String(value || '');
  const pairs = {};

  text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .forEach((line) => {
      const match = line.match(/^([^:]{2,120}):\s*(.+)$/);

      if (!match) {
        return;
      }

      const key = match[1]
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '');
      const parsedValue = match[2].trim();

      if (!key || !parsedValue || Object.prototype.hasOwnProperty.call(pairs, key)) {
        return;
      }

      pairs[key] = parsedValue;
    });

  return pairs;
}

function looksLikeTlsContext(...values) {
  const text = values
    .map((value) => String(value || '').toLowerCase())
    .join(' ');

  return /(tls|ssl|certificate|x\.509|x509)/i.test(text);
}

function looksLikeSshKeyContext(...values) {
  const text = values
    .map((value) => String(value || '').toLowerCase())
    .join(' ');

  return /(ssh|host key|public key|ssh-rsa|ssh-ed25519|ecdsa-sha2)/i.test(text);
}

function parseCertificateFromText(value) {
  const text = summarizeText(value, 4_000);

  if (!text || !looksLikeTlsContext(text)) {
    return null;
  }

  const pairs = parseLabelValuePairs(text);
  const subject = normalizeText(
    pairs.subject
    || pairs.subject_dn
    || pairs.subjectdistinguishedname
    || pairs.common_name
    || pairs.cn,
  );
  const issuer = normalizeText(
    pairs.issuer
    || pairs.issuer_dn
    || pairs.issuerdistinguishedname,
  );
  const serialNumber = normalizeText(
    pairs.serial
    || pairs.serial_number
    || pairs.serialnumber,
  );
  const fingerprintMatch = text.match(
    /(?:sha-?256[^:\n]*fingerprint|fingerprint[^:\n]*sha-?256)\s*:\s*([A-F0-9:]{32,}|SHA256:[A-Za-z0-9+/=]+)/i,
  ) || text.match(/(SHA256:[A-Za-z0-9+/=]{20,}|(?:[A-F0-9]{2}:){15,}[A-F0-9]{2})/i);

  const fingerprintSha256 = normalizeText(
    pairs.sha_256_fingerprint
    || pairs.sha256_fingerprint
    || pairs.fingerprint_sha_256
    || fingerprintMatch?.[1],
  );
  const notBefore = parseDateValue(
    pairs.not_before
    || pairs.valid_from
    || pairs.validity_not_before,
  );
  const notAfter = parseDateValue(
    pairs.not_after
    || pairs.valid_to
    || pairs.validity_not_after
    || pairs.expiration_date,
  );

  const hasSignal = subject || issuer || serialNumber || fingerprintSha256 || notBefore || notAfter;

  if (!hasSignal) {
    return null;
  }

  return {
    subject,
    issuer,
    serial_number: serialNumber,
    fingerprint_sha256: fingerprintSha256,
    not_before: notBefore,
    not_after: notAfter,
    raw_text: text,
    metadata: {
      parser: 'greenbone_report',
      fields: pairs,
    },
  };
}

function parseSshKeyFromText(value) {
  const text = summarizeText(value, 4_000);

  if (!text || !looksLikeSshKeyContext(text)) {
    return null;
  }

  const pairs = parseLabelValuePairs(text);
  const keyTypeMatch = text.match(/\b(ssh-(?:rsa|dss|ed25519)|ecdsa-[^\s:]+)\b/i);
  const fingerprintMatch = text.match(
    /(?:fingerprint|sha256)\s*:\s*([A-F0-9:]{16,}|SHA256:[A-Za-z0-9+/=]+)/i,
  ) || text.match(/(SHA256:[A-Za-z0-9+/=]{20,}|(?:[A-F0-9]{2}:){15,}[A-F0-9]{2})/i);
  const keyBitsRaw = Number.parseInt(
    pairs.key_bits
    || pairs.bits
    || pairs.key_size
    || '',
    10,
  );
  const keyBits = Number.isInteger(keyBitsRaw) && keyBitsRaw > 0 ? keyBitsRaw : null;
  const keyType = normalizeText(
    pairs.key_type
    || pairs.algorithm
    || keyTypeMatch?.[1],
  );
  const fingerprint = normalizeText(
    pairs.fingerprint
    || pairs.sha256_fingerprint
    || fingerprintMatch?.[1],
  );

  if (!keyType && !fingerprint && !keyBits) {
    return null;
  }

  return {
    key_type: keyType,
    fingerprint,
    key_bits: keyBits,
    raw_text: text,
    metadata: {
      parser: 'greenbone_report',
      fields: pairs,
    },
  };
}

function extractOsCandidate(...values) {
  const text = values
    .map((value) => String(value || '').trim())
    .filter(Boolean)
    .join('\n');

  if (!text) {
    return null;
  }

  const pairs = parseLabelValuePairs(text);
  const explicit = normalizeText(
    pairs.best_os_cpe
    || pairs.operating_system
    || pairs.remote_operating_system
    || pairs.os
    || pairs.cpe,
  );

  if (explicit && !/unknown|not available|could not/i.test(explicit)) {
    return explicit;
  }

  const cpeMatch = text.match(/\b(cpe:\/[a-z]:[^\s,;]+)/i);

  if (cpeMatch) {
    return cpeMatch[1];
  }

  const lineMatch = text.match(/(?:operating system|remote os|os guess)\s*(?:is|:)\s*([^\n]+)/i);

  if (!lineMatch) {
    return null;
  }

  const candidate = normalizeText(lineMatch[1]);

  if (!candidate || /unknown|not available|could not/i.test(candidate)) {
    return null;
  }

  return candidate;
}

function isInformationalFinding(threatValue, scoreValue) {
  const threat = String(threatValue || '').toLowerCase();

  if (threat.includes('log') || threat.includes('none') || threat.includes('info')) {
    return true;
  }

  return Number.isFinite(scoreValue) && scoreValue <= 0;
}

function parseTaskConcurrencyValue(value) {
  if (value === null || value === undefined || value === '') {
    return null;
  }

  const parsed = Number.parseInt(String(value).trim(), 10);

  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 64) {
    return null;
  }

  return parsed;
}

function buildTaskPreferencesXml(maxChecks, maxHosts) {
  const preferences = [];

  if (Number.isInteger(maxChecks) && maxChecks > 0) {
    preferences.push(`
      <preference>
        <scanner_name>max_checks</scanner_name>
        <value>${xmlEscape(maxChecks)}</value>
      </preference>
    `);
  }

  if (Number.isInteger(maxHosts) && maxHosts > 0) {
    preferences.push(`
      <preference>
        <scanner_name>max_hosts</scanner_name>
        <value>${xmlEscape(maxHosts)}</value>
      </preference>
    `);
  }

  if (preferences.length === 0) {
    return '';
  }

  return `
    <preferences>
      ${preferences.join('\n')}
    </preferences>
  `;
}

function isValidPortToken(token) {
  const trimmed = String(token || '').trim();

  if (!trimmed) {
    return false;
  }

  const singleMatch = trimmed.match(/^(\d{1,5})$/);

  if (singleMatch) {
    const port = Number(singleMatch[1]);
    return Number.isInteger(port) && port >= 1 && port <= 65535;
  }

  const rangeMatch = trimmed.match(/^(\d{1,5})-(\d{1,5})$/);

  if (!rangeMatch) {
    return false;
  }

  const start = Number(rangeMatch[1]);
  const end = Number(rangeMatch[2]);

  return Number.isInteger(start)
    && Number.isInteger(end)
    && start >= 1
    && end >= 1
    && start <= 65535
    && end <= 65535
    && start <= end;
}

function isValidGreenbonePortRange(value) {
  const normalized = String(value || '').trim();

  if (!normalized) {
    return false;
  }

  const normalizedUpper = normalized.toUpperCase();
  const sections = [];
  let cursor = 0;

  while (cursor < normalized.length) {
    const protocol = normalizedUpper[cursor];

    if ((protocol !== 'T' && protocol !== 'U') || normalized[cursor + 1] !== ':') {
      return false;
    }

    const valueStart = cursor + 2;
    const nextTcp = normalizedUpper.indexOf(',T:', valueStart);
    const nextUdp = normalizedUpper.indexOf(',U:', valueStart);
    const sectionEndCandidates = [nextTcp, nextUdp].filter((index) => index >= 0);
    const sectionEnd = sectionEndCandidates.length > 0
      ? Math.min(...sectionEndCandidates)
      : normalized.length;

    const sectionValue = normalized.slice(valueStart, sectionEnd).trim();

    if (!sectionValue) {
      return false;
    }

    sections.push({
      protocol,
      value: sectionValue,
    });

    if (sectionEnd >= normalized.length) {
      break;
    }

    cursor = sectionEnd + 1;
  }

  if (sections.length === 0 || sections.length > 2) {
    return false;
  }

  const seenProtocols = new Set();

  for (const section of sections) {
    const list = section.value
      .split(',')
      .map((token) => token.trim())
      .filter(Boolean);

    if (seenProtocols.has(section.protocol) || list.length === 0) {
      return false;
    }

    seenProtocols.add(section.protocol);

    if (!list.every(isValidPortToken)) {
      return false;
    }
  }

  return seenProtocols.size > 0;
}

function collectNodesByKey(node, key, bucket = []) {
  if (!node || typeof node !== 'object') {
    return bucket;
  }

  if (Object.prototype.hasOwnProperty.call(node, key)) {
    toArray(node[key]).forEach((entry) => {
      if (entry && typeof entry === 'object') {
        bucket.push(entry);
      }
    });
  }

  Object.values(node).forEach((value) => {
    if (Array.isArray(value)) {
      value.forEach((entry) => collectNodesByKey(entry, key, bucket));
      return;
    }

    if (value && typeof value === 'object') {
      collectNodesByKey(value, key, bucket);
    }
  });

  return bucket;
}

function normalizeName(value) {
  return String(value || '').trim().toLowerCase();
}

const PRIMARY_SCAN_CONFIG_ORDER = [
  'full and fast',
  'discovery',
  'host discovery',
  'system discovery',
];

function normalizeScanConfigEntries(configNodes) {
  const seen = new Set();
  const entries = [];

  configNodes.forEach((configNode) => {
    const id = configNode?.$?.id || null;

    if (!id || seen.has(id)) {
      return;
    }

    seen.add(id);
    entries.push({
      id,
      name: extractText(configNode?.name) || id,
      comment: extractText(configNode?.comment) || '',
    });
  });

  return entries.sort((left, right) => normalizeName(left.name).localeCompare(normalizeName(right.name)));
}

function selectPrimaryScanConfigs(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return [];
  }

  const byName = new Map();

  entries.forEach((entry) => {
    const key = normalizeName(entry.name);

    if (!byName.has(key)) {
      byName.set(key, entry);
    }
  });

  const primary = PRIMARY_SCAN_CONFIG_ORDER
    .map((name) => byName.get(name))
    .filter(Boolean);

  return primary.length > 0 ? primary : entries;
}

function selectScanConfigId(entries, requestedId) {
  if (requestedId) {
    const requested = entries.find((entry) => entry.id === requestedId);

    if (requested) {
      return requested.id;
    }
  }

  const preferredNames = [
    'full and fast',
    'system discovery',
    'host discovery',
    'discovery',
    'base',
  ];

  for (const preferredName of preferredNames) {
    const found = entries.find((entry) => normalizeName(entry.name) === preferredName);

    if (found) {
      return found.id;
    }
  }

  return entries[0]?.id || null;
}

async function fetchScanConfigEntries(socket) {
  const response = await sendGmpCommand(
    socket,
    '<get_configs details="1" ignore_pagination="1" />',
  );

  const configs = collectNodesByKey(response.rootNode, 'config', []);
  return normalizeScanConfigEntries(configs);
}

async function resolveScanConfigId(socket, requestedId) {
  const entries = await fetchScanConfigEntries(socket);

  if (entries.length === 0) {
    throw new GreenboneServiceError('No scan configurations are available in the vulnerability manager', {
      statusCode: 502,
      code: 'GREENBONE_CONFIG_NOT_FOUND',
    });
  }

  return selectScanConfigId(entries, requestedId);
}

async function resolveScannerId(socket, requestedId) {
  const response = await sendGmpCommand(
    socket,
    '<get_scanners details="0" ignore_pagination="1" />',
  );

  const scanners = collectNodesByKey(response.rootNode, 'scanner', []);
  const entries = scanners
    .map((scannerNode) => ({
      id: scannerNode?.$?.id || null,
      name: extractText(scannerNode?.name),
    }))
    .filter((entry) => entry.id);

  if (entries.length === 0) {
    throw new GreenboneServiceError('No scanners are available in the vulnerability manager', {
      statusCode: 502,
      code: 'GREENBONE_SCANNER_NOT_FOUND',
    });
  }

  if (requestedId) {
    const requested = entries.find((entry) => entry.id === requestedId);

    if (requested) {
      return requested.id;
    }
  }

  const openvasScanner = entries.find((entry) => normalizeName(entry.name).includes('openvas'));

  if (openvasScanner) {
    return openvasScanner.id;
  }

  return entries[0].id;
}

function mapTaskStatus(statusText) {
  const normalized = String(statusText || '').toLowerCase();

  if (normalized.includes('done') || normalized.includes('completed') || normalized.includes('finished')) {
    return 'completed';
  }

  if (
    normalized.includes('stop')
    || normalized.includes('interrupted')
    || normalized.includes('error')
    || normalized.includes('failed')
  ) {
    return 'failed';
  }

  if (normalized.includes('queued') || normalized.includes('requested') || normalized.includes('new')) {
    return 'queued';
  }

  return 'running';
}

async function parseXml(xml) {
  try {
    const parsed = await parseStringPromise(xml, { explicitArray: false });
    return parsed;
  } catch (error) {
    throw new GreenboneServiceError('Invalid response from vulnerability scanner', {
      statusCode: 502,
      code: 'GREENBONE_INVALID_XML',
      details: error.message,
    });
  }
}

function getRootNode(parsed) {
  const rootName = Object.keys(parsed || {})[0];

  if (!rootName) {
    throw new GreenboneServiceError('Unexpected vulnerability scanner response', {
      statusCode: 502,
      code: 'GREENBONE_EMPTY_RESPONSE',
    });
  }

  return { rootName, rootNode: parsed[rootName] };
}

function ensureSuccessResponse(rootName, rootNode) {
  const statusRaw = rootNode?.$?.status;

  if (!statusRaw) {
    return;
  }

  const statusNum = Number(statusRaw);

  if (!Number.isFinite(statusNum) || statusNum < 400) {
    return;
  }

  throw new GreenboneServiceError(rootNode?.$?.status_text || `Greenbone command failed (${rootName})`, {
    statusCode: 502,
    code: 'GREENBONE_GMP_ERROR',
    details: {
      response: rootName,
      status: statusNum,
      status_text: rootNode?.$?.status_text || null,
    },
  });
}

function connectSocket(config) {
  return new Promise((resolve, reject) => {
    const socket = config.socketPath
      ? net.connect({ path: config.socketPath })
      : config.useTls
        ? tls.connect({
          host: config.host,
          port: config.port,
          rejectUnauthorized: false,
        })
        : net.connect({
          host: config.host,
          port: config.port,
        });

    const onError = (error) => {
      socket.destroy();
      reject(new GreenboneServiceError('Unable to connect to vulnerability scanner', {
        statusCode: 502,
        code: 'GREENBONE_CONNECTION_FAILED',
        details: error.message,
      }));
    };

    socket.setTimeout(config.timeoutMs, () => {
      socket.destroy();
      reject(new GreenboneServiceError('Vulnerability scanner connection timed out', {
        statusCode: 504,
        code: 'GREENBONE_TIMEOUT',
      }));
    });

    socket.once('error', onError);

    const readyEvent = config.socketPath || !config.useTls ? 'connect' : 'secureConnect';

    socket.once(readyEvent, () => {
      socket.removeListener('error', onError);
      resolve(socket);
    });
  });
}

async function sendGmpCommand(socket, command) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    let settled = false;

    const cleanup = () => {
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
      socket.removeListener('timeout', onTimeout);
    };

    const resolveOnce = (value) => {
      if (settled) {
        return;
      }

      settled = true;
      cleanup();
      resolve(value);
    };

    const rejectOnce = (error) => {
      if (settled) {
        return;
      }

      settled = true;
      cleanup();
      reject(error);
    };

    const onError = (error) => {
      rejectOnce(new GreenboneServiceError('Vulnerability scanner connection failed', {
        statusCode: 502,
        code: 'GREENBONE_CONNECTION_FAILED',
        details: error.message,
      }));
    };

    const onTimeout = () => {
      rejectOnce(new GreenboneServiceError('Vulnerability scanner command timed out', {
        statusCode: 504,
        code: 'GREENBONE_TIMEOUT',
      }));
    };

    const parseBuffer = async (allowInvalidXml) => {
      const xml = String(buffer || '').replace(/\0/g, '').trim();

      if (!xml) {
        return false;
      }

      try {
        const parsed = await parseXml(xml);
        const { rootName, rootNode } = getRootNode(parsed);
        ensureSuccessResponse(rootName, rootNode);
        resolveOnce({
          xml,
          parsed,
          rootName,
          rootNode,
        });
        return true;
      } catch (error) {
        if (
          !allowInvalidXml
          && error instanceof GreenboneServiceError
          && error.code === 'GREENBONE_INVALID_XML'
        ) {
          return false;
        }

        rejectOnce(error);
        return true;
      }
    };

    const onClose = async () => {
      if (settled) {
        return;
      }

      const handled = await parseBuffer(true);

      if (handled || settled) {
        return;
      }

      rejectOnce(new GreenboneServiceError('Vulnerability scanner closed the connection', {
        statusCode: 502,
        code: 'GREENBONE_CONNECTION_CLOSED',
      }));
    };

    const onData = async (chunk) => {
      buffer += chunk.toString('utf8');

      if (buffer.includes('\0')) {
        await parseBuffer(true);
        return;
      }

      await parseBuffer(false);
    };

    socket.on('data', onData);
    socket.once('error', onError);
    socket.once('close', onClose);
    socket.once('timeout', onTimeout);

    socket.write(String(command || '').trim());
  });
}

async function withAuthenticatedSession(work) {
  ensureEnabled();

  const config = getConfig();
  const socket = await connectSocket(config);

  try {
    const authenticateCommand = `
      <authenticate>
        <credentials>
          <username>${xmlEscape(config.username)}</username>
          <password>${xmlEscape(config.password)}</password>
        </credentials>
      </authenticate>
    `;

    await sendGmpCommand(socket, authenticateCommand);
    return await work(socket, config);
  } finally {
    socket.end();
  }
}

async function listScanConfigs() {
  return withAuthenticatedSession(async (socket, config) => {
    const entries = selectPrimaryScanConfigs(await fetchScanConfigEntries(socket));

    return {
      configs: entries,
      defaultScanConfigId: selectScanConfigId(entries, config.scanConfigId),
    };
  });
}

function extractResponseId(response) {
  return response?.rootNode?.$?.id || null;
}

function findTaskNode(rootNode) {
  if (rootNode?.task) {
    return toArray(rootNode.task)[0] || null;
  }

  if (rootNode?.tasks?.task) {
    return toArray(rootNode.tasks.task)[0] || null;
  }

  return null;
}

function extractReportIdFromTask(taskNode) {
  if (!taskNode) {
    return null;
  }

  const reportNode = taskNode?.last_report?.report;

  if (!reportNode) {
    return null;
  }

  if (Array.isArray(reportNode)) {
    return reportNode[0]?.$?.id || extractText(reportNode[0]) || null;
  }

  return reportNode?.$?.id || extractText(reportNode) || null;
}

function collectResultNodes(node, bucket = []) {
  if (!node || typeof node !== 'object') {
    return bucket;
  }

  if (node.result) {
    toArray(node.result).forEach((entry) => {
      if (entry && typeof entry === 'object') {
        bucket.push(entry);
      }
    });
  }

  Object.values(node).forEach((value) => {
    if (Array.isArray(value)) {
      value.forEach((entry) => collectResultNodes(entry, bucket));
      return;
    }

    if (value && typeof value === 'object') {
      collectResultNodes(value, bucket);
    }
  });

  return bucket;
}

function normalizeDetailKey(value) {
  const normalized = String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');

  return normalized || 'detail';
}

function pickRicherText(left, right) {
  const leftText = normalizeText(left);
  const rightText = normalizeText(right);

  if (!leftText) {
    return rightText;
  }

  if (!rightText) {
    return leftText;
  }

  return rightText.length > leftText.length ? rightText : leftText;
}

function parseReportData(rootNode) {
  const results = collectResultNodes(rootNode, []);
  const vulnerabilities = [];
  const portObservations = new Map();
  const osDetections = new Map();
  const tlsCertificates = new Map();
  const sshHostKeys = new Map();
  const hostMetadata = new Map();

  const upsertHostMetadata = (host, metadataPatch) => {
    if (!host || !metadataPatch || typeof metadataPatch !== 'object') {
      return;
    }

    const existing = hostMetadata.get(host) || {};
    hostMetadata.set(host, mergeJsonValues(existing, metadataPatch));
  };

  const upsertPortObservation = ({
    host,
    port,
    protocol,
    service,
    version,
    metadata,
  }) => {
    if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
      return;
    }

    const normalizedProtocol = normalizeText(protocol)?.toLowerCase() || 'tcp';
    const key = `${host}|${port}|${normalizedProtocol}`;
    const current = portObservations.get(key) || {
      host,
      port,
      protocol: normalizedProtocol,
      state: 'open',
      service: null,
      version: null,
      source: 'greenbone',
      confidence: 0.95,
      metadata: {},
    };

    current.service = pickRicherText(current.service, service);
    current.version = pickRicherText(current.version, version);
    current.metadata = mergeJsonValues(current.metadata, metadata || {});

    if (Array.isArray(current.metadata.greenbone_findings) && current.metadata.greenbone_findings.length > 20) {
      current.metadata.greenbone_findings = current.metadata.greenbone_findings.slice(-20);
    }

    if (Array.isArray(current.metadata.tls_certificates) && current.metadata.tls_certificates.length > 20) {
      current.metadata.tls_certificates = current.metadata.tls_certificates.slice(-20);
    }

    if (Array.isArray(current.metadata.ssh_host_keys) && current.metadata.ssh_host_keys.length > 20) {
      current.metadata.ssh_host_keys = current.metadata.ssh_host_keys.slice(-20);
    }

    portObservations.set(key, current);
  };

  const upsertOsDetection = ({
    host,
    name,
    confidence = 0.95,
    evidence = null,
  }) => {
    if (!host) {
      return;
    }

    const osName = normalizeText(name);

    if (!osName) {
      return;
    }

    const key = `${host}|${osName.toLowerCase()}`;
    const normalizedConfidence = Number.isFinite(confidence)
      ? Math.max(0, Math.min(1, confidence))
      : 0.95;
    const existing = osDetections.get(key);

    if (!existing) {
      osDetections.set(key, {
        host,
        name: osName,
        source: 'greenbone',
        confidence: normalizedConfidence,
        evidence: evidence && typeof evidence === 'object' ? evidence : null,
      });
      return;
    }

    if (normalizedConfidence >= existing.confidence) {
      osDetections.set(key, {
        ...existing,
        confidence: normalizedConfidence,
        evidence: mergeJsonValues(existing.evidence, evidence),
      });
      return;
    }

    existing.evidence = mergeJsonValues(existing.evidence, evidence);
    osDetections.set(key, existing);
  };

  const upsertTlsCertificate = (entry) => {
    if (!entry?.host) {
      return;
    }

    const key = [
      entry.host,
      entry.port || 'none',
      entry.protocol || 'tcp',
      entry.fingerprint_sha256 || '',
      entry.serial_number || '',
      entry.subject || '',
    ]
      .map((part) => String(part || '').trim().toLowerCase())
      .join('|');
    const existing = tlsCertificates.get(key);

    if (!existing) {
      tlsCertificates.set(key, entry);
      return;
    }

    tlsCertificates.set(key, {
      ...existing,
      subject: pickRicherText(existing.subject, entry.subject),
      issuer: pickRicherText(existing.issuer, entry.issuer),
      serial_number: pickRicherText(existing.serial_number, entry.serial_number),
      fingerprint_sha256: pickRicherText(existing.fingerprint_sha256, entry.fingerprint_sha256),
      not_before: existing.not_before || entry.not_before || null,
      not_after: existing.not_after || entry.not_after || null,
      raw_text: pickRicherText(existing.raw_text, entry.raw_text),
      metadata: mergeJsonValues(existing.metadata, entry.metadata),
    });
  };

  const upsertSshHostKey = (entry) => {
    if (!entry?.host) {
      return;
    }

    const key = [
      entry.host,
      entry.port || 'none',
      entry.protocol || 'tcp',
      entry.fingerprint || '',
      entry.key_type || '',
    ]
      .map((part) => String(part || '').trim().toLowerCase())
      .join('|');
    const existing = sshHostKeys.get(key);

    if (!existing) {
      sshHostKeys.set(key, entry);
      return;
    }

    sshHostKeys.set(key, {
      ...existing,
      key_type: pickRicherText(existing.key_type, entry.key_type),
      fingerprint: pickRicherText(existing.fingerprint, entry.fingerprint),
      key_bits: existing.key_bits || entry.key_bits || null,
      raw_text: pickRicherText(existing.raw_text, entry.raw_text),
      metadata: mergeJsonValues(existing.metadata, entry.metadata),
    });
  };

  results.forEach((result) => {
    const hostText = extractText(result.host);
    const host = extractIpv4Candidate(hostText) || normalizeText(hostText);
    const portDescriptor = parsePortDescriptor(extractText(result.port));
    const cvssScore = parseCvssScore(
      extractText(result.severity),
      extractText(result.nvt?.cvss_base),
      extractText(result.cvss_base),
    );
    const threatText = extractText(result.threat)
      || extractText(result.cvss_severity)
      || extractText(result.nvt?.threat);
    const explicitSeverity = normalizeSeverityLabel(threatText);
    const cvssSeverity = explicitSeverity || severityFromScore(cvssScore);
    const name = extractText(result.name) || extractText(result.nvt?.name) || 'Unnamed vulnerability';
    const description = extractText(result.description) || extractText(result.nvt?.summary) || '';
    const nvtOid = normalizeText(result?.nvt?.$?.oid) || null;
    const cveList = parseCveList(
      [extractText(result.nvt?.cve), extractText(result.cve)]
        .filter(Boolean)
        .join(','),
    );
    const informational = isInformationalFinding(threatText, cvssScore);

    if (host && portDescriptor.port) {
      upsertPortObservation({
        host,
        port: portDescriptor.port,
        protocol: portDescriptor.protocol,
        service: portDescriptor.service,
        metadata: {
          greenbone_findings: [
            {
              name,
              threat: normalizeText(threatText),
              cvss_score: Number.isFinite(cvssScore) ? cvssScore : null,
              cves: cveList,
              description: summarizeText(description, 320),
            },
          ],
        },
      });
    }

    const osCandidate = extractOsCandidate(
      name,
      description,
      extractText(result.nvt?.tags),
      extractText(result.nvt?.summary),
    );

    if (host && osCandidate) {
      upsertOsDetection({
        host,
        name: osCandidate,
        confidence: informational ? 0.98 : 0.9,
        evidence: {
          finding_name: name,
          nvt_oid: nvtOid,
        },
      });
    }

    if (host && looksLikeTlsContext(name, description)) {
      const cert = parseCertificateFromText(`${name}\n${description}`);

      if (cert) {
        const certificateEntry = {
          ...cert,
          host,
          port: portDescriptor.port,
          protocol: portDescriptor.protocol || 'tcp',
          source: 'greenbone',
        };

        upsertTlsCertificate(certificateEntry);

        if (portDescriptor.port) {
          upsertPortObservation({
            host,
            port: portDescriptor.port,
            protocol: portDescriptor.protocol,
            metadata: {
              tls_certificates: [
                {
                  subject: certificateEntry.subject,
                  issuer: certificateEntry.issuer,
                  fingerprint_sha256: certificateEntry.fingerprint_sha256,
                  not_after: certificateEntry.not_after,
                },
              ],
            },
          });
        }
      }
    }

    if (host && looksLikeSshKeyContext(name, description)) {
      const key = parseSshKeyFromText(`${name}\n${description}`);

      if (key) {
        const keyEntry = {
          ...key,
          host,
          port: portDescriptor.port,
          protocol: portDescriptor.protocol || 'tcp',
          source: 'greenbone',
        };

        upsertSshHostKey(keyEntry);

        if (portDescriptor.port) {
          upsertPortObservation({
            host,
            port: portDescriptor.port,
            protocol: portDescriptor.protocol,
            metadata: {
              ssh_host_keys: [
                {
                  key_type: keyEntry.key_type,
                  fingerprint: keyEntry.fingerprint,
                  key_bits: keyEntry.key_bits,
                },
              ],
            },
          });
        }
      }
    }

    if (!informational) {
      vulnerabilities.push({
        host,
        port: portDescriptor.port,
        cve: cveList[0] || parseCve(extractText(result.nvt?.cve) || extractText(result.cve)),
        cve_list: cveList,
        nvt_oid: nvtOid,
        name,
        severity: cvssSeverity,
        cvss_score: cvssScore,
        cvss_severity: cvssSeverity,
        description,
        source: 'greenbone',
      });
    }
  });

  const hostDetailNodes = collectNodesByKey(rootNode, 'host', [])
    .filter((node) => toArray(node?.detail).length > 0);

  hostDetailNodes.forEach((hostNode) => {
    const hostText = extractText(hostNode.ip) || extractText(hostNode.name) || extractText(hostNode.host);
    const host = extractIpv4Candidate(hostText) || normalizeText(hostText);

    if (!host) {
      return;
    }

    const details = toArray(hostNode.detail);

    details.forEach((detail) => {
      const detailName = extractText(detail?.name);
      const detailSource = extractText(detail?.source?.name || detail?.source);
      const detailValue = extractText(detail?.value) || extractText(detail);
      const normalizedDetailName = normalizeDetailKey(detailName);

      if (!detailValue) {
        return;
      }

      upsertHostMetadata(host, {
        greenbone_host_details: {
          [normalizedDetailName]: summarizeText(detailValue, 800),
        },
      });

      const osCandidate = extractOsCandidate(detailName, detailValue);

      if (osCandidate) {
        upsertOsDetection({
          host,
          name: osCandidate,
          confidence: 0.99,
          evidence: {
            detail_name: detailName,
            detail_source: detailSource || null,
          },
        });
      }

      const derivedPort = parsePortDescriptor(`${detailName} ${detailValue}`);

      if (looksLikeTlsContext(detailName, detailValue)) {
        const cert = parseCertificateFromText(`${detailName}\n${detailValue}`);

        if (cert) {
          const certificateEntry = {
            ...cert,
            host,
            port: derivedPort.port,
            protocol: derivedPort.protocol || 'tcp',
            source: 'greenbone',
          };

          upsertTlsCertificate(certificateEntry);

          if (derivedPort.port) {
            upsertPortObservation({
              host,
              port: derivedPort.port,
              protocol: derivedPort.protocol,
              service: derivedPort.service,
              metadata: {
                tls_certificates: [
                  {
                    subject: certificateEntry.subject,
                    issuer: certificateEntry.issuer,
                    fingerprint_sha256: certificateEntry.fingerprint_sha256,
                    not_after: certificateEntry.not_after,
                  },
                ],
              },
            });
          }
        }
      }

      if (looksLikeSshKeyContext(detailName, detailValue)) {
        const sshKey = parseSshKeyFromText(`${detailName}\n${detailValue}`);

        if (sshKey) {
          const keyEntry = {
            ...sshKey,
            host,
            port: derivedPort.port,
            protocol: derivedPort.protocol || 'tcp',
            source: 'greenbone',
          };

          upsertSshHostKey(keyEntry);

          if (derivedPort.port) {
            upsertPortObservation({
              host,
              port: derivedPort.port,
              protocol: derivedPort.protocol,
              service: derivedPort.service,
              metadata: {
                ssh_host_keys: [
                  {
                    key_type: keyEntry.key_type,
                    fingerprint: keyEntry.fingerprint,
                    key_bits: keyEntry.key_bits,
                  },
                ],
              },
            });
          }
        }
      }
    });
  });

  return {
    vulnerabilities,
    ports: [...portObservations.values()],
    osDetections: [...osDetections.values()],
    tlsCertificates: [...tlsCertificates.values()],
    sshHostKeys: [...sshHostKeys.values()],
    hostMetadata: [...hostMetadata.entries()].map(([host, metadata]) => ({
      host,
      metadata,
    })),
  };
}

async function startScan(target, options = {}) {
  ensureEnabled();

  const safeTarget = String(target || '').trim();
  const requestedScanConfigId = String(options.scanConfigId || '').trim() || null;
  const requestedPortRange = String(options.portRange || '').trim() || null;
  const requestedMaxChecks = parseTaskConcurrencyValue(options.maxChecks);
  const requestedMaxHosts = parseTaskConcurrencyValue(options.maxHosts);

  if (!safeTarget) {
    throw new GreenboneServiceError('Target is required', {
      statusCode: 400,
      code: 'GREENBONE_INVALID_TARGET',
    });
  }

  return withAuthenticatedSession(async (socket, config) => {
    const suffix = Date.now();
    const resolvedConfigId = await resolveScanConfigId(socket, requestedScanConfigId || config.scanConfigId);
    const resolvedScannerId = await resolveScannerId(socket, config.scannerId);
    const resolvedPortRange = requestedPortRange || String(config.portRange || '').trim();
    const resolvedMaxChecks = requestedMaxChecks ?? parseTaskConcurrencyValue(config.maxChecks);
    const resolvedMaxHosts = requestedMaxHosts ?? parseTaskConcurrencyValue(config.maxHosts);
    const taskPreferencesXml = buildTaskPreferencesXml(resolvedMaxChecks, resolvedMaxHosts);

    if (!isValidGreenbonePortRange(resolvedPortRange)) {
      throw new GreenboneServiceError('Invalid Greenbone port range format', {
        statusCode: 400,
        code: 'GREENBONE_INVALID_PORT_RANGE',
        details: resolvedPortRange || null,
      });
    }

    const createTargetResponse = await sendGmpCommand(
      socket,
      `
        <create_target>
          <name>Watchdog-${xmlEscape(safeTarget)}-${suffix}</name>
          <hosts>${xmlEscape(safeTarget)}</hosts>
          <port_range>${xmlEscape(resolvedPortRange)}</port_range>
        </create_target>
      `,
    );

    const targetId = extractResponseId(createTargetResponse);

    if (!targetId) {
      throw new GreenboneServiceError('Unable to create Greenbone target', {
        code: 'GREENBONE_TARGET_CREATE_FAILED',
      });
    }

    const createTaskResponse = await sendGmpCommand(
      socket,
      `
        <create_task>
          <name>Watchdog Task ${xmlEscape(safeTarget)} ${suffix}</name>
          <config id="${xmlEscape(resolvedConfigId)}" />
          <target id="${xmlEscape(targetId)}" />
          <scanner id="${xmlEscape(resolvedScannerId)}" />
          ${taskPreferencesXml}
        </create_task>
      `,
    );

    const taskId = extractResponseId(createTaskResponse);

    if (!taskId) {
      throw new GreenboneServiceError('Unable to create Greenbone task', {
        code: 'GREENBONE_TASK_CREATE_FAILED',
      });
    }

    const startTaskResponse = await sendGmpCommand(
      socket,
      `<start_task task_id="${xmlEscape(taskId)}" />`,
    );

    const reportId = extractText(startTaskResponse?.rootNode?.report_id) || null;

    return {
      externalTaskId: taskId,
      reportId,
    };
  });
}

async function getTaskStatus(taskId) {
  ensureEnabled();

  const safeTaskId = String(taskId || '').trim();

  if (!safeTaskId) {
    throw new GreenboneServiceError('Task ID is required', {
      statusCode: 400,
      code: 'GREENBONE_TASK_ID_REQUIRED',
    });
  }

  return withAuthenticatedSession(async (socket) => {
    const response = await sendGmpCommand(
      socket,
      `<get_tasks task_id="${xmlEscape(safeTaskId)}" details="1" />`,
    );

    const taskNode = findTaskNode(response.rootNode);

    if (!taskNode) {
      throw new GreenboneServiceError('Greenbone task not found', {
        statusCode: 404,
        code: 'GREENBONE_TASK_NOT_FOUND',
      });
    }

    const rawStatus = extractText(taskNode.status);
    const mappedStatus = mapTaskStatus(rawStatus);
    const progressValue = Number.parseInt(extractText(taskNode.progress), 10);
    const boundedProgress = Number.isFinite(progressValue)
      ? Math.max(0, Math.min(100, progressValue))
      : null;
    const progressPercent = mappedStatus === 'completed'
      ? 100
      : mappedStatus === 'running'
        ? Math.max(1, boundedProgress ?? 10)
        : boundedProgress ?? 0;

    return {
      status: mappedStatus,
      progress_percent: progressPercent,
      report_id: extractReportIdFromTask(taskNode),
      raw_status: rawStatus,
    };
  });
}

async function fetchAndParseReport(taskId, reportId) {
  ensureEnabled();

  return withAuthenticatedSession(async (socket) => {
    let resolvedReportId = reportId ? String(reportId).trim() : '';

    if (!resolvedReportId) {
      const taskResponse = await sendGmpCommand(
        socket,
        `<get_tasks task_id="${xmlEscape(taskId)}" details="1" />`,
      );
      const taskNode = findTaskNode(taskResponse.rootNode);
      resolvedReportId = extractReportIdFromTask(taskNode) || '';
    }

    if (!resolvedReportId) {
      throw new GreenboneServiceError('No report available for Greenbone task yet', {
        statusCode: 409,
        code: 'GREENBONE_REPORT_NOT_READY',
      });
    }

    const reportResponse = await sendGmpCommand(
      socket,
      `<get_reports report_id="${xmlEscape(resolvedReportId)}" details="1" ignore_pagination="1" />`,
    );
    const parsedReport = parseReportData(reportResponse.rootNode);

    return {
      reportId: resolvedReportId,
      xml: reportResponse.xml,
      vulnerabilities: parsedReport.vulnerabilities,
      ports: parsedReport.ports,
      osDetections: parsedReport.osDetections,
      tlsCertificates: parsedReport.tlsCertificates,
      sshHostKeys: parsedReport.sshHostKeys,
      hostMetadata: parsedReport.hostMetadata,
    };
  });
}

module.exports = {
  GreenboneServiceError,
  isGreenboneEnabled,
  getConfig,
  listScanConfigs,
  startScan,
  getTaskStatus,
  fetchAndParseReport,
};
