const net = require('net');
const tls = require('tls');
const { parseStringPromise } = require('xml2js');

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

  return {
    host: process.env.GREENBONE_HOST || 'greenbone',
    port: Number(process.env.GREENBONE_PORT || 9390),
    username: process.env.GREENBONE_USERNAME || 'admin',
    password: process.env.GREENBONE_PASSWORD || 'admin',
    socketPath: socketPath || null,
    useTls: !socketPath && (process.env.GREENBONE_TLS || 'true').toLowerCase() !== 'false',
    timeoutMs: Number(process.env.GREENBONE_TIMEOUT_MS || 20_000),
    scanConfigId: process.env.GREENBONE_SCAN_CONFIG_ID || 'daba56c8-73ec-11df-a475-002264764cea',
    scannerId: process.env.GREENBONE_SCANNER_ID || '08b69003-5fc2-4037-a479-93b440211c73',
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

function parseCvssScore(...values) {
  for (const value of values) {
    const numeric = Number.parseFloat(String(value || '').trim());

    if (Number.isFinite(numeric)) {
      return numeric;
    }
  }

  return null;
}

function parseCve(value) {
  const raw = String(value || '').trim();

  if (!raw || raw.toLowerCase() === 'nocve') {
    return null;
  }

  const candidates = raw
    .split(/[,\s;]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);

  const match = candidates.find((entry) => /^CVE-\d{4}-\d{4,}$/i.test(entry));
  return match || null;
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

    const cleanup = () => {
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
      socket.removeListener('timeout', onTimeout);
    };

    const onError = (error) => {
      cleanup();
      reject(new GreenboneServiceError('Vulnerability scanner connection failed', {
        statusCode: 502,
        code: 'GREENBONE_CONNECTION_FAILED',
        details: error.message,
      }));
    };

    const onTimeout = () => {
      cleanup();
      reject(new GreenboneServiceError('Vulnerability scanner command timed out', {
        statusCode: 504,
        code: 'GREENBONE_TIMEOUT',
      }));
    };

    const onClose = () => {
      cleanup();
      reject(new GreenboneServiceError('Vulnerability scanner closed the connection', {
        statusCode: 502,
        code: 'GREENBONE_CONNECTION_CLOSED',
      }));
    };

    const onData = async (chunk) => {
      buffer += chunk.toString('utf8');
      const nullIndex = buffer.indexOf('\0');

      if (nullIndex === -1) {
        return;
      }

      cleanup();

      try {
        const xml = buffer.slice(0, nullIndex);
        const parsed = await parseXml(xml);
        const { rootName, rootNode } = getRootNode(parsed);
        ensureSuccessResponse(rootName, rootNode);

        resolve({
          xml,
          parsed,
          rootName,
          rootNode,
        });
      } catch (error) {
        reject(error);
      }
    };

    socket.on('data', onData);
    socket.once('error', onError);
    socket.once('close', onClose);
    socket.once('timeout', onTimeout);

    socket.write(`${command}\0`);
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

function parseReportVulnerabilities(rootNode) {
  const results = collectResultNodes(rootNode, []);

  return results.map((result) => {
    const host = extractText(result.host) || null;
    const portText = extractText(result.port);
    const cvssScore = parseCvssScore(
      extractText(result.severity),
      extractText(result.nvt?.cvss_base),
      extractText(result.cvss_base),
    );

    const explicitSeverity = normalizeSeverityLabel(
      extractText(result.threat)
      || extractText(result.cvss_severity)
      || extractText(result.nvt?.threat),
    );

    const cvssSeverity = explicitSeverity || severityFromScore(cvssScore);
    const name = extractText(result.name) || extractText(result.nvt?.name) || 'Unnamed vulnerability';
    const description = extractText(result.description) || extractText(result.nvt?.summary) || '';

    return {
      host,
      port: parsePort(portText),
      cve: parseCve(extractText(result.nvt?.cve) || extractText(result.cve)),
      name,
      severity: cvssSeverity,
      cvss_score: cvssScore,
      cvss_severity: cvssSeverity,
      description,
      source: 'greenbone',
    };
  });
}

async function startScan(target) {
  ensureEnabled();

  const safeTarget = String(target || '').trim();

  if (!safeTarget) {
    throw new GreenboneServiceError('Target is required', {
      statusCode: 400,
      code: 'GREENBONE_INVALID_TARGET',
    });
  }

  return withAuthenticatedSession(async (socket, config) => {
    const suffix = Date.now();

    const createTargetResponse = await sendGmpCommand(
      socket,
      `
        <create_target>
          <name>Watchdog-${xmlEscape(safeTarget)}-${suffix}</name>
          <hosts>${xmlEscape(safeTarget)}</hosts>
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
          <config id="${xmlEscape(config.scanConfigId)}" />
          <target id="${xmlEscape(targetId)}" />
          <scanner id="${xmlEscape(config.scannerId)}" />
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
    const progressPercent = Number.isFinite(progressValue)
      ? Math.max(0, Math.min(100, progressValue))
      : mappedStatus === 'completed'
        ? 100
        : mappedStatus === 'running'
          ? 10
          : 0;

    return {
      status: mappedStatus,
      progress_percent: mappedStatus === 'completed' ? 100 : progressPercent,
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

    return {
      reportId: resolvedReportId,
      xml: reportResponse.xml,
      vulnerabilities: parseReportVulnerabilities(reportResponse.rootNode),
    };
  });
}

module.exports = {
  GreenboneServiceError,
  isGreenboneEnabled,
  getConfig,
  startScan,
  getTaskStatus,
  fetchAndParseReport,
};
