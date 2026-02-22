const { spawn } = require('child_process');
const { parseStringPromise } = require('xml2js');
const { getScanArgs } = require('./scanProfiles');

function toArray(value) {
  if (!value) {
    return [];
  }

  return Array.isArray(value) ? value : [value];
}

function buildVersionString(serviceNode = {}) {
  const attrs = serviceNode.$ || {};
  const parts = [];

  if (attrs.product) {
    parts.push(attrs.product);
  }

  if (attrs.version) {
    parts.push(attrs.version);
  }

  if (attrs.extrainfo) {
    parts.push(`(${attrs.extrainfo})`);
  }

  return parts.length ? parts.join(' ') : null;
}

function normalizeText(value) {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function extractNodeText(node) {
  if (node === null || node === undefined) {
    return '';
  }

  if (typeof node === 'string' || typeof node === 'number' || typeof node === 'boolean') {
    return String(node);
  }

  if (Array.isArray(node)) {
    return extractNodeText(node[0]);
  }

  if (typeof node === 'object') {
    if (typeof node._ === 'string') {
      return node._;
    }

    const values = Object.values(node);

    for (const value of values) {
      const text = extractNodeText(value);

      if (text) {
        return text;
      }
    }
  }

  return '';
}

function parseScriptTree(node) {
  const branch = {};

  toArray(node?.elem).forEach((elemNode, index) => {
    const key = normalizeText(elemNode?.$?.key) || `value_${index + 1}`;
    const value = normalizeText(extractNodeText(elemNode));

    if (value) {
      branch[key] = value;
    }
  });

  toArray(node?.table).forEach((tableNode, index) => {
    const key = normalizeText(tableNode?.$?.key) || `table_${index + 1}`;
    const value = parseScriptTree(tableNode);

    if (value && (typeof value !== 'object' || Object.keys(value).length > 0)) {
      branch[key] = value;
    }
  });

  const textValue = normalizeText(node?._);

  if (textValue) {
    branch.text = textValue;
  }

  return Object.keys(branch).length > 0 ? branch : null;
}

function parseScriptResults(scriptNodes) {
  const scripts = {};

  toArray(scriptNodes).forEach((scriptNode) => {
    const id = normalizeText(scriptNode?.$?.id);

    if (!id) {
      return;
    }

    const output = normalizeText(scriptNode?.$?.output) || normalizeText(extractNodeText(scriptNode));
    const details = parseScriptTree(scriptNode);
    const entry = {};

    if (output) {
      entry.output = output;
    }

    if (details) {
      entry.details = details;
    }

    scripts[id] = Object.keys(entry).length > 0 ? entry : { output: '' };
  });

  return scripts;
}

function parseHost(hostNode) {
  const status = hostNode?.status?.$?.state || null;
  const addresses = toArray(hostNode?.address);
  const hostnames = toArray(hostNode?.hostnames?.hostname);
  const osMatches = toArray(hostNode?.os?.osmatch);
  const ports = toArray(hostNode?.ports?.port);
  const hostScripts = parseScriptResults([
    ...toArray(hostNode?.hostscript?.script),
    ...toArray(hostNode?.script),
  ]);

  const ipAddress = addresses.find((address) => address?.$?.addrtype === 'ipv4')?.$?.addr || null;
  const macAddress = addresses.find((address) => address?.$?.addrtype === 'mac')?.$?.addr || null;
  const osAttrs = osMatches[0]?.$ || {};
  const osAccuracyRaw = Number.parseFloat(osAttrs.accuracy);
  const osConfidence = Number.isFinite(osAccuracyRaw)
    ? Math.max(0, Math.min(1, osAccuracyRaw / 100))
    : null;

  const normalizedPorts = ports
    .map((portNode) => {
      const attrs = portNode?.$ || {};
      const state = portNode?.state?.$?.state || null;
      const serviceName = portNode?.service?.$?.name || null;

      if (!attrs.portid || !attrs.protocol || !state) {
        return null;
      }

      return {
        port: Number(attrs.portid),
        protocol: attrs.protocol,
        state,
        service: serviceName,
        version: buildVersionString(portNode.service),
        scriptResults: parseScriptResults(toArray(portNode?.script)),
      };
    })
    .filter(Boolean);

  return {
    isUp: status === 'up',
    ipAddress,
    macAddress,
    hostname: hostnames[0]?.$?.name || null,
    osGuess: osAttrs.name || null,
    osConfidence,
    scriptResults: hostScripts,
    ports: normalizedPorts,
  };
}

async function parseNmapXml(xml) {
  const parsed = await parseStringPromise(xml, { explicitArray: false });
  const hosts = toArray(parsed?.nmaprun?.host).map(parseHost);
  return { hosts };
}

function runNmapScan(target, scanType) {
  const args = [...getScanArgs(scanType), '-oX', '-', target];

  return new Promise((resolve, reject) => {
    const child = spawn('nmap', args, { shell: false });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', (error) => {
      reject(error);
    });

    child.on('close', (code) => {
      if (code !== 0) {
        return reject(new Error(`nmap exited with code ${code}: ${stderr.trim()}`));
      }

      return resolve({ xml: stdout, stderr });
    });
  });
}

module.exports = {
  runNmapScan,
  parseNmapXml,
};
