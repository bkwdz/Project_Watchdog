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

function parseHost(hostNode) {
  const status = hostNode?.status?.$?.state || null;
  const addresses = toArray(hostNode?.address);
  const hostnames = toArray(hostNode?.hostnames?.hostname);
  const osMatches = toArray(hostNode?.os?.osmatch);
  const ports = toArray(hostNode?.ports?.port);

  const ipAddress = addresses.find((address) => address?.$?.addrtype === 'ipv4')?.$?.addr || null;
  const macAddress = addresses.find((address) => address?.$?.addrtype === 'mac')?.$?.addr || null;

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
      };
    })
    .filter(Boolean);

  return {
    isUp: status === 'up',
    ipAddress,
    macAddress,
    hostname: hostnames[0]?.$?.name || null,
    osGuess: osMatches[0]?.$?.name || null,
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
