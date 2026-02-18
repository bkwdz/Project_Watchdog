const net = require('net');
const { parseStringPromise } = require('xml2js');

function isScannerEnabled() {
  return (process.env.GREENBONE_ENABLED || 'false').toLowerCase() === 'true';
}

function toPositiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function getScannerConfig() {
  const socketPath = String(process.env.GREENBONE_SOCKET_PATH || '').trim();

  return {
    host: process.env.GREENBONE_HOST || 'openvas-scanner',
    port: toPositiveInt(process.env.GREENBONE_PORT, 9390),
    socketPath: socketPath || null,
    timeoutMs: toPositiveInt(process.env.GREENBONE_TIMEOUT_MS, 60_000),
  };
}

function sendOspdCommand(commandXml, config) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(
      config.socketPath
        ? { path: config.socketPath }
        : {
          host: config.host,
          port: config.port,
        },
    );

    let buffer = '';
    let settled = false;

    const cleanup = () => {
      socket.removeAllListeners('connect');
      socket.removeAllListeners('data');
      socket.removeAllListeners('timeout');
      socket.removeAllListeners('error');
      socket.removeAllListeners('close');
    };

    const fail = (message, details) => {
      if (settled) {
        return;
      }

      settled = true;
      cleanup();
      socket.destroy();
      reject(new Error(details ? `${message}: ${details}` : message));
    };

    const finishWithXml = async (xmlPayload) => {
      if (settled) {
        return;
      }

      const safeXml = String(xmlPayload || '').trim();

      if (!safeXml) {
        fail('Scanner returned an empty response');
        return;
      }

      try {
        const parsed = await parseStringPromise(safeXml, { explicitArray: false, trim: true });
        settled = true;
        cleanup();
        socket.end();
        resolve({ xml: safeXml, parsed });
      } catch (error) {
        fail('Scanner returned invalid XML', error.message);
      }
    };

    socket.setTimeout(config.timeoutMs);

    socket.on('connect', () => {
      socket.write(`${commandXml}\0`);
    });

    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const nullTerminatorIndex = buffer.indexOf('\0');

      if (nullTerminatorIndex >= 0) {
        void finishWithXml(buffer.slice(0, nullTerminatorIndex));
      }
    });

    socket.on('timeout', () => {
      fail('Scanner connection timed out');
    });

    socket.on('error', (error) => {
      fail('Scanner connection failed', error.message);
    });

    socket.on('close', () => {
      if (!settled) {
        void finishWithXml(buffer);
      }
    });
  });
}

async function testScannerConnection() {
  if (!isScannerEnabled()) {
    return false;
  }

  const config = getScannerConfig();

  try {
    const response = await sendOspdCommand('<get_version/>', config);
    const rootNodeName = Object.keys(response.parsed || {})[0] || '';

    return rootNodeName.toLowerCase().includes('version');
  } catch (error) {
    return false;
  }
}

module.exports = {
  testScannerConnection,
};
