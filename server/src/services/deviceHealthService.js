const { spawn } = require('child_process');
const { query } = require('../db');

function toPositiveInt(rawValue, fallback) {
  const parsed = Number.parseInt(rawValue, 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function isHealthcheckEnabled() {
  return (process.env.DEVICE_HEALTHCHECK_ENABLED || 'true').toLowerCase() !== 'false';
}

const HEALTHCHECK_INTERVAL_MS = toPositiveInt(process.env.DEVICE_HEALTHCHECK_INTERVAL_MS, 60_000);
const HEALTHCHECK_TIMEOUT_SECONDS = toPositiveInt(process.env.DEVICE_HEALTHCHECK_TIMEOUT_SECONDS, 1);
const HEALTHCHECK_CONCURRENCY = toPositiveInt(process.env.DEVICE_HEALTHCHECK_CONCURRENCY, 16);

let intervalHandle = null;
let inFlight = false;

function pingHost(ipAddress) {
  return new Promise((resolve) => {
    const args = process.platform === 'win32'
      ? ['-n', '1', '-w', String(HEALTHCHECK_TIMEOUT_SECONDS * 1000), ipAddress]
      : ['-n', '-c', '1', '-W', String(HEALTHCHECK_TIMEOUT_SECONDS), ipAddress];

    let settled = false;

    const finish = (result) => {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(killTimer);
      resolve(result);
    };

    const child = spawn('ping', args, { stdio: 'ignore' });

    child.once('error', (error) => {
      if (error?.code === 'ENOENT') {
        finish(null);
        return;
      }

      finish(false);
    });

    child.once('close', (code) => {
      finish(code === 0);
    });

    const killTimer = setTimeout(() => {
      child.kill('SIGKILL');
      finish(false);
    }, (HEALTHCHECK_TIMEOUT_SECONDS + 1) * 1000);
  });
}

async function runWithConcurrency(items, worker, maxConcurrency) {
  if (!Array.isArray(items) || items.length === 0) {
    return;
  }

  const limit = Math.max(1, Math.min(maxConcurrency, items.length));
  let index = 0;

  const runners = Array.from({ length: limit }, async () => {
    while (index < items.length) {
      const current = items[index];
      index += 1;
      await worker(current);
    }
  });

  await Promise.all(runners);
}

async function refreshDeviceHealthStatuses() {
  if (inFlight) {
    return;
  }

  inFlight = true;

  try {
    const devicesResult = await query(
      `
        SELECT id, host(ip_address) AS ip_address
        FROM devices
        ORDER BY id ASC
      `,
    );

    const devices = devicesResult.rows;

    await runWithConcurrency(
      devices,
      async (device) => {
        const pingResult = await pingHost(device.ip_address);

        if (pingResult === null) {
          throw new Error('ping command is unavailable in backend container');
        }

        await query(
          `
            UPDATE devices
            SET online_status = $2,
                last_healthcheck_at = NOW()
            WHERE id = $1
          `,
          [device.id, pingResult],
        );
      },
      HEALTHCHECK_CONCURRENCY,
    );
  } catch (error) {
    console.error('Device health check refresh failed:', error.message || error);
  } finally {
    inFlight = false;
  }
}

async function startDeviceHealthChecks() {
  if (!isHealthcheckEnabled()) {
    console.log('Device health checks are disabled');
    return;
  }

  const pingProbe = await pingHost('127.0.0.1');

  if (pingProbe === null) {
    console.warn('Device health checks disabled because ping command is not available');
    return;
  }

  await refreshDeviceHealthStatuses();

  intervalHandle = setInterval(() => {
    void refreshDeviceHealthStatuses();
  }, HEALTHCHECK_INTERVAL_MS);

  intervalHandle.unref?.();

  console.log(`Device health checks enabled (interval ${HEALTHCHECK_INTERVAL_MS}ms)`);
}

module.exports = {
  startDeviceHealthChecks,
};
