const { query, withTransaction } = require('../db');
const { runNmapScan, parseNmapXml } = require('./nmapService');
const {
  upsertDeviceRecord,
  upsertPortRecord,
} = require('./dataReconciliation');

const queue = [];
const queuedSet = new Set();
let isProcessing = false;

function safeProgress(processed, total) {
  if (total <= 0) {
    return 95;
  }

  return Math.min(95, Math.max(10, Math.round((processed / total) * 95)));
}

async function updateScanStatus(scanId, fields) {
  const sets = [];
  const values = [];

  Object.entries(fields).forEach(([key, value], idx) => {
    sets.push(`${key} = $${idx + 2}`);
    values.push(value);
  });

  if (sets.length === 0) {
    return;
  }

  await query(`UPDATE scans SET ${sets.join(', ')} WHERE id = $1`, [scanId, ...values]);
}

async function upsertDeviceAndPorts(scanType, host) {
  return withTransaction(async (client) => {
    const device = await upsertDeviceRecord(client, {
      ipAddress: host.ipAddress,
      hostname: host.hostname,
      macAddress: host.macAddress,
      osDetection: host.osGuess
        ? {
          name: host.osGuess,
          source: 'nmap',
          confidence: host.osConfidence,
          evidence: {
            parser: 'nmap_osmatch',
          },
        }
        : null,
      scriptResults: host.scriptResults,
      metadata: {
        nmap: {
          last_scan_type: scanType,
        },
      },
      source: 'nmap',
      touchLastSeen: true,
    });

    const deviceId = device.id;

    if (scanType === 'discovery') {
      return deviceId;
    }

    for (const portEntry of host.ports) {
      if (!Number.isInteger(portEntry.port) || portEntry.port < 1 || portEntry.port > 65535) {
        continue;
      }

      await upsertPortRecord(client, {
        deviceId,
        port: portEntry.port,
        protocol: portEntry.protocol,
        service: portEntry.service,
        version: portEntry.version,
        state: portEntry.state,
        scriptResults: portEntry.scriptResults,
        metadata: {
          nmap: {
            state: portEntry.state,
          },
        },
        source: 'nmap',
        confidence: 1,
      });
    }

    return deviceId;
  });
}

async function processScan(scanId) {
  const scanResult = await query(
    `
      SELECT id, target, scan_type, COALESCE(scanner_type, 'nmap') AS scanner_type
      FROM scans
      WHERE id = $1
      LIMIT 1
    `,
    [scanId],
  );

  const scan = scanResult.rows[0];

  if (!scan) {
    return;
  }

  if (scan.scanner_type !== 'nmap') {
    return;
  }

  await updateScanStatus(scanId, {
    status: 'running',
    progress_percent: 10,
    started_at: new Date(),
  });

  try {
    const scanOutput = await runNmapScan(scan.target, scan.scan_type);
    const parsedOutput = await parseNmapXml(scanOutput.xml);
    const liveHosts = parsedOutput.hosts.filter((host) => host.isUp && host.ipAddress);

    let processedHosts = 0;

    for (const host of liveHosts) {
      await upsertDeviceAndPorts(scan.scan_type, host);
      processedHosts += 1;

      await updateScanStatus(scanId, {
        progress_percent: safeProgress(processedHosts, liveHosts.length),
      });
    }

    await updateScanStatus(scanId, {
      status: 'completed',
      progress_percent: 100,
      completed_at: new Date(),
    });
  } catch (error) {
    console.error(`Scan ${scanId} failed`, error);

    await updateScanStatus(scanId, {
      status: 'failed',
      completed_at: new Date(),
    });
  }
}

async function drainQueue() {
  if (isProcessing) {
    return;
  }

  isProcessing = true;

  while (queue.length > 0) {
    const scanId = queue.shift();
    queuedSet.delete(scanId);

    try {
      await processScan(scanId);
    } catch (error) {
      console.error(`Queue processing failed for scan ${scanId}`, error);
    }
  }

  isProcessing = false;
}

function enqueueScan(scanId) {
  const normalizedScanId = Number(scanId);

  if (!Number.isInteger(normalizedScanId)) {
    throw new Error('Invalid scan id');
  }

  if (queuedSet.has(normalizedScanId)) {
    return;
  }

  queue.push(normalizedScanId);
  queuedSet.add(normalizedScanId);
  void drainQueue();
}

async function resumeQueuedScans() {
  const result = await query(
    `
      SELECT id
      FROM scans
      WHERE status IN ('queued', 'running')
        AND COALESCE(scanner_type, 'nmap') = 'nmap'
      ORDER BY id ASC
    `,
  );

  result.rows.forEach((row) => {
    enqueueScan(row.id);
  });
}

module.exports = {
  enqueueScan,
  resumeQueuedScans,
};
