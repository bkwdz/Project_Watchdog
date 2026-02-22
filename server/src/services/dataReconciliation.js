const { createHash } = require('crypto');

const SOURCE_PRIORITY = Object.freeze({
  greenbone: 300,
  nmap: 100,
  unknown: 0,
});

const SOURCE_DEFAULT_CONFIDENCE = Object.freeze({
  greenbone: 0.95,
  nmap: 0.6,
  unknown: 0.4,
});

function toArray(value) {
  if (!value) {
    return [];
  }

  return Array.isArray(value) ? value : [value];
}

function clampConfidence(value, fallback = null) {
  const numeric = Number.parseFloat(value);

  if (!Number.isFinite(numeric)) {
    return fallback;
  }

  if (numeric < 0) {
    return 0;
  }

  if (numeric > 1) {
    return 1;
  }

  return numeric;
}

function normalizeText(value) {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizeSource(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return normalized || 'unknown';
}

function sourcePriority(value) {
  const source = normalizeSource(value);
  return SOURCE_PRIORITY[source] ?? SOURCE_PRIORITY.unknown;
}

function sourceConfidence(source, explicitConfidence = null) {
  const normalizedSource = normalizeSource(source);
  const fallback = SOURCE_DEFAULT_CONFIDENCE[normalizedSource] ?? SOURCE_DEFAULT_CONFIDENCE.unknown;
  return clampConfidence(explicitConfidence, fallback);
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function ensureJsonObject(value) {
  if (isPlainObject(value)) {
    return value;
  }

  return {};
}

function mergeArrays(left, right) {
  const items = [...toArray(left), ...toArray(right)];
  const merged = [];
  const seen = new Set();

  items.forEach((item) => {
    const key = typeof item === 'object'
      ? JSON.stringify(item)
      : `${typeof item}:${String(item)}`;

    if (seen.has(key)) {
      return;
    }

    seen.add(key);
    merged.push(item);
  });

  return merged;
}

function mergeJsonValues(left, right) {
  if (Array.isArray(left) || Array.isArray(right)) {
    return mergeArrays(left, right);
  }

  if (isPlainObject(left) || isPlainObject(right)) {
    const merged = {
      ...(isPlainObject(left) ? left : {}),
    };

    Object.entries(isPlainObject(right) ? right : {}).forEach(([key, value]) => {
      if (!Object.prototype.hasOwnProperty.call(merged, key)) {
        merged[key] = value;
        return;
      }

      merged[key] = mergeJsonValues(merged[key], value);
    });

    return merged;
  }

  return right === undefined ? left : right;
}

function looksGenericNmapOsGuess(value) {
  const normalized = String(value || '').toLowerCase();

  if (!normalized) {
    return false;
  }

  return /(unknown|generic|linux\s+[2-6]\.|kernel|unix-like)/i.test(normalized);
}

function normalizeOsDetection(entry) {
  if (!entry || typeof entry !== 'object') {
    return null;
  }

  const source = normalizeSource(entry.source);
  const name = normalizeText(entry.name || entry.value || entry.os_guess || entry.osGuess);

  if (!name) {
    return null;
  }

  let confidence = sourceConfidence(source, entry.confidence);

  if (source === 'nmap' && looksGenericNmapOsGuess(name)) {
    confidence = Math.min(confidence, 0.45);
  }

  return {
    name,
    source,
    confidence,
    evidence: entry.evidence && typeof entry.evidence === 'object' ? entry.evidence : null,
    detected_at: normalizeText(entry.detected_at) || new Date().toISOString(),
  };
}

function sortOsDetections(entries) {
  return [...entries].sort((left, right) => {
    const priorityDiff = sourcePriority(right.source) - sourcePriority(left.source);

    if (priorityDiff !== 0) {
      return priorityDiff;
    }

    const confidenceDiff = (right.confidence || 0) - (left.confidence || 0);

    if (confidenceDiff !== 0) {
      return confidenceDiff;
    }

    return String(right.detected_at || '').localeCompare(String(left.detected_at || ''));
  });
}

function mergeOsDetections(existingDetections, incomingDetections) {
  const map = new Map();

  [...toArray(existingDetections), ...toArray(incomingDetections)]
    .map(normalizeOsDetection)
    .filter(Boolean)
    .forEach((detection) => {
      const key = `${detection.source}:${detection.name.toLowerCase()}`;
      const current = map.get(key);

      if (!current) {
        map.set(key, detection);
        return;
      }

      const preferred = sortOsDetections([current, detection])[0];

      map.set(key, {
        ...preferred,
        evidence: mergeJsonValues(current.evidence, detection.evidence),
      });
    });

  return sortOsDetections([...map.values()]).slice(0, 20);
}

function selectBestOs(detections, currentDevice = null) {
  const candidates = [...toArray(detections)];

  if (currentDevice?.os_guess) {
    candidates.push({
      name: currentDevice.os_guess,
      source: normalizeSource(currentDevice.os_guess_source),
      confidence: sourceConfidence(
        currentDevice.os_guess_source,
        currentDevice.os_guess_confidence,
      ),
      detected_at: new Date().toISOString(),
      evidence: null,
    });
  }

  const ranked = sortOsDetections(candidates);
  const best = ranked[0] || null;

  return {
    osGuess: best?.name || null,
    osGuessSource: best?.source || null,
    osGuessConfidence: clampConfidence(best?.confidence, null),
  };
}

function choosePreferredText(existingValue, incomingValue, shouldPreferIncoming) {
  const normalizedIncoming = normalizeText(incomingValue);

  if (!normalizedIncoming) {
    return normalizeText(existingValue);
  }

  const normalizedExisting = normalizeText(existingValue);

  if (!normalizedExisting) {
    return normalizedIncoming;
  }

  return shouldPreferIncoming ? normalizedIncoming : normalizedExisting;
}

function shouldPreferIncomingSource(existingSource, existingConfidence, incomingSource, incomingConfidence) {
  const existingPriority = sourcePriority(existingSource);
  const incomingPriority = sourcePriority(incomingSource);

  if (incomingPriority !== existingPriority) {
    return incomingPriority > existingPriority;
  }

  return incomingConfidence >= existingConfidence;
}

function normalizeProtocol(value) {
  const normalized = normalizeText(value);

  if (!normalized) {
    return 'tcp';
  }

  return normalized.toLowerCase();
}

async function upsertDeviceRecord(client, {
  ipAddress,
  hostname,
  macAddress,
  osDetection = null,
  scriptResults = {},
  metadata = {},
  source = 'unknown',
  touchLastSeen = true,
}) {
  const ip = normalizeText(ipAddress);

  if (!ip) {
    throw new Error('Device IP address is required for upsert');
  }

  const incomingDetection = normalizeOsDetection({
    ...(osDetection || {}),
    source: osDetection?.source || source,
  });

  const existingResult = await client.query(
    `
      SELECT
        id,
        hostname,
        mac_address,
        os_guess,
        os_guess_source,
        os_guess_confidence,
        os_detections,
        script_results,
        metadata
      FROM devices
      WHERE ip_address = $1::inet
      LIMIT 1
      FOR UPDATE
    `,
    [ip],
  );

  if (existingResult.rows.length === 0) {
    const osDetections = mergeOsDetections([], incomingDetection ? [incomingDetection] : []);
    const bestOs = selectBestOs(osDetections, null);

    const insertResult = await client.query(
      `
        INSERT INTO devices (
          ip_address,
          hostname,
          mac_address,
          os_guess,
          os_guess_source,
          os_guess_confidence,
          os_detections,
          script_results,
          metadata,
          first_seen,
          last_seen
        )
        VALUES ($1::inet, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9::jsonb, NOW(), NOW())
        RETURNING id, ip_address
      `,
      [
        ip,
        normalizeText(hostname),
        normalizeText(macAddress),
        bestOs.osGuess,
        bestOs.osGuessSource,
        bestOs.osGuessConfidence,
        JSON.stringify(osDetections),
        JSON.stringify(ensureJsonObject(scriptResults)),
        JSON.stringify(ensureJsonObject(metadata)),
      ],
    );

    return insertResult.rows[0];
  }

  const existing = existingResult.rows[0];
  const osDetections = mergeOsDetections(
    existing.os_detections,
    incomingDetection ? [incomingDetection] : [],
  );
  const bestOs = selectBestOs(osDetections, existing);
  const mergedScripts = mergeJsonValues(existing.script_results, ensureJsonObject(scriptResults));
  const mergedMetadata = mergeJsonValues(existing.metadata, ensureJsonObject(metadata));

  const updateResult = await client.query(
    `
      UPDATE devices
      SET
        hostname = COALESCE($2, hostname),
        mac_address = COALESCE($3, mac_address),
        os_guess = $4,
        os_guess_source = $5,
        os_guess_confidence = $6,
        os_detections = $7::jsonb,
        script_results = $8::jsonb,
        metadata = $9::jsonb,
        last_seen = CASE WHEN $10::boolean THEN NOW() ELSE last_seen END
      WHERE id = $1
      RETURNING id, ip_address
    `,
    [
      existing.id,
      normalizeText(hostname),
      normalizeText(macAddress),
      bestOs.osGuess,
      bestOs.osGuessSource,
      bestOs.osGuessConfidence,
      JSON.stringify(osDetections),
      JSON.stringify(mergedScripts),
      JSON.stringify(mergedMetadata),
      Boolean(touchLastSeen),
    ],
  );

  return updateResult.rows[0];
}

async function upsertPortRecord(client, {
  deviceId,
  port,
  protocol = 'tcp',
  service = null,
  version = null,
  state = 'open',
  metadata = {},
  scriptResults = {},
  source = 'unknown',
  confidence = null,
}) {
  const normalizedPort = Number.parseInt(String(port), 10);

  if (!Number.isInteger(normalizedPort) || normalizedPort < 1 || normalizedPort > 65535) {
    return null;
  }

  const normalizedProtocol = normalizeProtocol(protocol);
  const normalizedState = normalizeText(state) || 'open';
  const normalizedSource = normalizeSource(source);
  const normalizedConfidence = sourceConfidence(normalizedSource, confidence);

  const existingResult = await client.query(
    `
      SELECT
        id,
        service,
        version,
        state,
        metadata,
        script_results,
        last_source,
        source_confidence
      FROM ports
      WHERE device_id = $1
        AND port = $2
        AND protocol = $3
      LIMIT 1
      FOR UPDATE
    `,
    [deviceId, normalizedPort, normalizedProtocol],
  );

  if (existingResult.rows.length === 0) {
    const insertResult = await client.query(
      `
        INSERT INTO ports (
          device_id,
          port,
          protocol,
          service,
          version,
          state,
          metadata,
          script_results,
          last_source,
          source_confidence
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10)
        RETURNING id
      `,
      [
        deviceId,
        normalizedPort,
        normalizedProtocol,
        normalizeText(service),
        normalizeText(version),
        normalizedState,
        JSON.stringify(ensureJsonObject(metadata)),
        JSON.stringify(ensureJsonObject(scriptResults)),
        normalizedSource,
        normalizedConfidence,
      ],
    );

    return insertResult.rows[0];
  }

  const existing = existingResult.rows[0];
  const existingConfidence = clampConfidence(
    existing.source_confidence,
    SOURCE_DEFAULT_CONFIDENCE.unknown,
  );
  const preferIncoming = shouldPreferIncomingSource(
    existing.last_source,
    existingConfidence,
    normalizedSource,
    normalizedConfidence,
  );

  const mergedMetadata = mergeJsonValues(existing.metadata, ensureJsonObject(metadata));
  const mergedScripts = mergeJsonValues(existing.script_results, ensureJsonObject(scriptResults));
  const nextService = choosePreferredText(existing.service, service, preferIncoming);
  const nextVersion = choosePreferredText(existing.version, version, preferIncoming);
  const nextSource = preferIncoming ? normalizedSource : normalizeSource(existing.last_source || normalizedSource);

  const updateResult = await client.query(
    `
      UPDATE ports
      SET
        service = $2,
        version = $3,
        state = $4,
        metadata = $5::jsonb,
        script_results = $6::jsonb,
        last_source = $7,
        source_confidence = GREATEST(COALESCE(source_confidence, 0), $8)
      WHERE id = $1
      RETURNING id
    `,
    [
      existing.id,
      nextService,
      nextVersion,
      normalizedState,
      JSON.stringify(mergedMetadata),
      JSON.stringify(mergedScripts),
      nextSource,
      normalizedConfidence,
    ],
  );

  return updateResult.rows[0];
}

function buildAssetHash(parts) {
  const normalized = toArray(parts)
    .map((part) => String(part || '').trim().toLowerCase())
    .filter(Boolean)
    .join('|');

  return createHash('sha256').update(normalized || 'unknown').digest('hex');
}

module.exports = {
  SOURCE_PRIORITY,
  SOURCE_DEFAULT_CONFIDENCE,
  normalizeSource,
  sourcePriority,
  sourceConfidence,
  mergeJsonValues,
  mergeOsDetections,
  selectBestOs,
  normalizeOsDetection,
  upsertDeviceRecord,
  upsertPortRecord,
  buildAssetHash,
};
