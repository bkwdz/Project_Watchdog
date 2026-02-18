const STORAGE_KEY = 'watchdog_known_scan_ids_v1';

function safeParse(json) {
  try {
    return JSON.parse(json);
  } catch {
    return [];
  }
}

export function getKnownScanIds() {
  const raw = localStorage.getItem(STORAGE_KEY);

  if (!raw) {
    return [];
  }

  const parsed = safeParse(raw);

  if (!Array.isArray(parsed)) {
    return [];
  }

  return parsed
    .map((value) => Number(value))
    .filter((value) => Number.isInteger(value) && value > 0)
    .slice(0, 100);
}

export function rememberScanId(scanId) {
  const normalized = Number(scanId);

  if (!Number.isInteger(normalized) || normalized <= 0) {
    return;
  }

  const known = getKnownScanIds();
  const next = [normalized, ...known.filter((id) => id !== normalized)].slice(0, 100);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
}

export function rememberScanIds(scanIds) {
  const nextIds = scanIds
    .map((value) => Number(value))
    .filter((value) => Number.isInteger(value) && value > 0);

  if (nextIds.length === 0) {
    return;
  }

  const known = getKnownScanIds();
  const merged = [...nextIds, ...known.filter((id) => !nextIds.includes(id))].slice(0, 100);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(merged));
}
