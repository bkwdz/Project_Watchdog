import { useCallback, useEffect, useMemo, useState } from 'react';
import { getScanById, getScansList } from '../api/endpoints';
import { getKnownScanIds, rememberScanId, rememberScanIds } from '../utils/scanStore';

function normalizeScan(scan) {
  return {
    ...scan,
    id: Number(scan.id),
  };
}

export default function useScansFeed() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [listUnavailable, setListUnavailable] = useState(false);

  const loadFromKnownIds = useCallback(async () => {
    const ids = getKnownScanIds();

    if (ids.length === 0) {
      return [];
    }

    const settled = await Promise.allSettled(ids.map((id) => getScanById(id)));
    const hydrated = settled
      .filter((result) => result.status === 'fulfilled')
      .map((result) => normalizeScan(result.value));

    rememberScanIds(hydrated.map((scan) => scan.id));

    return hydrated.sort((a, b) => b.id - a.id);
  }, []);

  const loadScans = useCallback(async () => {
    setError('');

    try {
      const data = await getScansList();
      const list = Array.isArray(data) ? data : data?.scans;

      if (!Array.isArray(list)) {
        throw new Error('Unexpected scans list response');
      }

      const normalized = list.map(normalizeScan).sort((a, b) => b.id - a.id);
      setListUnavailable(false);
      setScans(normalized);
      rememberScanIds(normalized.map((scan) => scan.id));
      return normalized;
    } catch (err) {
      const status = err?.response?.status;

      if (status === 404 || status === 405) {
        setListUnavailable(true);
        const fallback = await loadFromKnownIds();
        setScans(fallback);
        return fallback;
      }

      setError(err?.response?.data?.error || 'Unable to load scans');
      return [];
    } finally {
      setLoading(false);
    }
  }, [loadFromKnownIds]);

  const registerScan = useCallback((scan) => {
    const normalized = normalizeScan(scan);
    rememberScanId(normalized.id);

    setScans((current) => {
      const next = [normalized, ...current.filter((item) => item.id !== normalized.id)];
      return next.sort((a, b) => b.id - a.id);
    });
  }, []);

  useEffect(() => {
    void loadScans();
  }, [loadScans]);

  const runningCount = useMemo(
    () => scans.filter((scan) => scan.status === 'running' || scan.status === 'queued').length,
    [scans],
  );

  return {
    scans,
    loading,
    error,
    listUnavailable,
    runningCount,
    loadScans,
    registerScan,
  };
}
