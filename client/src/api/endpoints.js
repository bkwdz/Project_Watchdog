import api from './api';

export async function getDevices() {
  const response = await api.get('/devices');
  return response.data;
}

export async function getDevicesSummary() {
  const response = await api.get('/devices/summary');
  return response.data;
}

export async function getDeviceById(deviceId) {
  const response = await api.get(`/devices/${deviceId}`);
  return response.data;
}

export async function updateDevice(deviceId, payload) {
  const response = await api.patch(`/devices/${deviceId}`, payload);
  return response.data;
}

export async function createScan({ target, scan_type }) {
  const response = await api.post('/scans', { target, scan_type });
  return response.data;
}

export async function createScanLegacy({ ip, scan_type }) {
  const response = await api.post('/scans/start', { ip, scan_type });
  return response.data;
}

export async function getScanById(scanId) {
  const response = await api.get(`/scans/${scanId}`);
  return response.data;
}

export async function getScansList() {
  const response = await api.get('/scans');
  return response.data;
}

export async function createVulnerabilityScan(
  target,
  scanConfigId = '',
  {
    tcpPorts = '',
    udpPorts = '',
    credentials = null,
  } = {},
) {
  const payload = { target };

  if (scanConfigId) {
    payload.scan_config_id = scanConfigId;
  }

  if (typeof tcpPorts === 'string') {
    payload.tcp_ports = tcpPorts;
  }

  if (typeof udpPorts === 'string') {
    payload.udp_ports = udpPorts;
  }

  if (credentials && typeof credentials === 'object') {
    payload.credentials = credentials;
  }

  const response = await api.post('/scans/vuln', payload);
  return response.data;
}

export async function refreshDeviceFromGreenboneHistory(
  deviceId,
  {
    scanId = null,
    mode = 'selected',
  } = {},
) {
  const payload = {
    mode: String(mode || 'selected').trim().toLowerCase() === 'all' ? 'all' : 'selected',
  };

  if (Number.isInteger(Number(scanId)) && Number(scanId) > 0) {
    payload.scan_id = Number(scanId);
  }

  const response = await api.post(`/scans/vuln/refresh-device/${deviceId}`, payload);
  return response.data;
}

export async function getVulnerabilityScannerStatus() {
  const response = await api.get('/scans/vuln/status');
  return response.data;
}

export async function getVulnerabilityScanConfigs() {
  const response = await api.get('/scans/vuln/configs');
  return response.data;
}

export async function getVulnerabilityCredentials(type) {
  const response = await api.get('/scans/vuln/credentials', {
    params: {
      type,
    },
  });
  return response.data;
}

export async function getVulnerabilitySettings() {
  const response = await api.get('/scans/vuln/settings');
  return response.data;
}

export async function updateVulnerabilitySettings(payload) {
  const response = await api.put('/scans/vuln/settings', payload);
  return response.data;
}
