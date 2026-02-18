import api from './api';

export async function getDevices() {
  const response = await api.get('/devices');
  return response.data;
}

export async function getDeviceById(deviceId) {
  const response = await api.get(`/devices/${deviceId}`);
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
