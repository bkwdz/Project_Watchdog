import api from './api';

// Devices
export const getDevices = () => api.get('/devices');

// Scans
export const startScan = (ip) => api.post('/scans/start', { ip });
export const getScanResults = (deviceId) => api.get(`/scans/results/${deviceId}`);
export const getLatestScan = (deviceId) => api.get(`/scans/latest/${deviceId}`);
