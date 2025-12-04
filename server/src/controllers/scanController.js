const { Device, ScanResult } = require('../models');
const nmapService = require('../services/nmapService');

exports.startScan = async (req, res, next) => {
  try {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'ip required' });

    let device = await Device.findOne({ where: { ip } });
    if (!device) device = await Device.create({ ip, name: ip });

    // trigger scan async (non-blocking)
    nmapService.scanHost(ip)
      .then(async (result) => {
        await ScanResult.create({ deviceId: device.id, raw: result, summary: 'scan complete' });
      })
      .catch(err => console.error('scan error', err));

    res.json({ status: 'scan started' });
  } catch (err) { next(err); }
};

exports.resultsForDevice = async (req, res, next) => {
  try {
    const results = await ScanResult.findAll({ where: { deviceId: req.params.deviceId }, order: [['createdAt','DESC']] });
    res.json(results);
  } catch (err) { next(err); }
};

exports.latestForDevice = async (req, res, next) => {
  try {
    const result = await ScanResult.findOne({ where: { deviceId: req.params.deviceId }, order: [['createdAt','DESC']] });
    if (!result) return res.status(404).json({ error: 'No results' });
    res.json(result);
  } catch (err) { next(err); }
};
