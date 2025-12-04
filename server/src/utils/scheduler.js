const cron = require('node-cron');
const nmapService = require('../services/nmapService');
const { Device, ScanResult } = require('../models');

exports.startScheduledJobs = () => {
  // Example: every day at 03:00 run a quick ping/scan for all devices
  cron.schedule('0 3 * * *', async () => {
    console.log('Scheduler: starting daily scans...');
    try {
      const devices = await Device.findAll();
      for (const d of devices) {
        nmapService.scanHost(d.ip)
          .then(async (result) => {
            await ScanResult.create({ deviceId: d.id, raw: result, summary: 'scheduled scan' });
          })
          .catch(err => console.error('scheduled scan error', err));
      }
    } catch (err) {
      console.error('scheduler failed', err);
    }
  });
};
