const express = require('express');
const router = express.Router();
const controller = require('../controllers/scanController');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);

router.get('/', controller.listScans);
router.get('/vuln/status', controller.getVulnerabilityStatus);
router.get('/vuln/configs', controller.getVulnerabilityScanConfigs);
router.get('/vuln/settings', controller.getVulnerabilitySettings);
router.put('/vuln/settings', controller.updateVulnerabilitySettings);
router.post('/vuln', controller.createVulnerabilityScan);
router.post('/', controller.createScan);

// Backward-compatible alias for the current frontend.
router.post('/start', controller.startScan);
router.get('/:id', controller.getScan);

module.exports = router;
