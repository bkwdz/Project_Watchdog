const express = require('express');
const router = express.Router();
const controller = require('../controllers/scanController');

// Import the middleware
const { requireAuth, requireRole } = require('../middleware/auth');

// Protect scan-starting so only logged-in users can trigger scans
router.post('/start', requireAuth, controller.startScan);

//  Protect results 
router.get('/results/:deviceId', requireAuth, controller.resultsForDevice);

// Protect latest scan result
router.get('/latest/:deviceId', requireAuth, controller.latestForDevice);

// admin-only route
router.post('/admin-only', requireAuth, requireRole('admin'), (req, res) => {
    res.json({ message: "Admin route OK" });
});

// Public test route I SHOULD REMOVE LATER
router.get('/', (req, res) => {
    res.json({ message: "Scans API OK" });
});

module.exports = router;
