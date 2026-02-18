const express = require('express');
const router = express.Router();
const controller = require('../controllers/scanController');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);

router.post('/', controller.createScan);
router.get('/:id', controller.getScan);

// Backward-compatible alias for the current frontend.
router.post('/start', controller.startScan);

module.exports = router;