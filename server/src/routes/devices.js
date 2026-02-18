const express = require('express');
const router = express.Router();
const controller = require('../controllers/deviceController');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);
router.get('/', controller.list);
router.get('/:id', controller.get);

module.exports = router;
