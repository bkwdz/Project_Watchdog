const express = require('express');
const router = express.Router();
const controller = require('../controllers/deviceController');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);
router.get('/summary', controller.summary);
router.get('/', controller.list);
router.patch('/:id', controller.update);
router.get('/:id', controller.get);

module.exports = router;
