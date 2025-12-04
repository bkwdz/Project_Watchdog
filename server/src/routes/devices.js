const express = require('express');
const router = express.Router();
const controller = require('../controllers/deviceController');
const { requireAuth } = require('../middleware/auth');


router.use(requireAuth); // protect all device endpoints
router.get('/', controller.list);
router.post('/', controller.create);
router.get('/:id', controller.get);
router.put('/:id', controller.update);
router.delete('/:id', controller.remove);

module.exports = router;
