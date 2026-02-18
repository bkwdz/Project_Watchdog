const express = require('express');
const { testScannerConnection } = require('../services/openvasService');

const router = express.Router();

router.get('/health', async (_req, res) => {
  const reachable = await testScannerConnection();

  return res.json({
    scanner: reachable ? 'reachable' : 'unreachable',
  });
});

module.exports = router;

