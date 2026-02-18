const SCAN_PROFILES = {
  discovery: ['-sn'],
  quick: ['-F'],
  standard: ['-sS', '-sV'],
  aggressive: ['-A'],
  full: ['-p-', '-sS', '-sV'],
};

function isValidScanType(scanType) {
  return Object.prototype.hasOwnProperty.call(SCAN_PROFILES, scanType);
}

function getScanArgs(scanType) {
  if (!isValidScanType(scanType)) {
    throw new Error(`Unsupported scan type: ${scanType}`);
  }

  return SCAN_PROFILES[scanType];
}

module.exports = {
  SCAN_PROFILES,
  isValidScanType,
  getScanArgs,
};
