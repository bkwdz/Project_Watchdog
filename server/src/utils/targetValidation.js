function isValidIPv4(value) {
  if (typeof value !== 'string') {
    return false;
  }

  const parts = value.split('.');

  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }

    const num = Number(part);
    return num >= 0 && num <= 255;
  });
}

function isValidCidr(value) {
  if (typeof value !== 'string' || !value.includes('/')) {
    return false;
  }

  const [ip, prefix] = value.split('/');

  if (!isValidIPv4(ip) || !/^\d{1,2}$/.test(prefix || '')) {
    return false;
  }

  const prefixNum = Number(prefix);
  return prefixNum >= 0 && prefixNum <= 32;
}

function isValidTarget(value) {
  if (typeof value !== 'string') {
    return false;
  }

  const target = value.trim();
  return isValidIPv4(target) || isValidCidr(target);
}

module.exports = {
  isValidIPv4,
  isValidCidr,
  isValidTarget,
};
