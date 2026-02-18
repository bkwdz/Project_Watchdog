function parseIpv4(ip) {
  if (typeof ip !== 'string') {
    return null;
  }

  const parts = ip.split('.');

  if (parts.length !== 4) {
    return null;
  }

  const bytes = parts.map((part) => Number(part));

  if (bytes.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
    return null;
  }

  return bytes;
}

function ipv4ToNumber(ip) {
  const bytes = parseIpv4(ip);

  if (!bytes) {
    return null;
  }

  return ((bytes[0] * 256 + bytes[1]) * 256 + bytes[2]) * 256 + bytes[3];
}

export function isIpv4(ip) {
  return parseIpv4(ip) !== null;
}

export function isCidr(target) {
  if (typeof target !== 'string' || !target.includes('/')) {
    return false;
  }

  const [ip, prefixRaw] = target.split('/');
  const prefix = Number(prefixRaw);

  return isIpv4(ip) && Number.isInteger(prefix) && prefix >= 0 && prefix <= 32;
}

export function cidrContains(cidr, ip) {
  if (!isCidr(cidr) || !isIpv4(ip)) {
    return false;
  }

  const [networkIp, prefixRaw] = cidr.split('/');
  const prefix = Number(prefixRaw);

  const networkInt = ipv4ToNumber(networkIp);
  const ipInt = ipv4ToNumber(ip);

  if (networkInt === null || ipInt === null) {
    return false;
  }

  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;

  return (networkInt & mask) === (ipInt & mask);
}
