function normalizeName(value) {
  return String(value || '').trim().toLowerCase();
}

const PROFILE_DESCRIPTIONS = {
  'full and fast':
    'Balanced vulnerability assessment for common exposed services. Faster than deep profiles while still broad.',
  discovery:
    'Lightweight checks to identify reachable hosts and exposed services with minimal intrusive testing.',
  'host discovery':
    'Fast host reachability discovery focused on identifying live systems before deeper testing.',
  'system discovery':
    'Focused on operating system and hardware fingerprinting for asset identification with very low risk.',
};

export function getGreenboneProfileDescription(name, fallbackComment = '') {
  const key = normalizeName(name);

  if (PROFILE_DESCRIPTIONS[key]) {
    return PROFILE_DESCRIPTIONS[key];
  }

  const fallback = String(fallbackComment || '').trim();
  return fallback || 'Greenbone scan profile.';
}
