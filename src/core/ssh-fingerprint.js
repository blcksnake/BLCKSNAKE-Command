const HEX_SHA256_PATTERN = /^[a-f0-9]{64}$/iu;
const OPENSSH_SHA256_PATTERN = /^SHA256:([A-Za-z0-9+/]{43}=?)$/u;

export function normalizeSshSha256Fingerprint(value) {
  const fingerprint = String(value ?? '').trim();
  if (HEX_SHA256_PATTERN.test(fingerprint)) return fingerprint.toLocaleLowerCase('en-US');
  const match = fingerprint.match(OPENSSH_SHA256_PATTERN);
  if (!match) return null;
  const bytes = Buffer.from(match[1], 'base64');
  if (bytes.length !== 32 || bytes.toString('base64').replace(/=+$/u, '') !== match[1].replace(/=+$/u, '')) return null;
  return bytes.toString('hex');
}

export function opensshSshSha256Fingerprint(value) {
  const normalized = normalizeSshSha256Fingerprint(value);
  return normalized ? `SHA256:${Buffer.from(normalized, 'hex').toString('base64').replace(/=+$/u, '')}` : null;
}
