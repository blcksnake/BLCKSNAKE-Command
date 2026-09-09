import crypto from 'node:crypto';

export const OPERATOR_ROLES = Object.freeze({
  ADMIN: 'admin',
  MODERATOR: 'moderator',
});

const OPERATOR_ROLE_SET = new Set(Object.values(OPERATOR_ROLES));
const USERNAME_PATTERN = /^[A-Za-z0-9._-]{3,32}$/u;
const RESERVED_USERNAME_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const PASSWORD_MINIMUM_CODE_POINTS = 15;
const PASSWORD_MAXIMUM_CODE_POINTS = 128;
const PASSWORD_MAXIMUM_BYTES = 1_024;
const PASSWORD_CONTROL_PATTERN = /[\p{Cc}\p{Cs}]/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const SCRYPT_SCHEME = 'scrypt';
const SCRYPT_VERSION = 1;
const SCRYPT_KEY_BYTES = 32;
const MINIMUM_SALT_BYTES = 16;
const MAXIMUM_SALT_BYTES = 64;
const MAXIMUM_SCRYPT_MEMORY_BYTES = 128 * 1024 * 1024;
const MAXIMUM_SCRYPT_WORK = 2 ** 21;

const DEFAULT_SCRYPT_PARAMETERS = Object.freeze({
  N: 2 ** 17,
  r: 8,
  p: 1,
  saltBytes: 32,
  keyBytes: SCRYPT_KEY_BYTES,
  maxmem: 256 * 1024 * 1024,
});

const COMMON_PASSWORDS = new Set([
  '111111111111111',
  '123456789012345',
  '1234567890123456',
  'adminadminadmin',
  'administrator123',
  'changemechangeme',
  'correcthorsebatterystaple',
  'letmeinletmein',
  'passwordpassword',
  'password123456',
  'qwertyqwerty123',
  'qwertyuiopasdfgh',
  'welcome123456789',
]);

function credentialError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function normalizedComparison(value) {
  return String(value ?? '').normalize('NFC').trim().toLocaleLowerCase('en-US');
}

function compactComparison(value) {
  return normalizedComparison(value).replace(/[^a-z0-9]/gu, '');
}

function passwordIsContextual(password, { username = '', clusterName = '' } = {}) {
  const comparison = normalizedComparison(password);
  const compact = compactComparison(password);
  if (COMMON_PASSWORDS.has(comparison) || COMMON_PASSWORDS.has(compact)) return true;

  const candidates = new Set(['asa crosschat', 'asa-crosschat', 'asacrosschat', 'ark survival ascended']);
  if (typeof username === 'string' && username.trim()) candidates.add(username);
  if (typeof clusterName === 'string' && clusterName.trim()) candidates.add(clusterName);
  for (const candidate of candidates) {
    const literalBase = normalizedComparison(candidate);
    if (literalBase.length >= 3 && comparison === literalBase) return true;
    const base = compactComparison(candidate);
    if (base.length < 3) continue;
    if (compact === base) return true;
    const suffix = compact.slice(base.length);
    if (compact.startsWith(base) && /^(?:admin|owner|password|server|\d{1,8})$/u.test(suffix)) return true;
    const prefix = compact.slice(0, compact.length - base.length);
    if (compact.endsWith(base) && /^(?:admin|owner|password|server|\d{1,8})$/u.test(prefix)) return true;
  }
  return false;
}

function decodeCanonicalBase64Url(value, label) {
  if (typeof value !== 'string' || !BASE64URL_PATTERN.test(value)) {
    throw credentialError(`Password verifier ${label} is malformed.`, 'ERR_OPERATOR_VERIFIER_INVALID');
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) {
    throw credentialError(`Password verifier ${label} is malformed.`, 'ERR_OPERATOR_VERIFIER_INVALID');
  }
  return decoded;
}

function validateScryptWork(N, r, p) {
  if (!Number.isSafeInteger(N) || N < 2 || N > 2 ** 20 || (N & (N - 1)) !== 0) {
    throw credentialError('Password verifier scrypt cost is invalid.', 'ERR_OPERATOR_VERIFIER_INVALID');
  }
  if (!Number.isSafeInteger(r) || r < 1 || r > 32
    || !Number.isSafeInteger(p) || p < 1 || p > 16) {
    throw credentialError('Password verifier scrypt parameters are invalid.', 'ERR_OPERATOR_VERIFIER_INVALID');
  }
  const memoryBytes = 128 * N * r;
  const work = N * r * p;
  if (!Number.isSafeInteger(memoryBytes) || memoryBytes > MAXIMUM_SCRYPT_MEMORY_BYTES
    || !Number.isSafeInteger(work) || work > MAXIMUM_SCRYPT_WORK) {
    throw credentialError('Password verifier scrypt parameters exceed safety limits.', 'ERR_OPERATOR_VERIFIER_INVALID');
  }
  return { N, r, p, memoryBytes };
}

function normalizeServiceParameters(input = {}) {
  if (!isRecord(input)) throw credentialError('Password service parameters must be an object.', 'ERR_OPERATOR_PASSWORD_CONFIG');
  const parameters = { ...DEFAULT_SCRYPT_PARAMETERS, ...input };
  let work;
  try { work = validateScryptWork(parameters.N, parameters.r, parameters.p); }
  catch (error) { throw credentialError(error.message, 'ERR_OPERATOR_PASSWORD_CONFIG'); }
  if (!Number.isSafeInteger(parameters.saltBytes)
    || parameters.saltBytes < MINIMUM_SALT_BYTES || parameters.saltBytes > MAXIMUM_SALT_BYTES) {
    throw credentialError('Password service saltBytes must be an integer from 16 to 64.', 'ERR_OPERATOR_PASSWORD_CONFIG');
  }
  if (parameters.keyBytes !== SCRYPT_KEY_BYTES) {
    throw credentialError(`Password service keyBytes must be ${SCRYPT_KEY_BYTES}.`, 'ERR_OPERATOR_PASSWORD_CONFIG');
  }
  if (!Number.isSafeInteger(parameters.maxmem) || parameters.maxmem < work.memoryBytes + (1024 * 1024)
    || parameters.maxmem > 1024 * 1024 * 1024) {
    throw credentialError('Password service maxmem is outside its safe range.', 'ERR_OPERATOR_PASSWORD_CONFIG');
  }
  return Object.freeze({
    N: parameters.N,
    r: parameters.r,
    p: parameters.p,
    saltBytes: parameters.saltBytes,
    keyBytes: parameters.keyBytes,
    maxmem: parameters.maxmem,
  });
}

function defaultDerive(password, salt, keyLength, options) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keyLength, options, (error, derivedKey) => {
      if (error) reject(error);
      else resolve(derivedKey);
    });
  });
}

function verificationPassword(value) {
  if (typeof value !== 'string' || value.length > 2_048) {
    return { password: 'invalid operator password', valid: false };
  }
  let password;
  try { password = value.normalize('NFC'); }
  catch { return { password: 'invalid operator password', valid: false }; }
  const codePoints = Array.from(password).length;
  const valid = codePoints >= PASSWORD_MINIMUM_CODE_POINTS
    && codePoints <= PASSWORD_MAXIMUM_CODE_POINTS
    && Buffer.byteLength(password, 'utf8') <= PASSWORD_MAXIMUM_BYTES
    && !PASSWORD_CONTROL_PATTERN.test(password);
  return { password: valid ? password : 'invalid operator password', valid };
}

export function normalizeOperatorUsername(value) {
  if (typeof value !== 'string') {
    throw credentialError('Operator username must be text.', 'ERR_OPERATOR_USERNAME_INVALID');
  }
  const username = value.trim();
  const key = username.toLocaleLowerCase('en-US');
  if (!USERNAME_PATTERN.test(username) || RESERVED_USERNAME_KEYS.has(key)) {
    throw credentialError('Operator username must be 3-32 ASCII letters, numbers, dots, underscores, or hyphens.', 'ERR_OPERATOR_USERNAME_INVALID');
  }
  return { username, key };
}

export function normalizeOperatorRole(value) {
  if (typeof value !== 'string') {
    throw credentialError('Operator role must be admin or moderator.', 'ERR_OPERATOR_ROLE_INVALID');
  }
  const role = value.trim().toLocaleLowerCase('en-US');
  if (!OPERATOR_ROLE_SET.has(role)) {
    throw credentialError('Operator role must be admin or moderator.', 'ERR_OPERATOR_ROLE_INVALID');
  }
  return role;
}

export function validatePasswordVerifier(record) {
  if (!isRecord(record)) {
    throw credentialError('Password verifier is malformed.', 'ERR_OPERATOR_VERIFIER_INVALID');
  }
  const allowed = new Set(['scheme', 'version', 'N', 'r', 'p', 'salt', 'hash']);
  if (Object.keys(record).some((key) => !allowed.has(key))
    || record.scheme !== SCRYPT_SCHEME || record.version !== SCRYPT_VERSION) {
    throw credentialError('Password verifier version or scheme is unsupported.', 'ERR_OPERATOR_VERIFIER_INVALID');
  }
  validateScryptWork(record.N, record.r, record.p);
  const salt = decodeCanonicalBase64Url(record.salt, 'salt');
  const hash = decodeCanonicalBase64Url(record.hash, 'hash');
  if (salt.length < MINIMUM_SALT_BYTES || salt.length > MAXIMUM_SALT_BYTES || hash.length !== SCRYPT_KEY_BYTES) {
    throw credentialError('Password verifier material has an invalid length.', 'ERR_OPERATOR_VERIFIER_INVALID');
  }
  return {
    scheme: SCRYPT_SCHEME,
    version: SCRYPT_VERSION,
    N: record.N,
    r: record.r,
    p: record.p,
    salt: salt.toString('base64url'),
    hash: hash.toString('base64url'),
  };
}

export function validateOperatorPassword(password, { username = '', clusterName = '' } = {}) {
  if (typeof password !== 'string') {
    throw credentialError('Operator password must be text.', 'ERR_OPERATOR_PASSWORD_INVALID');
  }
  if (password.length > 2_048) {
    throw credentialError('Operator password must contain at most 128 Unicode characters.', 'ERR_OPERATOR_PASSWORD_INVALID');
  }
  let normalized;
  try { normalized = password.normalize('NFC'); }
  catch { throw credentialError('Operator password contains invalid Unicode.', 'ERR_OPERATOR_PASSWORD_INVALID'); }
  const codePoints = Array.from(normalized).length;
  if (codePoints < PASSWORD_MINIMUM_CODE_POINTS || codePoints > PASSWORD_MAXIMUM_CODE_POINTS) {
    throw credentialError('Operator password must contain 15-128 Unicode characters.', 'ERR_OPERATOR_PASSWORD_INVALID');
  }
  if (Buffer.byteLength(normalized, 'utf8') > PASSWORD_MAXIMUM_BYTES) {
    throw credentialError('Operator password must encode to at most 1024 bytes.', 'ERR_OPERATOR_PASSWORD_INVALID');
  }
  if (PASSWORD_CONTROL_PATTERN.test(normalized)) {
    throw credentialError('Operator password cannot contain control characters or invalid Unicode.', 'ERR_OPERATOR_PASSWORD_INVALID');
  }
  if (passwordIsContextual(normalized, { username, clusterName })) {
    throw credentialError('Operator password is too common or too closely related to this account.', 'ERR_OPERATOR_PASSWORD_BLOCKED');
  }
  return normalized;
}

export class OperatorPasswordService {
  constructor({
    derive = defaultDerive,
    randomBytes = crypto.randomBytes,
    params = {},
    maxConcurrent = 2,
    maxQueue = 32,
  } = {}) {
    if (typeof derive !== 'function' || typeof randomBytes !== 'function') {
      throw credentialError('Password service dependencies must be functions.', 'ERR_OPERATOR_PASSWORD_CONFIG');
    }
    if (!Number.isSafeInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 16
      || !Number.isSafeInteger(maxQueue) || maxQueue < 0 || maxQueue > 1_000) {
      throw credentialError('Password service concurrency limits are invalid.', 'ERR_OPERATOR_PASSWORD_CONFIG');
    }
    this.derive = derive;
    this.randomBytes = randomBytes;
    this.params = normalizeServiceParameters(params);
    this.maxConcurrent = maxConcurrent;
    this.maxQueue = maxQueue;
    this.active = 0;
    this.queue = [];
    const dummySalt = this.randomBytes(this.params.saltBytes);
    if (!Buffer.isBuffer(dummySalt) || dummySalt.length !== this.params.saltBytes) {
      throw credentialError(`Random generator must return ${this.params.saltBytes} bytes.`, 'ERR_OPERATOR_RANDOM_INVALID');
    }
    this.dummyVerifier = Object.freeze({
      scheme: SCRYPT_SCHEME,
      version: SCRYPT_VERSION,
      N: this.params.N,
      r: this.params.r,
      p: this.params.p,
      salt: dummySalt.toString('base64url'),
      hash: Buffer.alloc(this.params.keyBytes).toString('base64url'),
    });
  }

  async acquire() {
    if (this.active < this.maxConcurrent) {
      this.active += 1;
      return;
    }
    if (this.queue.length >= this.maxQueue) {
      throw credentialError('Password verification capacity is temporarily exhausted.', 'ERR_OPERATOR_PASSWORD_BUSY');
    }
    await new Promise((resolve) => { this.queue.push(resolve); });
  }

  release() {
    const next = this.queue.shift();
    if (next) next();
    else this.active -= 1;
  }

  async deriveKey(password, salt, parameters) {
    await this.acquire();
    const passwordBytes = Buffer.from(password, 'utf8');
    try {
      const derived = await this.derive(passwordBytes, salt, SCRYPT_KEY_BYTES, {
        N: parameters.N,
        r: parameters.r,
        p: parameters.p,
        maxmem: Math.max(this.params.maxmem, (128 * parameters.N * parameters.r) + (1024 * 1024)),
      });
      if (!Buffer.isBuffer(derived) && !(derived instanceof Uint8Array)) {
        throw credentialError('Password derivation returned invalid material.', 'ERR_OPERATOR_PASSWORD_DERIVE');
      }
      const key = Buffer.from(derived);
      if (key.length !== SCRYPT_KEY_BYTES) {
        key.fill(0);
        throw credentialError(`Password derivation must return ${SCRYPT_KEY_BYTES} bytes.`, 'ERR_OPERATOR_PASSWORD_DERIVE');
      }
      return key;
    } finally {
      passwordBytes.fill(0);
      this.release();
    }
  }

  async hash(password, context = {}) {
    const normalized = validateOperatorPassword(password, context);
    const salt = this.randomBytes(this.params.saltBytes);
    if (!Buffer.isBuffer(salt) || salt.length !== this.params.saltBytes) {
      throw credentialError(`Random generator must return ${this.params.saltBytes} bytes.`, 'ERR_OPERATOR_RANDOM_INVALID');
    }
    const derived = await this.deriveKey(normalized, salt, this.params);
    try {
      return validatePasswordVerifier({
        scheme: SCRYPT_SCHEME,
        version: SCRYPT_VERSION,
        N: this.params.N,
        r: this.params.r,
        p: this.params.p,
        salt: salt.toString('base64url'),
        hash: derived.toString('base64url'),
      });
    } finally {
      derived.fill(0);
    }
  }

  async verify(password, verifier) {
    const dummy = verifier == null;
    const normalizedVerifier = dummy ? this.dummyVerifier : validatePasswordVerifier(verifier);
    const candidate = verificationPassword(password);
    const salt = Buffer.from(normalizedVerifier.salt, 'base64url');
    const expected = Buffer.from(normalizedVerifier.hash, 'base64url');
    const derived = await this.deriveKey(candidate.password, salt, normalizedVerifier);
    try {
      const matches = crypto.timingSafeEqual(derived, expected);
      return !dummy && candidate.valid && matches;
    } finally {
      derived.fill(0);
      expected.fill(0);
    }
  }
}

export function generateTemporaryPassword(randomBytes = crypto.randomBytes) {
  if (typeof randomBytes !== 'function') {
    throw credentialError('Password generator must be a function.', 'ERR_OPERATOR_RANDOM_INVALID');
  }
  const bytes = randomBytes(24);
  if (!Buffer.isBuffer(bytes) || bytes.length !== 24) {
    throw credentialError('Password generator must return 24 bytes.', 'ERR_OPERATOR_RANDOM_INVALID');
  }
  return bytes.toString('base64url');
}
