import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import {
  OPERATOR_ROLES,
  normalizeOperatorRole,
  normalizeOperatorUsername,
  validatePasswordVerifier,
} from '../../core/operator-credentials.js';
import { normalizeName, normalizeWhitespace } from '../../core/sanitize.js';
import { moderationNoteId, normalizeModerationNoteType, validModerationNoteId } from '../../core/moderation-notes.js';
import { normalizeOperatorActionGrants } from '../../core/operator-permissions.js';
import {
  MAX_ITEM_PACKAGES, cleanItemPackageId, cloneItemPackage, normalizeItemPackageInput,
  normalizePersistedItemPackages,
} from '../../core/item-packages.js';
import { createBundledItemPackages } from '../../core/default-item-packages.js';
import {
  cleanDiscordUserId,
  cleanItemKey,
  cleanOperatorId,
  cleanOperatorRevision,
  cleanOperatorTimestamp,
  cleanPresetName,
} from '../../core/state-values.js';

const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const SERVER_ID_PATTERN = /^[a-z0-9_-]{1,32}$/i;
const ACCOUNT_ID_PATTERN = /^[A-Za-z0-9:_-]{1,128}$/;
const PLAYER_DATA_ID_MAX = 4_294_967_295n;
const MAX_ITEM_FAVORITES = 25;
const MAX_ITEM_PRESETS = 20;
const MAX_RECENT_ITEMS = 10;
const MAX_OPERATOR_ACCOUNTS = 64;
const MAX_INSTALLATION_SETTINGS_BYTES = 1024 * 1024;
const MAX_INSTALLATION_SETTINGS_DEPTH = 32;
const MAX_INSTALLATION_SETTINGS_NODES = 25_000;
const MAX_INSTALLATION_SETTINGS_ENTRIES = 10_000;
const MAX_INSTALLATION_SETTINGS_KEY_BYTES = 256;
const OPERATOR_ACTOR_PATTERN = /^(?:bootstrap|system|local:tls-rotate|op_[A-Za-z0-9_-]{22})$/;
const OPERATOR_ACCOUNT_FIELDS = new Set([
  'id', 'username', 'usernameKey', 'role', 'enabled', 'owner', 'passwordVerifier',
  'mustChangePassword', 'authRevision', 'recordRevision', 'createdAt', 'updatedAt',
  'createdBy', 'updatedBy', 'actionGrants',
]);
const OPERATOR_UPDATE_FIELDS = new Set([
  'role', 'enabled', 'passwordVerifier', 'mustChangePassword', 'updatedAt', 'updatedBy', 'actionGrants',
]);
const RESERVED_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const INSTALLATION_SETTINGS_INPUT_FIELDS = new Set(['version', 'configured', 'configuration']);
const INSTALLATION_SETTINGS_FIELDS = new Set([
  ...INSTALLATION_SETTINGS_INPUT_FIELDS, 'revision', 'createdAt', 'updatedAt', 'updatedBy',
]);
const INSTALLATION_SETTINGS_CONTROL_PATTERN = /[\u0000-\u001F\u007F-\u009F\u2028\u2029]/u;
const STATE_ENVELOPE_FORMAT = 'asa-crosschat-state';
const STATE_ENVELOPE_VERSION = 1;
const STATE_CIPHER = 'aes-256-gcm';
const STATE_AAD = Buffer.from(`${STATE_ENVELOPE_FORMAT}:v${STATE_ENVELOPE_VERSION}:${STATE_CIPHER}`, 'utf8');

async function readBoundedUtf8(file, maximum, { label, privateMode = false } = {}) {
  const handle = await fs.open(file, 'r');
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw new Error(`${label} path must be a regular file`);
    if (before.size > maximum) throw new Error(`${label} file exceeds the ${maximum}-byte safety limit`);
    if (privateMode && process.platform !== 'win32' && (before.mode & 0o077) !== 0) {
      throw new Error(`${label} file permissions must be 0600 or stricter`);
    }

    const chunks = []; let total = 0; let position = 0;
    while (true) {
      const capacity = Math.min(64 * 1024, maximum + 1 - total);
      if (capacity <= 0) throw new Error(`${label} file exceeds the ${maximum}-byte safety limit`);
      const buffer = Buffer.allocUnsafe(capacity);
      const { bytesRead } = await handle.read(buffer, 0, capacity, position);
      if (!bytesRead) break;
      chunks.push(buffer.subarray(0, bytesRead)); total += bytesRead; position += bytesRead;
      if (total > maximum) throw new Error(`${label} file exceeds the ${maximum}-byte safety limit`);
    }

    const after = await handle.stat();
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
      throw new Error(`${label} file changed while it was being read`);
    }
    return Buffer.concat(chunks, total).toString('utf8');
  } finally {
    await handle.close();
  }
}

function decodeEncryptionKey(value) {
  const text = String(value ?? '').trim();
  let key;
  if (/^(?:base64:)?[A-Za-z0-9+/]{43}=$/.test(text)) {
    key = Buffer.from(text.replace(/^base64:/, ''), 'base64');
  } else if (/^(?:hex:)?[a-f0-9]{64}$/i.test(text)) {
    key = Buffer.from(text.replace(/^hex:/i, ''), 'hex');
  } else {
    throw new Error('State encryption key must be exactly 32 bytes encoded as base64 or hexadecimal');
  }
  if (key.length !== 32) throw new Error('State encryption key must decode to exactly 32 bytes');
  return key;
}

function decodeEnvelopePart(value, label, expectedBytes = null) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new Error(`Encrypted state ${label} is malformed`);
  }
  const bytes = Buffer.from(value, 'base64');
  if (expectedBytes != null && bytes.length !== expectedBytes) throw new Error(`Encrypted state ${label} is malformed`);
  return bytes;
}

function isEncryptedEnvelope(value) {
  return value?.format === STATE_ENVELOPE_FORMAT;
}

function encryptState(serialized, key, randomBytes) {
  const iv = randomBytes(12);
  if (!Buffer.isBuffer(iv) || iv.length !== 12) throw new Error('State encryption IV generator must return 12 bytes');
  const cipher = crypto.createCipheriv(STATE_CIPHER, key, iv, { authTagLength: 16 });
  cipher.setAAD(STATE_AAD);
  const ciphertext = Buffer.concat([cipher.update(serialized, 'utf8'), cipher.final()]);
  return {
    format: STATE_ENVELOPE_FORMAT,
    version: STATE_ENVELOPE_VERSION,
    cipher: STATE_CIPHER,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

function decryptState(envelope, key) {
  if (envelope?.version !== STATE_ENVELOPE_VERSION || envelope?.cipher !== STATE_CIPHER) {
    throw new Error('Encrypted state format or cipher is unsupported');
  }
  const iv = decodeEnvelopePart(envelope.iv, 'IV', 12);
  const tag = decodeEnvelopePart(envelope.tag, 'authentication tag', 16);
  const ciphertext = decodeEnvelopePart(envelope.ciphertext, 'ciphertext');
  try {
    const decipher = crypto.createDecipheriv(STATE_CIPHER, key, iv, { authTagLength: 16 });
    decipher.setAAD(STATE_AAD); decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    throw new Error('Encrypted state could not be authenticated; verify the configured key');
  }
}

function cleanServerId(value) {
  const id = String(value ?? '').trim();
  if (!SERVER_ID_PATTERN.test(id)) throw new Error('Server ID must be 1-32 letters, numbers, underscores, or hyphens');
  return id;
}

function cleanAccountId(value) {
  const id = String(value ?? '').trim();
  if (!ACCOUNT_ID_PATTERN.test(id)) throw new Error('A valid EOS/account ID is required');
  return /^[a-f0-9]{32}$/i.test(id) ? id.toLocaleLowerCase('en-US') : id;
}

function cleanPlayerDataId(value) {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) {
    throw new Error('PlayerDataID must be an integer from 1 to 4294967295');
  }
  const text = String(value ?? '').trim();
  if (!/^\d+$/.test(text)) throw new Error('PlayerDataID must be an integer from 1 to 4294967295');
  const id = BigInt(text);
  if (id < 1n || id > PLAYER_DATA_ID_MAX) throw new Error('PlayerDataID must be an integer from 1 to 4294967295');
  return id.toString();
}

function playerDataKey(serverId, eosId) {
  return `${cleanServerId(serverId)}:${cleanAccountId(eosId)}`;
}

function presetIdentity(value) { return cleanPresetName(value).toLocaleLowerCase('en-US'); }

function cleanQuantity(value) {
  if (!Number.isInteger(value) || value < 1 || value > 10_000) throw new Error('Preset quantity must be an integer from 1 to 10000');
  return value;
}

function cleanQuality(value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 100) {
    throw new Error('Preset quality must be a finite number from 0 to 100');
  }
  return Object.is(value, -0) ? 0 : value;
}

function cleanBlueprint(value) {
  if (typeof value !== 'boolean') throw new Error('Preset blueprint must be a boolean');
  return value;
}

function cleanTimestamp(value, fallback = 0) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : fallback;
}

function cleanPreset(value, fallbackName) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Item preset must be an object');
  const name = cleanPresetName(value.name ?? fallbackName);
  const updatedAt = cleanTimestamp(value.updatedAt);
  return {
    name,
    itemKey: cleanItemKey(value.itemKey),
    quantity: cleanQuantity(value.quantity),
    quality: cleanQuality(value.quality),
    blueprint: cleanBlueprint(value.blueprint),
    createdAt: cleanTimestamp(value.createdAt, updatedAt),
    updatedAt,
  };
}

function uniqueItemKeys(value, maximum) {
  if (!Array.isArray(value)) return [];
  const keys = [];
  for (const candidate of value) {
    try {
      const key = cleanItemKey(candidate);
      if (!keys.includes(key)) keys.push(key);
      if (keys.length >= maximum) break;
    } catch { /* Invalid optional preferences are discarded during load. */ }
  }
  return keys;
}

function normalizeItemPreferences(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const normalized = {};
  for (const [rawUserId, rawPreferences] of Object.entries(value)) {
    try {
      const userId = cleanDiscordUserId(rawUserId);
      const preferences = Array.isArray(rawPreferences) ? { favorites: rawPreferences } : rawPreferences;
      if (!preferences || typeof preferences !== 'object') continue;
      const favorites = uniqueItemKeys(preferences.favorites, MAX_ITEM_FAVORITES);
      const recent = uniqueItemKeys(preferences.recent, MAX_RECENT_ITEMS);
      const rawPresets = Array.isArray(preferences.presets)
        ? preferences.presets.map((preset) => [undefined, preset])
        : preferences.presets && typeof preferences.presets === 'object'
          ? Object.entries(preferences.presets)
          : [];
      const presets = [];
      const identities = new Set();
      for (const [fallbackName, rawPreset] of rawPresets) {
        try {
          const preset = cleanPreset(rawPreset, fallbackName);
          const identity = presetIdentity(preset.name);
          if (!identities.has(identity)) { identities.add(identity); presets.push(preset); }
          if (presets.length >= MAX_ITEM_PRESETS) break;
        } catch { /* Invalid optional presets are discarded during load. */ }
      }
      if (favorites.length || recent.length || presets.length) normalized[userId] = { favorites, recent, presets };
    } catch { /* Invalid optional preference owners are discarded during load. */ }
  }
  return normalized;
}

function emptyItemPreferences() { return { favorites: [], recent: [], presets: [] }; }

function clonePreset(preset) { return { ...preset }; }

function cloneItemPreferences(preferences = emptyItemPreferences()) {
  return {
    favorites: [...(preferences.favorites ?? [])],
    recent: [...(preferences.recent ?? [])],
    presets: (preferences.presets ?? []).map(clonePreset),
  };
}

function hasItemPreferences(preferences) {
  return preferences.favorites.length > 0 || preferences.recent.length > 0 || preferences.presets.length > 0;
}

function normalizePlayerDataIds(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const normalized = {};
  const claimOwners = new Map();
  const conflictingClaims = new Set();
  for (const [key, entry] of Object.entries(value)) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const separator = key.indexOf(':');
    if (separator < 1) continue;
    try {
      const serverId = cleanServerId(key.slice(0, separator));
      const canonicalKey = playerDataKey(serverId, key.slice(separator + 1));
      const playerDataId = cleanPlayerDataId(entry.playerDataId);
      const claim = `${serverId}\0${playerDataId}`;
      if (conflictingClaims.has(claim)) continue;
      const previousOwner = claimOwners.get(claim);
      if (previousOwner) {
        delete normalized[previousOwner];
        claimOwners.delete(claim);
        conflictingClaims.add(claim);
        continue;
      }
      normalized[canonicalKey] = {
        playerDataId,
        displayName: typeof entry.displayName === 'string' ? normalizeWhitespace(entry.displayName) : '',
        characterName: typeof entry.characterName === 'string' ? normalizeWhitespace(entry.characterName) : '',
        actor: typeof entry.actor === 'string' ? normalizeWhitespace(entry.actor) : '',
        updatedAt: Number.isFinite(entry.updatedAt) ? entry.updatedAt : 0,
      };
      claimOwners.set(claim, canonicalKey);
    } catch {
      // Optional cached mappings must not prevent the service from starting.
    }
  }
  return normalized;
}

function normalizeStarterPackageGrants(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const output = {}; const allowedStates = new Set(['pending', 'attempted', 'succeeded', 'skipped']);
  for (const [rawEosId, rawGrant] of Object.entries(value)) {
    try {
      const eosId = String(rawEosId).trim().toLocaleLowerCase('en-US');
      if (!/^[a-f0-9]{32}$/u.test(eosId) || !rawGrant || typeof rawGrant !== 'object' || Array.isArray(rawGrant)
        || typeof rawGrant.eligible !== 'boolean' || !Number.isSafeInteger(rawGrant.observedAt) || rawGrant.observedAt < 0
        || !rawGrant.packages || typeof rawGrant.packages !== 'object' || Array.isArray(rawGrant.packages)) continue;
      const packages = {};
      for (const [rawPackageId, rawPackage] of Object.entries(rawGrant.packages).slice(0, MAX_ITEM_PACKAGES)) {
        const packageId = cleanItemPackageId(rawPackageId);
        if (!rawPackage || typeof rawPackage !== 'object' || Array.isArray(rawPackage)
          || !Number.isSafeInteger(rawPackage.revision) || rawPackage.revision < 1
          || !Array.isArray(rawPackage.itemStates) || rawPackage.itemStates.length < 1 || rawPackage.itemStates.length > 50
          || rawPackage.itemStates.some((status) => !allowedStates.has(status))) continue;
        packages[packageId] = { revision: rawPackage.revision, itemStates: [...rawPackage.itemStates] };
      }
      output[eosId] = { eligible: rawGrant.eligible, observedAt: rawGrant.observedAt, packages };
    } catch { /* Invalid optional starter-delivery records are discarded during load. */ }
  }
  return output;
}

function operatorRecord(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value;
}

function exactOperatorFields(value, allowed, label, optional = new Set()) {
  const keys = Object.keys(value);
  for (const key of keys) if (!allowed.has(key)) throw new Error(`${label} contains an unsupported field`);
  for (const key of allowed) if (!optional.has(key) && !Object.hasOwn(value, key)) throw new Error(`${label} is missing a required field`);
}

function cleanOperatorActor(value, label) {
  if (typeof value !== 'string' || !OPERATOR_ACTOR_PATTERN.test(value)) throw new Error(`${label} is invalid`);
  return value;
}

function clonePasswordVerifier(value) {
  const verifier = validatePasswordVerifier(value);
  return { ...verifier };
}

function passwordVerifiersEqual(left, right) {
  return left.scheme === right.scheme && left.version === right.version
    && left.N === right.N && left.r === right.r && left.p === right.p
    && left.salt === right.salt && left.hash === right.hash;
}

function normalizeOperatorAccount(value, directoryKey, { allowMissingUpdatedBy = false } = {}) {
  const account = operatorRecord(value, 'Operator account');
  exactOperatorFields(
    account,
    OPERATOR_ACCOUNT_FIELDS,
    'Operator account',
    allowMissingUpdatedBy ? new Set(['updatedBy', 'actionGrants']) : new Set(['actionGrants']),
  );
  const identity = normalizeOperatorUsername(account.username);
  if (account.username !== identity.username || account.usernameKey !== identity.key || directoryKey !== identity.key) {
    throw new Error('Operator account username fields are inconsistent');
  }
  const role = normalizeOperatorRole(account.role);
  if (role !== account.role) throw new Error('Operator account role is not canonical');
  if (typeof account.enabled !== 'boolean' || typeof account.owner !== 'boolean'
    || typeof account.mustChangePassword !== 'boolean') {
    throw new Error('Operator account flags must be booleans');
  }
  const createdAt = cleanOperatorTimestamp(account.createdAt, 'Operator createdAt');
  const updatedAt = cleanOperatorTimestamp(account.updatedAt, 'Operator updatedAt');
  if (updatedAt < createdAt) throw new Error('Operator updatedAt cannot precede createdAt');
  const createdBy = cleanOperatorActor(account.createdBy, 'Operator createdBy');
  const updatedBy = cleanOperatorActor(account.updatedBy ?? createdBy, 'Operator updatedBy');
  const normalized = {
    id: cleanOperatorId(account.id),
    username: identity.username,
    usernameKey: identity.key,
    role,
    enabled: account.enabled,
    owner: account.owner,
    passwordVerifier: clonePasswordVerifier(account.passwordVerifier),
    mustChangePassword: account.mustChangePassword,
    actionGrants: normalizeOperatorActionGrants(account.actionGrants, { role }),
    authRevision: cleanOperatorRevision(account.authRevision, 'Operator authRevision'),
    recordRevision: cleanOperatorRevision(account.recordRevision, 'Operator recordRevision'),
    createdAt,
    updatedAt,
    createdBy,
    updatedBy,
  };
  if (normalized.owner && (!normalized.enabled || normalized.role !== OPERATOR_ROLES.ADMIN)) {
    throw new Error('The owner operator must be an enabled administrator');
  }
  return normalized;
}

function emptyOperatorDirectory() { return { version: 1, accounts: {} }; }

function normalizeOperatorDirectory(value) {
  const directory = operatorRecord(value, 'Operator directory');
  const fields = new Set(['version', 'accounts']);
  exactOperatorFields(directory, fields, 'Operator directory');
  if (directory.version !== 1) throw new Error('Operator directory version is unsupported');
  const source = operatorRecord(directory.accounts, 'Operator accounts');
  const entries = Object.entries(source);
  if (entries.length > MAX_OPERATOR_ACCOUNTS) throw new Error(`Operator accounts are limited to ${MAX_OPERATOR_ACCOUNTS}`);
  const accounts = {}; const ids = new Set(); let owners = 0; let enabledAdmins = 0;
  for (const [key, value] of entries) {
    const account = normalizeOperatorAccount(value, key, { allowMissingUpdatedBy: true });
    if (ids.has(account.id)) throw new Error('Operator account IDs must be unique');
    ids.add(account.id); accounts[key] = account;
    if (account.owner) owners += 1;
    if (account.enabled && account.role === OPERATOR_ROLES.ADMIN) enabledAdmins += 1;
  }
  if (entries.length && owners !== 1) throw new Error('Operator directory must contain exactly one owner');
  if (entries.length && enabledAdmins < 1) throw new Error('Operator directory must contain an enabled administrator');
  return { version: 1, accounts };
}

function installationSettingsError(message) {
  return new Error(`Installation settings ${message}`);
}

function assertPlainInstallationObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw installationSettingsError(`${label} must be a plain JSON object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw installationSettingsError(`${label} must not use a custom prototype`);
  }
  return value;
}

function normalizeInstallationJson(value, context, depth = 0) {
  context.nodes += 1;
  if (context.nodes > MAX_INSTALLATION_SETTINGS_NODES) {
    throw installationSettingsError(`exceed the ${MAX_INSTALLATION_SETTINGS_NODES}-value safety limit`);
  }
  if (depth > MAX_INSTALLATION_SETTINGS_DEPTH) {
    throw installationSettingsError(`exceed the maximum nesting depth of ${MAX_INSTALLATION_SETTINGS_DEPTH}`);
  }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw installationSettingsError('must contain only finite JSON numbers');
    return Object.is(value, -0) ? 0 : value;
  }
  if (typeof value === 'string') {
    if (INSTALLATION_SETTINGS_CONTROL_PATTERN.test(value)) {
      throw installationSettingsError('must not contain control characters');
    }
    if (Buffer.byteLength(value, 'utf8') > MAX_INSTALLATION_SETTINGS_BYTES) {
      throw installationSettingsError(`exceed the ${MAX_INSTALLATION_SETTINGS_BYTES}-byte safety limit`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      throw installationSettingsError('must not use custom array prototypes');
    }
    if (value.length > MAX_INSTALLATION_SETTINGS_ENTRIES) {
      throw installationSettingsError(`arrays are limited to ${MAX_INSTALLATION_SETTINGS_ENTRIES} entries`);
    }
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.length !== value.length + 1 || ownKeys.some((key) => key !== 'length' && typeof key !== 'string')) {
      throw installationSettingsError('arrays must not contain symbols, holes, or custom properties');
    }
    const output = [];
    for (let index = 0; index < value.length; index += 1) {
      const key = String(index); const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw installationSettingsError('arrays must contain enumerable JSON values without accessors or holes');
      }
      output.push(normalizeInstallationJson(descriptor.value, context, depth + 1));
    }
    return output;
  }
  if (typeof value !== 'object') throw installationSettingsError('must contain only JSON values');
  const source = assertPlainInstallationObject(value, 'configuration value');
  const keys = Reflect.ownKeys(source);
  if (keys.length > MAX_INSTALLATION_SETTINGS_ENTRIES) {
    throw installationSettingsError(`objects are limited to ${MAX_INSTALLATION_SETTINGS_ENTRIES} fields`);
  }
  const output = {};
  for (const key of keys) {
    if (typeof key !== 'string') throw installationSettingsError('must not contain symbol keys');
    if (!key || Buffer.byteLength(key, 'utf8') > MAX_INSTALLATION_SETTINGS_KEY_BYTES
      || INSTALLATION_SETTINGS_CONTROL_PATTERN.test(key)) {
      throw installationSettingsError(`field names must contain 1-${MAX_INSTALLATION_SETTINGS_KEY_BYTES} bytes without control characters`);
    }
    if (RESERVED_OBJECT_KEYS.has(key)) throw installationSettingsError(`field name ${key} is reserved`);
    const descriptor = Object.getOwnPropertyDescriptor(source, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw installationSettingsError('must contain only enumerable data fields without accessors');
    }
    output[key] = normalizeInstallationJson(descriptor.value, context, depth + 1);
  }
  return output;
}

function exactInstallationFields(value, allowed, label) {
  for (const key of Object.keys(value)) if (!allowed.has(key)) {
    throw installationSettingsError(`${label} contains an unsupported field`);
  }
  for (const key of allowed) if (!Object.hasOwn(value, key)) {
    throw installationSettingsError(`${label} is missing required field ${key}`);
  }
}

function normalizeInstallationInput(value) {
  const normalized = normalizeInstallationJson(
    assertPlainInstallationObject(value, 'document'), { nodes: 0 },
  );
  exactInstallationFields(normalized, INSTALLATION_SETTINGS_INPUT_FIELDS, 'document');
  if (normalized.version !== 1) throw installationSettingsError('document version is unsupported');
  if (typeof normalized.configured !== 'boolean') throw installationSettingsError('configured must be a boolean');
  assertPlainInstallationObject(normalized.configuration, 'configuration');
  return normalized;
}

function assertInstallationSettingsSize(value) {
  const size = Buffer.byteLength(JSON.stringify(value), 'utf8');
  if (size > MAX_INSTALLATION_SETTINGS_BYTES) {
    throw installationSettingsError(`exceed the ${MAX_INSTALLATION_SETTINGS_BYTES}-byte safety limit`);
  }
  return value;
}

function normalizePersistedInstallationSettings(value) {
  if (value === null) return null;
  const normalized = normalizeInstallationJson(
    assertPlainInstallationObject(value, 'record'), { nodes: 0 },
  );
  exactInstallationFields(normalized, INSTALLATION_SETTINGS_FIELDS, 'record');
  if (normalized.version !== 1) throw installationSettingsError('record version is unsupported');
  cleanOperatorRevision(normalized.revision, 'Installation settings revision');
  if (typeof normalized.configured !== 'boolean') throw installationSettingsError('configured must be a boolean');
  assertPlainInstallationObject(normalized.configuration, 'configuration');
  cleanOperatorTimestamp(normalized.createdAt, 'Installation settings createdAt');
  cleanOperatorTimestamp(normalized.updatedAt, 'Installation settings updatedAt');
  if (normalized.updatedAt < normalized.createdAt) {
    throw installationSettingsError('updatedAt cannot precede createdAt');
  }
  cleanOperatorActor(normalized.updatedBy, 'Installation settings updatedBy');
  return assertInstallationSettingsSize(normalized);
}

function cloneInstallationSettings(value) { return value === null ? null : structuredClone(value); }

function cloneOperatorAccount(account, { safe = false } = {}) {
  if (!account) return null;
  if (safe) {
    const { passwordVerifier: _passwordVerifier, usernameKey: _usernameKey, ...publicAccount } = account;
    return { ...publicAccount, actionGrants: [...(publicAccount.actionGrants ?? [])] };
  }
  return { ...account, actionGrants: [...(account.actionGrants ?? [])], passwordVerifier: { ...account.passwordVerifier } };
}

function freshState() {
  return {
    version: 1, linksByDiscord: {}, linksByGame: {}, linkCodes: {}, mutes: {}, moderationNotes: {},
    scheduledRestarts: {}, playtimeByEos: {}, seenPlayers: {}, playerDataIds: {}, itemPreferencesByDiscord: {}, history: [],
    operatorDirectory: emptyOperatorDirectory(), installationSettings: null,
    itemPackages: {}, starterPackageGrants: {}, bundledItemPackagesSeeded: false,
  };
}

export class JsonStateStore {
  constructor({
    file, historyLimit = 500, maxFileBytes = 16 * 1024 * 1024,
    encryptionKey = '', encryptionKeyFile = '', encryptionRequired = false, generateEncryptionKey = false,
    allowPlaintextMigration = false, seedBundledItemPackages = false,
    now = () => Date.now(), randomBytes = crypto.randomBytes, encryptionRandomBytes = crypto.randomBytes,
  } = {}) {
    if (!file) throw new Error('State file is required');
    this.file = path.resolve(file);
    this.historyLimit = historyLimit;
    if (!Number.isInteger(maxFileBytes) || maxFileBytes < 1_024 || maxFileBytes > 64 * 1024 * 1024) {
      throw new Error('State maximum file size must be 1024-67108864 bytes');
    }
    if (encryptionKey && encryptionKeyFile) throw new Error('Configure only one state encryption key source');
    if (typeof encryptionRequired !== 'boolean' || typeof generateEncryptionKey !== 'boolean'
      || typeof allowPlaintextMigration !== 'boolean' || typeof seedBundledItemPackages !== 'boolean') {
      throw new Error('State encryption flags must be booleans');
    }
    if (generateEncryptionKey && !encryptionKeyFile) throw new Error('Automatic state key generation requires a key file');
    this.maxFileBytes = maxFileBytes;
    this.encryptionKey = encryptionKey ? decodeEncryptionKey(encryptionKey) : null;
    this.encryptionKeyFile = encryptionKeyFile ? path.resolve(encryptionKeyFile) : '';
    if (this.encryptionKeyFile === this.file) throw new Error('State data and encryption key files must be different');
    this.encryptionRequired = encryptionRequired;
    this.generateEncryptionKey = generateEncryptionKey;
    this.allowPlaintextMigration = allowPlaintextMigration;
    this.seedBundledItemPackages = seedBundledItemPackages;
    this.encryptionRandomBytes = encryptionRandomBytes;
    this.encryptionKeyPromise = null;
    this.now = now;
    this.randomBytes = randomBytes;
    this.state = freshState();
    this.writeChain = Promise.resolve();
    this.mutationChain = Promise.resolve();
    this.playerDataWriteChain = Promise.resolve();
    this.itemPreferencesWriteChain = Promise.resolve();
    this.operatorWriteChain = Promise.resolve();
    this.installationSettingsWriteChain = Promise.resolve();
  }

  async ensureEncryptionKey() {
    if (this.encryptionKey) return this.encryptionKey;
    if (!this.encryptionKeyFile) {
      if (this.encryptionRequired) throw new Error('State encryption is required but no key source is configured');
      return null;
    }
    if (this.encryptionKeyPromise) return this.encryptionKeyPromise;
    this.encryptionKeyPromise = (async () => {
      let encoded;
      try {
        encoded = await readBoundedUtf8(this.encryptionKeyFile, 256, {
          label: 'State encryption key', privateMode: true,
        });
      } catch (error) {
        if (error.code !== 'ENOENT' || !this.generateEncryptionKey) throw error;
        await fs.mkdir(path.dirname(this.encryptionKeyFile), { recursive: true });
        const generated = this.encryptionRandomBytes(32);
        if (!Buffer.isBuffer(generated) || generated.length !== 32) throw new Error('State key generator must return 32 bytes');
        const content = `base64:${generated.toString('base64')}\n`;
        try { await fs.writeFile(this.encryptionKeyFile, content, { encoding: 'utf8', mode: 0o600, flag: 'wx' }); }
        catch (writeError) {
          if (writeError.code !== 'EEXIST') throw writeError;
          encoded = await readBoundedUtf8(this.encryptionKeyFile, 256, {
            label: 'State encryption key', privateMode: true,
          });
        }
        encoded ??= content;
      }
      this.encryptionKey = decodeEncryptionKey(encoded);
      return this.encryptionKey;
    })();
    try { return await this.encryptionKeyPromise; }
    finally { this.encryptionKeyPromise = null; }
  }

  async readStateFile() {
    return readBoundedUtf8(this.file, this.maxFileBytes, { label: 'State' });
  }

  hydrateState(parsed) {
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('State document must contain a JSON object');
    }
    const operatorDirectory = Object.hasOwn(parsed, 'operatorDirectory')
      ? normalizeOperatorDirectory(parsed.operatorDirectory)
      : emptyOperatorDirectory();
    const installationSettings = Object.hasOwn(parsed, 'installationSettings')
      ? normalizePersistedInstallationSettings(parsed.installationSettings)
      : null;
    this.state = { ...freshState(), ...parsed, operatorDirectory, installationSettings };
    for (const key of ['linksByDiscord', 'linksByGame', 'linkCodes', 'mutes', 'moderationNotes', 'scheduledRestarts', 'playtimeByEos', 'seenPlayers']) {
      if (!this.state[key] || typeof this.state[key] !== 'object' || Array.isArray(this.state[key])) this.state[key] = {};
    }
    this.state.playerDataIds = normalizePlayerDataIds(this.state.playerDataIds);
    this.state.itemPreferencesByDiscord = normalizeItemPreferences(this.state.itemPreferencesByDiscord);
    this.state.itemPackages = normalizePersistedItemPackages(this.state.itemPackages);
    this.state.starterPackageGrants = normalizeStarterPackageGrants(this.state.starterPackageGrants);
    this.state.bundledItemPackagesSeeded = this.state.bundledItemPackagesSeeded === true;
    if (!Array.isArray(this.state.history)) this.state.history = [];
    return this.state;
  }

  async load() {
    await fs.mkdir(path.dirname(this.file), { recursive: true });
    const encryptionKey = await this.ensureEncryptionKey();
    let migratePlaintext = false; let created = false;
    try {
      let parsed = JSON.parse(await this.readStateFile());
      if (isEncryptedEnvelope(parsed)) {
        if (!encryptionKey) throw new Error('State file is encrypted but no encryption key is configured');
        parsed = JSON.parse(decryptState(parsed, encryptionKey));
      } else if (encryptionKey) {
        if (!this.allowPlaintextMigration) {
          throw new Error('Plaintext state was refused because an encryption key is configured; run the one-time state encryption migration');
        }
        migratePlaintext = true;
      }
      this.hydrateState(parsed);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      created = true;
    }
    const seeded = this.seedBundledPackagesIfNeeded();
    this.pruneExpired();
    if (created || migratePlaintext || seeded) await this.save();
    return this;
  }

  seedBundledPackagesIfNeeded() {
    if (!this.seedBundledItemPackages || this.state.bundledItemPackagesSeeded) return false;
    const itemPackages = Object.keys(this.state.itemPackages).length === 0
      ? createBundledItemPackages()
      : this.state.itemPackages;
    this.state = { ...this.state, itemPackages, bundledItemPackagesSeeded: true };
    return true;
  }

  save(snapshot = this.state) {
    let serialized;
    try { serialized = `${JSON.stringify(snapshot, null, 2)}\n`; }
    catch (error) { return Promise.reject(error); }
    const operation = async () => {
      await fs.mkdir(path.dirname(this.file), { recursive: true });
      const encryptionKey = await this.ensureEncryptionKey();
      if (this.encryptionRequired && !encryptionKey) throw new Error('State encryption is required but unavailable');
      const output = encryptionKey
        ? `${JSON.stringify(encryptState(serialized, encryptionKey, this.encryptionRandomBytes), null, 2)}\n`
        : serialized;
      if (Buffer.byteLength(output) > this.maxFileBytes) throw new Error(`Encrypted state exceeds the ${this.maxFileBytes}-byte safety limit`);
      const temp = `${this.file}.${process.pid}.${crypto.randomBytes(12).toString('hex')}.tmp`;
      let created = false;
      try {
        await fs.writeFile(temp, output, { mode: 0o600, flag: 'wx' }); created = true;
        await fs.rename(temp, this.file); created = false;
      } finally {
        if (created) await fs.unlink(temp).catch(() => undefined);
      }
    };
    const pending = this.writeChain.catch(() => undefined).then(operation);
    this.writeChain = pending;
    return pending;
  }

  enqueueMutation(operation, chainProperty = '') {
    if (this.closing || this.closed) return Promise.reject(new Error('State store is closed'));
    const guarded = async () => {
      const previousState = this.state;
      try { return await operation(); }
      catch (error) {
        this.state = previousState;
        throw error;
      }
    };
    const pending = this.mutationChain.catch(() => undefined).then(guarded);
    this.mutationChain = pending;
    if (chainProperty) this[chainProperty] = pending;
    return pending;
  }

  async commitMutation(nextState) {
    await this.save(nextState);
    this.state = nextState;
  }

  pruneExpired() {
    const at = this.now();
    for (const [code, item] of Object.entries(this.state.linkCodes)) if (!item || item.expiresAt <= at) delete this.state.linkCodes[code];
    for (const [key, mute] of Object.entries(this.state.mutes)) if (!mute || mute.until <= at) delete this.state.mutes[key];
  }

  countLinkedAccounts() { return Object.keys(this.state.linksByDiscord).length; }

  getInstallationSettings() { return cloneInstallationSettings(this.state.installationSettings); }

  setInstallationSettings(document, { expectedRevision, updatedBy } = {}) {
    const input = normalizeInstallationInput(document);
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
      throw installationSettingsError('expected revision must be a non-negative safe integer');
    }
    const actor = cleanOperatorActor(updatedBy, 'Installation settings updatedBy');
    const operation = async () => {
      const previous = this.state.installationSettings;
      const currentRevision = previous?.revision ?? 0;
      if (expectedRevision !== currentRevision) {
        const error = installationSettingsError('changed; refresh them and try again');
        error.code = 'installation_settings_revision_conflict';
        throw error;
      }
      if (currentRevision === Number.MAX_SAFE_INTEGER) throw installationSettingsError('revision limit reached');
      const now = cleanOperatorTimestamp(this.now(), 'Installation settings updatedAt');
      const next = assertInstallationSettingsSize({
        version: 1,
        revision: currentRevision + 1,
        configured: input.configured,
        configuration: input.configuration,
        createdAt: previous?.createdAt ?? now,
        updatedAt: previous ? Math.max(previous.updatedAt, now) : now,
        updatedBy: actor,
      });
      await this.commitMutation({ ...this.state, installationSettings: next });
      return cloneInstallationSettings(next);
    };
    return this.enqueueMutation(operation, 'installationSettingsWriteChain');
  }

  countOperatorAccounts() { return Object.keys(this.state.operatorDirectory.accounts).length; }

  findOperatorByUsername(username) {
    const { key } = normalizeOperatorUsername(username);
    return cloneOperatorAccount(this.state.operatorDirectory.accounts[key]);
  }

  getOperatorAccount(id) {
    const accountId = cleanOperatorId(id);
    const account = Object.values(this.state.operatorDirectory.accounts)
      .find((candidate) => candidate.id === accountId);
    return cloneOperatorAccount(account);
  }

  listOperatorAccounts() {
    return Object.values(this.state.operatorDirectory.accounts)
      .sort((left, right) => left.usernameKey.localeCompare(right.usernameKey))
      .map((account) => cloneOperatorAccount(account, { safe: true }));
  }

  async createOperatorAccount(account, { first = false } = {}) {
    if (typeof first !== 'boolean') throw new Error('Operator first-account flag must be a boolean');
    const normalized = normalizeOperatorAccount(account, account?.usernameKey);
    const operation = async () => {
      const previousDirectory = this.state.operatorDirectory;
      const currentAccounts = previousDirectory.accounts;
      const count = Object.keys(currentAccounts).length;
      if (first) {
        if (count !== 0) throw new Error('The first operator account has already been created');
        if (!normalized.owner || !normalized.enabled || normalized.role !== OPERATOR_ROLES.ADMIN) {
          throw new Error('The first operator account must be an enabled owner administrator');
        }
      } else {
        if (count === 0) throw new Error('Create the owner operator account first');
        if (normalized.owner) throw new Error('Only the first operator account can be the owner');
        if (count >= MAX_OPERATOR_ACCOUNTS) throw new Error(`Operator accounts are limited to ${MAX_OPERATOR_ACCOUNTS}`);
      }
      if (Object.hasOwn(currentAccounts, normalized.usernameKey)) throw new Error('Operator username is already in use');
      if (Object.values(currentAccounts).some((candidate) => candidate.id === normalized.id)) {
        throw new Error('Operator account ID is already in use');
      }
      const nextDirectory = {
        version: 1,
        accounts: { ...currentAccounts, [normalized.usernameKey]: cloneOperatorAccount(normalized) },
      };
      await this.commitMutation({ ...this.state, operatorDirectory: nextDirectory });
      return cloneOperatorAccount(normalized);
    };
    return this.enqueueMutation(operation, 'operatorWriteChain');
  }

  async updateOperatorAccount(id, changes, { expectedRevision } = {}) {
    const accountId = cleanOperatorId(id);
    const update = operatorRecord(changes, 'Operator account update');
    for (const key of Object.keys(update)) if (!OPERATOR_UPDATE_FIELDS.has(key)) {
      throw new Error('Operator account update contains an unsupported field');
    }
    if (!Object.keys(update).some((key) => !['updatedAt', 'updatedBy'].includes(key))) {
      throw new Error('Operator account update must change an account setting');
    }
    cleanOperatorRevision(expectedRevision, 'Expected operator record revision');
    const requested = { ...update };
    if (Object.hasOwn(requested, 'passwordVerifier')) requested.passwordVerifier = clonePasswordVerifier(requested.passwordVerifier);
    const operation = async () => {
      const previousDirectory = this.state.operatorDirectory;
      const entry = Object.entries(previousDirectory.accounts).find(([, candidate]) => candidate.id === accountId);
      if (!entry) return null;
      const [usernameKey, existing] = entry;
      if (existing.recordRevision !== expectedRevision) {
        const error = new Error('Operator account changed; refresh it and try again');
        error.code = 'operator_revision_conflict';
        throw error;
      }
      const role = Object.hasOwn(requested, 'role') ? normalizeOperatorRole(requested.role) : existing.role;
      if (Object.hasOwn(requested, 'role') && role !== requested.role) throw new Error('Operator account role is not canonical');
      const enabled = Object.hasOwn(requested, 'enabled') ? requested.enabled : existing.enabled;
      const mustChangePassword = Object.hasOwn(requested, 'mustChangePassword')
        ? requested.mustChangePassword : existing.mustChangePassword;
      const actionGrants = role === 'admin' ? [] : Object.hasOwn(requested, 'actionGrants')
        ? normalizeOperatorActionGrants(requested.actionGrants, { role })
        : normalizeOperatorActionGrants(existing.actionGrants, { role });
      if (typeof enabled !== 'boolean' || typeof mustChangePassword !== 'boolean') {
        throw new Error('Operator account flags must be booleans');
      }
      if (existing.owner && (!enabled || role !== OPERATOR_ROLES.ADMIN)) {
        throw new Error('The owner operator cannot be disabled or demoted');
      }
      const passwordVerifier = Object.hasOwn(requested, 'passwordVerifier')
        ? requested.passwordVerifier : { ...existing.passwordVerifier };
      const updatedAt = Object.hasOwn(requested, 'updatedAt')
        ? cleanOperatorTimestamp(requested.updatedAt, 'Operator updatedAt') : cleanOperatorTimestamp(this.now(), 'Operator updatedAt');
      if (updatedAt < existing.updatedAt) throw new Error('Operator updatedAt cannot move backwards');
      const updatedBy = Object.hasOwn(requested, 'updatedBy')
        ? cleanOperatorActor(requested.updatedBy, 'Operator updatedBy') : existing.updatedBy;
      const authorizationChanged = role !== existing.role || enabled !== existing.enabled
        || JSON.stringify(actionGrants) !== JSON.stringify(existing.actionGrants ?? [])
        || !passwordVerifiersEqual(passwordVerifier, existing.passwordVerifier);
      if (existing.recordRevision === Number.MAX_SAFE_INTEGER
        || (authorizationChanged && existing.authRevision === Number.MAX_SAFE_INTEGER)) {
        throw new Error('Operator account revision limit reached');
      }
      const next = {
        ...existing,
        role,
        enabled,
        passwordVerifier: { ...passwordVerifier },
        mustChangePassword,
        actionGrants,
        authRevision: existing.authRevision + (authorizationChanged ? 1 : 0),
        recordRevision: existing.recordRevision + 1,
        updatedAt,
        updatedBy,
      };
      const nextAccounts = { ...previousDirectory.accounts, [usernameKey]: next };
      if (!Object.values(nextAccounts).some((candidate) => candidate.enabled && candidate.role === OPERATOR_ROLES.ADMIN)) {
        throw new Error('At least one enabled administrator account is required');
      }
      const nextDirectory = { version: 1, accounts: nextAccounts };
      await this.commitMutation({ ...this.state, operatorDirectory: nextDirectory });
      return cloneOperatorAccount(next);
    };
    return this.enqueueMutation(operation, 'operatorWriteChain');
  }

  gameMuteKeys(identity = {}) {
    const keys = [];
    if (identity.eosId) keys.push(`game:eos:${identity.eosId}`);
    if (identity.playerName) keys.push(`game:player:${normalizeName(identity.playerName)}`);
    if (identity.characterName) keys.push(`game:character:${normalizeName(identity.characterName)}`);
    return [...new Set(keys)];
  }

  discordMuteKeys(discordUserId) { return discordUserId ? [`discord:${discordUserId}`] : []; }

  getMute(keys) {
    const at = this.now();
    for (const key of keys) {
      const mute = this.state.mutes[key];
      if (mute?.until > at) return { key, ...mute };
    }
    return null;
  }

  async setMute(keys, { minutes, reason = '', actor = '' } = {}) {
    if (!Number.isInteger(minutes) || minutes < 1) throw new Error('Mute minutes must be a positive integer');
    const unique = [...new Set(keys.filter(Boolean))];
    if (!unique.length) throw new Error('At least one mute identity is required');
    return this.enqueueMutation(async () => {
      const createdAt = this.now();
      const until = createdAt + minutes * 60_000;
      const mutes = { ...this.state.mutes };
      for (const key of unique) {
        mutes[key] = {
          until, reason: normalizeWhitespace(reason), actor: normalizeWhitespace(actor), createdAt,
        };
      }
      await this.commitMutation({ ...this.state, mutes });
      return until;
    });
  }

  async clearMute(keys) {
    const unique = [...new Set(keys.filter(Boolean))];
    return this.enqueueMutation(async () => {
      const mutes = { ...this.state.mutes };
      let removed = false;
      for (const key of unique) {
        if (mutes[key]) { delete mutes[key]; removed = true; }
      }
      if (removed) await this.commitMutation({ ...this.state, mutes });
      return removed;
    });
  }

  listMutes() {
    const at = this.now();
    return Object.entries(this.state.mutes)
      .filter(([, mute]) => mute?.until > at)
      .map(([key, mute]) => ({ key, ...mute }));
  }

  generateCode() {
    const bytes = this.randomBytes(6);
    return [...bytes].map((byte) => CODE_ALPHABET[byte % CODE_ALPHABET.length]).join('');
  }

  async createLinkCode(discordUserId, discordDisplayName) {
    if (!discordUserId) throw new Error('Discord user ID is required');
    const id = String(discordUserId);
    const displayName = normalizeWhitespace(discordDisplayName);
    return this.enqueueMutation(async () => {
      const at = this.now();
      const linkCodes = Object.fromEntries(Object.entries(this.state.linkCodes)
        .filter(([, pending]) => pending && pending.expiresAt > at && pending.discordUserId !== id));
      let code;
      for (let attempts = 0; attempts < 10; attempts += 1) {
        code = this.generateCode();
        if (!linkCodes[code]) break;
      }
      if (!code || linkCodes[code]) throw new Error('Could not allocate a unique link code');
      linkCodes[code] = { discordUserId: id, discordDisplayName: displayName, expiresAt: at + 600_000 };
      await this.commitMutation({ ...this.state, linkCodes });
      return code;
    });
  }

  async consumeLinkCode(rawCode, identity) {
    const code = String(rawCode ?? '').trim().toLocaleUpperCase('en-US');
    return this.enqueueMutation(async () => {
      const pending = this.state.linkCodes[code];
      if (!pending) return { ok: false, reason: 'invalid' };
      const at = this.now();
      if (pending.expiresAt <= at) {
        const linkCodes = { ...this.state.linkCodes }; delete linkCodes[code];
        await this.commitMutation({ ...this.state, linkCodes });
        return { ok: false, reason: 'expired' };
      }
      const link = {
        discordUserId: pending.discordUserId,
        discordDisplayName: pending.discordDisplayName,
        eosId: String(identity.eosId ?? ''),
        playerName: normalizeWhitespace(identity.playerName),
        characterName: normalizeWhitespace(identity.characterName),
        linkedAt: at,
      };
      const linksByDiscord = { ...this.state.linksByDiscord };
      const linksByGame = { ...this.state.linksByGame };
      this.unlinkDiscordFromMaps(pending.discordUserId, linksByDiscord, linksByGame);
      const stableConflict = link.eosId
        ? linksByGame[`eos:${link.eosId}`]
        : linksByGame[`player:${normalizeName(link.playerName)}`]
          ?? linksByGame[`character:${normalizeName(link.characterName)}`];
      if (stableConflict && stableConflict !== pending.discordUserId) {
        this.unlinkDiscordFromMaps(stableConflict, linksByDiscord, linksByGame);
      }
      linksByDiscord[pending.discordUserId] = link;
      if (link.eosId) linksByGame[`eos:${link.eosId}`] = pending.discordUserId;
      if (link.playerName) linksByGame[`player:${normalizeName(link.playerName)}`] = pending.discordUserId;
      if (link.characterName) linksByGame[`character:${normalizeName(link.characterName)}`] = pending.discordUserId;
      const linkCodes = { ...this.state.linkCodes }; delete linkCodes[code];
      await this.commitMutation({ ...this.state, linksByDiscord, linksByGame, linkCodes });
      return { ok: true, link };
    });
  }

  getLinkByDiscord(discordUserId) { return this.state.linksByDiscord[String(discordUserId)] ?? null; }

  getLinkByGame(identity = {}) {
    const keys = [
      identity.eosId && `eos:${identity.eosId}`,
      identity.playerName && `player:${normalizeName(identity.playerName)}`,
      identity.characterName && `character:${normalizeName(identity.characterName)}`,
    ].filter(Boolean);
    for (const key of keys) {
      const discordId = this.state.linksByGame[key];
      if (discordId && this.state.linksByDiscord[discordId]) return this.state.linksByDiscord[discordId];
    }
    return null;
  }

  unlinkDiscordFromMaps(discordUserId, linksByDiscord, linksByGame) {
    const id = String(discordUserId ?? '');
    if (!linksByDiscord[id]) return false;
    delete linksByDiscord[id];
    for (const [key, value] of Object.entries(linksByGame)) if (value === id) delete linksByGame[key];
    return true;
  }

  async unlinkDiscord(discordUserId, { save = true } = {}) {
    const id = String(discordUserId ?? '');
    return this.enqueueMutation(async () => {
      const linksByDiscord = { ...this.state.linksByDiscord };
      const linksByGame = { ...this.state.linksByGame };
      const removed = this.unlinkDiscordFromMaps(id, linksByDiscord, linksByGame);
      if (removed) {
        const nextState = { ...this.state, linksByDiscord, linksByGame };
        if (save) await this.commitMutation(nextState);
        else this.state = nextState;
      }
      return removed;
    });
  }

  getPlayerDataId(serverId, eosId) {
    return this.getPlayerDataMapping(serverId, eosId)?.playerDataId ?? null;
  }

  getPlayerDataMapping(serverId, eosId) {
    const entry = this.state.playerDataIds[playerDataKey(serverId, eosId)];
    return entry ? { ...entry } : null;
  }

  async setPlayerDataId(serverId, eosId, playerDataId, options = {}) {
    const operation = async () => {
      const { replace = false } = options;
      if (typeof replace !== 'boolean') throw new Error('PlayerDataID replace must be a boolean');
      const server = cleanServerId(serverId); const key = playerDataKey(server, eosId);
      const canonicalId = cleanPlayerDataId(playerDataId);
      const previousMappings = this.state.playerDataIds;
      const existing = previousMappings[key] ?? null;
      const serverPrefix = `${server}:`;
      const conflicts = Object.entries(previousMappings)
        .filter(([candidateKey, candidate]) => candidateKey !== key && candidateKey.startsWith(serverPrefix) && candidate?.playerDataId === canonicalId)
        .map(([candidateKey]) => candidateKey);
      if (conflicts.length && !replace) {
        throw new Error(`PlayerDataID ${canonicalId} is already mapped to another account on server ${server}`);
      }
      const metadata = (field) => options[field] === undefined
        ? existing?.[field] ?? ''
        : normalizeWhitespace(options[field]);
      const entry = {
        playerDataId: canonicalId,
        displayName: metadata('displayName'),
        characterName: metadata('characterName'),
        actor: metadata('actor'),
        updatedAt: this.now(),
      };
      const nextMappings = { ...previousMappings };
      for (const conflict of conflicts) delete nextMappings[conflict];
      nextMappings[key] = entry;
      await this.commitMutation({ ...this.state, playerDataIds: nextMappings });
      return { ...entry };
    };
    return this.enqueueMutation(operation, 'playerDataWriteChain');
  }

  async clearPlayerDataId(serverId, eosId) {
    const key = playerDataKey(serverId, eosId);
    return this.enqueueMutation(async () => {
      if (!this.state.playerDataIds[key]) return false;
      const playerDataIds = { ...this.state.playerDataIds }; delete playerDataIds[key];
      await this.commitMutation({ ...this.state, playerDataIds });
      return true;
    });
  }

  itemPreferences(discordUserId) {
    const userId = cleanDiscordUserId(discordUserId);
    return Object.hasOwn(this.state.itemPreferencesByDiscord, userId)
      ? this.state.itemPreferencesByDiscord[userId]
      : emptyItemPreferences();
  }

  updateItemPreferences(discordUserId, mutate) {
    const userId = cleanDiscordUserId(discordUserId);
    const operation = async () => {
      const previousAll = this.state.itemPreferencesByDiscord;
      const current = cloneItemPreferences(Object.hasOwn(previousAll, userId) ? previousAll[userId] : undefined);
      const change = mutate(current);
      if (!change.changed) return change.value;
      const nextAll = { ...previousAll };
      if (hasItemPreferences(change.next)) nextAll[userId] = change.next;
      else delete nextAll[userId];
      await this.commitMutation({ ...this.state, itemPreferencesByDiscord: nextAll });
      return change.value;
    };
    return this.enqueueMutation(operation, 'itemPreferencesWriteChain');
  }

  listItemFavorites(discordUserId) { return [...this.itemPreferences(discordUserId).favorites]; }

  async addItemFavorite(discordUserId, itemKey) {
    const key = cleanItemKey(itemKey);
    return this.updateItemPreferences(discordUserId, (current) => {
      if (current.favorites.includes(key)) return { changed: false, value: [...current.favorites] };
      if (current.favorites.length >= MAX_ITEM_FAVORITES) throw new Error(`Item favorites are limited to ${MAX_ITEM_FAVORITES}`);
      const favorites = [...current.favorites, key];
      return { changed: true, next: { ...current, favorites }, value: [...favorites] };
    });
  }

  async removeItemFavorite(discordUserId, itemKey) {
    const key = cleanItemKey(itemKey);
    return this.updateItemPreferences(discordUserId, (current) => {
      if (!current.favorites.includes(key)) return { changed: false, value: false };
      return { changed: true, next: { ...current, favorites: current.favorites.filter((item) => item !== key) }, value: true };
    });
  }

  listRecentItems(discordUserId) { return [...this.itemPreferences(discordUserId).recent]; }

  async recordRecentItem(discordUserId, itemKey) {
    const key = cleanItemKey(itemKey);
    return this.updateItemPreferences(discordUserId, (current) => {
      if (current.recent[0] === key) return { changed: false, value: [...current.recent] };
      const recent = [key, ...current.recent.filter((item) => item !== key)].slice(0, MAX_RECENT_ITEMS);
      return { changed: true, next: { ...current, recent }, value: [...recent] };
    });
  }

  listItemPresets(discordUserId) { return this.itemPreferences(discordUserId).presets.map(clonePreset); }

  async setItemPreset(discordUserId, preset, { replace = false } = {}) {
    if (typeof replace !== 'boolean') throw new Error('Item preset replace must be a boolean');
    const input = cleanPreset({
      ...preset,
      quantity: preset?.quantity ?? 1,
      quality: preset?.quality ?? 0,
      blueprint: preset?.blueprint ?? false,
    });
    const identity = presetIdentity(input.name);
    return this.updateItemPreferences(discordUserId, (current) => {
      const index = current.presets.findIndex((candidate) => presetIdentity(candidate.name) === identity);
      if (index >= 0 && !replace) throw new Error(`Item preset ${input.name} already exists; enable replace to update it`);
      if (index < 0 && current.presets.length >= MAX_ITEM_PRESETS) throw new Error(`Item presets are limited to ${MAX_ITEM_PRESETS}`);
      const at = this.now();
      const saved = { ...input, createdAt: index >= 0 ? current.presets[index].createdAt : at, updatedAt: at };
      const presets = current.presets.map(clonePreset);
      if (index >= 0) presets[index] = saved;
      else presets.push(saved);
      return { changed: true, next: { ...current, presets }, value: clonePreset(saved) };
    });
  }

  async removeItemPreset(discordUserId, name) {
    const identity = presetIdentity(name);
    return this.updateItemPreferences(discordUserId, (current) => {
      const index = current.presets.findIndex((preset) => presetIdentity(preset.name) === identity);
      if (index < 0) return { changed: false, value: false };
      return { changed: true, next: { ...current, presets: current.presets.filter((_, candidate) => candidate !== index) }, value: true };
    });
  }

  async addModerationNote(playerId, { text, actor, type = 'note' } = {}) {
    const key = String(playerId ?? '').trim(); const note = normalizeWhitespace(text);
    if (!key || !note) throw new Error('A player ID and note are required');
    const normalizedActor = normalizeWhitespace(actor); const normalizedType = normalizeModerationNoteType(type);
    return this.enqueueMutation(async () => {
      const saved = { text: note, actor: normalizedActor, type: normalizedType, at: this.now() };
      const notes = [...(this.state.moderationNotes[key] ?? []), saved].slice(-100);
      const moderationNotes = { ...this.state.moderationNotes, [key]: notes };
      await this.commitMutation({ ...this.state, moderationNotes });
      return { ...saved };
    });
  }

  listModerationNotes(playerId, limit = 5) {
    return (this.state.moderationNotes[String(playerId ?? '').trim()] ?? []).slice(-limit).reverse();
  }

  listModerationNotesWithIds(playerId, limit = 5) {
    const key = String(playerId ?? '').trim();
    const notes = this.state.moderationNotes[key] ?? [];
    return notes.map((note, index) => ({ ...note, id: moderationNoteId(key, note, index) })).slice(-limit).reverse();
  }

  async removeModerationNote(playerId, noteId) {
    const key = String(playerId ?? '').trim(); const id = validModerationNoteId(noteId);
    if (!key || !id) throw new Error('A player ID and valid moderation note ID are required');
    return this.enqueueMutation(async () => {
      const current = this.state.moderationNotes[key] ?? [];
      const index = current.findIndex((note, candidate) => moderationNoteId(key, note, candidate) === id);
      if (index < 0) return false;
      const nextNotes = current.filter((_, candidate) => candidate !== index);
      const moderationNotes = { ...this.state.moderationNotes };
      if (nextNotes.length) moderationNotes[key] = nextNotes;
      else delete moderationNotes[key];
      await this.commitMutation({ ...this.state, moderationNotes });
      return true;
    });
  }

  listScheduledRestarts() { return Object.entries(this.state.scheduledRestarts).map(([serverId, restart]) => ({ serverId, ...restart })); }

  async setScheduledRestart(serverId, restart) {
    const id = String(serverId ?? '').trim();
    if (!id || !Number.isFinite(restart?.deadline)) throw new Error('A server ID and restart deadline are required');
    const saved = {
      deadline: restart.deadline,
      reason: normalizeWhitespace(restart.reason),
      actor: normalizeWhitespace(restart.actor),
      warningMinutes: [...new Set(restart.warningMinutes ?? [])],
    };
    return this.enqueueMutation(async () => {
      const scheduledRestarts = { ...this.state.scheduledRestarts, [id]: saved };
      await this.commitMutation({ ...this.state, scheduledRestarts });
      return { ...saved, warningMinutes: [...saved.warningMinutes] };
    });
  }

  async clearScheduledRestart(serverId) {
    const id = String(serverId ?? '').trim();
    return this.enqueueMutation(async () => {
      if (!this.state.scheduledRestarts[id]) return false;
      const scheduledRestarts = { ...this.state.scheduledRestarts }; delete scheduledRestarts[id];
      await this.commitMutation({ ...this.state, scheduledRestarts });
      return true;
    });
  }

  async addHistory(entry) {
    if (this.historyLimit === 0) return;
    return this.enqueueMutation(async () => {
      const history = [...this.state.history, { at: this.now(), ...entry }].slice(-this.historyLimit);
      await this.commitMutation({ ...this.state, history });
    });
  }

  isFirstSeen(eosId) {
    const key = String(eosId ?? '').trim();
    if (!key) return false;
    const seen = Boolean(this.state.seenPlayers[key]);
    return !seen;
  }

  async markSeen(eosId, displayName) {
    const key = String(eosId ?? '').trim(); if (!key) return;
    const normalizedDisplayName = normalizeWhitespace(displayName);
    return this.enqueueMutation(async () => {
      if (this.state.seenPlayers[key]) return;
      const seenPlayers = {
        ...this.state.seenPlayers,
        [key]: { firstSeenAt: this.now(), displayName: normalizedDisplayName },
      };
      await this.commitMutation({ ...this.state, seenPlayers });
    });
  }

  async recordPlaytimeSession(eosId, seconds, displayName) {
    const key = String(eosId ?? '').trim();
    if (!key || !Number.isFinite(seconds) || seconds <= 0) return;
    const normalizedDisplayName = normalizeWhitespace(displayName);
    return this.enqueueMutation(async () => {
      const current = this.state.playtimeByEos[key] ?? { totalSeconds: 0, sessions: 0 };
      const entry = {
        ...current,
        totalSeconds: current.totalSeconds + Math.round(seconds),
        sessions: current.sessions + 1,
        displayName: normalizedDisplayName || current.displayName,
        lastSeenAt: this.now(),
      };
      const playtimeByEos = { ...this.state.playtimeByEos, [key]: entry };
      await this.commitMutation({ ...this.state, playtimeByEos });
    });
  }

  getPlaytime(eosId) {
    const entry = this.state.playtimeByEos[String(eosId ?? '').trim()];
    return entry ? { ...entry } : null;
  }

  listPlaytimeLeaderboard(limit = 10) {
    return Object.entries(this.state.playtimeByEos)
      .map(([eosId, entry]) => ({ eosId, ...entry }))
      .sort((a, b) => b.totalSeconds - a.totalSeconds)
      .slice(0, Math.max(1, limit));
  }

  listItemPackages({ includeDisabled = true } = {}) {
    return Object.values(this.state.itemPackages)
      .filter((itemPackage) => includeDisabled || itemPackage.enabled)
      .sort((left, right) => left.name.localeCompare(right.name, 'en-US'))
      .map(cloneItemPackage);
  }

  getItemPackage(packageId) {
    let id;
    try { id = cleanItemPackageId(packageId); } catch { return null; }
    return cloneItemPackage(this.state.itemPackages[id]);
  }

  async createItemPackage(value) {
    const input = normalizeItemPackageInput(value);
    return this.enqueueMutation(async () => {
      const current = this.state.itemPackages;
      if (Object.keys(current).length >= MAX_ITEM_PACKAGES) throw new Error(`Item packages are limited to ${MAX_ITEM_PACKAGES}`);
      if (Object.values(current).some((candidate) => candidate.name.toLocaleLowerCase('en-US') === input.name.toLocaleLowerCase('en-US'))) {
        throw new Error(`Item package ${input.name} already exists`);
      }
      let id;
      do { id = `pkg_${this.randomBytes(16).toString('base64url')}`; } while (current[id]);
      const at = this.now();
      const saved = { id, ...input, revision: 1, createdAt: at, updatedAt: at };
      await this.commitMutation({ ...this.state, itemPackages: { ...current, [id]: saved } });
      return cloneItemPackage(saved);
    });
  }

  async updateItemPackage(packageId, value, { expectedRevision } = {}) {
    const id = cleanItemPackageId(packageId); const input = normalizeItemPackageInput(value);
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1) throw new Error('Expected package revision must be a positive integer');
    return this.enqueueMutation(async () => {
      const current = this.state.itemPackages; const existing = current[id];
      if (!existing) throw new Error('That item package does not exist');
      if (existing.revision !== expectedRevision) throw new Error('That item package changed; refresh and try again');
      if (Object.values(current).some((candidate) => candidate.id !== id
        && candidate.name.toLocaleLowerCase('en-US') === input.name.toLocaleLowerCase('en-US'))) {
        throw new Error(`Item package ${input.name} already exists`);
      }
      const saved = { ...existing, ...input, revision: existing.revision + 1, updatedAt: this.now() };
      await this.commitMutation({ ...this.state, itemPackages: { ...current, [id]: saved } });
      return cloneItemPackage(saved);
    });
  }

  async deleteItemPackage(packageId, { expectedRevision } = {}) {
    const id = cleanItemPackageId(packageId);
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1) throw new Error('Expected package revision must be a positive integer');
    return this.enqueueMutation(async () => {
      const existing = this.state.itemPackages[id];
      if (!existing) return false;
      if (existing.revision !== expectedRevision) throw new Error('That item package changed; refresh and try again');
      const itemPackages = { ...this.state.itemPackages }; delete itemPackages[id];
      await this.commitMutation({ ...this.state, itemPackages });
      return true;
    });
  }

  async observePlayerForStarterPackages(eosId, displayName, { eligible = true } = {}) {
    const key = String(eosId ?? '').trim().toLocaleLowerCase('en-US');
    if (!/^[a-f0-9]{32}$/u.test(key)) return { firstSeen: false, grant: null };
    if (typeof eligible !== 'boolean') throw new Error('Starter eligibility must be a boolean');
    const normalizedDisplayName = normalizeWhitespace(displayName);
    return this.enqueueMutation(async () => {
      const existingGrant = this.state.starterPackageGrants[key];
      if (existingGrant) return { firstSeen: false, grant: structuredClone(existingGrant) };
      const alreadySeen = Boolean(this.state.seenPlayers[key]); const at = this.now();
      const packages = {};
      if (eligible && !alreadySeen) {
        for (const itemPackage of Object.values(this.state.itemPackages)) {
          if (!itemPackage.enabled || !itemPackage.starterEnabled) continue;
          packages[itemPackage.id] = { revision: itemPackage.revision, itemStates: itemPackage.items.map(() => 'pending') };
        }
      }
      const grant = { eligible: eligible && !alreadySeen, observedAt: at, packages };
      const seenPlayers = alreadySeen ? this.state.seenPlayers : {
        ...this.state.seenPlayers,
        [key]: { firstSeenAt: at, displayName: normalizedDisplayName },
      };
      const starterPackageGrants = { ...this.state.starterPackageGrants, [key]: grant };
      await this.commitMutation({ ...this.state, seenPlayers, starterPackageGrants });
      return { firstSeen: !alreadySeen, grant: structuredClone(grant) };
    });
  }

  getStarterPackageGrant(eosId) {
    const key = String(eosId ?? '').trim().toLocaleLowerCase('en-US');
    const grant = this.state.starterPackageGrants[key];
    return grant ? structuredClone(grant) : null;
  }

  async claimStarterPackageItem(eosId, packageId, packageRevision, itemIndex) {
    const key = String(eosId ?? '').trim().toLocaleLowerCase('en-US'); const id = cleanItemPackageId(packageId);
    if (!Number.isSafeInteger(packageRevision) || packageRevision < 1
      || !Number.isInteger(itemIndex) || itemIndex < 0 || itemIndex >= 50) return false;
    return this.enqueueMutation(async () => {
      const grant = this.state.starterPackageGrants[key]; const packageGrant = grant?.packages?.[id];
      if (!grant?.eligible || packageGrant?.revision !== packageRevision || packageGrant.itemStates[itemIndex] !== 'pending') return false;
      const itemStates = [...packageGrant.itemStates]; itemStates[itemIndex] = 'attempted';
      const nextGrant = { ...grant, packages: { ...grant.packages, [id]: { ...packageGrant, itemStates } } };
      await this.commitMutation({
        ...this.state,
        starterPackageGrants: { ...this.state.starterPackageGrants, [key]: nextGrant },
      });
      return true;
    });
  }

  async completeStarterPackageItem(eosId, packageId, packageRevision, itemIndex) {
    const key = String(eosId ?? '').trim().toLocaleLowerCase('en-US'); const id = cleanItemPackageId(packageId);
    return this.enqueueMutation(async () => {
      const grant = this.state.starterPackageGrants[key]; const packageGrant = grant?.packages?.[id];
      if (!grant?.eligible || packageGrant?.revision !== packageRevision || packageGrant.itemStates[itemIndex] !== 'attempted') return false;
      const itemStates = [...packageGrant.itemStates]; itemStates[itemIndex] = 'succeeded';
      const nextGrant = { ...grant, packages: { ...grant.packages, [id]: { ...packageGrant, itemStates } } };
      await this.commitMutation({
        ...this.state,
        starterPackageGrants: { ...this.state.starterPackageGrants, [key]: nextGrant },
      });
      return true;
    });
  }

  async skipStarterPackage(eosId, packageId, packageRevision) {
    const key = String(eosId ?? '').trim().toLocaleLowerCase('en-US'); const id = cleanItemPackageId(packageId);
    return this.enqueueMutation(async () => {
      const grant = this.state.starterPackageGrants[key]; const packageGrant = grant?.packages?.[id];
      if (!grant?.eligible || packageGrant?.revision !== packageRevision) return false;
      const itemStates = packageGrant.itemStates.map((status) => status === 'pending' ? 'skipped' : status);
      if (itemStates.every((status, index) => status === packageGrant.itemStates[index])) return false;
      const nextGrant = { ...grant, packages: { ...grant.packages, [id]: { ...packageGrant, itemStates } } };
      await this.commitMutation({
        ...this.state,
        starterPackageGrants: { ...this.state.starterPackageGrants, [key]: nextGrant },
      });
      return true;
    });
  }
}
