import crypto from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';
import { applyDefaults, loadConfig, validateConfig } from './config.js';
import { SqliteStateStore } from './adapters/state/sqlite-state-store.js';
import { syncDirectory } from './core/filesystem.js';
import { loadLogEncryptionKey, verifyLogDirectory } from './logging/secure-log-sink.js';
import {
  generateInstanceTlsIdentity, inspectTlsIdentity, normalizeTlsSubjectAltNames,
} from './security/instance-tls.js';
import {
  acquireManagedRuntimeLock,
  createManagedInitializationFile,
  createManagedKeyFile,
  decodeManagedKey,
  encodeManagedKey,
  hardenManagedPrivatePath,
  readManagedInitializationFile,
  readManagedKeyFile,
  reconcileManagedKeystorePublications,
  removeFirstRunSetupFile,
  removeIncompleteManagedKeyFile,
  removeManagedInitializationFile,
  writeFirstRunSetupFile,
} from './security/managed-keystore.js';

const INSTALLATION_VERSION = 1;
const MAX_SECRET_FILE_BYTES = 1024 * 1024;
const TOKEN_BYTES = 48;

function randomToken(randomBytes = crypto.randomBytes, bytes = TOKEN_BYTES) {
  const value = randomBytes(bytes);
  if (!Buffer.isBuffer(value) || value.length !== bytes) {
    if (Buffer.isBuffer(value)) value.fill(0);
    throw new Error('Managed token generator returned an invalid value');
  }
  try { return value.toString('base64url'); }
  finally { value.fill(0); }
}

function randomManagedKey(randomBytes = crypto.randomBytes, forbiddenKey = null) {
  if (forbiddenKey !== null && (!Buffer.isBuffer(forbiddenKey) || forbiddenKey.length !== 32)) {
    throw new Error('Managed forbidden encryption key is invalid');
  }
  // A collision is cryptographically negligible with a sound generator, but
  // explicit separation makes the invariant hold even with a faulty provider.
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const value = randomBytes(32);
    if (!Buffer.isBuffer(value) || value.length !== 32) {
      if (Buffer.isBuffer(value)) value.fill(0);
      throw new Error('Managed encryption-key generator returned an invalid value');
    }
    try {
      if (!forbiddenKey || !crypto.timingSafeEqual(value, forbiddenKey)) {
        return `base64:${value.toString('base64')}`;
      }
    } finally { value.fill(0); }
  }
  throw new Error('Managed encryption keys could not be generated independently');
}

async function exists(file) {
  try { await fs.access(file); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}

async function syncRegularFile(file, label) {
  const handle = await fs.open(file, fsConstants.O_RDWR | (fsConstants.O_NOFOLLOW ?? 0));
  try {
    const details = await handle.stat();
    if (!details.isFile()) throw new Error(`${label} must be a regular file`);
    await handle.sync();
  } finally { await handle.close(); }
}

function sameFileSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

async function boundedRegularSnapshot(file, maximum, label) {
  let details;
  try { details = await fs.lstat(file); }
  catch (error) {
    if (error.code === 'ENOENT') throw new Error(`${label} is missing`);
    throw error;
  }
  if (details.isSymbolicLink() || !details.isFile() || details.size < 1 || details.size > maximum) {
    throw new Error(`${label} must be one bounded regular file`);
  }
  return details;
}

async function digestStableFile(file, expected, maximum, label) {
  const before = await boundedRegularSnapshot(file, maximum, label);
  if (expected && !sameFileSnapshot(before, expected)) throw new Error(`${label} changed while it was being migrated`);
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  const handle = await fs.open(file, flags);
  const buffer = Buffer.allocUnsafe(64 * 1024);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !sameFileSnapshot(opened, before)) throw new Error(`${label} changed while it was being opened`);
    const digest = crypto.createHash('sha256');
    let position = 0;
    while (position < opened.size) {
      const length = Math.min(buffer.length, opened.size - position);
      const { bytesRead } = await handle.read(buffer, 0, length, position);
      if (bytesRead < 1) throw new Error(`${label} could not be read completely`);
      digest.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const after = await handle.stat();
    if (!sameFileSnapshot(after, opened)) throw new Error(`${label} changed while it was being read`);
    return digest.digest();
  } finally {
    buffer.fill(0);
    await handle.close();
  }
}

async function readBoundedRegularFile(file, label, maximum = MAX_SECRET_FILE_BYTES) {
  const absolute = path.resolve(file);
  const before = await fs.lstat(absolute);
  if (before.isSymbolicLink() || !before.isFile() || before.size < 1 || before.size > maximum) {
    throw new Error(`${label} must be one bounded regular file`);
  }
  const value = await fs.readFile(absolute);
  const after = await fs.lstat(absolute);
  if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
    throw new Error(`${label} changed while it was being imported`);
  }
  return value;
}

async function legacyStateKey(config) {
  if (config.persistence.encryptionKey) return config.persistence.encryptionKey;
  if (!config.persistence.encryptionKeyFile) throw new Error('Legacy state encryption key is unavailable');
  return (await readBoundedRegularFile(config.persistence.encryptionKeyFile, 'Legacy state encryption key', 256)).toString('utf8').trim();
}

async function authenticatedLegacyLogKey(config, hasHistory) {
  if (!hasHistory) return '';
  const stateKey = decodeManagedKey(await legacyStateKey(config));
  const logKey = loadLogEncryptionKey({ ...config.logging, generateEncryptionKey: false });
  try {
    if (crypto.timingSafeEqual(stateKey, logKey)) {
      throw new Error('Legacy state and encrypted log history must use independent encryption keys');
    }
    return `base64:${logKey.toString('base64')}`;
  } finally {
    stateKey.fill(0);
    logKey.fill(0);
  }
}

function tlsPassphrase(config) {
  if (config.http.tls.passphrase) return config.http.tls.passphrase;
  return '';
}

function importedTlsSubjectAltNames(certificate) {
  const source = certificate.subjectAltName;
  if (!source || /["\\]/u.test(source)) {
    return { subjectAltNames: [], requestedSubjectAltNames: [], rotationRequiresExplicitNames: true };
  }
  const values = []; const requested = [];
  let rotationRequiresExplicitNames = false;
  for (const entry of source.split(/,\s*/u)) {
    let value = '';
    if (entry.startsWith('IP Address:')) {
      value = entry.slice('IP Address:'.length);
      if (!net.isIP(value)) { rotationRequiresExplicitNames = true; continue; }
    } else if (entry.startsWith('DNS:')) {
      value = entry.slice('DNS:'.length).toLocaleLowerCase('en-US');
      if (/^(?=.{1,253}$)\*\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/u.test(value)) {
        if (!values.includes(value)) values.push(value);
        rotationRequiresExplicitNames = true;
        continue;
      }
      try { normalizeTlsSubjectAltNames([value]); }
      catch { rotationRequiresExplicitNames = true; continue; }
    } else {
      rotationRequiresExplicitNames = true;
      continue;
    }
    if (!values.includes(value)) values.push(value);
    if (!requested.includes(value)) requested.push(value);
  }
  if (!values.length || requested.length > 16) rotationRequiresExplicitNames = true;
  return {
    subjectAltNames: values,
    requestedSubjectAltNames: requested,
    rotationRequiresExplicitNames,
  };
}

async function importLegacyTls(config, rootDirectory, now = Date.now) {
  const source = config.http.tls;
  const passphrase = source.passphraseFile
    ? (await readBoundedRegularFile(source.passphraseFile, 'Legacy TLS passphrase', 4_096)).toString('utf8').replace(/[\r\n]+$/u, '')
    : tlsPassphrase(config);
  if (source.pfxFile) {
    const pfx = await readBoundedRegularFile(source.pfxFile, 'Legacy TLS PFX');
    const secureContext = tls.createSecureContext({ pfx, ...(passphrase ? { passphrase } : {}), minVersion: 'TLSv1.2' });
    const leafDer = secureContext.context.getCertificate();
    if (!Buffer.isBuffer(leafDer) || !leafDer.length) throw new Error('Legacy TLS PFX leaf certificate is unavailable');
    const leaf = new crypto.X509Certificate(leafDer);
    const validationTime = Number(now());
    assertImportedTlsLeafUsable(leaf, { now: validationTime });
    let caPem = '';
    const caCandidate = source.caFile || path.join(rootDirectory, '.secrets', 'dashboard-ca.pem');
    if (caCandidate && await exists(caCandidate)) {
      caPem = (await readBoundedRegularFile(caCandidate, 'Legacy dashboard CA')).toString('utf8');
      let authority;
      try { authority = new crypto.X509Certificate(caPem); }
      catch { throw new Error('Legacy dashboard CA certificate could not be parsed'); }
      const validFrom = Date.parse(authority.validFrom); const validTo = Date.parse(authority.validTo);
      if (!authority.ca || !Number.isFinite(validFrom) || !Number.isFinite(validTo)
        || validationTime < validFrom || validationTime > validTo) {
        throw new Error('Legacy dashboard CA must be a currently valid certificate authority');
      }
      if (leaf.issuer !== authority.subject || !leaf.verify(authority.publicKey)) {
        throw new Error('Legacy dashboard CA is not associated with the TLS PFX leaf certificate');
      }
    }
    const authority = caPem ? new crypto.X509Certificate(caPem) : null;
    const importedNames = importedTlsSubjectAltNames(leaf);
    return {
      mode: 'imported-pfx', pfxBase64: pfx.toString('base64'), passphrase,
      caBase64: caPem ? Buffer.from(caPem, 'utf8').toString('base64') : '',
      fingerprint: leaf.fingerprint256.replaceAll(':', '').toLocaleLowerCase('en-US'),
      expiresAt: new Date(leaf.validTo).toISOString(), leafMetadataKnown: true,
      caFingerprint: authority ? authority.fingerprint256.replaceAll(':', '').toLocaleLowerCase('en-US') : '',
      caExpiresAt: authority ? new Date(authority.validTo).toISOString() : '',
      ...importedNames,
      importedAt: new Date().toISOString(),
    };
  }
  if (source.keyFile && source.certFile) {
    const [keyPem, certPem, caPem] = await Promise.all([
      readBoundedRegularFile(source.keyFile, 'Legacy TLS private key').then((value) => value.toString('utf8')),
      readBoundedRegularFile(source.certFile, 'Legacy TLS certificate').then((value) => value.toString('utf8')),
      source.caFile ? readBoundedRegularFile(source.caFile, 'Legacy TLS CA').then((value) => value.toString('utf8')) : '',
    ]);
    const details = inspectTlsIdentity({ keyPem, certPem, caPem, passphrase });
    const importedNames = importedTlsSubjectAltNames(new crypto.X509Certificate(certPem));
    return {
      mode: 'imported-pem',
      keyBase64: Buffer.from(keyPem, 'utf8').toString('base64'),
      certBase64: Buffer.from(certPem, 'utf8').toString('base64'),
      caBase64: caPem ? Buffer.from(caPem, 'utf8').toString('base64') : '',
      passphrase, importedAt: new Date().toISOString(), leafMetadataKnown: true,
      ...details, ...importedNames,
    };
  }
  return encodeManagedTlsIdentity(generateInstanceTlsIdentity());
}

export function assertImportedTlsLeafUsable(certificate, { now = Date.now() } = {}) {
  const leaf = certificate instanceof crypto.X509Certificate
    ? certificate : new crypto.X509Certificate(certificate);
  const validFrom = Date.parse(leaf.validFrom);
  const validTo = Date.parse(leaf.validTo);
  if (!Number.isFinite(validFrom) || !Number.isFinite(validTo)
    || !Number.isFinite(now) || now < validFrom || now > validTo) {
    throw new Error('Legacy TLS PFX leaf certificate must be currently valid');
  }
  if (leaf.ca) throw new Error('Legacy TLS PFX leaf certificate must be an end-entity certificate');
  // Node exposes extended key usages as OIDs when that extension is present.
  // If constrained, the certificate must permit TLS server authentication.
  const usages = leaf.keyUsage;
  if (Array.isArray(usages) && usages.length
    && !usages.includes('1.3.6.1.5.5.7.3.1') && !usages.includes('2.5.29.37.0')) {
    throw new Error('Legacy TLS PFX leaf certificate is not valid for TLS server authentication');
  }
  return leaf;
}

export function encodeManagedTlsIdentity(identity) {
  return {
    mode: identity.mode,
    keyBase64: Buffer.from(identity.keyPem, 'utf8').toString('base64'),
    certBase64: Buffer.from(identity.certPem, 'utf8').toString('base64'),
    caBase64: identity.caPem ? Buffer.from(identity.caPem, 'utf8').toString('base64') : '',
    passphrase: identity.passphrase || '', generatedAt: identity.generatedAt,
    fingerprint: identity.fingerprint, expiresAt: identity.expiresAt, leafMetadataKnown: true,
    subjectAltNames: Array.isArray(identity.subjectAltNames) ? [...identity.subjectAltNames] : [],
    requestedSubjectAltNames: Array.isArray(identity.requestedSubjectAltNames) ? [...identity.requestedSubjectAltNames] : [],
    rotationRequiresExplicitNames: false,
  };
}

function runtimeSections(config) {
  return structuredClone({
    clusterName: config.clusterName,
    servers: config.servers,
    discord: config.discord,
    analytics: { enabled: Boolean(config.analytics?.enabled) },
    chat: config.chat,
    moderation: config.moderation,
    operations: config.operations,
  });
}

function infrastructureSections(config, { logDirectory = '' } = {}) {
  const { encryptionKey: _stateKey, encryptionKeyFile: _stateKeyFile, generateEncryptionKey: _stateGenerate,
    file: _stateFile, legacyJsonFile: _legacyFile, ...persistence } = config.persistence;
  const { encryptionKey: _logKey, encryptionKeyFile: _logKeyFile, generateEncryptionKey: _logGenerate,
    directory: _logDirectory, ...logging } = config.logging;
  const { adminToken: _adminToken, tls: _tls, ...http } = config.http;
  return structuredClone({
    persistence,
    logging: {
      ...logging,
      directory: path.resolve(logDirectory || config.logging.directory),
      fileEnabled: true, encryptionRequired: true, generateEncryptionKey: false, pretty: false,
    },
    http,
  });
}

function newInstallBase() {
  return applyDefaults({
    clusterName: 'BLCKSNAKE Command Cluster', servers: [],
    persistence: { driver: 'sqlite', legacyJsonFile: '', migrateLegacyJson: false },
    http: { enabled: true, host: '127.0.0.1', port: 8787, allowRemoteHttp: false },
    logging: { directory: './logs/current' },
  });
}

async function createInstallationDocument({
  legacyConfig = null, rootDirectory, logDirectory, importedLogEncryptionKey = '', tlsSubjectAltNames = [],
  stateEncryptionKey = null, randomBytes = crypto.randomBytes, now = Date.now,
}) {
  const base = legacyConfig ?? newInstallBase();
  const tlsIdentity = legacyConfig
    ? await importLegacyTls(legacyConfig, rootDirectory, now)
    : encodeManagedTlsIdentity(generateInstanceTlsIdentity({ randomBytes, subjectAltNames: tlsSubjectAltNames }));
  return {
    version: INSTALLATION_VERSION,
    configured: Boolean(legacyConfig?.servers?.length),
    configuration: {
      runtime: runtimeSections(base),
      infrastructure: infrastructureSections(base, { logDirectory }),
      secrets: {
        logEncryptionKey: importedLogEncryptionKey || randomManagedKey(randomBytes, stateEncryptionKey),
        automationToken: legacyConfig?.http?.adminToken || randomToken(randomBytes),
        automationTokenDeliveryId: '',
        pendingAutomationToken: '',
        pendingAutomationTokenDeliveryId: '',
        automationTokenDeliveryPending: false,
        ownerSetupToken: randomToken(randomBytes),
        tls: tlsIdentity,
      },
      instance: {
        id: crypto.randomUUID(),
        createdAt: Date.now(),
        importedLegacyConfiguration: Boolean(legacyConfig),
      },
    },
  };
}

function booleanEnvironment(value, fallback) {
  if (value == null || value === '') return fallback;
  if (/^(?:1|true|yes)$/iu.test(value)) return true;
  if (/^(?:0|false|no)$/iu.test(value)) return false;
  throw new Error('Managed boolean environment override must be true or false');
}

function portEnvironment(value, fallback) {
  if (value == null || value === '') return fallback;
  if (!/^\d{1,5}$/u.test(value)) throw new Error('Managed HTTP port override is invalid');
  const port = Number(value);
  if (port < 1 || port > 65_535) throw new Error('Managed HTTP port override is invalid');
  return port;
}

function initialTlsSubjectAltNames(environment) {
  const host = String(environment.CROSSCHAT_HTTP_HOST ?? '').trim();
  if (!host || ['0.0.0.0', '::', '[::]'].includes(host)) return [];
  return [host];
}

function tlsRuntime(identity) {
  if (identity.mode === 'imported-pfx') {
    return {
      enabled: true, keyFile: '', certFile: '', caFile: '', pfxFile: '',
      key: '', cert: '', ca: identity.caBase64 ? Buffer.from(identity.caBase64, 'base64').toString('utf8') : '',
      pfx: Buffer.from(identity.pfxBase64, 'base64'),
      passphrase: identity.passphrase || '', passphraseFile: '',
    };
  }
  return {
    enabled: true, keyFile: '', certFile: '', caFile: '', pfxFile: '',
    key: Buffer.from(identity.keyBase64, 'base64').toString('utf8'),
    cert: Buffer.from(identity.certBase64, 'base64').toString('utf8'),
    ca: identity.caBase64 ? Buffer.from(identity.caBase64, 'base64').toString('utf8') : '', pfx: null,
    passphrase: identity.passphrase || '', passphraseFile: '',
  };
}

export function materializeManagedConfig(record, {
  rootKey, dataDirectory, logDirectory, environment = process.env, initializedThisStart = false,
} = {}) {
  if (!record || record.version !== INSTALLATION_VERSION || !record.configuration) throw new Error('Managed installation settings are unavailable');
  const stored = record.configuration;
  const infrastructure = stored.infrastructure ?? {};
  const runtime = stored.runtime ?? {};
  const http = infrastructure.http ?? {};
  const rootEncoded = encodeManagedKey(rootKey);
  const input = {
    ...structuredClone(runtime),
    persistence: {
      ...(infrastructure.persistence ?? {}), driver: 'sqlite', file: path.join(dataDirectory, 'state.sqlite3'),
      legacyJsonFile: '', migrateLegacyJson: false, encryptionKey: rootEncoded, encryptionKeyFile: '',
      encryptionRequired: true, generateEncryptionKey: false,
    },
    logging: {
      ...(infrastructure.logging ?? {}), directory: logDirectory,
      encryptionKey: stored.secrets.logEncryptionKey, encryptionKeyFile: '',
      fileEnabled: true, encryptionRequired: true, generateEncryptionKey: false, pretty: false,
    },
    http: {
      ...http,
      enabled: true,
      host: environment.CROSSCHAT_HTTP_HOST || http.host || '127.0.0.1',
      port: portEnvironment(environment.CROSSCHAT_HTTP_PORT, http.port || 8787),
      allowRemoteHttp: booleanEnvironment(environment.CROSSCHAT_ALLOW_REMOTE_HTTPS, Boolean(http.allowRemoteHttp)),
      adminToken: stored.secrets.automationToken,
      ownerSetupToken: stored.secrets.ownerSetupToken,
      tls: tlsRuntime(stored.secrets.tls),
    },
    analytics: {
      ...(runtime.analytics ?? {}),
      endpoint: 'https://analytics.blcksnake.com/collect',
      token: '', tokenFile: '/app/.analytics-token',
      installationId: stored.instance.id,
    },
    managedInstance: {
      enabled: true,
      configured: record.configured,
      revision: record.revision,
      tlsMode: stored.secrets.tls.mode,
      initializedThisStart: Boolean(initializedThisStart),
      importedLegacyConfiguration: Boolean(stored.instance?.importedLegacyConfiguration),
      instanceId: stored.instance.id,
    },
  };
  const config = applyDefaults(input);
  return validateConfig(config, { allowNoServers: !record.configured, allowManagedSecrets: true });
}

async function resolveLegacyConfig(rootDirectory, environment) {
  const configPath = path.resolve(environment.CONFIG_PATH || path.join(rootDirectory, 'config.json'));
  if (!await exists(configPath)) return null;
  // Loading a legacy .env file is intentionally isolated. Managed startup must
  // never inject retired assignments into process.env or a caller-owned object.
  const legacyEnvironment = { ...environment };
  return loadConfig({ configPath, envPath: path.join(rootDirectory, '.env'), environment: legacyEnvironment });
}

function assertManagedLegacyStateSupported(config) {
  if (config?.persistence?.driver === 'json') {
    throw new Error('Legacy JSON state requires explicit migration; run npm run state:migrate with CONFIG_PATH before managed startup');
  }
}

function sameResolvedPath(left, right) {
  const normalize = (value) => process.platform === 'win32'
    ? path.resolve(value).toLocaleLowerCase('en-US') : path.resolve(value);
  return normalize(left) === normalize(right);
}

function withManagedLogDirectory(paths, logDirectory) {
  return Object.freeze({ ...paths, logDirectory: path.resolve(logDirectory) });
}

function legacyManagedPaths(config, paths, environment) {
  if (!config || sameResolvedPath(config.logging.directory, paths.logDirectory)) return paths;
  const legacyDefault = path.join(paths.root, 'logs');
  const managedDefault = path.join(paths.root, 'logs', 'current');
  if (!environment.CROSSCHAT_LOG_DIRECTORY
    && sameResolvedPath(config.logging.directory, legacyDefault)
    && sameResolvedPath(paths.logDirectory, managedDefault)) {
    return withManagedLogDirectory(paths, config.logging.directory);
  }
  throw new Error('Legacy log history uses a custom directory; set CROSSCHAT_LOG_DIRECTORY to that directory before managed startup');
}

async function authenticateLegacyLogHistory(config) {
  const directory = path.resolve(config.logging.directory);
  let details;
  try { details = await fs.lstat(directory); }
  catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  if (details.isSymbolicLink() || !details.isDirectory()) {
    throw new Error('Legacy encrypted log directory must be a real directory');
  }
  const names = await fs.readdir(directory);
  const hasHistory = names.some((name) => name === 'integrity.checkpoint.json'
    || /^(?:application|audit|security)(?:\..+)?\.jsonl\.enc$/u.test(name));
  if (!hasHistory) return false;
  for (const name of names) {
    if (name === 'integrity.checkpoint.json'
      || /^(?:application|audit|security)(?:\..+)?\.jsonl\.enc$/u.test(name)) {
      await hardenManagedPrivatePath(path.join(directory, name), { kind: 'file' });
    }
  }
  verifyLogDirectory({ ...config.logging, directory, generateEncryptionKey: false });
  return true;
}

function legacyConfigurationDigest(config, rootKey) {
  if (!config || !Buffer.isBuffer(rootKey) || rootKey.length !== 32) {
    throw new Error('Managed legacy initialization provenance is unavailable');
  }
  return crypto.createHmac('sha256', rootKey)
    .update('asa-crosschat:legacy-managed-configuration:v1:', 'utf8')
    .update(JSON.stringify(config), 'utf8')
    .digest('base64url');
}

function assertDigestMatches(actual, expected, message) {
  const left = Buffer.from(String(actual ?? ''), 'base64url');
  const right = Buffer.from(String(expected ?? ''), 'base64url');
  if (left.length !== 32 || right.length !== 32 || !crypto.timingSafeEqual(left, right)) {
    throw new Error(message);
  }
}

async function assertLegacyInitializationMatches(initialization, config) {
  if (!initialization || initialization.mode !== 'legacy-sqlite' || !config) {
    throw new Error('Managed legacy initialization requires its original CONFIG_PATH or config.json');
  }
  assertManagedLegacyStateSupported(config);
  const configuredKey = decodeManagedKey(await legacyStateKey(config));
  try {
    const expectedDigest = legacyConfigurationDigest(config, initialization.key);
    if (!crypto.timingSafeEqual(configuredKey, initialization.key)) {
      throw new Error('Managed legacy initialization no longer matches its original configuration');
    }
    assertDigestMatches(
      initialization.configurationDigest,
      expectedDigest,
      'Managed legacy initialization no longer matches its original configuration',
    );
  } finally { configuredKey.fill(0); }
}

async function assertLegacyConfigurationUsesKey(config, expectedKey) {
  const configuredKey = decodeManagedKey(await legacyStateKey(config));
  try {
    if (!crypto.timingSafeEqual(configuredKey, expectedKey)) {
      throw new Error('Managed legacy configuration does not match the encrypted state key');
    }
  } finally { configuredKey.fill(0); }
}

function assertCreatedInitialization(record, {
  mode, configurationDigest, stateDigest = '', expectedKey,
}) {
  const digestMatches = record.configurationDigest === configurationDigest && record.stateDigest === stateDigest;
  if (record.mode !== mode || !digestMatches || !crypto.timingSafeEqual(record.key, expectedKey)) {
    throw new Error('Managed initialization record conflicts with another startup');
  }
}

export function managedPaths({ rootDirectory = process.cwd(), environment = process.env } = {}) {
  const root = path.resolve(rootDirectory);
  const resolveDirectory = (value, fallback, label) => {
    if (value != null && typeof value !== 'string') throw new Error(`${label} directory override must be a string`);
    const selected = value || fallback;
    const resolved = path.isAbsolute(selected) ? path.resolve(selected) : path.resolve(root, selected);
    if (path.relative(path.parse(resolved).root, resolved) === '') {
      throw new Error(`${label} directory cannot be a filesystem root`);
    }
    return resolved;
  };
  const dataDirectory = resolveDirectory(environment.CROSSCHAT_DATA_DIRECTORY, 'data', 'Managed data');
  const logDirectory = resolveDirectory(environment.CROSSCHAT_LOG_DIRECTORY, path.join('logs', 'current'), 'Managed log');
  const keystoreDirectory = resolveDirectory(environment.CROSSCHAT_KEYSTORE_DIRECTORY, 'keystore', 'Managed keystore');
  const contains = (parent, child) => {
    const relative = path.relative(parent, child);
    return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
  };
  const directories = [dataDirectory, logDirectory, keystoreDirectory];
  for (let left = 0; left < directories.length; left += 1) {
    for (let right = left + 1; right < directories.length; right += 1) {
      if (contains(directories[left], directories[right]) || contains(directories[right], directories[left])) {
        throw new Error('Managed data, log, and keystore directories must be mutually disjoint');
      }
    }
  }
  return Object.freeze({
    root,
    dataDirectory,
    logDirectory,
    keystoreDirectory,
    get stateFile() { return path.join(this.dataDirectory, 'state.sqlite3'); },
    get rootKeyFile() { return path.join(this.keystoreDirectory, 'instance.key'); },
    get initializationKeyFile() { return path.join(this.keystoreDirectory, 'instance.initializing'); },
    get runtimeLockFile() { return path.join(this.keystoreDirectory, 'runtime-lock.sqlite3'); },
    get setupFile() { return path.join(this.keystoreDirectory, 'first-run-setup.txt'); },
  });
}

async function prepareManagedDirectories(paths) {
  const directories = [paths.dataDirectory, paths.logDirectory, paths.keystoreDirectory];
  for (const directory of directories) {
    await hardenManagedPrivatePath(directory, { kind: 'directory' });
  }
  const physical = await Promise.all(directories.map((directory) => fs.realpath(directory)));
  const contains = (parent, child) => {
    const relative = path.relative(parent, child);
    return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
  };
  for (let left = 0; left < physical.length; left += 1) {
    for (let right = left + 1; right < physical.length; right += 1) {
      if (contains(physical[left], physical[right]) || contains(physical[right], physical[left])) {
        throw new Error('Managed data, log, and keystore directories must be physically disjoint');
      }
    }
  }
}

async function reconcileManagedStatePublication(file) {
  const absolute = path.resolve(file);
  const directory = path.dirname(absolute);
  const escaped = path.basename(absolute).replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const pattern = new RegExp(`^${escaped}\\.\\d{1,10}\\.[a-f0-9]{24}\\.migrating(?:-(journal|wal|shm))?$`, 'u');
  let published = null;
  try { published = await fs.lstat(absolute); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (published && (published.isSymbolicLink() || !published.isFile())) {
    throw new Error('Managed SQLite publication is not a regular file');
  }
  const candidates = [];
  for (const name of await fs.readdir(directory)) {
    const match = name.match(pattern);
    if (!match) continue;
    const candidate = path.join(directory, name);
    const details = await fs.lstat(candidate);
    if (details.isSymbolicLink() || !details.isFile()) {
      throw new Error('Managed SQLite publication artifact is invalid');
    }
    candidates.push({ candidate, details, sidecar: Boolean(match[1]) });
  }
  const linked = candidates.filter(({ details, sidecar }) => !sidecar && published
    && details.dev === published.dev && details.ino === published.ino);
  if (published && published.nlink !== linked.length + 1) {
    throw new Error('Managed SQLite publication has an unexpected hard link');
  }
  for (const { details, sidecar } of candidates) {
    const linkedToPublished = !sidecar && published && details.dev === published.dev && details.ino === published.ino;
    if (details.nlink !== (linkedToPublished ? published.nlink : 1)) {
      throw new Error('Managed SQLite publication artifact has an unexpected hard link');
    }
  }
  for (const { candidate } of candidates) await fs.unlink(candidate);
  if (candidates.length) await syncDirectory(directory);
}

async function recoverInterruptedKeyPublication(paths, { initialize }) {
  const [keyExists, pendingExists, stateExists] = await Promise.all([
    exists(paths.rootKeyFile), exists(paths.initializationKeyFile), exists(paths.stateFile),
  ]);
  if (!keyExists || !pendingExists) return { keyExists, pendingExists, stateExists };
  if (!initialize) throw new Error('Managed initialization is incomplete; start the application to recover it');
  if (!stateExists) {
    throw new Error('Managed state is missing while the keystore exists; refusing to create a blank database');
  }
  const initialization = await readManagedInitializationFile(paths.initializationKeyFile);
  let publishedKey;
  try { publishedKey = await readManagedKeyFile(paths.rootKeyFile); }
  catch {
    // A pre-atomic writer may have left an exact prefix at the final path.
    // Keep the authenticated pending record until the database is opened and
    // only then permit narrowly-scoped repair in publishInitializedKey().
    initialization.key.fill(0);
    return { keyExists: false, pendingExists: true, stateExists };
  }
  try {
    if (!crypto.timingSafeEqual(publishedKey, initialization.key)) {
      throw new Error('Managed keystore contains conflicting initialization keys');
    }
  } finally {
    publishedKey.fill(0);
    initialization.key.fill(0);
  }
  // Keep the authenticated journal until the database, legacy provenance, and
  // installation document have all been revalidated. The mere appearance of
  // the final key is not a commit until that journal is safely removed.
  return { keyExists: true, pendingExists: true, stateExists };
}

async function assertExistingManagedInstallation(paths) {
  const [keyExists, pendingExists, stateExists, lockExists] = await Promise.all([
    exists(paths.rootKeyFile), exists(paths.initializationKeyFile),
    exists(paths.stateFile), exists(paths.runtimeLockFile),
  ]);
  if (!keyExists || pendingExists || !stateExists || !lockExists) {
    throw new Error('Managed maintenance requires an existing completed installation');
  }
}

async function annotateManagedPublicationError(error, paths, expectedKey) {
  let publishedKey = null;
  try {
    publishedKey = await readManagedKeyFile(paths.rootKeyFile);
    if (!crypto.timingSafeEqual(publishedKey, expectedKey)) return;
    Object.defineProperty(error, 'managedInitializationPublished', { value: true, enumerable: false });
    if (!await exists(paths.initializationKeyFile)) {
      Object.defineProperty(error, 'managedInitializationCommitted', { value: true, enumerable: false });
    }
  } catch { /* Preserve the original publication failure and fail closed. */ }
  finally { publishedKey?.fill(0); }
}

async function publishInitializedKey(paths, expectedKey, { afterKeyPublication = null } = {}) {
  let [keyExists, pendingExists] = await Promise.all([
    exists(paths.rootKeyFile), exists(paths.initializationKeyFile),
  ]);
  if (!pendingExists && !keyExists) {
    throw new Error('Managed initialization key disappeared before it could be published');
  }
  if (pendingExists) {
    const initialization = await readManagedInitializationFile(paths.initializationKeyFile);
    try {
      if (!crypto.timingSafeEqual(initialization.key, expectedKey)) {
        throw new Error('Managed keystore contains conflicting initialization keys');
      }
    } finally { initialization.key.fill(0); }
  }
  let publishedKey;
  if (keyExists) {
    try { publishedKey = await readManagedKeyFile(paths.rootKeyFile); }
    catch (readError) {
      try { await removeIncompleteManagedKeyFile(paths.rootKeyFile, expectedKey); }
      catch { throw readError; }
      keyExists = false;
    }
  }
  publishedKey ??= await createManagedKeyFile(paths.rootKeyFile, { encodedKey: encodeManagedKey(expectedKey) });
  try {
    if (!crypto.timingSafeEqual(publishedKey, expectedKey)) throw new Error('Managed initialization key publication was inconsistent');
  } finally {
    publishedKey.fill(0);
  }
  keyExists = true;
  if (afterKeyPublication) await afterKeyPublication();
  if (pendingExists) {
    await removeManagedInitializationFile(paths.initializationKeyFile);
    pendingExists = false;
  }
  if (!keyExists || pendingExists) throw new Error('Managed initialization key could not be published');
}

function legacyStateOptions(config, file, rootKey) {
  return {
    driver: 'sqlite', file, legacyJsonFile: '', migrateLegacyJson: false,
    historyLimit: config.persistence.historyLimit ?? 500,
    maxFileBytes: config.persistence.maxFileBytes ?? 16 * 1024 * 1024,
    maxDatabaseBytes: config.persistence.maxDatabaseBytes ?? 64 * 1024 * 1024,
    busyTimeoutMs: config.persistence.busyTimeoutMs ?? 5_000,
    encryptionKey: encodeManagedKey(rootKey), encryptionKeyFile: '', encryptionRequired: true, generateEncryptionKey: false,
  };
}

async function assertNoLegacySqliteSidecars(source) {
  for (const suffix of ['-journal', '-wal', '-shm']) {
    if (await exists(`${source}${suffix}`)) {
      throw new Error('Legacy SQLite state has an active journal; stop the legacy application before migration');
    }
  }
}

async function verifyLegacySqliteSnapshot(config, source, paths, rootKey, expectedStateDigest) {
  const maximum = config.persistence.maxDatabaseBytes ?? 64 * 1024 * 1024;
  const sourceBefore = await boundedRegularSnapshot(source, maximum, 'Legacy SQLite state database');
  await assertNoLegacySqliteSidecars(source);
  const temporary = `${path.resolve(paths.stateFile)}.${process.pid}.${crypto.randomBytes(12).toString('hex')}.migrating`;
  try {
    await fs.copyFile(source, temporary, fsConstants.COPYFILE_EXCL);
    await fs.chmod(temporary, 0o600).catch((error) => { if (process.platform !== 'win32') throw error; });
    const [sourceDigest, candidateDigest] = await Promise.all([
      digestStableFile(source, sourceBefore, maximum, 'Legacy SQLite state database'),
      digestStableFile(temporary, null, maximum, 'Managed SQLite migration candidate'),
    ]);
    if (!crypto.timingSafeEqual(sourceDigest, candidateDigest)) throw new Error('Legacy SQLite state changed during migration');
    await assertNoLegacySqliteSidecars(source);
    const candidate = new SqliteStateStore(legacyStateOptions(config, temporary, rootKey));
    let stateDigest = '';
    try {
      await candidate.load({ pruneExpired: false });
      candidate.health();
      stateDigest = candidate.authenticatedMigrationDigest();
    } finally { await candidate.close().catch(() => undefined); }
    assertDigestMatches(
      stateDigest,
      expectedStateDigest,
      'Managed legacy SQLite state no longer matches its authenticated migration snapshot',
    );
    await syncRegularFile(temporary, 'Managed SQLite migration candidate');
    const sourceAfter = await boundedRegularSnapshot(source, maximum, 'Legacy SQLite state database');
    const finalDigest = await digestStableFile(source, sourceBefore, maximum, 'Legacy SQLite state database');
    if (!sameFileSnapshot(sourceBefore, sourceAfter) || !crypto.timingSafeEqual(sourceDigest, finalDigest)) {
      throw new Error('Legacy SQLite state changed before migration commit');
    }
    await assertNoLegacySqliteSidecars(source);
    return stateDigest;
  } finally {
    await fs.unlink(temporary).catch(() => undefined);
    for (const suffix of ['-journal', '-wal', '-shm']) await fs.unlink(`${temporary}${suffix}`).catch(() => undefined);
    await syncDirectory(path.dirname(temporary));
  }
}

async function publishLegacySqliteState(config, paths, rootKey, {
  beforePublish = null, expectedStateDigest = '', allowPublishedDestination = false, migrationHook = null,
} = {}) {
  const configuredSource = path.resolve(config.persistence.file);
  const destination = path.resolve(paths.stateFile);
  const maximum = config.persistence.maxDatabaseBytes ?? 64 * 1024 * 1024;
  const destinationExists = await exists(destination);
  if (configuredSource !== destination && destinationExists && !allowPublishedDestination) {
    throw new Error('Managed SQLite destination already exists without authenticated migration provenance');
  }
  if (configuredSource !== destination && destinationExists && allowPublishedDestination) {
    // Until the journal is removed, both the original stopped source and the
    // published destination must still represent the committed snapshot. This
    // prevents silently dropping writes from a legacy service that resumed.
    await verifyLegacySqliteSnapshot(config, configuredSource, paths, rootKey, expectedStateDigest);
  }
  const shouldPublish = configuredSource !== destination && !destinationExists;
  const source = shouldPublish ? configuredSource : destination;
  const sourceBefore = await boundedRegularSnapshot(source, maximum, 'Legacy SQLite state database');
  await assertNoLegacySqliteSidecars(source);
  await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  const temporary = `${destination}.${process.pid}.${crypto.randomBytes(12).toString('hex')}.migrating`;
  let published = false;
  try {
    await fs.copyFile(source, temporary, fsConstants.COPYFILE_EXCL);
    await fs.chmod(temporary, 0o600).catch((error) => { if (process.platform !== 'win32') throw error; });
    const [sourceDigest, candidateDigest] = await Promise.all([
      digestStableFile(source, sourceBefore, maximum, 'Legacy SQLite state database'),
      digestStableFile(temporary, null, maximum, 'Managed SQLite migration candidate'),
    ]);
    if (!crypto.timingSafeEqual(sourceDigest, candidateDigest)) throw new Error('Legacy SQLite state changed during migration');
    await assertNoLegacySqliteSidecars(source);

    const candidate = new SqliteStateStore(legacyStateOptions(config, temporary, rootKey));
    let candidateStateDigest = '';
    try {
      await candidate.load({ pruneExpired: false });
      candidate.health();
      candidateStateDigest = candidate.authenticatedMigrationDigest();
    }
    finally { await candidate.close().catch(() => undefined); }
    if (expectedStateDigest) {
      assertDigestMatches(
        candidateStateDigest,
        expectedStateDigest,
        'Managed legacy SQLite state no longer matches its authenticated migration snapshot',
      );
    }
    await syncRegularFile(temporary, 'Managed SQLite migration candidate');
    const sourceAfter = await boundedRegularSnapshot(source, maximum, 'Legacy SQLite state database');
    if (!sameFileSnapshot(sourceBefore, sourceAfter)) throw new Error('Legacy SQLite state changed during migration');
    if (beforePublish) await beforePublish(candidateStateDigest);
    if (migrationHook) await migrationHook('initialization-published');
    const finalSourceDigest = await digestStableFile(source, sourceBefore, maximum, 'Legacy SQLite state database');
    if (!crypto.timingSafeEqual(sourceDigest, finalSourceDigest)) {
      throw new Error('Legacy SQLite state changed before migration publication');
    }
    await assertNoLegacySqliteSidecars(source);

    if (shouldPublish) {
      try {
        await fs.link(temporary, destination);
        published = true;
        await syncDirectory(path.dirname(destination));
      } catch (error) {
        if (error.code === 'EEXIST') {
          throw new Error('Managed SQLite destination appeared during authenticated migration publication');
        }
        throw error;
      }
    }
    if (migrationHook) await migrationHook('destination-published');
    return { published, stateDigest: candidateStateDigest };
  } finally {
    await fs.unlink(temporary).catch(() => undefined);
    for (const suffix of ['-journal', '-wal', '-shm']) await fs.unlink(`${temporary}${suffix}`).catch(() => undefined);
    if (published) await syncDirectory(path.dirname(destination));
  }
}

async function openManagedInstanceWithLock({
  rootDirectory, environment, randomBytes, now, initialize, requireExisting, paths, runtimeLock, migrationHook,
}) {
  let { keyExists, pendingExists, stateExists } = await recoverInterruptedKeyPublication(paths, { initialize });
  if (requireExisting && (!keyExists || pendingExists || !stateExists)) {
    throw new Error('Managed maintenance requires an existing completed installation');
  }
  if (!initialize && (!keyExists || pendingExists || !stateExists)) {
    throw new Error('Managed instance is not initialized; start the application before running operational checks');
  }
  if (keyExists && !stateExists) {
    throw new Error('Managed state is missing while the keystore exists; refusing to create a blank database');
  }
  let rootKey = null;
  let state = null;
  let initialization = null;
  try {
    if (pendingExists) initialization = await readManagedInitializationFile(paths.initializationKeyFile);

    // Published managed instances never inspect retired config/.env files.
    // An unfinished legacy import, however, is cryptographically bound to the
    // exact isolated legacy configuration that began it.
    let legacyConfig = null;
    let preparedInstallation = null;
    if (initialize && ((!keyExists && initialization?.mode !== 'fresh')
      || (pendingExists && initialization?.mode === 'legacy-sqlite'))) {
      legacyConfig = await resolveLegacyConfig(paths.root, environment);
      assertManagedLegacyStateSupported(legacyConfig);
      if (legacyConfig) {
        paths = legacyManagedPaths(legacyConfig, paths, environment);
        await prepareManagedDirectories(paths);
        const hasLegacyLogHistory = await authenticateLegacyLogHistory(legacyConfig);
        const importedLogEncryptionKey = await authenticatedLegacyLogKey(legacyConfig, hasLegacyLogHistory);
        // Import every external secret (including TLS/PFX/CA material) before
        // publishing either a managed-state snapshot or a root-key journal.
        const stateEncryptionKey = decodeManagedKey(await legacyStateKey(legacyConfig));
        try {
          preparedInstallation = await createInstallationDocument({
            legacyConfig, rootDirectory: paths.root, logDirectory: paths.logDirectory,
            importedLogEncryptionKey, stateEncryptionKey, randomBytes, now,
          });
        } finally { stateEncryptionKey.fill(0); }
      }
      if (initialization) await assertLegacyInitializationMatches(initialization, legacyConfig);
    }
    if (!keyExists && !pendingExists && stateExists && !legacyConfig) {
      throw new Error('Managed keystore is missing while encrypted state already exists; refusing to generate a replacement key');
    }

    if (!initialize || keyExists) {
      rootKey = await readManagedKeyFile(paths.rootKeyFile);
    } else if (initialization) {
      rootKey = initialization.key;
    } else if (legacyConfig) {
      const encoded = await legacyStateKey(legacyConfig);
      rootKey = decodeManagedKey(encoded);
      const configurationDigest = legacyConfigurationDigest(legacyConfig, rootKey);
      let created = null;
      // Authentication occurs against a private copy. The bound initialization
      // record is created only after that copy has passed integrity checks.
      await publishLegacySqliteState(legacyConfig, paths, rootKey, {
        beforePublish: async (stateDigest) => {
          created = await createManagedInitializationFile(paths.initializationKeyFile, {
            mode: 'legacy-sqlite', configurationDigest, stateDigest, encodedKey: encoded,
          });
          try {
            assertCreatedInitialization(created, {
              mode: 'legacy-sqlite', configurationDigest, stateDigest, expectedKey: rootKey,
            });
          }
          catch (error) { created.key.fill(0); created = null; throw error; }
          initialization = created;
          pendingExists = true;
        },
        migrationHook,
      });
      if (!created) throw new Error('Managed legacy initialization record was not published');
      rootKey.fill(0);
      rootKey = created.key;
      stateExists = await exists(paths.stateFile);
    } else {
      const created = await createManagedInitializationFile(paths.initializationKeyFile, {
        mode: 'fresh', randomBytes,
      });
      try {
        assertCreatedInitialization(created, {
          mode: 'fresh', configurationDigest: '', stateDigest: '', expectedKey: created.key,
        });
      }
      catch (error) { created.key.fill(0); throw error; }
      rootKey = created.key;
      initialization = created;
      pendingExists = true;
    }

    if (initialize && initialization?.mode === 'legacy-sqlite' && legacyConfig) {
      await publishLegacySqliteState(legacyConfig, paths, rootKey, {
        expectedStateDigest: initialization.stateDigest,
        allowPublishedDestination: true,
      });
      stateExists = await exists(paths.stateFile);
    }
    const useLegacyLimits = legacyConfig?.persistence ?? null;
    state = new SqliteStateStore({
      driver: 'sqlite', file: paths.stateFile, legacyJsonFile: '', migrateLegacyJson: false,
      historyLimit: useLegacyLimits?.historyLimit ?? 500,
      maxFileBytes: useLegacyLimits?.maxFileBytes ?? 16 * 1024 * 1024,
      // Existing managed state is opened under the supported absolute ceiling;
      // its persisted lower bound is restored immediately after decryption.
      maxDatabaseBytes: useLegacyLimits?.maxDatabaseBytes ?? (stateExists ? 1024 * 1024 * 1024 : 64 * 1024 * 1024),
      busyTimeoutMs: useLegacyLimits?.busyTimeoutMs ?? 5_000,
      encryptionKey: encodeManagedKey(rootKey), encryptionKeyFile: '', encryptionRequired: true, generateEncryptionKey: false,
      // A legacy snapshot must be authenticated byte-for-byte before any
      // release defaults are added to the newly published destination.
      seedBundledItemPackages: initialization?.mode !== 'legacy-sqlite',
    });
    // Only a protected, unpublished initialization key may recover an empty
    // application schema left between SQLite schema creation and its first
    // atomic state save. Published instances continue to fail closed.
    await state.load({
      allowEmptyExisting: Boolean(initialize && pendingExists && !keyExists && initialization?.mode === 'fresh'),
      pruneExpired: initialization?.mode !== 'legacy-sqlite',
    });
    if (initialize) await hardenManagedPrivatePath(paths.stateFile, { kind: 'file' });
    if (initialization?.mode === 'legacy-sqlite') {
      assertDigestMatches(
        state.authenticatedMigrationDigest(),
        initialization.stateDigest,
        'Managed legacy SQLite state no longer matches its authenticated migration snapshot',
      );
    }
    let installation = state.getInstallationSettings?.() ?? null;
    let initializedThisStart = false;
    if (!installation) {
      if (!initialize) throw new Error('Managed installation settings are missing; start the application to initialize them');
      // This only covers interrupted pre-protocol migrations: a database and
      // published key exist, but no managed installation document was committed.
      if (!legacyConfig && !initialization && keyExists) {
        legacyConfig = await resolveLegacyConfig(paths.root, environment);
      }
      assertManagedLegacyStateSupported(legacyConfig);
      if (legacyConfig) {
        paths = legacyManagedPaths(legacyConfig, paths, environment);
        await prepareManagedDirectories(paths);
        const hasLegacyLogHistory = await authenticateLegacyLogHistory(legacyConfig);
        const importedLogEncryptionKey = await authenticatedLegacyLogKey(legacyConfig, hasLegacyLogHistory);
        if (!preparedInstallation) {
          const stateEncryptionKey = decodeManagedKey(await legacyStateKey(legacyConfig));
          try {
            preparedInstallation = await createInstallationDocument({
              legacyConfig, rootDirectory: paths.root, logDirectory: paths.logDirectory,
              importedLogEncryptionKey, stateEncryptionKey, randomBytes, now,
            });
          } finally { stateEncryptionKey.fill(0); }
        }
      }
      if (legacyConfig) {
        await assertLegacyConfigurationUsesKey(legacyConfig, rootKey);
        if (!initialization) await publishLegacySqliteState(legacyConfig, paths, rootKey);
      }
      const initial = preparedInstallation ?? await createInstallationDocument({
        legacyConfig, rootDirectory: paths.root, logDirectory: paths.logDirectory,
        tlsSubjectAltNames: initialTlsSubjectAltNames(environment), stateEncryptionKey: rootKey, randomBytes, now,
      });
      installation = await state.setInstallationSettings(initial, { expectedRevision: 0, updatedBy: 'system' });
      initializedThisStart = true;
      if (initialization?.mode === 'legacy-sqlite' && migrationHook) {
        await migrationHook('installation-committed');
      }
    }
    const storedLogDirectory = installation.configuration.infrastructure?.logging?.directory;
    if (storedLogDirectory) {
      if (environment.CROSSCHAT_LOG_DIRECTORY
        && !sameResolvedPath(paths.logDirectory, storedLogDirectory)) {
        throw new Error('Managed log directory override does not match the committed encrypted log history');
      }
      if (!environment.CROSSCHAT_LOG_DIRECTORY && !sameResolvedPath(paths.logDirectory, storedLogDirectory)) {
        paths = withManagedLogDirectory(paths, storedLogDirectory);
        if (initialize) await prepareManagedDirectories(paths);
      }
    }
    const config = materializeManagedConfig(installation, {
      rootKey, dataDirectory: paths.dataDirectory, logDirectory: paths.logDirectory, environment, initializedThisStart,
    });
    await state.applyPersistenceLimits(config.persistence);
    if (initialization?.mode === 'legacy-sqlite') state.pruneExpired();
    if (initialize) {
      if (state.countOperatorAccounts?.() === 0) {
        const caBase64 = installation.configuration.secrets.tls.caBase64 || '';
        await writeFirstRunSetupFile(paths.setupFile, installation.configuration.secrets.ownerSetupToken, {
          caPem: caBase64 ? Buffer.from(caBase64, 'base64').toString('utf8') : '',
        });
      } else {
        await removeFirstRunSetupFile(paths.setupFile);
      }
    }
    // Verified root-key publication plus authenticated-journal removal is the
    // commit point. All setup, validation, and state work that may fail is
    // complete first, so callers never observe a routine post-commit rejection.
    if (initialize && pendingExists) {
      try {
        await publishInitializedKey(paths, rootKey, {
          afterKeyPublication: migrationHook
            ? () => migrationHook('root-key-published') : null,
        });
      } catch (error) {
        await annotateManagedPublicationError(error, paths, rootKey);
        throw error;
      }
      keyExists = true;
      pendingExists = false;
    }
    // A legacy migration remains bound to its authenticated source snapshot
    // until the root key is published and the recovery journal is removed.
    // Seed only after that commit point so an interrupted migration can retry.
    if (initialization?.mode === 'legacy-sqlite' && !pendingExists) {
      state.seedBundledItemPackages = true;
      if (state.seedBundledPackagesIfNeeded()) await state.save();
    }
    return {
      managed: true, config, state, paths, runtimeLock,
      get installation() { return installation; },
      setInstallation(value) { installation = value; },
      async ownerSetupCompleted() { await removeFirstRunSetupFile(paths.setupFile); },
      async close() {
        let stateError = null;
        try { await state.close?.(); } catch (error) { stateError = error; }
        try { await runtimeLock?.release?.(); }
        catch (error) { if (stateError) throw new AggregateError([stateError, error], 'Managed runtime close failed'); throw error; }
        if (stateError) throw stateError;
      },
    };
  } catch (error) {
    await state?.close?.().catch(() => undefined);
    throw error;
  } finally {
    if (initialization?.key && initialization.key !== rootKey) initialization.key.fill(0);
    rootKey?.fill(0);
  }
}

export async function openManagedInstance({
  rootDirectory = process.cwd(), environment = process.env, randomBytes = crypto.randomBytes, initialize = true,
  requireExisting = false, migrationHook = null, now = Date.now,
} = {}) {
  if (typeof initialize !== 'boolean') throw new Error('Managed initialization mode must be a boolean');
  if (typeof requireExisting !== 'boolean' || (requireExisting && !initialize)) {
    throw new Error('Managed existing-installation mode requires initialization access');
  }
  if (migrationHook !== null && typeof migrationHook !== 'function') throw new Error('Managed migration hook must be a function');
  if (typeof now !== 'function') throw new Error('Managed clock must be a function');
  const paths = managedPaths({ rootDirectory, environment });
  let runtimeLock = null;
  try {
    if (initialize) {
      if (requireExisting) await assertExistingManagedInstallation(paths);
      runtimeLock = await acquireManagedRuntimeLock(paths.runtimeLockFile, { requireExisting });
      if (requireExisting) await assertExistingManagedInstallation(paths);
      await prepareManagedDirectories(paths);
      await reconcileManagedKeystorePublications({
        keyFile: paths.rootKeyFile,
        initializationFile: paths.initializationKeyFile,
        setupFile: paths.setupFile,
      });
      await reconcileManagedStatePublication(paths.stateFile);
    }
    return await openManagedInstanceWithLock({
      rootDirectory, environment, randomBytes, now, initialize, requireExisting, paths, runtimeLock,
      migrationHook,
    });
  } catch (error) {
    await runtimeLock?.release?.().catch(() => undefined);
    throw error;
  }
}

export async function openRuntimeContext(options = {}) {
  const environment = options.environment ?? process.env;
  if (environment.CONFIG_PATH || environment.CROSSCHAT_CONFIGURATION_MODE === 'legacy') {
    const rootDirectory = path.resolve(options.rootDirectory ?? process.cwd());
    const configPath = path.resolve(environment.CONFIG_PATH || path.join(rootDirectory, 'config.json'));
    return {
      managed: false,
      config: await loadConfig({ configPath, envPath: path.join(rootDirectory, '.env'), environment }),
      state: null,
      close: async () => undefined,
    };
  }
  return openManagedInstance(options);
}

export const MANAGED_INSTALLATION_VERSION = INSTALLATION_VERSION;
