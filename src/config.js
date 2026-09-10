import fs from 'node:fs/promises';
import path from 'node:path';
import {
  RESTART_MAX_DELAY_MINUTES, announcementMessageMaxLength, codePointLength, restartNotice,
} from './core/announcement-policy.js';
import { normalizeSshSha256Fingerprint } from './core/ssh-fingerprint.js';
import { isPathWithin } from './core/filesystem.js';
import { isLoopbackHost } from './core/network.js';

const DEFAULT_SERVER = Object.freeze({
  enabled: true,
  pollIntervalMs: 1_000,
  playerRefreshIntervalMs: 15_000,
  connectTimeoutMs: 3_000,
  commandTimeoutMs: 5_000,
  fragmentIdleMs: 100,
  retries: 2,
  allowPublicRcon: false,
});

const DEFAULT_PROFILE_IMPORT = Object.freeze({
  enabled: false,
  host: '',
  port: 22,
  username: '',
  password: '',
  hostKeySha256: '',
  mapName: '',
  directory: '',
  directories: [],
  connectTimeoutMs: 5_000,
  operationTimeoutMs: 15_000,
  retryIntervalMs: 60_000,
  revalidateIntervalMs: 300_000,
  maxFileBytes: 16 * 1024 * 1024,
});

export const DEFAULT_ANNOUNCEMENT_TEMPLATES = Object.freeze({
  Welcome: 'Welcome survivors! Please review the server rules and contact staff if you need help.',
  'Maintenance soon': 'Server maintenance will begin soon. Move to a safe location and prepare for a restart.',
  'World save': 'A world save is being performed. Brief lag may occur.',
  'Event starting': 'A server event is starting soon. Watch chat for details and follow staff instructions.',
  'Rules reminder': 'Reminder: respect other players, avoid blocking access, and report disputes to staff.',
});

const DEFAULTS = Object.freeze({
  clusterName: 'ASA Cluster',
  servers: [],
  discord: {
    enabled: false, token: '', applicationId: '', guildId: '', chatChannelId: '', auditChannelId: '',
    adminRoleIds: [], moderatorRoleIds: [], relayRoleIds: [], allowUnlinkedChat: true, registerCommands: true,
  },
  analytics: {
    enabled: false, endpoint: 'https://analytics.blcksnake.com/collect', token: '', tokenFile: '', installationId: '',
  },
  chat: {
    relayChannels: ['Global'], gamePrefix: '[CC]', discordPrefix: '[Discord]', commandPrefix: '!cc',
    emojiMode: 'shortcode', gameMaxLength: 420, discordMaxLength: 1_900, includeServerName: true,
    gameDuplicateTtlSeconds: 2, echoTtlSeconds: 90,
  },
  moderation: {
    messageBurst: 5, messageWindowSeconds: 10, defaultMuteMinutes: 15, maxMuteMinutes: 43_200,
    blockedTerms: [], blockedRegexes: [], adminPlayerIds: [], adminPlayerNames: [],
    allowRawRcon: false, rawRconAllowlist: ['ListPlayers', 'SaveWorld', 'GetChat'],
    announcementTemplates: DEFAULT_ANNOUNCEMENT_TEMPLATES,
    announcementTemplatesInitialized: true,
  },
  operations: {
    joinLeaveAlerts: true, restartWarningMinutes: [15, 10, 5, 1], serverStatusAlerts: true,
    welcomeMessage: { enabled: true, text: 'Welcome to {cluster}, {name}! Type {prefix} help for commands.' },
  },
  persistence: {
    driver: 'sqlite', file: './data/state.sqlite3', legacyJsonFile: './data/state.json', migrateLegacyJson: true,
    historyLimit: 500, maxFileBytes: 16 * 1024 * 1024, maxDatabaseBytes: 64 * 1024 * 1024, busyTimeoutMs: 5_000,
    encryptionKey: '', encryptionKeyFile: './.secrets/state.key', encryptionRequired: true, generateEncryptionKey: true,
  },
  http: {
    enabled: true, host: '127.0.0.1', port: 8787, adminToken: '', allowRemoteHttp: false,
    requestTimeoutMs: 15_000, headersTimeoutMs: 10_000, keepAliveTimeoutMs: 5_000, maxRequestsPerSocket: 100,
    tls: {
      enabled: false, keyFile: '', certFile: '', caFile: '', pfxFile: '',
      passphrase: '', passphraseFile: '',
    },
  },
  logging: {
    level: 'info', pretty: false, consoleEnabled: false, fileEnabled: true, directory: './logs',
    maxFileBytes: 10 * 1024 * 1024, maxFiles: 20, retentionDays: 14, auditRetentionDays: 90,
    securityRetentionDays: 90, maxRecordBytes: 64 * 1024, memoryRecords: 500, encryptionKey: '',
    encryptionKeyFile: './.secrets/log.key', encryptionRequired: true, generateEncryptionKey: true,
  },
});

function merge(base, override) {
  return { ...base, ...(override ?? {}) };
}

function parseEnvLine(line) {
  const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
  if (!match) return null;
  let value = match[2];
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
  else value = value.replace(/\s+#.*$/, '');
  return [match[1], value.replace(/\\n/g, '\n')];
}

export async function loadEnvFile(file = '.env', environment = process.env) {
  let text;
  try { text = await fs.readFile(file, 'utf8'); }
  catch (error) { if (error.code === 'ENOENT') return environment; throw error; }
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const parsed = parseEnvLine(line);
    if (parsed && environment[parsed[0]] == null) environment[parsed[0]] = parsed[1];
  }
  return environment;
}

function resolveSecrets(value, environment) {
  if (typeof value === 'string' && value.startsWith('$ENV:')) {
    const key = value.slice(5);
    if (!environment[key]) throw new Error(`Required environment variable ${key} is not set`);
    return environment[key];
  }
  if (Array.isArray(value)) return value.map((item) => resolveSecrets(item, environment));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, resolveSecrets(item, environment)]));
  return value;
}

function assert(condition, message) {
  if (!condition) throw new Error(`Configuration error: ${message}`);
}

function positiveInteger(value, field, minimum = 1, maximum = Number.MAX_SAFE_INTEGER) {
  assert(Number.isInteger(value) && value >= minimum && value <= maximum, `${field} must be an integer from ${minimum} to ${maximum}`);
}

function isRemoteProfileDirectory(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.includes('\\') || /[*?[\]{}\0\r\n]/u.test(value)) return false;
  if (value === '/') return true;
  if (value.endsWith('/') || path.posix.normalize(value) !== value) return false;
  return value.slice(1).split('/').every((segment) => segment && segment !== '.' && segment !== '..');
}

function isStateEncryptionKey(value) {
  return /^(?:base64:)?[A-Za-z0-9+/]{43}=$/.test(value)
    || /^(?:hex:)?[a-f0-9]{64}$/i.test(value);
}

export function validateConfig(config, { allowNoServers = false, allowManagedSecrets = false } = {}) {
  assert(typeof config.clusterName === 'string' && config.clusterName.trim(), 'clusterName is required');
  assert(config.analytics && typeof config.analytics === 'object' && !Array.isArray(config.analytics), 'analytics must be an object');
  assert(typeof config.analytics.enabled === 'boolean', 'analytics.enabled must be true or false');
  assert(typeof config.analytics.endpoint === 'string', 'analytics.endpoint must be a string');
  assert(typeof config.analytics.token === 'string' && config.analytics.token.length <= 512,
    'analytics.token must contain at most 512 characters');
  assert(typeof config.analytics.tokenFile === 'string' && config.analytics.tokenFile.length <= 4_096,
    'analytics.tokenFile must contain at most 4096 characters');
  assert(typeof config.analytics.installationId === 'string' && config.analytics.installationId.length <= 128,
    'analytics.installationId must contain at most 128 characters');
  let analyticsEndpoint = null;
  try { analyticsEndpoint = new URL(config.analytics.endpoint); } catch { /* validated below */ }
  assert(analyticsEndpoint?.protocol === 'https:' && !analyticsEndpoint.username && !analyticsEndpoint.password
    && !analyticsEndpoint.hash, 'analytics.endpoint must be an HTTPS URL without credentials or a fragment');
  assert(Array.isArray(config.servers) && (allowNoServers || config.servers.length > 0), 'at least one server is required');
  const ids = new Set();
  for (const [index, server] of config.servers.entries()) {
    const prefix = `servers[${index}]`;
    assert(/^[a-z0-9_-]{1,32}$/i.test(server.id ?? ''), `${prefix}.id must be 1-32 letters, numbers, underscores, or hyphens`);
    assert(!ids.has(server.id), `server ID ${server.id} is duplicated`); ids.add(server.id);
    assert(typeof server.name === 'string' && server.name.trim(), `${prefix}.name is required`);
    assert(typeof server.host === 'string' && server.host.trim(), `${prefix}.host is required`);
    positiveInteger(server.port, `${prefix}.port`, 1, 65535);
    assert(typeof server.password === 'string' && server.password.length > 0, `${prefix}.password is required`);
    positiveInteger(server.pollIntervalMs, `${prefix}.pollIntervalMs`, 250, 3_600_000);
    positiveInteger(server.playerRefreshIntervalMs, `${prefix}.playerRefreshIntervalMs`, 500, 3_600_000);
    positiveInteger(server.connectTimeoutMs, `${prefix}.connectTimeoutMs`, 100, 120_000);
    positiveInteger(server.commandTimeoutMs, `${prefix}.commandTimeoutMs`, 100, 300_000);
    positiveInteger(server.fragmentIdleMs, `${prefix}.fragmentIdleMs`, 10, 10_000);
    positiveInteger(server.retries + 1, `${prefix}.retries + 1`, 1, 11);
    assert(typeof server.allowPublicRcon === 'boolean', `${prefix}.allowPublicRcon must be true or false`);
    const profile = server.profileImport;
    assert(profile && typeof profile === 'object' && !Array.isArray(profile), `${prefix}.profileImport must be an object`);
    assert(typeof profile.enabled === 'boolean', `${prefix}.profileImport.enabled must be true or false`);
    assert(Array.isArray(profile.directories), `${prefix}.profileImport.directories must be an array`);
    assert(profile.directories.every(isRemoteProfileDirectory), `${prefix}.profileImport.directories must contain canonical absolute POSIX paths`);
    assert(!profile.directory || isRemoteProfileDirectory(profile.directory), `${prefix}.profileImport.directory must be a canonical absolute POSIX path`);
    positiveInteger(profile.connectTimeoutMs, `${prefix}.profileImport.connectTimeoutMs`, 100, 120_000);
    positiveInteger(profile.operationTimeoutMs, `${prefix}.profileImport.operationTimeoutMs`, 100, 300_000);
    positiveInteger(profile.retryIntervalMs, `${prefix}.profileImport.retryIntervalMs`, 1_000, 86_400_000);
    positiveInteger(profile.revalidateIntervalMs, `${prefix}.profileImport.revalidateIntervalMs`, 10_000, 86_400_000);
    positiveInteger(profile.maxFileBytes, `${prefix}.profileImport.maxFileBytes`, 1_024, 64 * 1024 * 1024);
    if (profile.enabled) {
      assert(typeof profile.host === 'string' && profile.host.trim(), `${prefix}.profileImport.host is required when enabled`);
      positiveInteger(profile.port, `${prefix}.profileImport.port`, 1, 65535);
      assert(typeof profile.username === 'string' && profile.username, `${prefix}.profileImport.username is required when enabled`);
      assert(typeof profile.password === 'string' && profile.password, `${prefix}.profileImport.password is required when enabled`);
      assert(Boolean(normalizeSshSha256Fingerprint(profile.hostKeySha256)), `${prefix}.profileImport.hostKeySha256 must be a SHA-256 hex or OpenSSH fingerprint`);
      assert(/^[A-Za-z0-9_-]{1,64}$/.test(profile.mapName ?? ''), `${prefix}.profileImport.mapName is required when enabled`);
    }
  }
  assert(['shortcode', 'unicode', 'strip'].includes(config.chat.emojiMode), 'chat.emojiMode must be shortcode, unicode, or strip');
  assert(Array.isArray(config.chat.relayChannels) && config.chat.relayChannels.length, 'chat.relayChannels cannot be empty');
  positiveInteger(config.chat.gameMaxLength, 'chat.gameMaxLength', 40, 2_000);
  restartNotice('cancelled', {}, config.chat.gameMaxLength);
  restartNotice('deadline', {}, config.chat.gameMaxLength);
  restartNotice('scheduled', { minutes: RESTART_MAX_DELAY_MINUTES }, config.chat.gameMaxLength);
  positiveInteger(config.chat.discordMaxLength, 'chat.discordMaxLength', 100, 2_000);
  positiveInteger(config.chat.gameDuplicateTtlSeconds, 'chat.gameDuplicateTtlSeconds', 1, 30);
  positiveInteger(config.chat.echoTtlSeconds, 'chat.echoTtlSeconds', 1, 3_600);
  positiveInteger(config.moderation.messageBurst, 'moderation.messageBurst', 1, 1_000);
  positiveInteger(config.moderation.messageWindowSeconds, 'moderation.messageWindowSeconds', 1, 3_600);
  positiveInteger(config.moderation.defaultMuteMinutes, 'moderation.defaultMuteMinutes', 1, 525_600);
  positiveInteger(config.moderation.maxMuteMinutes, 'moderation.maxMuteMinutes', 1, 525_600);
  assert(config.moderation.defaultMuteMinutes <= config.moderation.maxMuteMinutes, 'defaultMuteMinutes cannot exceed maxMuteMinutes');
  assert(config.moderation.announcementTemplates && typeof config.moderation.announcementTemplates === 'object' && !Array.isArray(config.moderation.announcementTemplates), 'moderation.announcementTemplates must be an object');
  assert(typeof config.moderation.announcementTemplatesInitialized === 'boolean', 'moderation.announcementTemplatesInitialized must be true or false');
  assert(Object.keys(config.moderation.announcementTemplates).length <= 32, 'moderation.announcementTemplates cannot contain more than 32 templates');
  const announcementMaximum = announcementMessageMaxLength(config.chat.gameMaxLength);
  const announcementNames = new Set();
  for (const [name, message] of Object.entries(config.moderation.announcementTemplates)) {
    assert(/^[A-Za-z0-9][A-Za-z0-9 _-]{0,39}$/u.test(name), `moderation.announcementTemplates.${name} has an invalid name`);
    const canonicalName = name.toLocaleLowerCase('en-US');
    assert(!['__proto__', 'constructor', 'prototype'].includes(canonicalName), `moderation.announcementTemplates.${name} uses a reserved name`);
    assert(!announcementNames.has(canonicalName), `moderation.announcementTemplates.${name} duplicates another name`);
    announcementNames.add(canonicalName);
    assert(typeof message === 'string' && message.trim(), `moderation.announcementTemplates.${name} must be non-empty text`);
    assert(codePointLength(message.trim()) <= announcementMaximum,
      `moderation.announcementTemplates.${name} exceeds the ${announcementMaximum}-character announcement limit`);
  }
  assert(typeof config.moderation.allowRawRcon === 'boolean', 'moderation.allowRawRcon must be true or false');
  assert(Array.isArray(config.moderation.rawRconAllowlist), 'moderation.rawRconAllowlist must be an array');
  assert(config.moderation.rawRconAllowlist.every((verb) => typeof verb === 'string' && /^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(verb)), 'moderation.rawRconAllowlist must contain only single command verbs');
  assert(typeof config.operations.joinLeaveAlerts === 'boolean', 'operations.joinLeaveAlerts must be true or false');
  assert(Array.isArray(config.operations.restartWarningMinutes) && config.operations.restartWarningMinutes.every((value) => Number.isInteger(value) && value > 0 && value <= RESTART_MAX_DELAY_MINUTES), 'operations.restartWarningMinutes must contain positive whole minutes');
  assert(typeof config.operations.serverStatusAlerts === 'boolean', 'operations.serverStatusAlerts must be true or false');
  assert(config.operations.welcomeMessage && typeof config.operations.welcomeMessage === 'object', 'operations.welcomeMessage must be an object');
  assert(typeof config.operations.welcomeMessage.enabled === 'boolean', 'operations.welcomeMessage.enabled must be true or false');
  assert(typeof config.operations.welcomeMessage.text === 'string' && config.operations.welcomeMessage.text.trim(), 'operations.welcomeMessage.text is required');
  positiveInteger(config.persistence.historyLimit + 1, 'persistence.historyLimit + 1', 1, 1_000_001);
  positiveInteger(config.persistence.maxFileBytes, 'persistence.maxFileBytes', 1_024, 64 * 1024 * 1024);
  assert(['sqlite', 'json'].includes(config.persistence.driver), 'persistence.driver must be sqlite or json');
  assert(typeof config.persistence.file === 'string' && config.persistence.file, 'persistence.file is required');
  assert(typeof config.persistence.legacyJsonFile === 'string', 'persistence.legacyJsonFile must be a string');
  assert(typeof config.persistence.migrateLegacyJson === 'boolean', 'persistence.migrateLegacyJson must be true or false');
  positiveInteger(config.persistence.maxDatabaseBytes, 'persistence.maxDatabaseBytes', 1024 * 1024, 1024 * 1024 * 1024);
  positiveInteger(config.persistence.busyTimeoutMs, 'persistence.busyTimeoutMs', 100, 60_000);
  assert(typeof config.persistence.encryptionKey === 'string', 'persistence.encryptionKey must be a string');
  assert(typeof config.persistence.encryptionKeyFile === 'string', 'persistence.encryptionKeyFile must be a string');
  assert(typeof config.persistence.encryptionRequired === 'boolean', 'persistence.encryptionRequired must be true or false');
  assert(typeof config.persistence.generateEncryptionKey === 'boolean', 'persistence.generateEncryptionKey must be true or false');
  assert(!(config.persistence.encryptionKey && config.persistence.encryptionKeyFile), 'configure only one persistence encryption key source');
  assert(!config.persistence.encryptionKey || isStateEncryptionKey(config.persistence.encryptionKey), 'persistence.encryptionKey must be exactly 32 bytes encoded as base64 or hexadecimal');
  assert(!config.persistence.generateEncryptionKey || Boolean(config.persistence.encryptionKeyFile), 'persistence.generateEncryptionKey requires persistence.encryptionKeyFile');
  assert(!config.persistence.generateEncryptionKey || !config.persistence.encryptionKey, 'persistence.generateEncryptionKey cannot be used with persistence.encryptionKey');
  assert(!config.persistence.encryptionRequired || Boolean(config.persistence.encryptionKey || config.persistence.encryptionKeyFile), 'persistence encryption is required but no key source is configured');
  assert(config.persistence.driver !== 'sqlite' || config.persistence.encryptionRequired, 'SQLite persistence requires encryptionRequired=true');
  assert(!config.persistence.legacyJsonFile || config.persistence.file !== config.persistence.legacyJsonFile, 'persistence.file and persistence.legacyJsonFile must be different');
  assert(!config.persistence.encryptionKeyFile || config.persistence.file !== config.persistence.encryptionKeyFile, 'state data and encryption key files must be different');
  assert(!config.persistence.legacyJsonFile || !config.persistence.encryptionKeyFile || config.persistence.legacyJsonFile !== config.persistence.encryptionKeyFile, 'legacy state and encryption key files must be different');
  if (config.discord.enabled) {
    for (const field of ['token', 'applicationId', 'guildId', 'chatChannelId']) assert(typeof config.discord[field] === 'string' && config.discord[field], `discord.${field} is required when Discord is enabled`);
  }
  if (config.http.enabled) {
    positiveInteger(config.http.port, 'http.port', 1, 65535);
    assert(typeof config.http.host === 'string' && config.http.host, 'http.host is required');
    positiveInteger(config.http.requestTimeoutMs, 'http.requestTimeoutMs', 1_000, 120_000);
    positiveInteger(config.http.headersTimeoutMs, 'http.headersTimeoutMs', 1_000, 120_000);
    positiveInteger(config.http.keepAliveTimeoutMs, 'http.keepAliveTimeoutMs', 100, 120_000);
    positiveInteger(config.http.maxRequestsPerSocket, 'http.maxRequestsPerSocket', 1, 10_000);
    assert(typeof config.http.allowRemoteHttp === 'boolean', 'http.allowRemoteHttp must be true or false');
    assert(config.http.allowRemoteHttp || isLoopbackHost(config.http.host), 'http.host must be loopback unless http.allowRemoteHttp=true');
    assert(typeof config.http.adminToken === 'string', 'http.adminToken must be a string');
    assert(config.http.adminToken.length === 0 || config.http.adminToken.length >= 32,
      'http.adminToken must contain at least 32 characters when configured');
    assert(config.http.adminToken.length <= 256, 'http.adminToken must contain at most 256 characters');
    assert(!config.http.allowRemoteHttp || config.http.adminToken.length >= 32, 'http.adminToken must contain at least 32 characters when remote HTTP is allowed');
    assert(config.http.tls && typeof config.http.tls === 'object' && !Array.isArray(config.http.tls), 'http.tls must be an object');
    assert(typeof config.http.tls.enabled === 'boolean', 'http.tls.enabled must be true or false');
    for (const field of ['keyFile', 'certFile', 'caFile', 'pfxFile', 'passphrase', 'passphraseFile']) {
      assert(typeof config.http.tls[field] === 'string', `http.tls.${field} must be a string`);
    }
    for (const field of ['key', 'cert', 'ca']) {
      assert(config.http.tls[field] == null || typeof config.http.tls[field] === 'string', `http.tls.${field} must be a string when managed in memory`);
    }
    assert(config.http.tls.pfx == null || Buffer.isBuffer(config.http.tls.pfx), 'http.tls.pfx must be a Buffer when managed in memory');
    const pemPair = Boolean(config.http.tls.keyFile && config.http.tls.certFile);
    const managedPemPair = Boolean(config.http.tls.key && config.http.tls.cert);
    const partialManagedPemPair = Boolean(config.http.tls.key || config.http.tls.cert) && !managedPemPair;
    const managedPfx = Buffer.isBuffer(config.http.tls.pfx) && config.http.tls.pfx.length > 0;
    const partialPemPair = Boolean(config.http.tls.keyFile || config.http.tls.certFile) && !pemPair;
    assert(!partialPemPair, 'http.tls.keyFile and http.tls.certFile must be configured together');
    assert(!partialManagedPemPair, 'managed HTTP TLS key and certificate must be configured together');
    assert(allowManagedSecrets || (!managedPemPair && !managedPfx && !config.http.tls.ca), 'in-memory HTTP TLS material is reserved for the managed instance store');
    const tlsSources = [pemPair, Boolean(config.http.tls.pfxFile), managedPemPair, managedPfx].filter(Boolean).length;
    assert(!config.http.tls.enabled || tlsSources > 0, 'enabled HTTP TLS requires a PEM key/certificate pair or PFX file');
    assert(tlsSources <= 1, 'configure either HTTP PEM files or one PFX source, not both');
    assert(config.http.tls.enabled || tlsSources === 0, 'disabled HTTP TLS cannot include active key material');
    assert(!(config.http.tls.passphrase && config.http.tls.passphraseFile), 'configure only one HTTP TLS passphrase source');
    assert(!config.http.allowRemoteHttp || config.http.tls.enabled, 'remote HTTP administration requires http.tls.enabled=true');
    assert(config.http.headersTimeoutMs <= config.http.requestTimeoutMs, 'http.headersTimeoutMs cannot exceed http.requestTimeoutMs');
  }
  assert(config.logging && typeof config.logging === 'object' && !Array.isArray(config.logging), 'logging must be an object');
  assert(['debug', 'info', 'warn', 'error'].includes(config.logging.level), 'logging.level must be debug, info, warn, or error');
  assert(typeof config.logging.pretty === 'boolean', 'logging.pretty must be true or false');
  assert(typeof config.logging.consoleEnabled === 'boolean', 'logging.consoleEnabled must be true or false');
  assert(typeof config.logging.fileEnabled === 'boolean', 'logging.fileEnabled must be true or false');
  assert(typeof config.logging.directory === 'string' && config.logging.directory, 'logging.directory is required');
  positiveInteger(config.logging.maxFileBytes, 'logging.maxFileBytes', 64 * 1024, 1024 * 1024 * 1024);
  positiveInteger(config.logging.maxFiles, 'logging.maxFiles', 2, 1_000);
  positiveInteger(config.logging.retentionDays, 'logging.retentionDays', 1, 3_650);
  positiveInteger(config.logging.auditRetentionDays, 'logging.auditRetentionDays', 1, 3_650);
  positiveInteger(config.logging.securityRetentionDays, 'logging.securityRetentionDays', 1, 3_650);
  positiveInteger(config.logging.maxRecordBytes, 'logging.maxRecordBytes', 1_024, 1024 * 1024);
  positiveInteger(config.logging.memoryRecords, 'logging.memoryRecords', 100, 10_000);
  assert(typeof config.logging.encryptionKey === 'string', 'logging.encryptionKey must be a string');
  assert(typeof config.logging.encryptionKeyFile === 'string', 'logging.encryptionKeyFile must be a string');
  assert(typeof config.logging.encryptionRequired === 'boolean', 'logging.encryptionRequired must be true or false');
  assert(typeof config.logging.generateEncryptionKey === 'boolean', 'logging.generateEncryptionKey must be true or false');
  assert(!(config.logging.encryptionKey && config.logging.encryptionKeyFile), 'configure only one log encryption key source');
  assert(!config.logging.encryptionKey || isStateEncryptionKey(config.logging.encryptionKey), 'logging.encryptionKey must be exactly 32 bytes encoded as base64 or hexadecimal');
  assert(!config.logging.generateEncryptionKey || Boolean(config.logging.encryptionKeyFile), 'logging.generateEncryptionKey requires logging.encryptionKeyFile');
  assert(!config.logging.generateEncryptionKey || !config.logging.encryptionKey, 'logging.generateEncryptionKey cannot be used with logging.encryptionKey');
  assert(!config.logging.fileEnabled || config.logging.encryptionRequired, 'file logging requires logging.encryptionRequired=true');
  assert(!config.logging.fileEnabled || Boolean(config.logging.encryptionKey || config.logging.encryptionKeyFile), 'encrypted file logging requires a key source');
  assert(!config.logging.encryptionKeyFile || config.logging.encryptionKeyFile !== config.persistence.encryptionKeyFile, 'state and log encryption keys must be different files');
  assert(!config.logging.encryptionKeyFile || !isPathWithin(config.logging.directory, config.logging.encryptionKeyFile), 'the log encryption key must be outside logging.directory');
  assert(path.resolve(config.logging.directory) !== path.resolve(path.dirname(config.persistence.file)), 'logging.directory must be separate from the state-data directory');
  return config;
}

export function applyDefaults(input = {}) {
  const suppliedModeration = input.moderation ?? {};
  const suppliedTemplates = suppliedModeration.announcementTemplates;
  const initializeAnnouncementTemplates = suppliedModeration.announcementTemplatesInitialized !== true
    && (!suppliedTemplates || Object.keys(suppliedTemplates).length === 0);
  const config = {
    ...DEFAULTS,
    ...input,
    servers: (input.servers ?? []).map((server) => ({
      ...DEFAULT_SERVER,
      ...server,
      profileImport: {
        ...DEFAULT_PROFILE_IMPORT,
        ...(server.profileImport ?? {}),
        host: server.profileImport?.host || server.host || '',
        directories: [...(server.profileImport?.directories ?? [])],
      },
    })),
    discord: merge(DEFAULTS.discord, input.discord),
    analytics: merge(DEFAULTS.analytics, input.analytics),
    chat: merge(DEFAULTS.chat, input.chat),
    moderation: {
      ...merge(DEFAULTS.moderation, suppliedModeration),
      announcementTemplates: { ...(initializeAnnouncementTemplates ? DEFAULT_ANNOUNCEMENT_TEMPLATES : suppliedTemplates ?? DEFAULT_ANNOUNCEMENT_TEMPLATES) },
      announcementTemplatesInitialized: true,
    },
    operations: merge(DEFAULTS.operations, input.operations),
    persistence: {
      ...merge(DEFAULTS.persistence, input.persistence),
      ...(input.persistence?.encryptionKey && input.persistence?.encryptionKeyFile == null ? { encryptionKeyFile: '' } : {}),
    },
    http: {
      ...merge(DEFAULTS.http, input.http),
      tls: merge(DEFAULTS.http.tls, input.http?.tls),
    },
    logging: {
      ...merge(DEFAULTS.logging, input.logging),
      ...(input.logging?.encryptionKey && input.logging?.encryptionKeyFile == null ? { encryptionKeyFile: '' } : {}),
    },
  };
  return config;
}

export async function loadConfig({ configPath = process.env.CONFIG_PATH ?? './config.json', envPath = '.env', environment = process.env } = {}) {
  await loadEnvFile(envPath, environment);
  const absolute = path.resolve(configPath);
  const raw = JSON.parse(await fs.readFile(absolute, 'utf8'));
  const resolved = resolveSecrets(raw, environment);
  const config = applyDefaults(resolved);
  config.persistence.file = path.resolve(path.dirname(absolute), config.persistence.file);
  if (config.persistence.legacyJsonFile) {
    config.persistence.legacyJsonFile = path.resolve(path.dirname(absolute), config.persistence.legacyJsonFile);
  }
  if (config.persistence.encryptionKeyFile) {
    config.persistence.encryptionKeyFile = path.resolve(path.dirname(absolute), config.persistence.encryptionKeyFile);
  }
  for (const field of ['keyFile', 'certFile', 'caFile', 'pfxFile', 'passphraseFile']) {
    if (config.http.tls[field]) config.http.tls[field] = path.resolve(path.dirname(absolute), config.http.tls[field]);
  }
  config.logging.directory = path.resolve(path.dirname(absolute), config.logging.directory);
  if (config.logging.encryptionKeyFile) {
    config.logging.encryptionKeyFile = path.resolve(path.dirname(absolute), config.logging.encryptionKeyFile);
  }
  return validateConfig(config);
}
