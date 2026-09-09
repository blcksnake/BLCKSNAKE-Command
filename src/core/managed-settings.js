import crypto from 'node:crypto';
import { isPrivateNetworkAddress } from '../adapters/rcon/source-rcon.js';
import { applyDefaults } from '../config.js';
import { encodeManagedTlsIdentity, materializeManagedConfig } from '../managed-instance.js';
import { readManagedKeyFile } from '../security/managed-keystore.js';
import { generateInstanceTlsIdentity } from '../security/instance-tls.js';

const SERVER_FIELDS = new Set([
  'id', 'name', 'host', 'port', 'enabled', 'pollIntervalMs', 'playerRefreshIntervalMs',
  'connectTimeoutMs', 'commandTimeoutMs', 'fragmentIdleMs', 'retries', 'password', 'profileImport',
]);
const PROFILE_FIELDS = new Set([
  'enabled', 'host', 'port', 'username', 'password', 'clearPassword', 'hostKeySha256', 'mapName', 'directories',
  'connectTimeoutMs', 'operationTimeoutMs', 'retryIntervalMs', 'revalidateIntervalMs', 'maxFileBytes',
]);
const DISCORD_FIELDS = new Set([
  'enabled', 'token', 'clearToken', 'applicationId', 'guildId', 'chatChannelId', 'auditChannelId',
  'adminRoleIds', 'moderatorRoleIds', 'relayRoleIds', 'allowUnlinkedChat', 'registerCommands',
]);
const MODERATION_FIELDS = new Set(['allowRawRcon', 'rawRconAllowlist']);
const ANALYTICS_FIELDS = new Set(['enabled']);
const SETTINGS_FIELDS = new Set(['clusterName', 'servers', 'discord', 'analytics', 'moderation']);
const UPDATE_FIELDS = new Set([
  'expectedRevision', 'settings', 'rotateAutomationToken', 'regenerateTls', 'tlsSubjectAltNames',
]);
const CONTROL_PATTERN = /[\u0000-\u001F\u007F-\u009F\u2028\u2029]/u;

function randomToken(randomBytes) {
  const value = randomBytes(48);
  if (!Buffer.isBuffer(value) || value.length !== 48) {
    if (Buffer.isBuffer(value)) value.fill(0);
    throw new Error('Managed token generator returned an invalid value');
  }
  try { return value.toString('base64url'); }
  finally { value.fill(0); }
}

function automationTokenDigest(value) {
  return crypto.createHash('sha256').update(String(value ?? '')).digest('base64url');
}

function automationTokenDeliveryId(value) {
  return crypto.createHash('sha256').update('asa-crosschat:automation-token-delivery:v1\0')
    .update(String(value ?? '')).digest('base64url');
}

export class ManagedSettingsError extends Error {
  constructor(status, code, message) {
    super(message); this.name = 'ManagedSettingsError'; this.status = status; this.code = code;
  }
}

function fail(status, code, message) { throw new ManagedSettingsError(status, code, message); }

function record(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail(400, 'invalid_settings', `${label} must be an object.`);
  }
  return value;
}

function exact(value, fields, label, optional = new Set()) {
  const source = record(value, label);
  for (const key of Object.keys(source)) if (!fields.has(key)) fail(400, 'invalid_settings', `${label} contains an unsupported field.`);
  for (const key of fields) if (!optional.has(key) && !Object.hasOwn(source, key)) fail(400, 'invalid_settings', `${label} is missing ${key}.`);
  return source;
}

function text(value, label, { minimum = 0, maximum = 256, pattern = null } = {}) {
  if (typeof value !== 'string' || CONTROL_PATTERN.test(value)) fail(400, 'invalid_settings', `${label} is invalid.`);
  const clean = value.trim();
  if (clean.length < minimum || clean.length > maximum || (pattern && !pattern.test(clean))) {
    fail(400, 'invalid_settings', `${label} is invalid.`);
  }
  return clean;
}

function secret(value, label, minimum = 1, maximum = 512) {
  if (typeof value !== 'string' || value.length < minimum || value.length > maximum || CONTROL_PATTERN.test(value)) {
    fail(400, 'invalid_settings', `${label} replacement is invalid.`);
  }
  return value;
}

function integer(value, label, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) fail(400, 'invalid_settings', `${label} is invalid.`);
  return value;
}

function flag(value, label) {
  if (typeof value !== 'boolean') fail(400, 'invalid_settings', `${label} must be true or false.`);
  return value;
}

function stringArray(value, label, { maximum = 64, pattern = null } = {}) {
  if (!Array.isArray(value) || value.length > maximum) fail(400, 'invalid_settings', `${label} is invalid.`);
  const result = [];
  for (const item of value) {
    const normalized = text(item, label, { minimum: 1, maximum: 256, pattern });
    if (!result.includes(normalized)) result.push(normalized);
  }
  return result;
}

function remoteDirectory(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.includes('\\')
    || /[*?[\]{}\u0000\r\n]/u.test(value)) return false;
  if (value === '/') return true;
  if (value.endsWith('/')) return false;
  return value.slice(1).split('/').every((segment) => segment && segment !== '.' && segment !== '..');
}

function normalizeProfile(raw, current, serverHost) {
  const source = exact(raw, PROFILE_FIELDS, 'Profile import settings', new Set(['password', 'clearPassword']));
  const enabled = flag(source.enabled, 'Profile import enabled');
  const existing = current ?? applyDefaults({ servers: [{ id: 'default', name: 'Default', host: serverHost, port: 1, password: 'x' }] }).servers[0].profileImport;
  const clearPassword = Object.hasOwn(source, 'clearPassword') ? flag(source.clearPassword, 'Clear SFTP password') : false;
  if (clearPassword && Object.hasOwn(source, 'password')) {
    fail(400, 'invalid_settings', 'Replace and clear cannot both be selected for the SFTP password.');
  }
  const password = clearPassword ? '' : Object.hasOwn(source, 'password')
    ? secret(source.password, 'SFTP password', 16, 512) : String(existing.password ?? '');
  const directories = stringArray(source.directories, 'Profile directories', { maximum: 16 });
  if (directories.some((directory) => !remoteDirectory(directory))) {
    fail(400, 'invalid_settings', 'Profile directories must be canonical absolute POSIX paths.');
  }
  const output = {
    enabled,
    host: text(source.host || serverHost, 'SFTP host', { minimum: 1, maximum: 255 }),
    port: integer(source.port, 'SFTP port', 1, 65_535),
    username: text(source.username, 'SFTP username', { maximum: 128 }),
    password,
    hostKeySha256: text(source.hostKeySha256, 'SFTP host-key fingerprint', {
      maximum: 64, pattern: enabled ? /^[a-f0-9]{64}$/iu : /^(?:[a-f0-9]{64})?$/iu,
    }).toLocaleLowerCase('en-US'),
    mapName: text(source.mapName, 'Profile map name', {
      maximum: 64, pattern: enabled ? /^[A-Za-z0-9_-]{1,64}$/u : /^(?:[A-Za-z0-9_-]{1,64})?$/u,
    }),
    directory: '',
    directories,
    connectTimeoutMs: integer(source.connectTimeoutMs, 'SFTP connect timeout', 100, 120_000),
    operationTimeoutMs: integer(source.operationTimeoutMs, 'SFTP operation timeout', 100, 300_000),
    retryIntervalMs: integer(source.retryIntervalMs, 'SFTP retry interval', 1_000, 86_400_000),
    revalidateIntervalMs: integer(source.revalidateIntervalMs, 'SFTP revalidation interval', 10_000, 86_400_000),
    maxFileBytes: integer(source.maxFileBytes, 'Profile maximum file size', 1_024, 64 * 1024 * 1024),
  };
  if (enabled && (!output.username || !output.password)) fail(400, 'invalid_settings', 'Enabled SFTP import requires credentials.');
  return output;
}

function normalizeServer(raw, current) {
  const source = exact(raw, SERVER_FIELDS, 'Map server settings', new Set(['password']));
  const id = text(source.id, 'Map ID', { minimum: 1, maximum: 32, pattern: /^[A-Za-z0-9_-]{1,32}$/u });
  const host = text(source.host, 'RCON host', { minimum: 1, maximum: 255 });
  if (!isPrivateNetworkAddress(host)) fail(400, 'public_rcon_refused', 'RCON hosts must be private or loopback IP literals.');
  const password = Object.hasOwn(source, 'password')
    ? secret(source.password, 'RCON password', 16, 256) : String(current?.password ?? '');
  if (!password) fail(400, 'rcon_password_required', `Map ${id} requires an RCON password.`);
  return {
    id,
    name: text(source.name, 'Map name', { minimum: 1, maximum: 96 }),
    host,
    port: integer(source.port, 'RCON port', 1, 65_535),
    password,
    enabled: flag(source.enabled, 'Map enabled'),
    pollIntervalMs: integer(source.pollIntervalMs, 'Polling interval', 250, 3_600_000),
    playerRefreshIntervalMs: integer(source.playerRefreshIntervalMs, 'Player refresh interval', 500, 3_600_000),
    connectTimeoutMs: integer(source.connectTimeoutMs, 'RCON connect timeout', 100, 120_000),
    commandTimeoutMs: integer(source.commandTimeoutMs, 'RCON command timeout', 100, 300_000),
    fragmentIdleMs: integer(source.fragmentIdleMs, 'RCON fragment idle time', 10, 10_000),
    retries: integer(source.retries, 'RCON retry count', 0, 10),
    allowPublicRcon: false,
    profileImport: normalizeProfile(source.profileImport, current?.profileImport, host),
  };
}

function normalizeDiscord(raw, current) {
  const source = exact(raw, DISCORD_FIELDS, 'Discord settings', new Set(['token', 'clearToken']));
  const clearToken = Object.hasOwn(source, 'clearToken') ? flag(source.clearToken, 'Clear Discord token') : false;
  if (clearToken && Object.hasOwn(source, 'token')) {
    fail(400, 'invalid_settings', 'Replace and clear cannot both be selected for the Discord token.');
  }
  const token = clearToken ? '' : Object.hasOwn(source, 'token')
    ? secret(source.token, 'Discord token', 20, 512) : String(current?.token ?? '');
  const enabled = flag(source.enabled, 'Discord enabled');
  const snowflake = /^(?:\d{17,20})?$/u;
  const output = {
    enabled,
    token,
    applicationId: text(source.applicationId, 'Discord application ID', { maximum: 20, pattern: snowflake }),
    guildId: text(source.guildId, 'Discord guild ID', { maximum: 20, pattern: snowflake }),
    chatChannelId: text(source.chatChannelId, 'Discord chat channel ID', { maximum: 20, pattern: snowflake }),
    auditChannelId: text(source.auditChannelId, 'Discord audit channel ID', { maximum: 20, pattern: snowflake }),
    adminRoleIds: stringArray(source.adminRoleIds, 'Discord administrator roles', { pattern: /^\d{17,20}$/u }),
    moderatorRoleIds: stringArray(source.moderatorRoleIds, 'Discord moderator roles', { pattern: /^\d{17,20}$/u }),
    relayRoleIds: stringArray(source.relayRoleIds, 'Discord relay roles', { pattern: /^\d{17,20}$/u }),
    allowUnlinkedChat: flag(source.allowUnlinkedChat, 'Allow unlinked Discord chat'),
    registerCommands: flag(source.registerCommands, 'Register Discord commands'),
  };
  if (enabled && (!token || !output.applicationId || !output.guildId || !output.chatChannelId)) {
    fail(400, 'discord_credentials_required', 'Enabled Discord relay requires its token, application, guild, and chat channel.');
  }
  return output;
}

function normalizeModeration(raw, current = {}) {
  if (raw == null) return structuredClone(current);
  const source = exact(raw, MODERATION_FIELDS, 'Advanced console settings');
  const allowRawRcon = flag(source.allowRawRcon, 'Allowlisted console enabled');
  const rawRconAllowlist = stringArray(source.rawRconAllowlist, 'Allowlisted console verbs', {
    maximum: 64, pattern: /^[A-Za-z][A-Za-z0-9_-]{0,63}$/u,
  });
  if (allowRawRcon && rawRconAllowlist.length === 0) {
    fail(400, 'invalid_settings', 'The advanced console requires at least one allowlisted command verb.');
  }
  return { ...structuredClone(current), allowRawRcon, rawRconAllowlist };
}

function normalizeAnalytics(raw, current = {}) {
  if (raw == null) return { enabled: current.enabled === true };
  const source = exact(raw, ANALYTICS_FIELDS, 'Analytics settings');
  return { enabled: flag(source.enabled, 'Optional analytics enabled') };
}

function normalizeSettings(raw, currentRuntime) {
  const source = exact(raw, SETTINGS_FIELDS, 'Settings', new Set(['analytics', 'moderation']));
  if (!Array.isArray(source.servers) || source.servers.length > 64) fail(400, 'invalid_settings', 'Map servers must be an array of at most 64 entries.');
  const currentServers = new Map((currentRuntime.servers ?? []).map((server) => [server.id, server]));
  const servers = source.servers.map((server) => normalizeServer(server, currentServers.get(server?.id)));
  if (new Set(servers.map((server) => server.id.toLocaleLowerCase('en-US'))).size !== servers.length) {
    fail(400, 'duplicate_server', 'Each map server must have a unique ID, ignoring letter case.');
  }
  const passwords = servers.map((server) => server.password);
  if (new Set(passwords).size !== passwords.length) fail(400, 'rcon_password_reused', 'Each map must use a different RCON password.');
  return {
    clusterName: text(source.clusterName, 'Cluster name', { minimum: 1, maximum: 96 }),
    servers,
    discord: normalizeDiscord(source.discord, currentRuntime.discord),
    analytics: normalizeAnalytics(source.analytics, currentRuntime.analytics),
    moderation: normalizeModeration(source.moderation, currentRuntime.moderation),
  };
}

function projectProfile(profile = {}) {
  return {
    enabled: Boolean(profile.enabled), host: profile.host ?? '', port: profile.port ?? 22,
    username: profile.username ?? '', passwordConfigured: Boolean(profile.password),
    hostKeySha256: profile.hostKeySha256 ?? '', mapName: profile.mapName ?? '',
    directories: [...(profile.directories ?? [])],
    connectTimeoutMs: profile.connectTimeoutMs ?? 5_000,
    operationTimeoutMs: profile.operationTimeoutMs ?? 15_000,
    retryIntervalMs: profile.retryIntervalMs ?? 60_000,
    revalidateIntervalMs: profile.revalidateIntervalMs ?? 300_000,
    maxFileBytes: profile.maxFileBytes ?? 16 * 1024 * 1024,
  };
}

function projectServer(server) {
  return {
    id: server.id, name: server.name, host: server.host, port: server.port, enabled: server.enabled !== false,
    passwordConfigured: Boolean(server.password), pollIntervalMs: server.pollIntervalMs,
    playerRefreshIntervalMs: server.playerRefreshIntervalMs, connectTimeoutMs: server.connectTimeoutMs,
    commandTimeoutMs: server.commandTimeoutMs, fragmentIdleMs: server.fragmentIdleMs, retries: server.retries,
    profileImport: projectProfile(server.profileImport),
  };
}

function tlsRotationRequiresExplicitNames(tls = {}) {
  if (tls.rotationRequiresExplicitNames === true) return true;
  if (tls.rotationRequiresExplicitNames === false) return false;
  return typeof tls.mode === 'string' && tls.mode.startsWith('imported-');
}

export function projectManagedSettings(installation, {
  activeRevision = installation?.revision,
  activeTlsCaBase64 = installation?.configuration?.secrets?.tls?.caBase64 ?? '',
  activeAutomationTokenDigest = automationTokenDigest(
    installation?.configuration?.secrets?.automationToken ?? '',
  ),
} = {}) {
  const config = installation.configuration; const runtime = config.runtime; const discord = runtime.discord;
  const tls = config.secrets.tls;
  const pfxMetadataUnknown = tls.mode === 'imported-pfx' && !tls.leafMetadataKnown;
  const tokenActivationPending = automationTokenDigest(config.secrets.automationToken) !== activeAutomationTokenDigest;
  const activeDeliveryId = String(config.secrets.automationTokenDeliveryId ?? '');
  return {
    revision: installation.revision,
    managed: true,
    restartRequired: installation.revision !== activeRevision,
    instance: {
      instanceId: config.instance.id,
      keystore: 'protected',
      tls: {
        mode: tls.mode,
        fingerprint: pfxMetadataUnknown ? '' : (tls.fingerprint || ''),
        expiresAt: pfxMetadataUnknown ? '' : (tls.expiresAt || ''),
        expiryKnown: !pfxMetadataUnknown && Boolean(tls.expiresAt),
        trustUpdateRequired: String(tls.caBase64 ?? '') !== String(activeTlsCaBase64 ?? ''),
        rotationRequiresExplicitNames: tlsRotationRequiresExplicitNames(tls),
        subjectAltNames: Array.isArray(tls.subjectAltNames) ? [...tls.subjectAltNames] : [],
        additionalSubjectAltNames: Array.isArray(tls.requestedSubjectAltNames)
          ? [...tls.requestedSubjectAltNames] : [],
      },
      automationToken: {
        configured: Boolean(config.secrets.automationToken),
        activationPending: tokenActivationPending,
        deliveryPending: Boolean(config.secrets.pendingAutomationToken)
          || config.secrets.automationTokenDeliveryPending === true,
        // This is a non-secret receipt digest, not a bearer. Keeping the last
        // promoted receipt lets a browser reconcile a lost ACK response even
        // when the process restarted before it could refresh Settings.
        activationReceipt: /^[A-Za-z0-9_-]{43}$/u.test(activeDeliveryId) ? activeDeliveryId : '',
      },
    },
    settings: {
      clusterName: runtime.clusterName,
      servers: runtime.servers.map(projectServer),
      discord: {
        enabled: Boolean(discord.enabled), tokenConfigured: Boolean(discord.token),
        applicationId: discord.applicationId ?? '', guildId: discord.guildId ?? '',
        chatChannelId: discord.chatChannelId ?? '', auditChannelId: discord.auditChannelId ?? '',
        adminRoleIds: [...(discord.adminRoleIds ?? [])], moderatorRoleIds: [...(discord.moderatorRoleIds ?? [])],
        relayRoleIds: [...(discord.relayRoleIds ?? [])], allowUnlinkedChat: Boolean(discord.allowUnlinkedChat),
        registerCommands: Boolean(discord.registerCommands),
      },
      analytics: { enabled: Boolean(runtime.analytics?.enabled) },
      moderation: {
        allowRawRcon: Boolean(runtime.moderation?.allowRawRcon),
        rawRconAllowlist: [...(runtime.moderation?.rawRconAllowlist ?? [])],
      },
    },
  };
}

export class ManagedSettingsService {
  constructor({
    context, state, paths, environment = process.env, randomBytes = crypto.randomBytes,
    analyticsConsentHandler = null,
  } = {}) {
    this.context = context; this.state = state; this.paths = paths; this.environment = environment;
    this.randomBytes = randomBytes; this.activeRevision = context.installation.revision;
    this.activeTlsCaBase64 = context.installation.configuration.secrets.tls.caBase64 ?? '';
    this.activeAutomationTokenDigest = automationTokenDigest(
      context.installation.configuration.secrets.automationToken ?? '',
    );
    this.analyticsConsentHandler = analyticsConsentHandler;
  }

  setAnalyticsConsentHandler(handler) {
    this.analyticsConsentHandler = typeof handler === 'function' ? handler : null;
  }

  current() {
    return projectManagedSettings(this.context.installation, {
      activeRevision: this.activeRevision, activeTlsCaBase64: this.activeTlsCaBase64,
      activeAutomationTokenDigest: this.activeAutomationTokenDigest,
    });
  }

  publicCa() {
    const encoded = this.context.installation.configuration.secrets.tls.caBase64 || '';
    if (!encoded) return '';
    const pem = Buffer.from(encoded, 'base64').toString('utf8');
    let certificate;
    try { certificate = new crypto.X509Certificate(pem); }
    catch { throw new Error('Managed HTTPS CA is invalid'); }
    if (!certificate.ca) throw new Error('Managed HTTPS trust anchor is not a certificate authority');
    return certificate.toString();
  }

  async saveConfiguration(current, nextConfiguration, { configured, expectedRevision, updatedBy }) {
    const rootKey = await readManagedKeyFile(this.paths.rootKeyFile);
    try {
      materializeManagedConfig({ ...current, configured, configuration: nextConfiguration }, {
        rootKey, dataDirectory: this.paths.dataDirectory, logDirectory: this.paths.logDirectory, environment: this.environment,
      });
    } finally { rootKey.fill(0); }
    let saved;
    try {
      saved = await this.state.setInstallationSettings({
        version: 1, configured, configuration: nextConfiguration,
      }, { expectedRevision, updatedBy });
    } catch (error) {
      if (error?.code === 'installation_settings_revision_conflict') fail(409, 'settings_conflict', 'Settings changed. Refresh and review them again.');
      throw error;
    }
    this.context.setInstallation(saved);
    return saved;
  }

  async rotateTlsLocally({ subjectAltNames, updatedBy = 'local:tls-rotate' } = {}) {
    const current = this.context.installation;
    if (subjectAltNames == null && tlsRotationRequiresExplicitNames(current.configuration.secrets.tls)) {
      const error = new Error('Imported HTTPS certificate names cannot be preserved safely; provide explicit DNS/IP names for rotation.');
      error.code = 'tls_rotation_explicit_names_required';
      throw error;
    }
    const nextConfiguration = structuredClone(current.configuration);
    const effectiveSubjectAltNames = subjectAltNames == null
      ? (current.configuration.secrets.tls.requestedSubjectAltNames ?? [])
      : subjectAltNames;
    nextConfiguration.secrets.tls = encodeManagedTlsIdentity(generateInstanceTlsIdentity({
      randomBytes: this.randomBytes, subjectAltNames: effectiveSubjectAltNames,
    }));
    const saved = await this.saveConfiguration(current, nextConfiguration, {
      configured: current.configured, expectedRevision: current.revision, updatedBy,
    });
    return projectManagedSettings(saved, {
      activeRevision: this.activeRevision, activeTlsCaBase64: this.activeTlsCaBase64,
      activeAutomationTokenDigest: this.activeAutomationTokenDigest,
    });
  }

  async update(raw, { updatedBy } = {}) {
    const body = exact(raw, UPDATE_FIELDS, 'Settings update', new Set([
      'rotateAutomationToken', 'regenerateTls', 'tlsSubjectAltNames',
    ]));
    const expectedRevision = integer(body.expectedRevision, 'Expected settings revision', 1, Number.MAX_SAFE_INTEGER);
    const current = this.context.installation;
    if (current.revision !== expectedRevision) fail(409, 'settings_conflict', 'Settings changed. Refresh and review them again.');
    const nextSettings = normalizeSettings(body.settings, current.configuration.runtime);
    const nextConfiguration = structuredClone(current.configuration);
    nextConfiguration.runtime = { ...nextConfiguration.runtime, ...nextSettings };
    const rotate = body.rotateAutomationToken == null ? false : flag(body.rotateAutomationToken, 'Rotate automation token');
    const regenerate = body.regenerateTls == null ? false : flag(body.regenerateTls, 'Regenerate HTTPS identity');
    const tlsSubjectAltNames = body.tlsSubjectAltNames == null ? []
      : stringArray(body.tlsSubjectAltNames, 'HTTPS certificate names', { maximum: 16 });
    if (!regenerate && body.tlsSubjectAltNames != null) {
      fail(400, 'invalid_settings', 'HTTPS certificate names can be changed only while regenerating the HTTPS identity.');
    }
    if (regenerate && tlsRotationRequiresExplicitNames(current.configuration.secrets.tls)
      && (body.tlsSubjectAltNames == null || tlsSubjectAltNames.length === 0)) {
      fail(400, 'tls_names_required', 'Enter the complete replacement DNS/IP name set before regenerating this imported HTTPS identity.');
    }
    let oneTimeAutomationToken = '';
    if (rotate) {
      oneTimeAutomationToken = randomToken(this.randomBytes);
      // Stage the replacement separately. A crash or restart before the browser
      // explicitly acknowledges receipt must keep the known active token.
      nextConfiguration.secrets.pendingAutomationToken = oneTimeAutomationToken;
      nextConfiguration.secrets.pendingAutomationTokenDeliveryId = automationTokenDeliveryId(oneTimeAutomationToken);
      nextConfiguration.secrets.automationTokenDeliveryPending = true;
    }
    if (regenerate) {
      try {
        nextConfiguration.secrets.tls = encodeManagedTlsIdentity(generateInstanceTlsIdentity({
          randomBytes: this.randomBytes, subjectAltNames: tlsSubjectAltNames,
        }));
      } catch {
        fail(400, 'invalid_settings', 'One or more HTTPS certificate names are invalid.');
      }
    }
    if (JSON.stringify(nextConfiguration) === JSON.stringify(current.configuration)) {
      fail(400, 'settings_unchanged', 'No settings changes were supplied.');
    }
    const saved = await this.saveConfiguration(current, nextConfiguration, {
      configured: nextSettings.servers.length > 0, expectedRevision, updatedBy,
    });
    let analyticsContact = null;
    if (Boolean(current.configuration.runtime.analytics?.enabled) !== nextSettings.analytics.enabled
      && this.analyticsConsentHandler) {
      try { analyticsContact = await this.analyticsConsentHandler(nextSettings.analytics.enabled); }
      catch { analyticsContact = { attempted: true, delivered: false }; }
    }
    return {
      ...projectManagedSettings(saved, {
        activeRevision: this.activeRevision, activeTlsCaBase64: this.activeTlsCaBase64,
        activeAutomationTokenDigest: this.activeAutomationTokenDigest,
      }),
      ...(oneTimeAutomationToken ? {
        automationToken: oneTimeAutomationToken,
        automationTokenDeliveryId: nextConfiguration.secrets.pendingAutomationTokenDeliveryId,
      } : {}),
      ...(analyticsContact ? { analyticsContact } : {}),
    };
  }

  async acknowledgeAutomationToken(raw, { updatedBy } = {}) {
    const body = exact(raw, new Set(['expectedRevision', 'deliveryId']), 'Automation token acknowledgment');
    const expectedRevision = integer(body.expectedRevision, 'Expected settings revision', 1, Number.MAX_SAFE_INTEGER);
    const current = this.context.installation;
    const deliveryId = text(body.deliveryId, 'Automation token delivery receipt', { minimum: 43, maximum: 43, pattern: /^[A-Za-z0-9_-]{43}$/u });
    const pendingToken = current.configuration.secrets.pendingAutomationToken;
    const pendingDeliveryId = current.configuration.secrets.pendingAutomationTokenDeliveryId;
    if (current.configuration.secrets.automationTokenDeliveryPending !== true
      || typeof pendingToken !== 'string' || !/^[A-Za-z0-9_-]{64}$/u.test(pendingToken)) {
      fail(409, 'token_delivery_not_pending', 'No unacknowledged automation token is pending.');
    }
    if (typeof pendingDeliveryId !== 'string' || pendingDeliveryId !== deliveryId
      || pendingDeliveryId !== automationTokenDeliveryId(pendingToken)) {
      fail(409, 'token_delivery_replaced', 'That displayed token is no longer the pending replacement. Rotate and save a new token.');
    }
    if (current.revision < expectedRevision) fail(409, 'settings_conflict', 'Settings changed. Refresh and review them again.');
    const nextConfiguration = structuredClone(current.configuration);
    nextConfiguration.secrets.automationToken = pendingToken;
    nextConfiguration.secrets.automationTokenDeliveryId = pendingDeliveryId;
    nextConfiguration.secrets.pendingAutomationToken = '';
    nextConfiguration.secrets.pendingAutomationTokenDeliveryId = '';
    nextConfiguration.secrets.automationTokenDeliveryPending = false;
    const saved = await this.saveConfiguration(current, nextConfiguration, {
      configured: current.configured, expectedRevision: current.revision, updatedBy,
    });
    return projectManagedSettings(saved, {
      activeRevision: this.activeRevision,
      activeTlsCaBase64: this.activeTlsCaBase64,
      activeAutomationTokenDigest: this.activeAutomationTokenDigest,
    });
  }
}
