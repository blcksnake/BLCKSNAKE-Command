import crypto from 'node:crypto';
import {
  RESTART_MAX_DELAY_MINUTES, announcementMessageMaxLength, restartReasonMaxLength,
} from '../core/announcement-policy.js';
import { getItem, searchItems } from '../core/item-catalog.js';
import {
  OperatorPasswordService, generateTemporaryPassword, normalizeOperatorRole, normalizeOperatorUsername,
  validateOperatorPassword,
} from '../core/operator-credentials.js';
import { PermissionLevel } from '../core/permissions.js';
import { isLoopbackHost } from '../core/network.js';
import { redactText } from '../core/redaction.js';
import { SlidingWindowRateLimiter } from '../core/rate-limiter.js';
import { normalizeWhitespace, truncateCodePoints } from '../core/sanitize.js';
import { redact } from '../logger.js';

const SESSION_COOKIE = 'asa_admin_session';
const SECURE_SESSION_COOKIE = '__Host-asa_admin_session';
const SESSION_TTL_MS = 8 * 60 * 60_000;
const SESSION_IDLE_TTL_MS = 30 * 60_000;
const RECENT_AUTH_TTL_MS = 10 * 60_000;
const MAX_SESSIONS_PER_OPERATOR = 5;
const CONFIRMATION_TTL_MS = 2 * 60_000;
const IDEMPOTENCY_TTL_MS = 15 * 60_000;
const SESSION_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const CONFIRMATION_PATTERN = /^[A-Za-z0-9_-]{32}$/;
const PLAYER_SELECTION_PATTERN = /^p2:[A-Za-z0-9_-]{24}$/;
const IDEMPOTENCY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const SERVER_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;
const ITEM_KEY_PATTERN = /^[a-z0-9][a-z0-9-]{0,99}$/;
const DIAGNOSTIC_CHANNELS = new Set(['application', 'audit', 'security']);
const DIAGNOSTIC_LEVELS = new Set(['debug', 'info', 'warn', 'error']);
const OWNER_SETUP_PROOF_CONTEXT = 'asa-crosschat:first-owner-setup:v1';

const ACTIONS = Object.freeze([
  { id: 'announce', minimumLevel: PermissionLevel.MODERATOR, label: 'Send announcement', group: 'Communication', risk: 'low', server: 'optional', description: 'Send an administrator message to one map or the cluster.' },
  { id: 'announce-template', minimumLevel: PermissionLevel.MODERATOR, label: 'Use announcement template', group: 'Communication', risk: 'low', server: 'optional', description: 'Send a configured announcement template.' },
  { id: 'save-world', minimumLevel: PermissionLevel.ADMIN, label: 'Save world', group: 'Maintenance', risk: 'medium', server: 'optional', description: 'Request a world save on one map or every map.' },
  { id: 'restart', minimumLevel: PermissionLevel.MODERATOR, label: 'Schedule restart window', group: 'Maintenance', risk: 'medium', server: 'optional', description: 'Send countdown warnings and save at the deadline; the host process is not restarted.' },
  { id: 'cancel-restart', minimumLevel: PermissionLevel.MODERATOR, label: 'Cancel restart window', group: 'Maintenance', risk: 'low', server: 'optional', description: 'Cancel the selected map or cluster restart schedule.' },
  { id: 'give-item', minimumLevel: PermissionLevel.ADMIN, label: 'Give item', group: 'Player', risk: 'medium', player: true, description: 'Grant a trusted built-in catalog item to a connected player.' },
  { id: 'give-xp', minimumLevel: PermissionLevel.ADMIN, label: 'Give XP', group: 'Player', risk: 'medium', player: true, description: 'Grant experience to a connected player.' },
  { id: 'refresh-player-id', minimumLevel: PermissionLevel.ADMIN, label: 'Refresh targeting ID', group: 'Player', risk: 'low', player: true, description: 'Re-read and verify the player profile through the map SFTP source.' },
  { id: 'player', minimumLevel: PermissionLevel.MODERATOR, label: 'Player details', group: 'Player', risk: 'low', player: true, description: 'View protected moderation and targeting details.' },
  { id: 'warn', minimumLevel: PermissionLevel.MODERATOR, label: 'Warn player', group: 'Moderation', risk: 'low', player: true, description: 'Send a private staff warning to a connected player.' },
  { id: 'note', minimumLevel: PermissionLevel.MODERATOR, label: 'Add moderation note', group: 'Moderation', risk: 'low', player: true, description: 'Save a private staff note in encrypted state.' },
  { id: 'mute-player', minimumLevel: PermissionLevel.MODERATOR, label: 'Mute relay', group: 'Moderation', risk: 'medium', player: true, description: 'Temporarily block the player from Cluster Chat relay.' },
  { id: 'unmute-player', minimumLevel: PermissionLevel.MODERATOR, label: 'Unmute relay', group: 'Moderation', risk: 'low', player: true, description: 'Remove the player Cluster Chat relay mute.' },
  { id: 'kick', minimumLevel: PermissionLevel.MODERATOR, label: 'Kick player', group: 'Moderation', risk: 'medium', player: true, description: 'Disconnect the selected online player.' },
  { id: 'ban', minimumLevel: PermissionLevel.ADMIN, label: 'Ban player', group: 'Moderation', risk: 'high', player: true, description: 'Ban the selected online player account.' },
  { id: 'whitelist', minimumLevel: PermissionLevel.ADMIN, label: 'Add to join allowlist', group: 'Moderation', risk: 'medium', player: true, description: 'Allow the selected connected account to join without checks.' },
  { id: 'unwhitelist', minimumLevel: PermissionLevel.ADMIN, label: 'Remove from join allowlist', group: 'Moderation', risk: 'medium', player: true, description: 'Remove the selected connected account from the no-check list.' },
  { id: 'destroy-wild-dinos', minimumLevel: PermissionLevel.ADMIN, label: 'Wipe wild dinos', group: 'Maintenance', risk: 'critical', server: 'required', challenge: true, description: 'Destroy every untamed creature on one map.' },
  { id: 'rcon', minimumLevel: PermissionLevel.ADMIN, label: 'Allowlisted console command', group: 'Advanced', risk: 'high', server: 'required', description: 'Run one explicitly allowlisted RCON verb; raw output stays suppressed.' },
]);

const ACTION_BY_ID = new Map(ACTIONS.map((action) => [action.id, action]));
const PLAYER_PURPOSES = new Set(ACTIONS.filter((action) => action.player).map((action) => action.id));
const UNCERTAIN_ON_FAILURE = new Set([
  'announce', 'announce-template', 'save-world', 'restart', 'cancel-restart', 'give-item', 'give-xp',
  'warn', 'kick', 'ban', 'whitelist', 'unwhitelist', 'destroy-wild-dinos', 'rcon',
]);

export class AdminApiError extends Error {
  constructor(status, code, message, headers = {}) {
    super(message); this.name = 'AdminApiError'; this.status = status; this.code = code; this.headers = headers;
    this.securityReported = false;
  }
}

function fail(status, code, message, headers) { throw new AdminApiError(status, code, message, headers); }
function failCommittedMutation(code, message, { temporaryCredentialDeliveryFailed = false } = {}) {
  fail(503, code, message, {
    'X-Mutation-Committed': 'true',
    'X-Temporary-Credential-Delivery-Failed': temporaryCredentialDeliveryFailed ? 'true' : 'false',
  });
}
function isRecord(value) { return value && typeof value === 'object' && !Array.isArray(value); }
function digest(value) { return crypto.createHash('sha256').update(String(value)).digest('base64url'); }
function strictEqual(left, right) {
  const a = Buffer.from(String(left ?? '')); const b = Buffer.from(String(right ?? ''));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function randomToken(randomBytes, bytes) {
  const value = randomBytes(bytes);
  if (!Buffer.isBuffer(value) || value.length !== bytes) throw new Error(`Random generator must return ${bytes} bytes`);
  return value.toString('base64url');
}
function permissionLevelForRole(role) {
  return role === 'admin' ? PermissionLevel.ADMIN : role === 'moderator' ? PermissionLevel.MODERATOR : PermissionLevel.NONE;
}
function roleForPermissionLevel(level) { return level >= PermissionLevel.ADMIN ? 'admin' : 'moderator'; }
export function deriveOwnerSetupProof(adminToken) {
  const token = typeof adminToken === 'string' ? adminToken : '';
  if (token.length < 32 || token.length > 256) return '';
  return crypto.createHmac('sha256', token).update(OWNER_SETUP_PROOF_CONTEXT, 'utf8').digest('base64url');
}
function publicAction(action) {
  const { minimumLevel, ...safe } = action;
  return { ...safe, minimumRole: roleForPermissionLevel(minimumLevel) };
}
function exactObject(value, allowed, message = 'Request body contains unsupported fields.') {
  if (!isRecord(value)) fail(400, 'invalid_input', 'Request body must be a JSON object.');
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(400, 'invalid_input', message);
  return value;
}
function safeOperatorId(value) {
  const id = String(value ?? '');
  if (!/^[A-Za-z0-9_-]{16,64}$/u.test(id)) fail(404, 'operator_not_found', 'That operator account was not found.');
  return id;
}
function publicOperator(account) {
  if (!account) return null;
  return {
    id: account.id, username: account.username, role: account.role, enabled: account.enabled, owner: account.owner,
    mustChangePassword: account.mustChangePassword, recordRevision: account.recordRevision,
    createdAt: account.createdAt, updatedAt: account.updatedAt,
  };
}
function operatorIdentity(value) {
  try { return normalizeOperatorUsername(value); }
  catch (error) { fail(400, 'invalid_username', error?.message || 'Choose a valid username.'); }
}
function operatorRole(value) {
  try { return normalizeOperatorRole(value); }
  catch (error) { fail(400, 'invalid_role', error?.message || 'Choose a valid operator role.'); }
}
function operatorPassword(value, context) {
  try { return validateOperatorPassword(value, context); }
  catch (error) { fail(400, 'invalid_password', error?.message || 'Choose a valid password.'); }
}
function bearerToken(request) {
  const header = String(request.headers.authorization ?? '');
  const match = header.match(/^Bearer ([^\s]+)$/i);
  return match?.[1] ?? '';
}
function mediaType(request) { return String(request.headers['content-type'] ?? '').split(';', 1)[0].trim().toLocaleLowerCase('en-US'); }
function singleQueryParameter(url, name) {
  const values = url.searchParams.getAll(name);
  if (values.length > 1) fail(400, 'invalid_query', `${name} may be provided only once.`);
  return String(values[0] ?? '');
}

function requiredText(value, label, maximum) {
  if (typeof value !== 'string' || /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(value)) {
    fail(400, 'invalid_input', `${label} must be text without control characters.`);
  }
  const text = value.trim();
  if (!text || Array.from(text).length > maximum) fail(400, 'invalid_input', `${label} must contain 1-${maximum} characters.`);
  return text;
}
function optionalText(value, label, maximum) {
  if (value == null || value === '') return undefined;
  return requiredText(value, label, maximum);
}
function integer(value, label, minimum, maximum, fallback) {
  const candidate = value == null ? fallback : value;
  if (!Number.isInteger(candidate) || candidate < minimum || candidate > maximum) {
    fail(400, 'invalid_input', `${label} must be a whole number from ${minimum} to ${maximum}.`);
  }
  return candidate;
}
function finiteNumber(value, label, minimum, maximum, fallback) {
  const candidate = value == null ? fallback : value;
  if (typeof candidate !== 'number' || !Number.isFinite(candidate) || candidate < minimum || candidate > maximum) {
    fail(400, 'invalid_input', `${label} must be a number from ${minimum} to ${maximum}.`);
  }
  return Object.is(candidate, -0) ? 0 : candidate;
}
function booleanValue(value, label, fallback = false) {
  const candidate = value == null ? fallback : value;
  if (typeof candidate !== 'boolean') fail(400, 'invalid_input', `${label} must be true or false.`);
  return candidate;
}
function playerSelection(value) {
  if (typeof value !== 'string' || !PLAYER_SELECTION_PATTERN.test(value)) {
    fail(400, 'invalid_player_selection', 'Choose a currently connected player from the protected player list.');
  }
  return value;
}
function serverSelection(value, required = false) {
  if (value == null || value === '') {
    if (required) fail(400, 'invalid_server', 'Choose a map server.');
    return undefined;
  }
  if (typeof value !== 'string' || !SERVER_PATTERN.test(value)) fail(400, 'invalid_server', 'Choose a valid map server.');
  return value;
}
function itemSelection(value) {
  if (typeof value !== 'string' || !ITEM_KEY_PATTERN.test(value) || !getItem(value)) {
    fail(400, 'invalid_item', 'Choose one trusted item from the built-in catalog.');
  }
  return value;
}
function optionsRecord(value) {
  if (!isRecord(value)) fail(400, 'invalid_input', 'Action options must be a JSON object.');
  return value;
}
function rejectUnknown(options, allowed) {
  for (const key of Object.keys(options)) if (!allowed.includes(key)) {
    fail(400, 'invalid_input', `Unsupported option ${key}.`);
  }
}
function addServer(output, options, required = false) {
  const server = serverSelection(options.server, required); if (server) output.server = server;
}

export function normalizeAdminAction(action, rawOptions, config = {}) {
  const name = String(action ?? '').trim(); const definition = ACTION_BY_ID.get(name);
  if (!definition) fail(404, 'unknown_action', 'That dashboard action is not available.');
  const options = optionsRecord(rawOptions ?? {}); const output = {};
  switch (name) {
    case 'announce':
      rejectUnknown(options, ['message', 'server']);
      output.message = requiredText(options.message, 'Announcement', announcementMessageMaxLength(config.chat?.gameMaxLength));
      addServer(output, options); break;
    case 'announce-template':
      rejectUnknown(options, ['template', 'server']); output.template = requiredText(options.template, 'Template', 64); addServer(output, options); break;
    case 'save-world': case 'cancel-restart':
      rejectUnknown(options, ['server']); addServer(output, options); break;
    case 'restart':
      rejectUnknown(options, ['minutes', 'server', 'reason']);
      output.minutes = integer(options.minutes, 'Restart delay', 1, RESTART_MAX_DELAY_MINUTES); addServer(output, options);
      {
        const reason = optionalText(options.reason, 'Restart reason', restartReasonMaxLength(config.chat?.gameMaxLength));
        if (reason) output.reason = reason;
      }
      break;
    case 'give-item':
      rejectUnknown(options, ['player', 'item', 'quantity', 'quality', 'blueprint']); output.player = playerSelection(options.player);
      output.item = itemSelection(options.item); output.quantity = integer(options.quantity, 'Quantity', 1, 10_000, 1);
      output.quality = finiteNumber(options.quality, 'Quality', 0, 100, 0); output.blueprint = booleanValue(options.blueprint, 'Blueprint'); break;
    case 'give-xp':
      rejectUnknown(options, ['player', 'amount', 'from-tribe', 'share-with-tribe']); output.player = playerSelection(options.player);
      output.amount = finiteNumber(options.amount, 'XP amount', 1, 1_000_000_000);
      output['from-tribe'] = booleanValue(options['from-tribe'], 'From tribe');
      output['share-with-tribe'] = booleanValue(options['share-with-tribe'], 'Share with tribe'); break;
    case 'refresh-player-id': case 'player': case 'unmute-player': case 'whitelist': case 'unwhitelist':
      rejectUnknown(options, ['player']); output.player = playerSelection(options.player); break;
    case 'warn':
      rejectUnknown(options, ['player', 'message']); output.player = playerSelection(options.player); output.message = requiredText(options.message, 'Warning', 500); break;
    case 'note':
      rejectUnknown(options, ['player', 'note']); output.player = playerSelection(options.player); output.note = requiredText(options.note, 'Note', 1_000); break;
    case 'mute-player':
      rejectUnknown(options, ['player', 'minutes', 'reason']); output.player = playerSelection(options.player);
      output.minutes = integer(options.minutes, 'Mute duration', 1, config.moderation?.maxMuteMinutes ?? 43_200, config.moderation?.defaultMuteMinutes ?? 15);
      if (optionalText(options.reason, 'Reason', 500)) output.reason = optionalText(options.reason, 'Reason', 500); break;
    case 'kick': case 'ban':
      rejectUnknown(options, ['player', 'reason']); output.player = playerSelection(options.player);
      if (optionalText(options.reason, 'Reason', 500)) output.reason = optionalText(options.reason, 'Reason', 500); break;
    case 'destroy-wild-dinos':
      rejectUnknown(options, ['server']); addServer(output, options, true); output.confirm = true; break;
    case 'rcon': {
      rejectUnknown(options, ['server', 'command']); addServer(output, options, true);
      const command = requiredText(options.command, 'RCON command', 1_000);
      if (/[\u0000-\u001F\u007F;|&]/u.test(command)) fail(400, 'invalid_rcon', 'RCON command contains prohibited separators or control characters.');
      const verb = command.split(/\s+/, 1)[0].toLocaleLowerCase('en-US');
      const allowlist = new Set((config.moderation?.rawRconAllowlist ?? []).map((entry) => String(entry).toLocaleLowerCase('en-US')));
      if (!config.moderation?.allowRawRcon || !allowlist.has(verb)) fail(403, 'rcon_disabled', 'That RCON command is not enabled and allowlisted.');
      output.command = command; break;
    }
    default: fail(404, 'unknown_action', 'That dashboard action is not available.');
  }
  return { action: name, options: output, definition };
}

function actionPayloadHash(action, options) { return digest(JSON.stringify({ action, options })); }
function safeSnippet(value, secrets, maximum = 96) {
  return truncateCodePoints(normalizeWhitespace(redactText(value, secrets)), maximum, '...');
}

function settingsMutationSummary(body) {
  const settings = isRecord(body?.settings) ? body.settings : {};
  const servers = Array.isArray(settings.servers) ? settings.servers.slice(0, 64) : [];
  return {
    requestedMapCount: servers.length,
    rconCredentialsReplaced: servers.filter((server) => isRecord(server) && typeof server.password === 'string').length,
    sftpCredentialsReplaced: servers.filter((server) => isRecord(server?.profileImport)
      && typeof server.profileImport.password === 'string').length,
    sftpCredentialsCleared: servers.filter((server) => isRecord(server?.profileImport)
      && server.profileImport.clearPassword === true).length,
    discordCredentialReplaced: typeof settings.discord?.token === 'string',
    discordCredentialCleared: settings.discord?.clearToken === true,
    automationTokenRotated: body?.rotateAutomationToken === true,
    tlsIdentityRegenerated: body?.regenerateTls === true,
    tlsCertificateNameCount: Array.isArray(body?.tlsSubjectAltNames)
      ? Math.min(body.tlsSubjectAltNames.length, 16) : 0,
    consolePolicyIncluded: isRecord(settings.moderation),
  };
}

export class AdminApi {
  constructor({
    config, bridge, state = null, statusProjector, metrics = null, logger = null,
    now = () => Date.now(), randomBytes = crypto.randomBytes, passwordService = null,
    settingsService = null, onOwnerSetupCompleted = null,
  } = {}) {
    const bridgeConfig = bridge?.config ?? {};
    this.config = {
      ...bridgeConfig,
      ...(config ?? {}),
      moderation: bridgeConfig.moderation ?? config?.moderation ?? {},
      redactionSecrets: config?.redactionSecrets ?? [],
    };
    this.bridge = bridge; this.state = state ?? bridge?.state; this.statusProjector = statusProjector; this.metrics = metrics; this.logger = logger;
    this.settingsService = settingsService; this.onOwnerSetupCompleted = onOwnerSetupCompleted;
    if (!this.state) throw new Error('Admin API requires the encrypted state store');
    this.now = now; this.randomBytes = randomBytes; this.sessions = new Map(); this.confirmations = new Map(); this.idempotency = new Map(); this.activity = [];
    this.operatorMutationChain = Promise.resolve();
    this.passwordService = passwordService ?? new OperatorPasswordService();
    this.sessionSecret = randomToken(randomBytes, 32);
    this.loginAddressLimiter = new SlidingWindowRateLimiter({ limit: 10, windowMs: 5 * 60_000, maxKeys: 1_000, now });
    this.loginAccountLimiter = new SlidingWindowRateLimiter({ limit: 5, windowMs: 15 * 60_000, maxKeys: 1_000, now });
    this.loginGlobalLimiter = new SlidingWindowRateLimiter({ limit: 100, windowMs: 5 * 60_000, maxKeys: 2, now });
    this.readLimiter = new SlidingWindowRateLimiter({ limit: 180, windowMs: 60_000, maxKeys: 1_000, now });
    this.actionLimiter = new SlidingWindowRateLimiter({ limit: 30, windowMs: 60_000, maxKeys: 1_000, now });
    this.staffRecordLimiter = new SlidingWindowRateLimiter({ limit: 30, windowMs: 60_000, maxKeys: 1_000, now });
    this.identifierDisclosureLimiter = new SlidingWindowRateLimiter({ limit: 12, windowMs: 60_000, maxKeys: 1_000, now });
    this.settingsMutationLimiter = new SlidingWindowRateLimiter({ limit: 10, windowMs: 60 * 60_000, maxKeys: 128, now });
  }

  security(event, fields = {}, level = 'warn') {
    this.logger?.security?.(event, { component: 'admin-api', ...fields }, level);
  }

  audit(event, fields = {}) {
    return this.logger?.audit?.(event, { component: 'admin-api', ...fields }) !== false;
  }

  prune() {
    const at = this.now();
    for (const [key, value] of this.sessions) {
      if (value.expiresAt <= at || value.idleExpiresAt <= at) this.sessions.delete(key);
    }
    for (const [key, value] of this.confirmations) if (value.expiresAt <= at) this.confirmations.delete(key);
    for (const [key, value] of this.idempotency) if (value.expiresAt <= at) this.idempotency.delete(key);
    while (this.sessions.size > 64) this.sessions.delete(this.sessions.keys().next().value);
    while (this.confirmations.size > 1_000) this.confirmations.delete(this.confirmations.keys().next().value);
    while (this.idempotency.size > 2_000) this.idempotency.delete(this.idempotency.keys().next().value);
  }

  close() {
    this.sessions.clear(); this.confirmations.clear(); this.idempotency.clear(); this.activity.length = 0;
  }

  runOperatorMutation(operation) {
    const pending = this.operatorMutationChain.catch(() => undefined).then(operation);
    this.operatorMutationChain = pending;
    return pending;
  }

  assertJson(request) {
    if (mediaType(request) !== 'application/json') fail(415, 'unsupported_media_type', 'Use application/json for this request.');
  }

  assertSameOrigin(request) {
    const origin = String(request.headers.origin ?? ''); const host = String(request.headers.host ?? '').toLocaleLowerCase('en-US');
    const fetchSite = String(request.headers['sec-fetch-site'] ?? '').toLocaleLowerCase('en-US');
    const rejectOrigin = (code = 'origin_rejected', reasonCode = 'origin_mismatch') => {
      this.security('access.origin_rejected', { outcome: 'denied', reasonCode });
      fail(403, code, code === 'secure_origin_required'
        ? 'Remote administration requires an HTTPS origin.' : 'This request did not come from the dashboard origin.');
    };
    if (!origin || !host || (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none')) {
      rejectOrigin('origin_rejected', 'missing_or_cross_site');
    }
    let parsed;
    try { parsed = new URL(origin); } catch { rejectOrigin('origin_rejected', 'invalid_origin'); }
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.host.toLocaleLowerCase('en-US') !== host || parsed.username || parsed.password) {
      rejectOrigin('origin_rejected', 'origin_mismatch');
    }
    if (this.config.allowRemoteHttp || this.config.tls?.enabled) {
      if (parsed.protocol !== 'https:') rejectOrigin('secure_origin_required', 'insecure_origin');
    }
    if (!this.config.allowRemoteHttp && (!isLoopbackHost(parsed.hostname) || !isLoopbackHost(request.socket?.remoteAddress))) {
      this.security('access.loopback_rejected', { outcome: 'denied', reasonCode: 'non_loopback' });
      fail(403, 'loopback_required', 'Local dashboard access is restricted to this host.');
    }
  }

  sessionCookie(request) {
    const header = String(request.headers.cookie ?? ''); const expectedName = this.cookieName();
    for (const part of header.split(';')) {
      const separator = part.indexOf('='); if (separator < 0) continue;
      if (part.slice(0, separator).trim() !== expectedName) continue;
      const token = part.slice(separator + 1).trim(); return SESSION_PATTERN.test(token) ? token : '';
    }
    return '';
  }

  requireSession(request) {
    this.prune(); const token = this.sessionCookie(request); const key = token ? digest(token) : '';
    const session = key ? this.sessions.get(key) : null;
    const account = session ? this.state.getOperatorAccount?.(session.accountId) : null;
    if (!session || session.expiresAt <= this.now() || session.idleExpiresAt <= this.now()
      || !account?.enabled || account.authRevision !== session.authRevision || account.role !== session.role) {
      if (key) this.sessions.delete(key);
      // A GET bootstrap from a previously loaded tab immediately after a
      // restart is a routine session-discovery miss, not an authentication
      // attack. Mutations and every other protected route remain warnings.
      const routineBootstrap = request.method === 'GET'
        && String(request.url ?? '').split('?', 1)[0] === '/admin/api/bootstrap';
      this.security('auth.session_rejected', {
        outcome: 'denied', reasonCode: session ? 'expired' : 'missing_or_invalid',
      }, routineBootstrap ? 'info' : 'warn');
      fail(401, 'authentication_required', 'Sign in to continue.');
    }
    return { ...session, key, token };
  }

  touchSession(session) {
    const stored = this.sessions.get(session.key);
    if (!stored) return session;
    stored.idleExpiresAt = Math.min(stored.expiresAt, this.now() + SESSION_IDLE_TTL_MS);
    session.idleExpiresAt = stored.idleExpiresAt;
    return session;
  }

  requireRead(request) {
    const session = this.requireSession(request);
    const rate = this.readLimiter.consume(session.key);
    if (!rate.allowed) {
      this.security('auth.rate_limited', { outcome: 'denied', reasonCode: 'read_limit' });
      fail(429, 'rate_limited', 'Too many dashboard refreshes. Try again shortly.', {
        'Retry-After': String(Math.ceil(rate.retryAfterMs / 1_000)),
      });
    }
    return request.headers['x-operator-activity'] === '1' ? this.touchSession(session) : session;
  }

  csrfToken(session) {
    return crypto.createHmac('sha256', this.sessionSecret).update(`csrf\u001f${session.token}`).digest('base64url');
  }

  requireMutation(request) {
    this.assertJson(request); this.assertSameOrigin(request); const session = this.requireSession(request);
    if (!strictEqual(request.headers['x-csrf-token'], this.csrfToken(session))) {
      this.security('access.csrf_rejected', { outcome: 'denied', reasonCode: 'token_mismatch' });
      fail(403, 'csrf_rejected', 'The dashboard session check failed. Refresh and try again.');
    }
    return this.touchSession(session);
  }

  requireCurrentPassword(session) {
    if (session.mustChangePassword) fail(403, 'password_change_required', 'Change the temporary password before using the dashboard.');
    return session;
  }

  requireAdmin(request, { recent = false } = {}) {
    const session = this.requireCurrentPassword(this.requireMutation(request));
    if (session.permissionLevel < PermissionLevel.ADMIN) {
      this.security('access.role_rejected', { outcome: 'denied', reasonCode: 'administrator_required' });
      fail(403, 'administrator_required', 'Administrator access is required.');
    }
    if (recent && this.now() - session.reauthenticatedAt > RECENT_AUTH_TTL_MS) {
      fail(403, 'reauthentication_required', 'Sign out and sign in again before this sensitive administrator operation.');
    }
    return session;
  }

  requireAdminRead(request) {
    const session = this.requireCurrentPassword(this.requireRead(request));
    if (session.permissionLevel < PermissionLevel.ADMIN) {
      this.security('access.role_rejected', { outcome: 'denied', reasonCode: 'administrator_required' });
      fail(403, 'administrator_required', 'Administrator access is required.');
    }
    return session;
  }

  assertActionAllowed(session, definition) {
    this.requireCurrentPassword(session);
    if (session.permissionLevel < definition.minimumLevel) {
      this.security('access.role_rejected', { action: definition.id, outcome: 'denied', reasonCode: 'insufficient_role' });
      fail(403, 'action_forbidden', 'Your operator role cannot use that action.');
    }
    if (['rcon', 'destroy-wild-dinos'].includes(definition.id)
      && this.now() - session.reauthenticatedAt > RECENT_AUTH_TTL_MS) {
      fail(403, 'reauthentication_required', 'Sign out and sign in again before using this high-risk action.');
    }
  }

  assertCredentialTransport(request) {
    let origin;
    try { origin = new URL(String(request.headers.origin ?? '')); } catch { origin = null; }
    if (!this.config.tls?.enabled || !request.socket?.encrypted || origin?.protocol !== 'https:') {
      this.security('auth.transport_rejected', { outcome: 'denied', reasonCode: 'https_required' });
      fail(403, 'secure_transport_required', 'Operator credentials are accepted only over HTTPS.');
    }
  }

  accountCount() { return this.state.countOperatorAccounts?.() ?? 0; }

  authMode() {
    const setupRequired = this.accountCount() === 0;
    const setupCredential = String(this.config.ownerSetupToken ?? this.config.adminToken ?? '');
    const setupTokenRequired = setupRequired && setupCredential.length >= 32;
    return {
      mode: 'credentials', setupRequired, setupTokenRequired, remote: Boolean(this.config.allowRemoteHttp),
      secure: Boolean(this.config.tls?.enabled), sessionHours: SESSION_TTL_MS / 3_600_000,
    };
  }

  hasCurrentSession(request) {
    this.prune();
    const token = this.sessionCookie(request);
    if (!token) return false;
    const key = digest(token); const session = this.sessions.get(key);
    const account = session ? this.state.getOperatorAccount?.(session.accountId) : null;
    const at = this.now();
    const current = Boolean(session && session.expiresAt > at && session.idleExpiresAt > at
      && account?.enabled && account.authRevision === session.authRevision && account.role === session.role);
    if (!current) this.sessions.delete(key);
    return current;
  }

  cookieName() { return this.config.tls?.enabled ? SECURE_SESSION_COOKIE : SESSION_COOKIE; }

  clearCookieHeader() {
    const secure = this.config.tls?.enabled ? '; Secure' : '';
    return `${this.cookieName()}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`;
  }

  revokeOperatorSessions(accountId, exceptKey = '') {
    let revoked = 0;
    for (const [key, session] of this.sessions) {
      if (session.accountId === accountId && key !== exceptKey) { this.sessions.delete(key); revoked += 1; }
    }
    return revoked;
  }

  issueSession(account, authenticationMode = 'credentials', { committedMutationFailure = null } = {}) {
    this.prune();
    const token = randomToken(this.randomBytes, 32); const key = digest(token); const createdAt = this.now();
    const permissionLevel = permissionLevelForRole(account.role);
    const session = {
      accountId: account.id, actorId: `web_session_${randomToken(this.randomBytes, 18)}`, username: account.username, role: account.role,
      permissionLevel, authRevision: account.authRevision, mustChangePassword: Boolean(account.mustChangePassword),
      createdAt, reauthenticatedAt: createdAt, expiresAt: createdAt + SESSION_TTL_MS,
      idleExpiresAt: createdAt + SESSION_IDLE_TTL_MS, playerSelections: new Map(),
    };
    const siblingSessions = [...this.sessions.entries()]
      .filter(([, candidate]) => candidate.accountId === account.id)
      .sort((left, right) => left[1].createdAt - right[1].createdAt);
    while (siblingSessions.length >= MAX_SESSIONS_PER_OPERATOR) {
      const [oldest] = siblingSessions.shift(); this.sessions.delete(oldest);
    }
    if (!this.audit('auth.session_created', {
      principalId: account.id, role: account.role, outcome: 'succeeded', authenticationMode,
    })) {
      if (committedMutationFailure) {
        failCommittedMutation(committedMutationFailure.code, committedMutationFailure.message,
          { temporaryCredentialDeliveryFailed: committedMutationFailure.temporaryCredentialDeliveryFailed });
      }
      fail(503, 'audit_unavailable', 'Audit logging is unavailable; no session was created.');
    }
    this.sessions.set(key, session); this.prune();
    const secure = this.config.tls?.enabled ? '; Secure' : '';
    return {
      status: 201,
      headers: { 'Set-Cookie': `${this.cookieName()}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1_000}${secure}` },
      body: { ok: true, expiresAt: session.expiresAt, idleExpiresAt: session.idleExpiresAt, mustChangePassword: session.mustChangePassword },
    };
  }

  async setupOwner(request, body) {
    this.assertJson(request); this.assertSameOrigin(request); this.assertCredentialTransport(request);
    let origin;
    try { origin = new URL(String(request.headers.origin ?? '')); } catch { origin = null; }
    const localRequest = Boolean(origin && isLoopbackHost(origin.hostname) && isLoopbackHost(request.socket?.remoteAddress));
    const configuredToken = String(this.config.ownerSetupToken ?? this.config.adminToken ?? '');
    const tokenRequired = configuredToken.length >= 32;
    const suppliedToken = bearerToken(request);
    const expectedProof = deriveOwnerSetupProof(configuredToken);
    const tokenAccepted = tokenRequired && strictEqual(suppliedToken, expectedProof);
    if ((!localRequest && !tokenAccepted) || (tokenRequired && !tokenAccepted)) {
      const reasonCode = tokenRequired ? 'bootstrap_token_rejected' : 'loopback_required';
      this.security('auth.setup_rejected', { outcome: 'denied', reasonCode });
      fail(403, tokenRequired ? 'setup_authorization_required' : 'loopback_required', tokenRequired
        ? 'The one-time setup authorization was not accepted.'
        : 'First-owner setup is available only from this server over local HTTPS.');
    }
    if (this.accountCount() !== 0) fail(409, 'setup_complete', 'The server owner account has already been created.');
    if (this.logger?.healthy === false || !this.audit('auth.owner_setup_started', { outcome: 'started' })) {
      fail(503, 'audit_unavailable', 'Audit logging is unavailable; owner setup was not started.');
    }
    exactObject(body, ['username', 'password', 'passwordConfirmation']);
    const identity = operatorIdentity(body.username);
    const password = operatorPassword(body.password, { username: identity.username, clusterName: this.bridge?.config?.clusterName });
    const confirmation = operatorPassword(body.passwordConfirmation, { username: identity.username, clusterName: this.bridge?.config?.clusterName });
    if (!strictEqual(password, confirmation)) fail(400, 'password_mismatch', 'The password confirmation does not match.');
    const passwordVerifier = await this.passwordService.hash(password, { username: identity.username, clusterName: this.bridge?.config?.clusterName });
    const at = this.now(); const id = `op_${randomToken(this.randomBytes, 16)}`;
    let account;
    try {
      account = await this.state.createOperatorAccount({
        id, username: identity.username, usernameKey: identity.key, role: 'admin', enabled: true, owner: true,
        passwordVerifier, mustChangePassword: false, authRevision: 1, recordRevision: 1,
        createdAt: at, updatedAt: at, createdBy: 'bootstrap', updatedBy: 'bootstrap',
      }, { first: true });
    } catch (error) {
      if (/already|empty|first/i.test(String(error?.message))) fail(409, 'setup_complete', 'The server owner account has already been created.');
      throw error;
    }
    const ownerSetupAudited = this.audit('auth.owner_setup_completed', {
      principalId: account.id, role: account.role, outcome: 'succeeded',
    });
    try { await this.onOwnerSetupCompleted?.(); }
    catch {
      this.security('auth.setup_artifact_cleanup_failed', { outcome: 'failed', reasonCode: 'cleanup_failed' }, 'warn');
    }
    const committedMutationFailure = {
      code: 'owner_setup_committed_audit_failed',
      message: 'Owner setup was committed, but audit confirmation failed and no session was delivered. Repair audit log storage, restart the service, then sign in with the owner credentials you chose.',
    };
    if (!ownerSetupAudited) {
      failCommittedMutation(committedMutationFailure.code, committedMutationFailure.message);
    }
    return this.issueSession(account, 'owner-setup', { committedMutationFailure });
  }

  async createSession(request, body) {
    this.assertJson(request); this.assertSameOrigin(request); this.assertCredentialTransport(request);
    exactObject(body, ['username', 'password']);
    if (this.accountCount() === 0) fail(409, 'setup_required', 'Create the server owner account from local HTTPS first.');
    let identity = null;
    try { identity = normalizeOperatorUsername(body.username); } catch { /* Generic authentication failure below. */ }
    const accountKey = digest(identity?.key ?? String(body.username ?? '').slice(0, 128));
    const rates = [
      this.loginAddressLimiter.consume(String(request.socket?.remoteAddress ?? 'unknown')),
      this.loginAccountLimiter.consume(accountKey), this.loginGlobalLimiter.consume('all'),
    ];
    const blocked = rates.find((candidate) => !candidate.allowed);
    if (blocked) {
      this.security('auth.rate_limited', { outcome: 'denied', reasonCode: 'login_limit' });
      fail(429, 'rate_limited', 'Too many sign-in attempts. Try again shortly.', { 'Retry-After': String(Math.ceil(blocked.retryAfterMs / 1_000)) });
    }
    const account = identity ? this.state.findOperatorByUsername?.(identity.username) : null;
    const verified = await this.passwordService.verify(body.password, account?.passwordVerifier ?? null);
    if (!verified || !account?.enabled) {
      this.security('auth.session_rejected', { outcome: 'denied', reasonCode: 'invalid_credentials' });
      this.audit('auth.login_failed', { outcome: 'denied', reasonCode: 'invalid_credentials' });
      fail(401, 'invalid_credentials', 'The username or password was not accepted.');
    }
    return this.issueSession(account);
  }

  closeSession(request) {
    const session = this.requireMutation(request); this.sessions.delete(session.key);
    this.audit('auth.session_closed', { principalId: session.accountId, role: session.role, outcome: 'succeeded' });
    return {
      status: 200,
      headers: { 'Set-Cookie': this.clearCookieHeader() },
      body: { ok: true },
    };
  }

  bootstrap(request) {
    const session = this.requireRead(request);
    const publicSession = {
      username: session.username, role: session.role, csrfToken: this.csrfToken(session), expiresAt: session.expiresAt,
      idleExpiresAt: session.idleExpiresAt, mustChangePassword: session.mustChangePassword,
    };
    if (session.mustChangePassword) {
      return {
        session: publicSession,
        status: {},
        capabilities: {
          actions: [], rawRcon: { enabled: false, verbs: [] }, templates: [],
          announcementMaxLength: announcementMessageMaxLength(this.config.chat?.gameMaxLength),
          restartReasonMaxLength: restartReasonMaxLength(this.config.chat?.gameMaxLength),
        },
      };
    }
    const status = this.statusProjector(this.bridge.status(), this.config.redactionSecrets);
    const announcementMaxLength = announcementMessageMaxLength(this.config.chat?.gameMaxLength);
    const restartReasonMaximum = restartReasonMaxLength(this.config.chat?.gameMaxLength);
    const templates = Object.entries(this.config.moderation?.announcementTemplates ?? {}).map(([name, message]) => ({
      name: safeSnippet(name, this.config.redactionSecrets, 64),
      message: safeSnippet(message, this.config.redactionSecrets, announcementMaxLength),
    }));
    const allowedActions = ACTIONS.filter((action) => session.permissionLevel >= action.minimumLevel);
    const rawRcon = session.permissionLevel >= PermissionLevel.ADMIN && Boolean(this.config.moderation?.allowRawRcon);
    return {
      session: publicSession,
      status,
      capabilities: {
        actions: allowedActions.map((action) => ({ ...publicAction(action), name: action.id, enabled: action.id !== 'rcon' || rawRcon })),
        rawRcon: {
          enabled: rawRcon,
          verbs: rawRcon ? [...(this.config.moderation.rawRconAllowlist ?? [])] : [],
        },
        templates,
        announcementMaxLength,
        restartReasonMaxLength: restartReasonMaximum,
        defaultMuteMinutes: this.config.moderation?.defaultMuteMinutes ?? 15,
        maxMuteMinutes: this.config.moderation?.maxMuteMinutes ?? 43_200,
      },
    };
  }

  players(request, url) {
    const session = this.requireCurrentPassword(this.requireRead(request)); const query = String(url.searchParams.get('q') ?? '');
    if (Array.from(query).length > 96) fail(400, 'invalid_query', 'Player search is too long.');
    const requestedPurpose = String(url.searchParams.get('purpose') ?? 'player');
    if (!PLAYER_PURPOSES.has(requestedPurpose)) fail(400, 'invalid_query', 'Choose a valid player action.');
    const purpose = requestedPurpose;
    this.assertActionAllowed(session, ACTION_BY_ID.get(purpose));
    const players = this.bridge.adminPlayerChoices(query, session.actorId, { purpose, limit: 100 });
    const stored = this.sessions.get(session.key);
    for (const player of players) {
      stored.playerSelections.delete(player.selection);
      stored.playerSelections.set(player.selection, {
        name: player.name, survivorName: player.survivorName, serverId: player.serverId, serverName: player.serverName, purpose,
      });
    }
    while (stored.playerSelections.size > 500) stored.playerSelections.delete(stored.playerSelections.keys().next().value);
    return { players };
  }

  async playerRecord(request, body) {
    let session = this.requireMutation(request);
    this.assertActionAllowed(session, ACTION_BY_ID.get('player'));
    const rate = this.staffRecordLimiter.consume(session.key);
    if (!rate.allowed) {
      this.security('auth.rate_limited', { action: 'player', outcome: 'denied', reasonCode: 'staff_record_limit' });
      fail(429, 'rate_limited', 'Too many staff-record requests. Try again shortly.', {
        'Retry-After': String(Math.ceil(rate.retryAfterMs / 1_000)),
      });
    }
    let selection;
    try {
      exactObject(body, ['player']);
      selection = playerSelection(body.player);
    } catch (error) {
      this.security('player.staff_record_rejected', { outcome: 'denied', reasonCode: 'invalid_request' });
      throw error;
    }
    const selected = this.sessions.get(session.key)?.playerSelections.get(selection);
    if (!selected || selected.purpose !== 'player') {
      this.security('player.staff_record_rejected', { outcome: 'denied', reasonCode: 'invalid_selection' });
      fail(409, 'player_selection_expired', 'Refresh the connected-player list and choose the player again.');
    }
    if (this.logger?.healthy === false || typeof this.logger?.audit !== 'function') {
      this.security('player.staff_record_rejected', { outcome: 'denied', reasonCode: 'audit_unavailable' });
      fail(503, 'audit_unavailable', 'Audit logging is unavailable; the staff record was not disclosed.');
    }
    let record;
    try {
      record = await this.bridge.adminPlayerStaffRecord(selection, session.actorId, { purpose: 'player', noteLimit: 10 });
    } catch (error) {
      const unavailable = error?.code === 'PLAYER_STATUS_UNAVAILABLE';
      this.security('player.staff_record_rejected', {
        outcome: 'denied', reasonCode: unavailable ? 'player_status_unavailable' : 'invalid_selection',
      });
      fail(unavailable ? 503 : 409, unavailable ? 'player_status_unavailable' : 'player_selection_expired', unavailable
        ? 'Connected-player status could not be refreshed. Try again shortly.'
        : 'Refresh the connected-player list and choose the player again.');
    }
    // Player refresh is network I/O. Re-authorize after it completes so a
    // concurrent account disable, role change, logout, CSRF/session change, or
    // selector consumption wins before any protected record is disclosed.
    session = this.requireMutation(request);
    this.assertActionAllowed(session, ACTION_BY_ID.get('player'));
    const currentSelection = this.sessions.get(session.key)?.playerSelections.get(selection);
    if (!currentSelection || currentSelection.purpose !== 'player') {
      this.security('player.staff_record_rejected', { outcome: 'denied', reasonCode: 'invalid_selection' });
      fail(409, 'player_selection_expired', 'Refresh the connected-player list and choose the player again.');
    }
    if (!this.audit('player.staff_record_viewed', {
      principalId: session.accountId,
      role: session.role,
      server: record.serverId,
      noteCount: record.notes.length,
      outcome: 'succeeded',
    })) {
      this.security('player.staff_record_rejected', { outcome: 'denied', reasonCode: 'audit_unavailable' });
      fail(503, 'audit_unavailable', 'Audit logging is unavailable; the staff record was not disclosed.');
    }
    return {
      status: 200,
      headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' },
      body: { record },
    };
  }

  playerIdentifiers(request, body) {
    let session;
    try {
      session = this.requireAdmin(request, { recent: true });
    } catch (error) {
      if (error instanceof AdminApiError && error.code === 'reauthentication_required') {
        this.security('player.identifier_disclosure_rejected', { outcome: 'denied', reasonCode: 'recent_auth_required' });
        error.securityReported = true;
      }
      throw error;
    }
    const rate = this.identifierDisclosureLimiter.consume(session.key);
    if (!rate.allowed) {
      this.security('auth.rate_limited', { outcome: 'denied', reasonCode: 'identifier_disclosure_limit' });
      fail(429, 'rate_limited', 'Too many identifier requests. Try again shortly.', {
        'Retry-After': String(Math.ceil(rate.retryAfterMs / 1_000)),
      });
    }
    let selection;
    try {
      exactObject(body, ['player']);
      selection = playerSelection(body.player);
    } catch (error) {
      this.security('player.identifier_disclosure_rejected', { outcome: 'denied', reasonCode: 'invalid_request' });
      throw error;
    }
    const selected = this.sessions.get(session.key)?.playerSelections.get(selection);
    if (!selected || selected.purpose !== 'player') {
      this.security('player.identifier_disclosure_rejected', { outcome: 'denied', reasonCode: 'invalid_selection' });
      fail(409, 'player_selection_expired', 'Refresh the connected-player list and choose the player again.');
    }
    if (this.logger?.healthy === false || typeof this.logger?.audit !== 'function') {
      this.security('player.identifier_disclosure_rejected', { outcome: 'denied', reasonCode: 'audit_unavailable' });
      fail(503, 'audit_unavailable', 'Audit logging is unavailable; player identifiers were not disclosed.');
    }
    let resolved;
    try {
      resolved = this.bridge.adminPlayerIdentifiers(selection, session.actorId, { purpose: 'player' });
    } catch {
      this.security('player.identifier_disclosure_rejected', { outcome: 'denied', reasonCode: 'invalid_selection' });
      fail(409, 'player_selection_expired', 'Refresh the connected-player list and choose the player again.');
    }
    this.sessions.get(session.key)?.playerSelections.delete(selection);
    const identifierKinds = resolved.playerDataId == null
      ? ['eos-product-user-id'] : ['eos-product-user-id', 'asa-player-data-id'];
    if (!this.audit('player.identifiers_disclosed', {
      principalId: session.accountId,
      role: session.role,
      server: resolved.serverId,
      identifierKinds,
      outcome: 'succeeded',
    })) {
      this.security('player.identifier_disclosure_rejected', { outcome: 'denied', reasonCode: 'audit_unavailable' });
      fail(503, 'audit_unavailable', 'Audit logging is unavailable; player identifiers were not disclosed.');
    }
    return {
      status: 200,
      headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' },
      body: {
        player: {
          name: resolved.name,
          survivorName: resolved.survivorName,
          serverId: resolved.serverId,
          serverName: resolved.serverName,
        },
        identifiers: {
          eosProductUserId: resolved.eosProductUserId,
          playerDataId: resolved.playerDataId,
        },
        disclosedAt: new Date(this.now()).toISOString(),
      },
    };
  }

  items(request, url) {
    this.requireCurrentPassword(this.requireRead(request)); const query = String(url.searchParams.get('q') ?? '');
    if (Array.from(query).length > 128) fail(400, 'invalid_query', 'Item search is too long.');
    return { items: searchItems(query, 25).map((item) => ({
      key: item.key, name: item.name, category: item.category, gfi: item.gfi,
      itemNumber: item.itemNumber, blueprintPath: item.blueprintPath,
    })) };
  }

  activityLog(request) {
    const session = this.requireCurrentPassword(this.requireRead(request));
    const visible = session.permissionLevel >= PermissionLevel.ADMIN
      ? this.activity : this.activity.filter((entry) => entry.principalId === session.accountId);
    return {
      activity: visible.slice(0, 100).map(({ principalId, ...entry }) => ({ ...entry })),
    };
  }

  diagnostics(request, url) {
    const session = this.requireAdminRead(request);
    if (typeof this.logger?.recentRecords !== 'function') {
      fail(503, 'diagnostics_unavailable', 'Live diagnostics are not available from this process.');
    }
    const channel = singleQueryParameter(url, 'channel');
    const minLevel = singleQueryParameter(url, 'level') || 'warn';
    const query = singleQueryParameter(url, 'q').trim();
    const rawLimit = singleQueryParameter(url, 'limit') || '100';
    if (channel && !DIAGNOSTIC_CHANNELS.has(channel)) fail(400, 'invalid_query', 'Choose a valid diagnostic channel.');
    if (!DIAGNOSTIC_LEVELS.has(minLevel)) fail(400, 'invalid_query', 'Choose a valid minimum diagnostic level.');
    if (Array.from(query).length > 128 || /[\u0000-\u001F\u007F]/u.test(query)) {
      fail(400, 'invalid_query', 'Diagnostic search must be at most 128 characters without control characters.');
    }
    if (!/^\d{1,3}$/u.test(rawLimit)) fail(400, 'invalid_query', 'Diagnostic limit must be a whole number from 1 to 250.');
    const limit = Number(rawLimit);
    if (limit < 1 || limit > 250) fail(400, 'invalid_query', 'Diagnostic limit must be a whole number from 1 to 250.');
    const records = this.logger.recentRecords({ channel, minLevel, query, limit }).map((record) => ({
      time: record.time,
      level: record.level,
      channel: record.channel,
      event: record.event,
      message: safeSnippet(record.message, this.config.redactionSecrets, 512),
      details: safeSnippet(JSON.stringify(redact(record.details ?? {}, new WeakSet(), this.config.redactionSecrets)), this.config.redactionSecrets, 2_000),
    }));
    if (!this.audit('logs.viewed', {
      principalId: session.accountId, actor: 'http:dashboard', surface: 'dashboard', outcome: 'succeeded',
      channel: channel || 'all', minimumLevel: minLevel, queryUsed: Boolean(query), resultCount: records.length,
    })) fail(503, 'audit_unavailable', 'Audit logging is unavailable; diagnostics were not disclosed.');
    return { records, scope: 'current-process-memory', newestFirst: true };
  }

  settings(request) {
    const session = this.requireAdminRead(request);
    if (!this.settingsService) fail(404, 'managed_settings_unavailable', 'Managed settings are not enabled for this installation.');
    if (this.logger?.healthy === false) fail(503, 'audit_unavailable', 'Audit logging is unavailable; settings were not disclosed.');
    const projection = this.settingsService.current();
    if (!this.audit('settings.viewed', {
      principalId: session.accountId, role: session.role, revision: projection.revision,
      mapCount: projection.settings?.servers?.length ?? 0, discordEnabled: Boolean(projection.settings?.discord?.enabled),
      outcome: 'succeeded',
    })) fail(503, 'audit_unavailable', 'Audit logging is unavailable; settings were not disclosed.');
    return projection;
  }

  authorizeUpdateSettings(request) {
    return this.requireAdmin(request, { recent: true });
  }

  async updateSettings(request, body) {
    let session = this.requireAdmin(request, { recent: true });
    if (!this.settingsService) fail(404, 'managed_settings_unavailable', 'Managed settings are not enabled for this installation.');
    if (this.logger?.healthy === false) fail(503, 'audit_unavailable', 'Audit logging is unavailable; settings were not changed.');
    const changeSummary = settingsMutationSummary(body);
    const rate = this.settingsMutationLimiter.consume(session.key);
    if (!rate.allowed) {
      this.security('auth.rate_limited', { outcome: 'denied', reasonCode: 'settings_update_limit' });
      fail(429, 'rate_limited', 'Too many settings changes. Try again later.', {
        'Retry-After': String(Math.ceil(rate.retryAfterMs / 1_000)),
      });
    }
    if (!this.audit('settings.update_started', {
      principalId: session.accountId, role: session.role, outcome: 'started', ...changeSummary,
    })) fail(503, 'audit_unavailable', 'Audit logging is unavailable; settings were not changed.');
    let result;
    try {
      // Re-check authorization immediately before the encrypted compare-and-swap.
      session = this.requireAdmin(request, { recent: true });
      result = await this.settingsService.update(body, { updatedBy: session.accountId });
    } catch (error) {
      this.audit('settings.update_failed', {
        principalId: session?.accountId, role: session?.role, outcome: 'failed',
        reasonCode: error?.code ?? error?.name ?? 'update_failed', ...changeSummary,
      });
      if (Number.isInteger(error?.status) && typeof error?.code === 'string') {
        fail(error.status, error.code, error.message);
      }
      throw error;
    }
    if (!this.audit('settings.updated', {
      principalId: session.accountId, role: session.role, revision: result.revision,
      restartRequired: result.restartRequired, outcome: 'succeeded', ...changeSummary,
    })) {
      const automationTokenDeliveryFailed = changeSummary.automationTokenRotated;
      const tlsTrustInstruction = changeSummary.tlsIdentityRegenerated
        ? ' Before restarting, download and trust the current or staged CA on every administrator device.' : '';
      const automationTokenInstruction = automationTokenDeliveryFailed
        ? ' The replacement automation token was staged but not delivered, so the currently active token was preserved. Repair audit logging, restart, sign in, rotate and save another token, acknowledge it, then restart once more to activate it.' : '';
      fail(503, 'settings_committed_audit_failed',
        `Settings were committed, but audit confirmation failed.${tlsTrustInstruction}${automationTokenInstruction}${automationTokenDeliveryFailed ? '' : ' Restart before making another change.'}`, {
          'X-Settings-Committed': 'true',
          'X-TLS-Trust-Update-Required': changeSummary.tlsIdentityRegenerated ? 'true' : 'false',
          'X-Automation-Token-Delivery-Failed': automationTokenDeliveryFailed ? 'true' : 'false',
          'X-Settings-Revision': String(result.revision),
        });
    }
    return result;
  }

  async acknowledgeAutomationToken(request, body) {
    let session = this.requireAdmin(request, { recent: true });
    if (!this.settingsService || typeof this.settingsService.acknowledgeAutomationToken !== 'function') {
      fail(404, 'managed_settings_unavailable', 'Managed settings are not enabled for this installation.');
    }
    if (this.logger?.healthy === false) {
      fail(503, 'audit_unavailable', 'Audit logging is unavailable; token delivery was not acknowledged.');
    }
    if (!this.audit('settings.automation_token_delivery_ack_started', {
      principalId: session.accountId, role: session.role, outcome: 'started',
    })) fail(503, 'audit_unavailable', 'Audit logging is unavailable; token delivery was not acknowledged.');
    let result;
    try {
      session = this.requireAdmin(request, { recent: true });
      result = await this.settingsService.acknowledgeAutomationToken(body, { updatedBy: session.accountId });
    } catch (error) {
      this.audit('settings.automation_token_delivery_ack_failed', {
        principalId: session?.accountId, role: session?.role, outcome: 'failed',
        reasonCode: error?.code ?? error?.name ?? 'update_failed',
      });
      if (Number.isInteger(error?.status) && typeof error?.code === 'string') {
        fail(error.status, error.code, error.message);
      }
      throw error;
    }
    if (!this.audit('settings.automation_token_delivery_acknowledged', {
      principalId: session.accountId, role: session.role, revision: result.revision, outcome: 'succeeded',
    })) {
      fail(503, 'automation_token_ack_committed_audit_failed',
        'Token delivery acknowledgment was committed, but audit confirmation failed. Repair audit log storage and restart the service before making another change.', {
          'X-Mutation-Committed': 'true',
          'X-Settings-Committed': 'true',
          'X-Settings-Revision': String(result.revision),
        });
    }
    return result;
  }

  operators(request) {
    const session = this.requireAdminRead(request);
    const operators = (this.state.listOperatorAccounts?.() ?? []).map((account) => ({
      ...publicOperator(account), isSelf: account.id === session.accountId,
    }));
    return { operators, count: operators.length, maximum: 64 };
  }

  async createOperator(request, body) {
    let session = this.requireAdmin(request, { recent: true });
    if (this.logger?.healthy === false) fail(503, 'audit_unavailable', 'Audit logging is unavailable; operator access was not changed.');
    exactObject(body, ['username', 'role']);
    const identity = operatorIdentity(body.username); const role = operatorRole(body.role ?? 'moderator');
    const temporaryPassword = generateTemporaryPassword(this.randomBytes);
    const passwordVerifier = await this.passwordService.hash(temporaryPassword, {
      username: identity.username, clusterName: this.bridge?.config?.clusterName,
    });
    const at = this.now(); const id = `op_${randomToken(this.randomBytes, 16)}`;
    let account;
    try {
      account = await this.runOperatorMutation(async () => {
        // Password derivation is intentionally expensive and state persistence
        // is queued. Re-authorize inside the shared mutation boundary so a
        // revocation already waiting for storage always wins before this write.
        session = this.requireAdmin(request, { recent: true });
        if (!this.audit('auth.operator_create_started', {
          principalId: session.accountId, targetPrincipalId: id, targetRole: role, outcome: 'started',
        })) fail(503, 'audit_unavailable', 'Audit logging is unavailable; operator access was not changed.');
        return this.state.createOperatorAccount({
          id, username: identity.username, usernameKey: identity.key, role, enabled: true, owner: false,
          passwordVerifier, mustChangePassword: true, authRevision: 1, recordRevision: 1,
          createdAt: at, updatedAt: at, createdBy: session.accountId, updatedBy: session.accountId,
        });
      });
    } catch (error) {
      if (error instanceof AdminApiError) throw error;
      const message = String(error?.message ?? '');
      if (/already|duplicate|unique/i.test(message)) fail(409, 'username_unavailable', 'That username is already in use.');
      if (/limited|maximum|64/i.test(message)) fail(409, 'operator_limit', 'The operator account limit has been reached.');
      throw error;
    }
    if (!this.audit('auth.operator_created', {
      principalId: session.accountId, targetPrincipalId: account.id, targetRole: account.role, outcome: 'succeeded',
    })) failCommittedMutation('operator_create_committed_audit_failed',
      'Operator creation was committed, but audit confirmation failed and the temporary password was not delivered. Repair audit log storage, restart the service, refresh Operators, then reset the created account to generate a new temporary password.',
      { temporaryCredentialDeliveryFailed: true });
    return { status: 201, body: { ok: true, operator: publicOperator(account), temporaryPassword } };
  }

  async updateOperator(request, operatorId, body) {
    let session = this.requireAdmin(request, { recent: true }); const id = safeOperatorId(operatorId);
    if (this.logger?.healthy === false) fail(503, 'audit_unavailable', 'Audit logging is unavailable; operator access was not changed.');
    exactObject(body, ['role', 'enabled', 'expectedRevision']);
    const expectedRevision = integer(body.expectedRevision, 'Expected revision', 1, Number.MAX_SAFE_INTEGER);
    const changes = { updatedAt: this.now(), updatedBy: session.accountId };
    if (Object.hasOwn(body, 'role')) changes.role = operatorRole(body.role);
    if (Object.hasOwn(body, 'enabled')) {
      if (typeof body.enabled !== 'boolean') fail(400, 'invalid_input', 'Enabled must be true or false.');
      changes.enabled = body.enabled;
    }
    if (!Object.hasOwn(changes, 'role') && !Object.hasOwn(changes, 'enabled')) {
      fail(400, 'invalid_input', 'Choose a role or account status to update.');
    }
    let account;
    try {
      account = await this.runOperatorMutation(async () => {
        session = this.requireAdmin(request, { recent: true });
        if (id === session.accountId && (changes.enabled === false || (changes.role && changes.role !== 'admin'))) {
          fail(409, 'self_access_protected', 'You cannot disable or demote your own signed-in account.');
        }
        if (!this.audit('auth.operator_update_started', {
          principalId: session.accountId, targetPrincipalId: id, outcome: 'started',
        })) fail(503, 'audit_unavailable', 'Audit logging is unavailable; operator access was not changed.');
        return this.state.updateOperatorAccount(id, changes, { expectedRevision });
      });
    }
    catch (error) {
      if (error instanceof AdminApiError) throw error;
      const message = String(error?.message ?? '');
      if (/not found/i.test(message)) fail(404, 'operator_not_found', 'That operator account was not found.');
      if (error?.code === 'operator_revision_conflict' || /revision|conflict|changed.*refresh/i.test(message)) {
        fail(409, 'operator_conflict', 'That account changed. Refresh the list and try again.');
      }
      if (/owner|enabled admin|last admin|demote|disable/i.test(message)) fail(409, 'owner_protected', 'The server owner and final enabled administrator must remain active.');
      throw error;
    }
    if (!account) fail(404, 'operator_not_found', 'That operator account was not found.');
    const revokedSessions = this.revokeOperatorSessions(id, id === session.accountId ? session.key : '');
    if (!this.audit('auth.operator_updated', {
      principalId: session.accountId, targetPrincipalId: id, targetRole: account.role,
      targetEnabled: account.enabled, revokedSessions, outcome: 'succeeded',
    })) failCommittedMutation('operator_update_committed_audit_failed',
      'Operator access was committed, but audit confirmation failed. Repair audit log storage, restart the service, then refresh Operators to verify the saved state.');
    return { ok: true, operator: publicOperator(account), revokedSessions };
  }

  async resetOperatorPassword(request, operatorId, body) {
    let session = this.requireAdmin(request, { recent: true }); const id = safeOperatorId(operatorId);
    if (id === session.accountId) fail(409, 'self_reset_use_change_password', 'Use Change password for your own account.');
    if (this.logger?.healthy === false) fail(503, 'audit_unavailable', 'Audit logging is unavailable; the password was not reset.');
    exactObject(body, ['expectedRevision']);
    const expectedRevision = integer(body.expectedRevision, 'Expected revision', 1, Number.MAX_SAFE_INTEGER);
    const target = this.state.getOperatorAccount?.(id);
    if (!target) fail(404, 'operator_not_found', 'That operator account was not found.');
    if (target.owner) fail(409, 'owner_protected', 'The server owner password cannot be reset by another operator.');
    const temporaryPassword = generateTemporaryPassword(this.randomBytes);
    const passwordVerifier = await this.passwordService.hash(temporaryPassword, {
      username: target.username, clusterName: this.bridge?.config?.clusterName,
    });
    let account;
    try {
      account = await this.runOperatorMutation(async () => {
        session = this.requireAdmin(request, { recent: true });
        const currentTarget = this.state.getOperatorAccount?.(id);
        if (!currentTarget) fail(404, 'operator_not_found', 'That operator account was not found.');
        if (currentTarget.owner) fail(409, 'owner_protected', 'The server owner password cannot be reset by another operator.');
        if (!this.audit('auth.operator_password_reset_started', {
          principalId: session.accountId, targetPrincipalId: id, outcome: 'started',
        })) fail(503, 'audit_unavailable', 'Audit logging is unavailable; the password was not reset.');
        return this.state.updateOperatorAccount(id, {
          passwordVerifier, mustChangePassword: true, updatedAt: this.now(), updatedBy: session.accountId,
        }, { expectedRevision });
      });
    } catch (error) {
      if (error instanceof AdminApiError) throw error;
      const message = String(error?.message ?? '');
      if (/not found/i.test(message)) fail(404, 'operator_not_found', 'That operator account was not found.');
      if (error?.code === 'operator_revision_conflict' || /revision|conflict|changed.*refresh/i.test(message)) {
        fail(409, 'operator_conflict', 'That account changed. Refresh the list and try again.');
      }
      throw error;
    }
    if (!account) fail(404, 'operator_not_found', 'That operator account was not found.');
    const revokedSessions = this.revokeOperatorSessions(id);
    if (!this.audit('auth.operator_password_reset', {
      principalId: session.accountId, targetPrincipalId: id, revokedSessions, outcome: 'succeeded',
    })) failCommittedMutation('operator_password_reset_committed_audit_failed',
      'The password reset was committed, but audit confirmation failed and the temporary password was not delivered. Repair audit log storage, restart the service, refresh Operators, then reset the account again to replace the unknown credential.',
      { temporaryCredentialDeliveryFailed: true });
    return { ok: true, operator: publicOperator(account), temporaryPassword, revokedSessions };
  }

  async changePassword(request, body) {
    let session = this.requireMutation(request);
    if (this.logger?.healthy === false) fail(503, 'audit_unavailable', 'Audit logging is unavailable; the password was not changed.');
    exactObject(body, ['currentPassword', 'newPassword', 'passwordConfirmation']);
    const account = this.state.getOperatorAccount?.(session.accountId);
    if (!account?.enabled || !await this.passwordService.verify(body.currentPassword, account.passwordVerifier)) {
      this.security('auth.password_change_rejected', { principalId: session.accountId, outcome: 'denied', reasonCode: 'invalid_current_password' });
      fail(401, 'invalid_current_password', 'The current password was not accepted.');
    }
    const context = { username: account.username, clusterName: this.bridge?.config?.clusterName };
    const password = operatorPassword(body.newPassword, context);
    const confirmation = operatorPassword(body.passwordConfirmation, context);
    if (!strictEqual(password, confirmation)) fail(400, 'password_mismatch', 'The password confirmation does not match.');
    if (await this.passwordService.verify(password, account.passwordVerifier)) {
      fail(400, 'password_reused', 'Choose a password different from the current password.');
    }
    const passwordVerifier = await this.passwordService.hash(password, context);
    const updated = await this.runOperatorMutation(async () => {
      session = this.requireMutation(request);
      if (!this.audit('auth.password_change_started', { principalId: session.accountId, outcome: 'started' })) {
        fail(503, 'audit_unavailable', 'Audit logging is unavailable; the password was not changed.');
      }
      return this.state.updateOperatorAccount(account.id, {
        passwordVerifier, mustChangePassword: false, updatedAt: this.now(), updatedBy: account.id,
      }, { expectedRevision: account.recordRevision });
    });
    const revokedSessions = this.revokeOperatorSessions(account.id);
    const committedMutationFailure = {
      code: 'password_change_committed_audit_failed',
      message: 'The password change was committed, but audit confirmation failed and all existing sessions were revoked. Repair audit log storage, restart the service, then sign in with the new password.',
    };
    if (!this.audit('auth.password_changed', {
      principalId: session.accountId, revokedSessions, outcome: 'succeeded',
    })) failCommittedMutation(committedMutationFailure.code, committedMutationFailure.message);
    return this.issueSession(updated, 'password-change', { committedMutationFailure });
  }

  serverLabel(serverId) {
    if (!serverId) return 'the cluster';
    const server = this.bridge.servers?.find((candidate) => candidate.id === serverId);
    return server ? `${safeSnippet(server.name, this.config.redactionSecrets, 64)} (${server.id})` : serverId;
  }

  actionSummary(session, action, options) {
    const player = options.player ? this.sessions.get(session.key)?.playerSelections.get(options.player) : null;
    if (options.player && !player) fail(400, 'invalid_player_selection', 'Refresh the connected-player list and choose the player again.');
    if (player && player.purpose !== action) fail(409, 'player_selection_scope', 'Refresh and choose this player for the selected action.');
    const playerLabel = player ? `${player.survivorName ? `${player.survivorName} / ` : ''}${player.name} on ${player.serverName}` : 'the connected player';
    const server = this.serverLabel(options.server); const item = options.item ? getItem(options.item) : null;
    switch (action) {
      case 'announce': return `Send announcement to ${server}: ${safeSnippet(options.message, this.config.redactionSecrets)}`;
      case 'announce-template': return `Send template ${safeSnippet(options.template, this.config.redactionSecrets, 64)} to ${server}`;
      case 'save-world': return `Save world on ${server}`;
      case 'restart': return `Schedule a ${options.minutes}-minute save/restart window for ${server}; host restart remains manual`;
      case 'cancel-restart': return `Cancel the restart window for ${server}`;
      case 'give-item': return `Give ${options.quantity}x ${item?.name ?? 'catalog item'}${options.blueprint ? ' blueprint' : ''} to ${playerLabel}`;
      case 'give-xp': return `Give ${options.amount} XP to ${playerLabel}`;
      case 'refresh-player-id': return `Verify the protected targeting ID for ${playerLabel}`;
      case 'player': return `View protected staff details for ${playerLabel}`;
      case 'warn': return `Warn ${playerLabel}: ${safeSnippet(options.message, this.config.redactionSecrets)}`;
      case 'note': return `Add a private note for ${playerLabel}: ${safeSnippet(options.note, this.config.redactionSecrets)}`;
      case 'mute-player': return `Mute ${playerLabel} from Cluster Chat for ${options.minutes} minutes`;
      case 'unmute-player': return `Remove the Cluster Chat mute from ${playerLabel}`;
      case 'kick': return `Kick ${playerLabel}`;
      case 'ban': return `Ban ${playerLabel}`;
      case 'whitelist': return `Add ${playerLabel} to the no-check join list`;
      case 'unwhitelist': return `Remove ${playerLabel} from the no-check join list`;
      case 'destroy-wild-dinos': return `Destroy every untamed creature on ${server}`;
      case 'rcon': return `Run allowlisted RCON verb ${safeSnippet(options.command.split(/\s+/, 1)[0], [], 64)} on ${server}; raw output will be suppressed`;
      default: return 'Run dashboard action';
    }
  }

  preview(request, body) {
    const session = this.requireMutation(request);
    if (this.bridge?.controlPlaneOnly) {
      fail(503, 'data_plane_unavailable', 'Server operations are unavailable. Repair Settings and restart the service.');
    }
    if (!isRecord(body)) fail(400, 'invalid_input', 'Request body must be a JSON object.');
    const requestedDefinition = ACTION_BY_ID.get(String(body.action ?? '').trim());
    if (requestedDefinition) this.assertActionAllowed(session, requestedDefinition);
    const normalized = normalizeAdminAction(body.action, body.options, this.config);
    const summary = this.actionSummary(session, normalized.action, normalized.options);
    const token = randomToken(this.randomBytes, 24); const key = digest(token); const expiresAt = this.now() + CONFIRMATION_TTL_MS;
    const challenge = normalized.definition.challenge ? `WIPE ${normalized.options.server}` : '';
    this.confirmations.set(key, {
      sessionKey: session.key, payloadHash: actionPayloadHash(normalized.action, normalized.options), expiresAt, challenge,
    });
    this.prune();
    return { confirmationToken: token, summary, risk: normalized.definition.risk, challenge, expiresAt };
  }

  requireIdempotency(request) {
    const key = String(request.headers['idempotency-key'] ?? '');
    if (!IDEMPOTENCY_PATTERN.test(key)) fail(400, 'idempotency_required', 'Supply a random Idempotency-Key containing 16-128 safe characters.');
    return key;
  }

  addActivity(entry) {
    this.activity.unshift(Object.freeze({ ...entry }));
    if (this.activity.length > 100) this.activity.length = 100;
  }

  async execute(request, body) {
    const session = this.requireMutation(request);
    if (this.bridge?.controlPlaneOnly) {
      fail(503, 'data_plane_unavailable', 'Server operations are unavailable. Repair Settings and restart the service.');
    }
    if (!isRecord(body)) fail(400, 'invalid_input', 'Request body must be a JSON object.');
    const requestedDefinition = ACTION_BY_ID.get(String(body.action ?? '').trim());
    if (requestedDefinition) this.assertActionAllowed(session, requestedDefinition);
    const normalized = normalizeAdminAction(body.action, body.options, this.config);
    if (this.logger?.healthy === false) fail(503, 'audit_unavailable', 'Security audit logging is unavailable; privileged actions are temporarily disabled.');
    const payloadHash = actionPayloadHash(normalized.action, normalized.options); const idempotencyKey = this.requireIdempotency(request);
    const cacheKey = `${session.key}\u001f${idempotencyKey}`; this.prune(); const cached = this.idempotency.get(cacheKey);
    if (cached) {
      if (!strictEqual(cached.payloadHash, payloadHash)) {
        this.security('admin.idempotency_rejected', { action: normalized.action, outcome: 'denied', reasonCode: 'payload_conflict' });
        fail(409, 'idempotency_conflict', 'That Idempotency-Key was already used for a different action.');
      }
      this.audit('admin.action_replayed', { action: normalized.action, outcome: 'replayed' });
      return cached.promise;
    }

    const confirmationToken = String(body.confirmationToken ?? '');
    if (!CONFIRMATION_PATTERN.test(confirmationToken)) fail(400, 'confirmation_required', 'Preview and confirm this exact action first.');
    const confirmationKey = digest(confirmationToken); const confirmation = this.confirmations.get(confirmationKey);
    if (!confirmation || confirmation.expiresAt <= this.now() || confirmation.sessionKey !== session.key
      || !strictEqual(confirmation.payloadHash, payloadHash)) {
      this.security('admin.confirmation_rejected', { action: normalized.action, outcome: 'denied', reasonCode: 'expired_or_mismatch' });
      fail(409, 'confirmation_expired', 'That action preview expired or no longer matches. Preview it again.');
    }
    this.confirmations.delete(confirmationKey);
    if (confirmation.challenge && body.challengeResponse !== confirmation.challenge) {
      this.security('admin.confirmation_rejected', { action: normalized.action, outcome: 'denied', reasonCode: 'challenge_mismatch' });
      fail(409, 'challenge_failed', 'Enter the exact confirmation phrase shown in the preview.');
    }
    const rate = this.actionLimiter.consume(session.key);
    if (!rate.allowed) {
      this.security('auth.rate_limited', { action: normalized.action, outcome: 'denied', reasonCode: 'action_limit' });
      fail(429, 'rate_limited', 'Too many admin actions. Try again shortly.', { 'Retry-After': String(Math.ceil(rate.retryAfterMs / 1_000)) });
    }

    const operationId = randomToken(this.randomBytes, 12); const startedAt = this.now();
    const summary = this.actionSummary(session, normalized.action, normalized.options);
    if (!this.audit('admin.action_started', {
      principalId: session.accountId, role: session.role, operationId, action: normalized.action,
      server: normalized.options.server ?? 'cluster', outcome: 'started',
    })) {
      fail(503, 'audit_unavailable', 'Security audit logging is unavailable; no administrator action was sent.');
    }
    const promise = (async () => {
      try {
        const result = await this.bridge.executeStaffCommand({
          command: normalized.action, options: normalized.options, level: session.permissionLevel,
          principalId: session.actorId, actor: 'http:dashboard', surface: 'dashboard',
        });
        const message = safeSnippet(result, this.config.redactionSecrets, 1_900); const completedAt = this.now();
        this.addActivity({ principalId: session.accountId, operationId, action: normalized.action, summary, outcome: 'succeeded', occurredAt: completedAt, durationMs: Math.max(0, completedAt - startedAt) });
        this.metrics?.increment?.('http_admin_actions_total', { action: normalized.action, outcome: 'succeeded' });
        this.audit('admin.action_succeeded', { principalId: session.accountId, role: session.role, operationId, action: normalized.action, server: normalized.options.server ?? 'cluster', outcome: 'succeeded', durationMs: Math.max(0, completedAt - startedAt) });
        return { status: 200, body: { ok: true, outcome: 'succeeded', operationId, message } };
      } catch (error) {
        const completedAt = this.now(); const outcome = UNCERTAIN_ON_FAILURE.has(normalized.action) ? 'uncertain' : 'failed';
        const message = safeSnippet(error?.message || 'The action failed.', this.config.redactionSecrets, 500);
        this.addActivity({ principalId: session.accountId, operationId, action: normalized.action, summary, outcome, occurredAt: completedAt, durationMs: Math.max(0, completedAt - startedAt), message });
        this.metrics?.increment?.('http_admin_actions_total', { action: normalized.action, outcome });
        this.audit(outcome === 'uncertain' ? 'admin.action_uncertain' : 'admin.action_failed', {
          principalId: session.accountId, role: session.role, operationId, action: normalized.action, server: normalized.options.server ?? 'cluster', outcome,
          reasonCode: error?.code ?? error?.name ?? 'operation_failed', durationMs: Math.max(0, completedAt - startedAt),
        });
        this.logger?.warn?.('Dashboard admin action failed', { event: 'admin.action_failed', action: normalized.action, outcome, error: message });
        return { status: 502, body: { ok: false, outcome, operationId, error: 'action_failed', message } };
      }
    })();
    this.idempotency.set(cacheKey, { payloadHash, promise, expiresAt: this.now() + IDEMPOTENCY_TTL_MS });
    return promise;
  }
}

export function listAdminActions() { return ACTIONS.map((action) => ({ ...action })); }
