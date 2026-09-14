import { randomBytes } from 'node:crypto';
import { ContentFilter } from './content-filter.js';
import {
  ANNOUNCEMENT_PREFIX, RESTART_MAX_DELAY_MINUTES, announcementMessageMaxLength, codePointLength,
  restartNotice, restartReasonMaxLength,
} from './announcement-policy.js';
import { parseGameCommand, parseDurationMinutes } from './command-parser.js';
import { toDiscordEmoji, toGameEmoji } from './emoji.js';
import { getItem, resolveItemInput, searchItems } from './item-catalog.js';
import { Metrics } from './metrics.js';
import { PermissionLevel, getPermissionLevel } from './permissions.js';
import { findPlayer } from './player-parser.js';
import { SlidingWindowRateLimiter } from './rate-limiter.js';
import {
  chunkText, escapeDiscordMarkdown, fingerprint, normalizeName,
  sanitizeForDiscord, sanitizeForGame, sanitizeIdentity, truncateCodePoints,
} from './sanitize.js';
import { TtlDedupe } from './ttl-dedupe.js';
import { configuredRedactionSecrets, redactText } from './redaction.js';

function optionMap(subcommand) {
  return Object.fromEntries((subcommand?.options ?? []).map((option) => [option.name, option.value]));
}
const PLAYER_CHOICE_PREFIX = 'p2:';
const LEGACY_PLAYER_CHOICE_PREFIX = 'p1:';
const PLAYER_CHOICE_TTL_MS = 2 * 60_000;
const PLAYER_CHOICE_MAX_ENTRIES = 2_000;
const ADMIN_AUTOCOMPLETE_COMMANDS = new Set([
  'save-world', 'give-item', 'remember-player-id', 'refresh-player-id', 'give-xp', 'whitelist', 'unwhitelist',
  'destroy-wild-dinos', 'ban', 'unban', 'rcon', 'favorite-item', 'unfavorite-item', 'save-item-preset',
  'delete-item-preset', 'give-item-preset',
]);
const STAFF_COMMAND_ROOTS = new Set(['asa-admin', 'asa-ops']);
const OPS_COMMANDS = new Set([
  'status', 'restart', 'cancel-restart', 'save-world', 'give-item', 'remember-player-id', 'refresh-player-id',
  'give-xp', 'whitelist', 'unwhitelist', 'destroy-wild-dinos', 'announce-template', 'announce', 'rcon',
  'favorite-item', 'unfavorite-item', 'save-item-preset', 'delete-item-preset', 'give-item-preset',
]);
const SYSTEMIC_PROFILE_ERROR_CODES = new Set([
  'SFTP_AUTH_FAILED', 'HOST_KEY_REJECTED', 'SFTP_TIMEOUT', 'SFTP_READ_FAILED',
  'ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH', 'ENOTFOUND',
]);

function profileErrorCode(error) {
  const code = String(error?.code ?? '').toLocaleUpperCase('en-US');
  return /^[A-Z][A-Z0-9_]{1,63}$/.test(code) ? code : 'PROFILE_IMPORT_FAILED';
}

function profileBackoffError(server, failure) {
  const error = new Error(`Automatic player ID access is temporarily paused on ${server.name} after ${failure.code}`);
  error.code = 'PROFILE_SOURCE_BACKOFF';
  error.sourceCode = failure.code;
  error.retryAt = failure.retryAt;
  return error;
}

function determinateOperationError(message, code = 'PRECONDITION_FAILED') {
  const error = new Error(message);
  error.code = code;
  error.operationOutcome = 'failed';
  return error;
}

function choiceScore(label, query) {
  const normalized = normalizeName(label); const search = normalizeName(query);
  if (!search) return 3;
  if (normalized === search) return 0;
  if (normalized.startsWith(search)) return 1;
  return normalized.includes(search) ? 2 : Number.POSITIVE_INFINITY;
}

function focusedOption(subcommand) {
  return (subcommand?.options ?? []).find((option) => option.focused === true);
}
function interactionUser(interaction) { return interaction.member?.user ?? interaction.user ?? {}; }
function interactionDisplayName(interaction) {
  const user = interactionUser(interaction);
  return sanitizeIdentity(interaction.member?.nick ?? user.global_name ?? user.username ?? user.id, 48);
}
function messageDisplayName(message) {
  return sanitizeIdentity(message.member?.nick ?? message.author?.global_name ?? message.author?.username ?? message.author?.id, 48);
}
function formatDuration(ms) {
  const minutes = Math.max(1, Math.ceil(ms / 60_000));
  if (minutes >= 1_440 && minutes % 1_440 === 0) return `${minutes / 1_440}d`;
  if (minutes >= 60 && minutes % 60 === 0) return `${minutes / 60}h`;
  return `${minutes}m`;
}
function formatAge(timestamp, now) {
  if (!timestamp) return 'never';
  const seconds = Math.max(0, Math.floor((now - timestamp) / 1_000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3_600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3_600)}h ago`;
  return `${Math.floor(seconds / 86_400)}d ago`;
}
function looksLikePlayerId(value) { return /^[A-Za-z0-9:_-]{12,}$/.test(String(value ?? '').trim()); }
function visiblePlayerTarget(value, fallback = 'account selection') {
  return looksLikePlayerId(value) ? fallback : sanitizeIdentity(value, 48);
}
function attachmentSuffix(message) {
  const attachments = Array.isArray(message.attachments) ? message.attachments : Object.values(message.attachments ?? {});
  if (!attachments.length) return '';
  const names = attachments.slice(0, 3).map((item) => sanitizeIdentity(item.filename ?? 'file', 40));
  return ` [attachment: ${names.join(', ')}]`;
}

export class ClusterBridge {
  constructor({
    config, servers, discord, state, profileSources = new Map(), metrics = new Metrics(), logger = null,
    now = () => Date.now(), setIntervalFn = setInterval, clearIntervalFn = clearInterval, randomBytesFn = randomBytes,
  } = {}) {
    if (!config) throw new Error('Bridge config is required');
    if (!state) throw new Error('State store is required');
    this.config = config; this.servers = Array.from(servers ?? []);
    this.serverMap = new Map(this.servers.map((server) => [server.id, server]));
    this.discord = discord; this.state = state; this.metrics = metrics; this.logger = logger; this.now = now;
    this.redactionSecrets = configuredRedactionSecrets(config);
    this.profileSources = profileSources instanceof Map ? new Map(profileSources) : new Map(Object.entries(profileSources ?? {}));
    this.profileValidatedAt = new Map(); this.profileFailuresAt = new Map(); this.profileFailureDetails = new Map();
    this.profileSourceFailures = new Map(); this.profileLastAttempts = new Map(); this.profileLastSuccesses = new Map();
    this.profileLastErrors = new Map(); this.pendingProfileImports = new Map();
    this.startedAt = now(); this.started = false;
    this.gameDedupe = new TtlDedupe({ ttlMs: config.chat.gameDuplicateTtlSeconds * 1_000, now });
    this.discordDedupe = new TtlDedupe({ ttlMs: config.chat.echoTtlSeconds * 1_000, now });
    this.interactionDedupe = new TtlDedupe({ ttlMs: 15 * 60_000, maxEntries: 10_000, now });
    this.noticeDedupe = new TtlDedupe({ ttlMs: 15_000, maxEntries: 2_000, now });
    this.rateLimiter = new SlidingWindowRateLimiter({
      limit: config.moderation.messageBurst, windowMs: config.moderation.messageWindowSeconds * 1_000, now,
    });
    this.filter = new ContentFilter(config.moderation); this.boundServerHandlers = new Map(); this.sessionStarts = new Map();
    this.initialPlayerSnapshots = new Set(); this.pendingStarterDeliveries = new Map();
    this.playerChoiceTokens = new Map(); this.playerChoiceTokensByTarget = new Map(); this.randomBytesFn = randomBytesFn;
    this.setIntervalFn = setIntervalFn; this.clearIntervalFn = clearIntervalFn; this.restartTimer = null; this.scheduledRestarts = new Map();
    this.stopPromise = null;
    this.boundDiscordMessage = (message) => this.guard('Discord message', () => this.handleDiscordMessage(message));
    this.boundDiscordInteraction = (interaction) => this.guard('Discord interaction', () => this.handleInteraction(interaction));
  }

  async guard(context, operation) {
    try { await operation(); }
    catch (error) {
      this.logger?.error?.(`${context} failed`, { error: error.message, stack: error.stack });
      this.metrics.increment('errors_total', { context: normalizeName(context).replace(/\s+/g, '_') });
    }
  }

  async start() {
    if (this.started) return;
    if (this.stopPromise) { await this.stopPromise; this.stopPromise = null; }
    this.started = true;
    try {
      for (const server of this.servers) {
        const onChat = (event) => this.guard('ARK chat', () => this.handleGameChat(server, event));
        const onPollError = (error) => {
          // ArkServer.execute already emits the canonical bounded warning after
          // its retries are exhausted. Keep this observer as debug context and
          // a metric so one outage does not appear as two separate warnings.
          this.logger?.debug?.('ARK polling cycle failed', {
            event: 'rcon.poll_failed', component: 'rcon', server: server.id,
            outcome: 'failed', reasonCode: error?.code ?? error?.name ?? 'poll_failed',
          });
          this.metrics.increment('poll_errors_total', { server: server.id });
        };
        const onPlayerJoined = (player) => this.guard('ARK player join', () => this.handlePlayerJoin(server, player));
        const onPlayerLeft = (player) => this.guard('ARK player leave', () => this.handlePlayerLeave(server, player));
        const onPlayers = (players) => this.guard('ARK player snapshot', () => this.handlePlayerSnapshot(server, players));
        const onConnected = () => this.guard('ARK connection restored', () => this.handleServerConnectionChange(server, true));
        const onDisconnected = (_server, error) => this.guard('ARK connection lost', () => this.handleServerConnectionChange(server, false, error));
        this.boundServerHandlers.set(server.id, { onChat, onPollError, onPlayerJoined, onPlayerLeft, onPlayers, onConnected, onDisconnected });
        server.on('chat', onChat); server.on('pollError', onPollError); server.on('playerJoined', onPlayerJoined); server.on('playerLeft', onPlayerLeft);
        server.on('players', onPlayers); server.on('connected', onConnected); server.on('disconnected', onDisconnected); server.startPolling();
      }
      if (this.discord?.config?.enabled) {
        this.discord.on('messageCreate', this.boundDiscordMessage);
        this.discord.on('interactionCreate', this.boundDiscordInteraction);
        await this.discord.start();
      }
      for (const restart of this.state.listScheduledRestarts?.() ?? []) {
        if (this.serverMap.has(restart.serverId) && restart.deadline > this.now()) {
          this.scheduledRestarts.set(restart.serverId, { ...restart, warningMinutes: new Set(restart.warningMinutes ?? []) });
        } else await this.state.clearScheduledRestart?.(restart.serverId);
      }
      this.restartTimer = this.setIntervalFn(() => this.guard('Scheduled restarts', () => this.processScheduledRestarts()), 1_000);
    } catch (error) { await this.stop().catch(() => undefined); throw error; }
  }

  stop() {
    if (this.stopPromise) return this.stopPromise;
    if (!this.started) {
      this.playerChoiceTokens.clear(); this.playerChoiceTokensByTarget.clear();
      return Promise.resolve();
    }
    this.started = false;
    const stoppedAt = this.now(); const sessions = [...this.sessionStarts.values()];
    // Claim every active session before the first persistence await. A leave
    // handler or repeated shutdown can then observe only an already-drained
    // session and cannot count the same interval twice.
    this.sessionStarts.clear();
    for (const server of this.servers) {
      const handlers = this.boundServerHandlers.get(server.id);
      if (handlers) { server.off('chat', handlers.onChat); server.off('pollError', handlers.onPollError); server.off('playerJoined', handlers.onPlayerJoined); server.off('playerLeft', handlers.onPlayerLeft); server.off('players', handlers.onPlayers); server.off('connected', handlers.onConnected); server.off('disconnected', handlers.onDisconnected); }
      server.stopPolling();
    }
    this.boundServerHandlers.clear(); this.pendingProfileImports.clear(); this.initialPlayerSnapshots.clear(); this.pendingStarterDeliveries.clear();
    this.playerChoiceTokens.clear(); this.playerChoiceTokensByTarget.clear();
    this.clearIntervalFn(this.restartTimer); this.restartTimer = null; this.scheduledRestarts.clear();
    if (this.discord) {
      this.discord.off('messageCreate', this.boundDiscordMessage);
      this.discord.off('interactionCreate', this.boundDiscordInteraction);
      this.discord.stop();
    }
    this.stopPromise = this.flushPlayerSessions(sessions, stoppedAt);
    return this.stopPromise;
  }

  async flushPlayerSessions(sessions, stoppedAt) {
    const failures = [];
    for (const session of sessions) {
      const eosId = String(session?.eosId ?? '').trim();
      if (!eosId || typeof this.state.recordPlaytimeSession !== 'function') continue;
      try {
        await this.state.recordPlaytimeSession(eosId, (stoppedAt - session.startedAt) / 1_000, session.displayName);
      } catch (error) {
        failures.push(error);
        this.logger?.warn?.('Player playtime shutdown flush failed', {
          player: sanitizeIdentity(session.displayName, 48), error: error.message,
        });
        this.metrics.increment('errors_total', { context: 'playtime_shutdown_flush' });
      }
    }
    if (failures.length) throw new AggregateError(failures, `Failed to persist ${failures.length} active player session${failures.length === 1 ? '' : 's'} during shutdown`);
  }

  status() {
    const servers = this.servers.map((server) => ({
      ...server.snapshot(), players: server.players.map((player) => ({ name: player.name, id: player.id })),
      profileImport: this.profileImportSnapshot(server),
    }));
    const discord = this.discord?.snapshot() ?? { enabled: false, started: false, ready: false };
    return {
      clusterName: this.config.clusterName, started: this.started,
      uptimeSeconds: Math.floor((this.now() - this.startedAt) / 1_000),
      ready: servers.some((server) => server.connected) && (!this.config.discord.enabled || Boolean(discord.ready)),
      discord, servers, activeMutes: this.state.listMutes().length,
      linkedAccounts: this.state.countLinkedAccounts?.() ?? Object.keys(this.state.state?.linksByDiscord ?? {}).length,
      scheduledRestarts: [...this.scheduledRestarts].map(([serverId, restart]) => ({ serverId, deadline: restart.deadline, reason: restart.reason })),
    };
  }

  resolveGameIdentity(server, event) {
    const exact = findPlayer(server.players ?? [], event.playerName).player;
    return { eosId: exact?.id ?? '', playerName: event.playerName, characterName: event.characterName };
  }

  async handlePlayerPresence(server, player, action) {
    this.logger?.audit?.('player.presence_changed', { component: 'bridge', action, server: server.id, outcome: 'observed' });
    if (!this.config.operations.joinLeaveAlerts || !this.config.discord.enabled) return;
    const name = sanitizeIdentity(player.name, 48);
    await this.discord.sendAudit(`PLAYER ${action.toLocaleUpperCase('en-US')} ${name} on ${sanitizeIdentity(server.name, 32)}`);
    this.metrics.increment('player_presence_events_total', { action, server: server.id });
  }

  sessionKey(server, player) { return `${server.id}:${player.id || normalizeName(player.name)}`; }

  startPlayerSession(server, player, startedAt = this.now()) {
    const key = this.sessionKey(server, player);
    if (!this.sessionStarts.has(key)) {
      this.sessionStarts.set(key, {
        startedAt,
        eosId: String(player.id ?? '').trim(),
        displayName: String(player.name ?? '').trim(),
      });
    }
  }

  profileKey(server, player) { return `${server.id}:${String(player.id ?? '').toLocaleLowerCase('en-US')}`; }

  profileSource(server) { return this.profileSources.get(server.id) ?? null; }

  profileMapping(server, player) {
    const stored = this.state.getPlayerDataMapping?.(server.id, player.id);
    if (stored) return stored;
    const playerDataId = player.playerDataId ?? this.state.getPlayerDataId?.(server.id, player.id);
    return playerDataId ? { playerDataId: String(playerDataId), displayName: '', characterName: '', actor: '', updatedAt: 0 } : null;
  }

  activeProfileSourceFailure(server, source = this.profileSource(server), at = this.now()) {
    const failure = this.profileSourceFailures.get(server.id);
    if (!failure || !source) return null;
    const retryAt = failure.at + (source.config?.retryIntervalMs ?? 60_000);
    if (at >= retryAt) { this.profileSourceFailures.delete(server.id); return null; }
    return { ...failure, retryAt };
  }

  profileImportSnapshot(server) {
    const source = this.profileSource(server); const players = server.players ?? [];
    const eligible = players.filter((player) => /^[a-f0-9]{32}$/i.test(String(player.id ?? '').trim()));
    const mappedPlayers = eligible.filter((player) => this.profileMapping(server, player)).length;
    if (!source) {
      return {
        enabled: false, state: 'disabled', eligiblePlayers: eligible.length, mappedPlayers,
        verifiedPlayers: 0, pendingPlayers: 0, failedPlayers: 0,
        lastAttemptAt: null, lastSuccessAt: null, lastErrorAt: null, lastErrorCode: null, retryAt: null,
      };
    }
    const now = this.now(); const revalidateMs = source.config?.revalidateIntervalMs ?? 300_000;
    let verifiedPlayers = 0; let pendingPlayers = 0; let failedPlayers = 0; let latestPlayerFailure = null;
    for (const player of eligible) {
      const key = this.profileKey(server, player); const validatedAt = this.profileValidatedAt.get(key);
      if (validatedAt != null && now - validatedAt < revalidateMs) verifiedPlayers += 1;
      if (this.pendingProfileImports.has(key)) pendingPlayers += 1;
      const failure = this.profileFailureDetails.get(key);
      if (failure) {
        failedPlayers += 1;
        if (!latestPlayerFailure || failure.at > latestPlayerFailure.at) latestPlayerFailure = failure;
      }
    }
    const trackedError = this.profileLastErrors.get(server.id) ?? null;
    const lastError = !trackedError || (latestPlayerFailure && latestPlayerFailure.at > trackedError.at) ? latestPlayerFailure : trackedError;
    const sourceFailure = this.activeProfileSourceFailure(server, source, now);
    let state = 'checking';
    if (lastError || failedPlayers) state = 'degraded';
    else if (pendingPlayers) state = 'checking';
    else if (!eligible.length) state = 'idle';
    else if (verifiedPlayers === eligible.length) state = 'healthy';
    return {
      enabled: true, state, eligiblePlayers: eligible.length, mappedPlayers, verifiedPlayers,
      pendingPlayers, failedPlayers, lastAttemptAt: this.profileLastAttempts.get(server.id) ?? null,
      lastSuccessAt: this.profileLastSuccesses.get(server.id) ?? null,
      lastErrorAt: lastError?.at ?? null, lastErrorCode: lastError?.code ?? null,
      retryAt: sourceFailure?.retryAt ?? (lastError ? lastError.at + (source.config?.retryIntervalMs ?? 60_000) : null),
    };
  }

  async importPlayerProfile(server, player, { force = false } = {}) {
    const source = this.profileSource(server); const eosId = String(player?.id ?? '').trim();
    if (!source || !/^[a-f0-9]{32}$/i.test(eosId)) return null;
    const key = this.profileKey(server, player); const now = this.now();
    const current = this.profileMapping(server, player)?.playerDataId ?? null;
    const revalidateMs = source.config?.revalidateIntervalMs ?? 300_000;
    const retryMs = source.config?.retryIntervalMs ?? 60_000;
    if (!force && this.profileValidatedAt.has(key) && now - this.profileValidatedAt.get(key) < revalidateMs) return current;
    if (this.pendingProfileImports.has(key)) return this.pendingProfileImports.get(key);
    const sourceFailure = this.activeProfileSourceFailure(server, source, now);
    if (!force && sourceFailure) throw profileBackoffError(server, sourceFailure);
    if (!force && this.profileFailuresAt.has(key) && now - this.profileFailuresAt.get(key) < retryMs) return null;

    const operation = (async () => {
      this.profileLastAttempts.set(server.id, this.now());
      try {
        const profile = await source.getProfile(eosId);
        if (String(profile?.eosId ?? '').toLocaleLowerCase('en-US') !== eosId.toLocaleLowerCase('en-US')
          || (profile.serverId && profile.serverId !== server.id)) {
          const mismatch = new Error('Profile source returned an identity for a different account or map');
          mismatch.code = 'PROFILE_IDENTITY_MISMATCH'; throw mismatch;
        }
        const succeededAt = this.now();
        this.profileLastSuccesses.set(server.id, succeededAt); this.profileLastErrors.delete(server.id); this.profileSourceFailures.delete(server.id);
        this.profileFailuresAt.delete(key); this.profileFailureDetails.delete(key);
        const stillConnected = (server.players ?? []).some((candidate) => String(candidate.id ?? '').toLocaleLowerCase('en-US') === eosId.toLocaleLowerCase('en-US'));
        if (!stillConnected) return null;
        const displayName = String(profile.playerName || player.name || '');
        const characterName = String(profile.characterName || '');
        const existing = this.profileMapping(server, player);
        const unchanged = existing?.playerDataId === String(profile.playerDataId)
          && (!displayName || existing.displayName === displayName)
          && (!characterName || existing.characterName === characterName);
        const saved = unchanged ? existing : await this.state.setPlayerDataId(server.id, eosId, profile.playerDataId, {
          displayName, characterName, actor: 'sftp-profile-import', replace: false,
        });
        this.profileValidatedAt.set(key, succeededAt);
        this.metrics.increment('player_profile_imports_total', { server: server.id, result: 'success' });
        this.logger?.info?.('Player numeric ID verified from read-only profile', {
          event: 'sftp.profile_read_succeeded', component: 'profile-import', server: server.id, outcome: 'succeeded',
        });
        return saved.playerDataId;
      } catch (error) {
        const failedAt = this.now(); const code = profileErrorCode(error);
        this.profileFailuresAt.set(key, failedAt); this.profileFailureDetails.set(key, { at: failedAt, code });
        this.profileLastErrors.set(server.id, { at: failedAt, code });
        if (SYSTEMIC_PROFILE_ERROR_CODES.has(code)) this.profileSourceFailures.set(server.id, { at: failedAt, code });
        this.metrics.increment('player_profile_imports_total', { server: server.id, result: 'error' });
        throw error;
      }
    })();
    this.pendingProfileImports.set(key, operation);
    try { return await operation; }
    finally { if (this.pendingProfileImports.get(key) === operation) this.pendingProfileImports.delete(key); }
  }

  async syncPlayerProfiles(server, players = server.players ?? []) {
    const source = this.profileSource(server);
    if (!source || this.activeProfileSourceFailure(server, source)) return;
    for (const player of players) {
      try { await this.importPlayerProfile(server, player); }
      catch (error) {
        const code = profileErrorCode(error);
        if (code === 'PROFILE_SOURCE_BACKOFF') return;
        this.logger?.warn?.('Automatic player ID import failed', {
          event: 'sftp.profile_read_failed', component: 'profile-import', server: server.id,
          outcome: 'failed', reasonCode: code,
        });
        if (SYSTEMIC_PROFILE_ERROR_CODES.has(code)) return;
      }
    }
  }

  async handlePlayerSnapshot(server, players = server.players ?? []) {
    const startedAt = this.now(); const initialSnapshot = !this.initialPlayerSnapshots.has(server.id);
    this.initialPlayerSnapshots.add(server.id);
    for (const player of players) {
      this.startPlayerSession(server, player, startedAt);
      await this.observePlayerForStarterPackages(player, { eligible: !initialSnapshot, welcome: false });
    }
    await this.syncPlayerProfiles(server, players);
    for (const player of players) await this.deliverStarterPackages(server, player);
  }

  formatTemplate(template, vars) {
    return String(template ?? '').replace(/\{(\w+)\}/g, (match, key) => (key in vars ? String(vars[key]) : match));
  }

  async sendWelcome(server, player) {
    const welcome = this.config.operations.welcomeMessage;
    if (!welcome?.enabled) return;
    const identity = { eosId: player.id, playerName: player.name, characterName: player.name };
    const text = this.formatTemplate(welcome.text, {
      name: sanitizeIdentity(player.name, 32), cluster: this.config.clusterName, prefix: this.config.chat.commandPrefix,
    });
    await this.replyToPlayer(server, identity, text);
  }

  async handlePlayerJoin(server, player) {
    if (/^[a-f0-9]{32}$/i.test(String(player.id ?? '').trim())) {
      const key = this.profileKey(server, player);
      this.profileValidatedAt.delete(key); this.profileFailuresAt.delete(key); this.profileFailureDetails.delete(key);
    }
    this.startPlayerSession(server, player);
    await this.observePlayerForStarterPackages(player, { eligible: true, welcome: true, server });
    await this.handlePlayerPresence(server, player, 'joined');
  }

  async observePlayerForStarterPackages(player, { eligible, welcome, server } = {}) {
    const eosId = String(player?.id ?? '').trim(); let firstSeen = false;
    if (eosId && typeof this.state.observePlayerForStarterPackages === 'function') {
      const observation = await this.state.observePlayerForStarterPackages(eosId, player.name, { eligible });
      if (observation?.grant) firstSeen = Boolean(observation.firstSeen);
      else {
        firstSeen = Boolean(this.state.isFirstSeen?.(eosId));
        await this.state.markSeen?.(eosId, player.name);
      }
    } else if (eosId) {
      firstSeen = Boolean(this.state.isFirstSeen?.(eosId));
      await this.state.markSeen?.(eosId, player.name);
    }
    if (welcome && firstSeen && server) await this.sendWelcome(server, player);
    return firstSeen;
  }

  async sendPackageItem(server, playerDataId, entry) {
    const item = getItem(entry.itemKey);
    if (!item) throw new Error('The package contains an unavailable catalog item.');
    if (item.blueprintPath) {
      await server.giveItemToPlayer(playerDataId, item.blueprintPath, entry.quantity, entry.quality, entry.blueprint);
    } else if (item.itemNumber != null) {
      await server.giveItemNumToPlayer(playerDataId, item.itemNumber, entry.quantity, entry.quality, entry.blueprint);
    } else throw new Error('The package contains an item without a usable grant identifier.');
    return item;
  }

  deliverStarterPackages(server, player) {
    const eosId = String(player?.id ?? '').trim().toLocaleLowerCase('en-US');
    if (!/^[a-f0-9]{32}$/u.test(eosId) || typeof this.state.getStarterPackageGrant !== 'function') return Promise.resolve();
    const key = `${server.id}:${eosId}`;
    if (this.pendingStarterDeliveries.has(key)) return this.pendingStarterDeliveries.get(key);
    const operation = (async () => {
      const grant = this.state.getStarterPackageGrant(eosId);
      if (!grant?.eligible) return;
      const mapping = this.profileMapping(server, player); const playerDataId = mapping?.playerDataId;
      if (!playerDataId) return;
      for (const [packageId, packageGrant] of Object.entries(grant.packages ?? {})) {
        if (!packageGrant.itemStates?.includes('pending')) continue;
        const itemPackage = this.state.getItemPackage?.(packageId);
        if (!itemPackage || itemPackage.revision !== packageGrant.revision) {
          await this.state.skipStarterPackage?.(eosId, packageId, packageGrant.revision);
          this.logger?.warn?.('Starter package changed before delivery and was not sent automatically', {
            event: 'starter_package.revision_changed', component: 'bridge', server: server.id,
            packageId, outcome: 'skipped', reasonCode: 'package_changed',
          });
          continue;
        }
        for (let index = 0; index < itemPackage.items.length; index += 1) {
          if (packageGrant.itemStates[index] !== 'pending') continue;
          if (this.logger?.healthy === false || this.logger?.audit?.('starter_package.item_started', {
            component: 'bridge', server: server.id, packageId, packageRevision: itemPackage.revision,
            itemIndex: index, outcome: 'started',
          }) === false) return;
          const claimed = await this.state.claimStarterPackageItem?.(eosId, packageId, itemPackage.revision, index);
          if (!claimed) continue;
          try {
            await this.sendPackageItem(server, playerDataId, itemPackage.items[index]);
            await this.state.completeStarterPackageItem?.(eosId, packageId, itemPackage.revision, index);
            this.logger?.audit?.('starter_package.item_succeeded', {
              component: 'bridge', server: server.id, packageId, packageRevision: itemPackage.revision,
              itemIndex: index, outcome: 'succeeded',
            });
            this.metrics.increment('starter_package_items_total', { server: server.id, result: 'succeeded' });
          } catch (error) {
            // The RCON response can be lost after the server applies a grant.
            // The durable pre-send claim intentionally prevents an automatic retry.
            this.metrics.increment('starter_package_items_total', { server: server.id, result: 'uncertain' });
            this.logger?.warn?.('Automatic starter package item outcome is uncertain', {
              event: 'starter_package.item_uncertain', component: 'bridge', server: server.id,
              packageId, outcome: 'uncertain', reasonCode: error?.code ?? error?.name ?? 'grant_failed',
            });
            this.logger?.audit?.('starter_package.item_uncertain', {
              component: 'bridge', server: server.id, packageId, packageRevision: itemPackage.revision,
              itemIndex: index, outcome: 'uncertain', reasonCode: error?.code ?? error?.name ?? 'grant_failed',
            });
            break;
          }
        }
      }
    })();
    this.pendingStarterDeliveries.set(key, operation);
    return operation.finally(() => { if (this.pendingStarterDeliveries.get(key) === operation) this.pendingStarterDeliveries.delete(key); });
  }

  async handlePlayerLeave(server, player) {
    const key = this.sessionKey(server, player); const session = this.sessionStarts.get(key);
    if (session) {
      this.sessionStarts.delete(key);
      if (session.eosId) await this.state.recordPlaytimeSession?.(session.eosId, (this.now() - session.startedAt) / 1_000, session.displayName);
    }
    if (/^[a-f0-9]{32}$/i.test(String(player.id ?? '').trim())) {
      const profileKey = this.profileKey(server, player);
      this.profileValidatedAt.delete(profileKey); this.profileFailuresAt.delete(profileKey); this.profileFailureDetails.delete(profileKey);
    }
    await this.handlePlayerPresence(server, player, 'left');
  }

  async handleServerConnectionChange(server, connected, error) {
    this.logger?.audit?.('server.connection_changed', {
      component: 'bridge', server: server.id, outcome: connected ? 'recovered' : 'unavailable',
      reasonCode: error?.code ?? (connected ? 'connected' : 'connection_failed'),
    });
    if (!this.config.operations.serverStatusAlerts) return;
    this.metrics.increment('server_connection_events_total', { server: server.id, state: connected ? 'up' : 'down' });
    if (!this.config.discord.enabled) return;
    const name = sanitizeIdentity(server.name, 32);
    const details = redactText(error?.message ?? 'unreachable', this.redactionSecrets);
    const message = connected ? `SERVER RECOVERED ${name}` : `SERVER DOWN ${name}: ${details}`;
    await this.discord.sendAudit(message);
  }

  isGameAdmin(identity) {
    if (identity.eosId && (this.config.moderation.adminPlayerIds ?? []).includes(identity.eosId)) return true;
    const names = new Set((this.config.moderation.adminPlayerNames ?? []).map(normalizeName));
    return names.has(normalizeName(identity.playerName)) || names.has(normalizeName(identity.characterName));
  }

  async replyToPlayer(server, identity, message, executeOptions) {
    const safeMessage = redactText(message, this.redactionSecrets);
    const content = `${this.config.chat.gamePrefix} ${safeMessage}`;
    const attempts = [
      identity.eosId && typeof server.sendPrivateById === 'function'
        ? { mode: 'EOS ID', send: () => server.sendPrivateById(identity.eosId, content, executeOptions) } : null,
      identity.playerName && typeof server.sendPrivateByName === 'function'
        ? { mode: 'player name', send: () => server.sendPrivateByName(identity.playerName, content, executeOptions) } : null,
    ].filter(Boolean);
    for (const attempt of attempts) {
      try { return await attempt.send(); }
      catch (error) { this.logger?.debug?.('Private chat response failed', { server: server.id, mode: attempt.mode, error: error.message }); }
    }
    // Never expose link details, EOS IDs, or moderation reasons globally when
    // a host does not support either ASA private-chat command.
    const character = sanitizeIdentity(identity.characterName || identity.playerName, 32);
    this.logger?.debug?.('Private chat unavailable; using privacy-safe server notice', { server: server.id });
    return server.sendChat(`${this.config.chat.gamePrefix} ${character}: Private Cluster Chat response unavailable.`, executeOptions);
  }

  async notifyOnce(server, identity, key, message) {
    const identityKey = identity.eosId || normalizeName(identity.playerName);
    if (this.noticeDedupe.seen(`${server.id}:${identityKey}:${key}`)) return;
    await this.replyToPlayer(server, identity, message);
  }

  async handleGameChat(server, event) {
    if (!event || event.kind !== 'chat') return;
    if (!this.config.chat.relayChannels.includes(event.channel)) return;
    if (event.text.startsWith(this.config.chat.gamePrefix)) return;
    const identity = this.resolveGameIdentity(server, event);
    const command = parseGameCommand(event.text, this.config.chat.commandPrefix);
    if (command) { await this.handleGameCommand(server, identity, command); return; }

    const duplicate = fingerprint(['game', server.id, event.channel, identity.playerName, identity.characterName, event.text]);
    if (this.gameDedupe.seen(duplicate)) {
      this.metrics.increment('messages_dropped_total', { source: 'game', reason: 'duplicate' }); return;
    }
    const mute = this.state.getMute(this.state.gameMuteKeys(identity));
    if (mute) {
      this.metrics.increment('messages_dropped_total', { source: 'game', reason: 'muted' });
      await this.notifyOnce(server, identity, 'muted', `Cluster Chat muted for ${formatDuration(mute.until - this.now())}. ${mute.reason}`.trim()); return;
    }
    const rate = this.rateLimiter.consume(`game:${identity.eosId || normalizeName(identity.playerName)}`);
    if (!rate.allowed) {
      this.metrics.increment('messages_dropped_total', { source: 'game', reason: 'rate_limit' });
      await this.notifyOnce(server, identity, 'rate', `Slow down; retry in ${Math.ceil(rate.retryAfterMs / 1_000)}s.`); return;
    }
    const inspection = this.filter.inspect(event.text);
    if (!inspection.allowed) {
      this.metrics.increment('messages_dropped_total', { source: 'game', reason: inspection.reason });
      await this.notifyOnce(server, identity, 'filter', 'That message was blocked by the Cluster Chat filter.');
      await this.audit(`FILTER game/${server.id} ${identity.playerName} (${identity.characterName}): ${inspection.reason}`); return;
    }

    const safeEventText = redactText(event.text, this.redactionSecrets);
    const character = sanitizeIdentity(identity.characterName);
    const gameHeader = this.config.chat.includeServerName
      ? `${this.config.chat.gamePrefix}[${sanitizeIdentity(server.name, 32)}] ${character}: `
      : `${this.config.chat.gamePrefix} ${character}: `;
    const discordHeader = this.config.chat.includeServerName
      ? `**[${escapeDiscordMarkdown(sanitizeIdentity(server.name, 32))}] ${escapeDiscordMarkdown(character)}**: `
      : `**${escapeDiscordMarkdown(character)}**: `;
    const gameResult = await this.relayGameText(gameHeader, toGameEmoji(safeEventText, this.config.chat.emojiMode), this.servers.filter((item) => item.id !== server.id));
    let discordDelivered = false;
    if (this.config.discord.enabled) {
      try {
        await this.discord.sendChat(sanitizeForDiscord(`${discordHeader}${toDiscordEmoji(safeEventText)}`, 20_000));
        discordDelivered = true;
      } catch (error) {
        this.logger?.warn?.('Discord chat relay failed', { error: error.message });
        this.metrics.increment('relay_failures_total', { destination: 'discord' });
      }
    }
    this.metrics.increment('messages_relayed_total', { source: 'game' });
    await this.state.addHistory({
      source: 'game', sourceServerId: server.id, playerName: identity.playerName,
      characterName: identity.characterName, text: safeEventText,
      deliveredServers: gameResult.delivered, deliveredServerIds: gameResult.deliveredServerIds,
      deliveryCount: gameResult.deliveries, discord: discordDelivered,
    });
  }

  async handleGameCommand(server, identity, parsed) {
    const { command, args } = parsed;
    if (command === 'help') return this.replyToPlayer(server, identity, 'Commands: help, online, link CODE, whoami. Admins: announce, mute, unmute, kick, ban.');
    if (command === 'online') {
      const summary = this.servers.map((item) => `${item.name}:${item.players.length}`).join(' | ');
      return this.replyToPlayer(server, identity, `Online ${this.servers.reduce((sum, item) => sum + item.players.length, 0)} | ${summary}`);
    }
    if (command === 'link') {
      if (!args[0]) return this.replyToPlayer(server, identity, `Use /asa link in Discord, then ${this.config.chat.commandPrefix} link CODE here.`);
      const result = await this.state.consumeLinkCode(args[0], identity);
      const messages = { invalid: 'That link code is invalid.', expired: 'That link code expired; create another with /asa link.' };
      await this.replyToPlayer(server, identity, result.ok ? `Linked to Discord user ${result.link.discordDisplayName}.` : messages[result.reason] ?? 'Could not link that account.');
      if (result.ok) await this.audit(`LINK ${identity.playerName}/${identity.characterName} -> Discord ${result.link.discordDisplayName || 'member'}`);
      return;
    }
    if (command === 'whoami') {
      const link = this.state.getLinkByGame(identity);
      return this.replyToPlayer(server, identity, link
        ? `Linked to ${link.discordDisplayName}; account identity is protected.`
        : 'Not linked; account identity is protected.');
    }
    if (!this.isGameAdmin(identity)) {
      this.logger?.security?.('access.authorization_denied', {
        component: 'bridge', surface: 'game', command, server: server.id,
        requiredLevel: PermissionLevel.ADMIN, outcome: 'denied',
      });
      return this.replyToPlayer(server, identity, 'Unknown command or administrator permission required.');
    }
    if (this.logger?.healthy === false) {
      return this.replyToPlayer(server, identity, 'Security audit logging is unavailable; administrator commands are temporarily disabled.');
    }

    const operationId = randomBytes(12).toString('base64url');
    const startedAt = this.now();
    if (this.logger?.audit?.('admin.action_started', {
      component: 'bridge', surface: 'game', operationId, action: command, server: server.id, outcome: 'started',
    }) === false) {
      return this.replyToPlayer(server, identity, 'Security audit logging is unavailable; no administrator command was sent.');
    }

    const actor = `game:${sanitizeIdentity(identity.characterName || identity.playerName, 48)}`;
    const terminalAudit = (outcome, reasonCode = '') => this.logger?.audit?.(
      outcome === 'succeeded' ? 'admin.action_succeeded'
        : outcome === 'uncertain' ? 'admin.action_uncertain' : 'admin.action_failed',
      {
        component: 'bridge', surface: 'game', operationId, action: command, server: server.id, outcome,
        durationMs: Math.max(0, this.now() - startedAt),
        ...(reasonCode ? { reasonCode } : {}),
      },
    );
    let response; let outcome = 'succeeded'; let reasonCode = '';
    try {
      if (command === 'announce') {
        const message = args.join(' ');
        if (!message) {
          response = 'Usage: !cc announce MESSAGE'; outcome = 'failed'; reasonCode = 'invalid_arguments';
        } else {
          await this.broadcastAnnouncement(message, actor); response = 'Announcement sent.';
        }
      } else if (command === 'mute') {
        const query = args.shift();
        if (!query) {
          response = 'Usage: !cc mute "PLAYER" [15m] [reason]'; outcome = 'failed'; reasonCode = 'invalid_arguments';
        } else {
          const duration = parseDurationMinutes(args[0], this.config.moderation.defaultMuteMinutes, this.config.moderation.maxMuteMinutes);
          if (duration == null) {
            response = 'Invalid duration; use values such as 15m, 2h, or 1d.'; outcome = 'failed'; reasonCode = 'invalid_arguments';
          } else {
            if (args[0] && /^\d+(?:m|h|d)?$/i.test(args[0])) args.shift();
            const result = await this.muteGamePlayer(query, duration, args.join(' '), actor, server.id);
            response = result.message;
          }
        }
      } else if (command === 'unmute') {
        const query = args.join(' ');
        if (!query) {
          response = 'Usage: !cc unmute PLAYER'; outcome = 'failed'; reasonCode = 'invalid_arguments';
        } else {
          const result = await this.unmuteGamePlayer(query, actor, server.id); response = result.message;
        }
      } else if (command === 'kick' || command === 'ban') {
        const query = args.join(' ');
        if (!query) {
          response = `Usage: !cc ${command} PLAYER`; outcome = 'failed'; reasonCode = 'invalid_arguments';
        } else {
          const result = await this.runPlayerAction(command, query, server.id, actor, 'in-game command');
          response = result.message;
        }
      } else {
        response = 'Unknown administrator command.'; outcome = 'failed'; reasonCode = 'unknown_command';
      }
    } catch (error) {
      const failureCode = String(error?.code ?? error?.name ?? 'command_failed')
        .replace(/[^a-z0-9_-]/giu, '_').slice(0, 64) || 'command_failed';
      terminalAudit('uncertain', failureCode);
      throw error;
    }
    const auditWritten = terminalAudit(outcome, reasonCode);
    if (auditWritten === false && outcome === 'succeeded') {
      response = `${response} Audit logging became unavailable; verify the action before retrying.`;
    }
    return this.replyToPlayer(server, identity, response);
  }

  async handleDiscordMessage(message) {
    if (!this.config.discord.enabled || message.channel_id !== this.config.discord.chatChannelId) return;
    if (message.guild_id && message.guild_id !== this.config.discord.guildId) return;
    if (message.author?.bot || message.webhook_id || !message.author?.id) return;
    const userId = message.author.id;
    const dedupe = fingerprint(['discord', message.id || `${message.channel_id}:${userId}:${message.content ?? ''}:${message.timestamp ?? ''}`]);
    if (this.discordDedupe.seen(dedupe)) {
      this.metrics.increment('messages_dropped_total', { source: 'discord', reason: 'duplicate' }); return;
    }
    const level = getPermissionLevel(message.member, this.config.discord);
    if (level < PermissionLevel.RELAY) {
      this.metrics.increment('messages_dropped_total', { source: 'discord', reason: 'role' }); return;
    }
    const link = this.state.getLinkByDiscord(userId);
    if (!link && !this.config.discord.allowUnlinkedChat) {
      this.metrics.increment('messages_dropped_total', { source: 'discord', reason: 'unlinked' });
      await this.audit(`UNLINKED Discord relay rejected for ${messageDisplayName(message)}`); return;
    }
    if (this.state.getMute(this.state.discordMuteKeys(userId))) {
      this.metrics.increment('messages_dropped_total', { source: 'discord', reason: 'muted' }); return;
    }
    const rawText = `${message.content ?? ''}${attachmentSuffix(message)}`.trim();
    if (!rawText) return;
    const rate = this.rateLimiter.consume(`discord:${userId}`);
    if (!rate.allowed) { this.metrics.increment('messages_dropped_total', { source: 'discord', reason: 'rate_limit' }); return; }
    const inspection = this.filter.inspect(rawText);
    if (!inspection.allowed) {
      this.metrics.increment('messages_dropped_total', { source: 'discord', reason: inspection.reason });
      await this.audit(`FILTER discord/${messageDisplayName(message)}: ${inspection.reason}`); return;
    }
    const relayText = redactText(rawText, this.redactionSecrets);
    const display = sanitizeIdentity(link?.characterName || messageDisplayName(message));
    const result = await this.relayGameText(
      `${this.config.chat.gamePrefix}${this.config.chat.discordPrefix} ${display}: `,
      toGameEmoji(relayText, this.config.chat.emojiMode), this.servers,
    );
    this.metrics.increment('messages_relayed_total', { source: 'discord' });
    await this.state.addHistory({
      source: 'discord', displayName: display, text: relayText,
      deliveredServers: result.delivered, deliveredServerIds: result.deliveredServerIds, deliveryCount: result.deliveries,
    });
  }

  async relayGameText(header, text, servers) {
    const max = this.config.chat.gameMaxLength;
    let safeHeader = truncateCodePoints(sanitizeForGame(redactText(header, this.redactionSecrets), max - 1), max - 1, '');
    if (/\s$/u.test(String(header ?? '')) && Array.from(safeHeader).length < max) safeHeader += ' ';
    const safeBody = sanitizeForGame(redactText(text, this.redactionSecrets), 20_000);
    if (!safeBody) return { delivered: 0, deliveredServerIds: [], deliveries: 0, failed: 0, chunks: 0 };
    const chunks = chunkText(safeHeader, safeBody, max);
    let deliveries = 0; let failed = 0;
    const completeByServer = new Map(servers.map((server) => [server.id, true]));
    for (const chunk of chunks) {
      const results = await Promise.allSettled(servers.map((server) => server.sendChat(chunk)));
      results.forEach((result, index) => {
        if (result.status === 'fulfilled') deliveries += 1;
        else { failed += 1; completeByServer.set(servers[index].id, false); }
      });
    }
    const deliveredServerIds = [...completeByServer].filter(([, complete]) => complete).map(([id]) => id);
    this.metrics.increment('relay_deliveries_total', { destination: 'game' }, deliveries);
    if (failed) this.metrics.increment('relay_failures_total', { destination: 'game' }, failed);
    return { delivered: deliveredServerIds.length, deliveredServerIds, deliveries, failed, chunks: chunks.length };
  }

  async handleInteraction(interaction) {
    if (![2, 4].includes(interaction.type) || !['asa', ...STAFF_COMMAND_ROOTS].includes(interaction.data?.name)) return;
    // Command registration disables DMs; enforce the configured guild again
    // at the handler boundary instead of trusting client-supplied context.
    if (interaction.guild_id !== this.config.discord.guildId) return;
    if (interaction.type === 4) {
      await this.handleAutocomplete(interaction);
      return;
    }
    if (interaction.id && this.interactionDedupe.seen(`interaction:${interaction.id}`)) {
      this.metrics.increment('messages_dropped_total', { source: 'discord-interaction', reason: 'duplicate' });
      return;
    }
    await this.discord.deferInteraction(interaction, { ephemeral: true });
    const staffCommand = STAFF_COMMAND_ROOTS.has(interaction.data?.name);
    const commandName = String(interaction.data?.options?.[0]?.name ?? 'status').slice(0, 64);
    const operationId = randomBytes(12).toString('base64url');
    const auditReady = !staffCommand || this.logger?.audit?.('admin.action_started', {
      component: 'bridge', surface: 'discord', operationId, action: commandName, outcome: 'started',
    }) !== false;
    let response;
    if (!auditReady) {
      await this.discord.editInteraction(interaction, 'Security audit logging is unavailable; no privileged command was sent.');
      return;
    }
    try {
      response = await this.executeInteraction(interaction);
      if (staffCommand) this.logger?.audit?.('admin.action_succeeded', {
        component: 'bridge', surface: 'discord', operationId, action: commandName, outcome: 'succeeded',
      });
    }
    catch (error) {
      if (staffCommand) this.logger?.audit?.('admin.action_failed', {
        component: 'bridge', surface: 'discord', operationId, action: commandName,
        outcome: 'failed', reasonCode: error?.code ?? error?.name ?? 'command_failed',
      });
      this.logger?.warn?.('Discord command failed', {
        event: 'discord.command_failed', component: 'discord', command: commandName,
        outcome: 'failed', reasonCode: error?.code ?? error?.name ?? 'command_failed',
      });
      response = `Command failed: ${error.message}`;
    }
    await this.discord.editInteraction(interaction, sanitizeForDiscord(response, 1_900));
  }

  async handleAutocomplete(interaction) {
    let choices = [];
    try { choices = this.autocompleteChoices(interaction); }
    catch (error) {
      this.logger?.warn?.('Discord autocomplete failed', { command: interaction.data?.options?.[0]?.name, error: error.message });
    }
    await this.discord.autocompleteInteraction(interaction, choices);
  }

  autocompleteChoices(interaction) {
    const subcommand = interaction.data?.options?.[0]; const command = subcommand?.name;
    const focused = focusedOption(subcommand); if (!command || !focused) return [];
    const level = getPermissionLevel(interaction.member, this.config.discord);
    const root = interaction.data?.name;
    if (STAFF_COMMAND_ROOTS.has(root)) {
      if (root === 'asa-ops' && !OPS_COMMANDS.has(command)) return [];
      const required = ADMIN_AUTOCOMPLETE_COMMANDS.has(command) ? PermissionLevel.ADMIN : PermissionLevel.MODERATOR;
      if (level < required) return [];
    } else if (command !== 'players' || level < PermissionLevel.RELAY) return [];

    const query = String(focused.value ?? '');
    if (focused.name === 'server') return this.serverChoices(query);
    if (focused.name === 'player') return this.playerChoices(query, command, interactionUser(interaction).id);
    if (focused.name === 'item' && ['give-item', 'favorite-item', 'unfavorite-item', 'save-item-preset'].includes(command)) {
      return this.itemChoices(interaction, query, command);
    }
    if (focused.name === 'preset' && ['delete-item-preset', 'give-item-preset'].includes(command)) {
      return this.itemPresetChoices(interaction, query);
    }
    if (focused.name === 'template' && command === 'announce-template') {
      return Object.keys(this.config.moderation.announcementTemplates ?? {})
        .map((name) => ({ name, value: name, score: choiceScore(name, query) }))
        .filter((choice) => Number.isFinite(choice.score))
        .sort((a, b) => a.score - b.score || a.name.localeCompare(b.name))
        .slice(0, 25)
        .map(({ name, value }) => ({ name, value }));
    }
    return [];
  }

  catalogItemChoice(item) {
    const details = [item.key.slice(-8), item.gfi ? `GFI ${sanitizeIdentity(item.gfi, 24)}` : null,
      item.itemNumber == null ? null : `#${item.itemNumber}`].filter(Boolean).join(' | ');
    return {
      // Bound the name before the unique key suffix so truncation can never
      // make two otherwise-identical choices look the same.
      name: `${truncateCodePoints(item.name, 55, '...')} [${details}] - ${sanitizeIdentity(item.category, 18)}`,
      value: item.key,
    };
  }

  itemChoices(interaction, query, command) {
    const userId = interactionUser(interaction).id;
    const favoriteItems = (this.state.listItemFavorites?.(userId) ?? []).map(getItem).filter(Boolean);
    if (command === 'unfavorite-item') {
      if (!String(query).trim()) return favoriteItems.slice(0, 25).map((item) => this.catalogItemChoice(item));
      const matches = new Set(searchItems(query, 25).map((item) => item.key));
      return favoriteItems.filter((item) => matches.has(item.key)).slice(0, 25).map((item) => this.catalogItemChoice(item));
    }
    const base = searchItems(query, 25);
    if (String(query).trim()) return base.map((item) => this.catalogItemChoice(item));
    const recentItems = (this.state.listRecentItems?.(userId) ?? []).map(getItem).filter(Boolean);
    const ordered = []; const seen = new Set();
    for (const item of [...favoriteItems, ...recentItems, ...base]) {
      if (seen.has(item.key)) continue;
      seen.add(item.key); ordered.push(item);
      if (ordered.length === 25) break;
    }
    return ordered.map((item) => this.catalogItemChoice(item));
  }

  itemPresetChoices(interaction, query) {
    return (this.state.listItemPresets?.(interactionUser(interaction).id) ?? [])
      .map((preset) => {
        const item = getItem(preset.itemKey);
        const label = `${preset.name} - ${item?.name ?? 'catalog item unavailable'} x${preset.quantity}${preset.blueprint ? ' blueprint' : ''}`;
        return { name: truncateCodePoints(label, 100, '...'), value: preset.name, score: choiceScore(label, query) };
      })
      .filter((choice) => Number.isFinite(choice.score))
      .sort((a, b) => a.score - b.score || a.name.localeCompare(b.name))
      .slice(0, 25)
      .map(({ name, value }) => ({ name, value }));
  }

  serverChoices(query) {
    return this.servers
      .map((server) => ({ name: `${server.name} (${server.id})`, value: server.id, score: choiceScore(`${server.name} ${server.id}`, query) }))
      .filter((choice) => Number.isFinite(choice.score))
      .sort((a, b) => a.score - b.score || a.name.localeCompare(b.name))
      .slice(0, 25)
      .map(({ name, value }) => ({ name, value }));
  }

  playerChoiceTargetKey(discordUserId, server, player, scope = '') {
    return `${discordUserId}\u001f${scope}\u001f${server.id}\u001f${String(player.id ?? '').toLocaleLowerCase('en-US')}`;
  }

  deletePlayerChoiceToken(token) {
    const record = this.playerChoiceTokens.get(token);
    if (!record) return;
    this.playerChoiceTokens.delete(token);
    if (this.playerChoiceTokensByTarget.get(record.targetKey) === token) this.playerChoiceTokensByTarget.delete(record.targetKey);
  }

  prunePlayerChoiceTokens(now = this.now()) {
    for (const [token, record] of this.playerChoiceTokens) {
      if (record.expiresAt <= now) this.deletePlayerChoiceToken(token);
    }
    while (this.playerChoiceTokens.size >= PLAYER_CHOICE_MAX_ENTRIES) {
      const oldest = this.playerChoiceTokens.keys().next().value;
      if (!oldest) break;
      this.deletePlayerChoiceToken(oldest);
    }
  }

  playerChoiceToken(server, player, discordUserId, scope = '') {
    const userId = String(discordUserId ?? '').trim();
    const eosId = String(player?.id ?? '').trim();
    if (!userId || !server?.id || !eosId) throw new Error('A Discord user and connected player are required for a secure player selection.');
    const now = this.now(); this.prunePlayerChoiceTokens(now);
    const safeScope = String(scope ?? '').trim();
    const targetKey = this.playerChoiceTargetKey(userId, server, player, safeScope);
    const currentToken = this.playerChoiceTokensByTarget.get(targetKey);
    const current = currentToken ? this.playerChoiceTokens.get(currentToken) : null;
    if (current && current.expiresAt > now) return currentToken;
    if (currentToken) this.deletePlayerChoiceToken(currentToken);

    let token = '';
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const opaque = Buffer.from(this.randomBytesFn(18)).toString('base64url');
      const candidate = `${PLAYER_CHOICE_PREFIX}${opaque}`;
      if (/^p2:[A-Za-z0-9_-]{24}$/.test(candidate) && !this.playerChoiceTokens.has(candidate)) { token = candidate; break; }
    }
    if (!token) throw new Error('Could not create a secure player selection; retry autocomplete.');
    this.playerChoiceTokens.set(token, {
      targetKey, discordUserId: userId, scope: safeScope, serverId: server.id, eosId, expiresAt: now + PLAYER_CHOICE_TTL_MS,
    });
    this.playerChoiceTokensByTarget.set(targetKey, token);
    return token;
  }

  resolvePlayerChoice(value, discordUserId) {
    const token = String(value ?? '').trim();
    if (!token.startsWith(PLAYER_CHOICE_PREFIX) && !token.startsWith(LEGACY_PLAYER_CHOICE_PREFIX)) return null;
    const invalid = () => { throw new Error('That player selection is invalid or expired; choose the player again.'); };
    if (!/^p2:[A-Za-z0-9_-]{24}$/.test(token)) return invalid();
    const record = this.playerChoiceTokens.get(token);
    if (!record) return invalid();
    const now = this.now();
    if (record.expiresAt <= now) { this.deletePlayerChoiceToken(token); return invalid(); }
    if (!discordUserId || record.discordUserId !== String(discordUserId)) return invalid();

    // A valid owner resolution consumes the token. Discord retries are already
    // deduplicated by interaction ID, and one-time handles limit replay if a
    // command payload is copied from logs or client diagnostics.
    this.deletePlayerChoiceToken(token);
    const server = this.serverMap.get(record.serverId);
    if (!server) return invalid();
    const players = (server.players ?? []).filter((player) => String(player.id ?? '') === record.eosId);
    if (players.length !== 1) throw new Error('That player is no longer connected; choose the player again.');
    return { server, player: players[0] };
  }

  assertPlayerChoiceScope(value, principalId, scope) {
    const token = String(value ?? '').trim();
    if (!token.startsWith(PLAYER_CHOICE_PREFIX)) return;
    const record = this.playerChoiceTokens.get(token);
    if (!record || record.discordUserId !== String(principalId ?? '') || (record.scope && record.scope !== scope)) {
      throw new Error('That player selection is invalid or expired; choose the player again.');
    }
  }

  playerChoices(query, command, discordUserId) {
    const grants = command === 'give-item' || command === 'give-package' || command === 'give-xp' || command === 'give-item-preset';
    const choices = [];
    for (const server of this.servers) for (const player of server.players ?? []) {
      const mapping = this.profileMapping(server, player); const mapped = mapping?.playerDataId;
      const source = this.profileSource(server); const key = this.profileKey(server, player); const now = this.now();
      const failedAt = this.profileFailuresAt.get(key);
      const failed = source && (this.activeProfileSourceFailure(server, source, now)
        || (failedAt != null && now - failedAt < (source.config?.retryIntervalMs ?? 60_000)));
      const validatedAt = this.profileValidatedAt.get(key);
      const verified = source && validatedAt != null && now - validatedAt < (source.config?.revalidateIntervalMs ?? 300_000);
      const eligible = /^[a-f0-9]{32}$/i.test(String(player.id ?? '').trim());
      let status = '';
      if (grants) {
        if (source && !eligible) status = ' - EOS unavailable';
        else if (source && failed) status = mapped ? ' - cached ID; recheck failed' : ' - ID lookup unavailable';
        else if (source && mapped && verified) status = ' - ready';
        else if (source && mapped) status = ' - ID verification pending';
        else if (source) status = ' - ID lookup pending';
        else status = mapped ? ' - ready' : ' - numeric ID needed';
      }
      const accountName = sanitizeIdentity(player.name, 96);
      const survivorName = mapping?.characterName ? sanitizeIdentity(mapping.characterName, 96) : '';
      const displayName = survivorName && normalizeName(survivorName) !== normalizeName(accountName)
        ? `${survivorName} / ${accountName}` : accountName;
      const score = choiceScore(`${displayName} ${player.id} ${server.name} ${server.id}`, query);
      if (!Number.isFinite(score)) continue;
      const value = this.playerChoiceToken(server, player, discordUserId, command);
      // Keep every visible choice distinguishable without exposing an account
      // ID. The component bounds keep the server ID, opaque discriminator, and
      // grant-readiness suffix inside Discord's 100-code-point name limit.
      const suffix = ` - ${sanitizeIdentity(server.name, 10)} (${server.id}) #${value.slice(-8)}${status}`;
      const playerLimit = Math.max(1, 100 - Array.from(suffix).length);
      const name = `${truncateCodePoints(displayName, playerLimit, '...')}${suffix}`;
      choices.push({ name, value, score, server: server.id, player: player.name });
    }
    return choices
      .sort((a, b) => a.score - b.score || a.player.localeCompare(b.player) || a.server.localeCompare(b.server))
      .slice(0, 25)
      .map(({ name, value }) => ({ name, value }));
  }

  /**
   * Build the richer, still identifier-free player projection used by the
   * authenticated web console. The opaque selection is principal-bound,
   * short-lived, and one-time; stable EOS and PlayerData identifiers never
   * cross the HTTP boundary.
   */
  adminPlayerChoices(query, principalId, { purpose = 'player', limit = 100 } = {}) {
    const userId = String(principalId ?? '').trim();
    if (!userId) throw new Error('An authenticated principal is required for player selections.');
    const maximum = Math.min(100, Math.max(1, Number.isSafeInteger(limit) ? limit : 100));
    const grants = ['give-item', 'give-package', 'give-xp', 'give-item-preset'].includes(String(purpose));
    const choices = [];
    for (const server of this.servers) for (const player of server.players ?? []) {
      const mapping = this.profileMapping(server, player); const source = this.profileSource(server);
      const key = this.profileKey(server, player); const now = this.now();
      const failedAt = this.profileFailuresAt.get(key);
      const failed = source && (this.activeProfileSourceFailure(server, source, now)
        || (failedAt != null && now - failedAt < (source.config?.retryIntervalMs ?? 60_000)));
      const validatedAt = this.profileValidatedAt.get(key);
      const verified = source && validatedAt != null && now - validatedAt < (source.config?.revalidateIntervalMs ?? 300_000);
      const eligible = /^[a-f0-9]{32}$/i.test(String(player.id ?? '').trim());
      let targeting = 'not-required';
      if (grants) {
        if (source && !eligible) targeting = 'eos-unavailable';
        else if (source && failed) targeting = mapping ? 'recheck-failed' : 'lookup-unavailable';
        else if (source && mapping && verified) targeting = 'ready';
        else if (source) targeting = mapping ? 'verifying' : 'lookup-pending';
        else targeting = mapping ? 'ready' : 'id-needed';
      }
      const accountName = sanitizeIdentity(player.name, 96);
      const survivorName = mapping?.characterName ? sanitizeIdentity(mapping.characterName, 96) : '';
      const displayName = survivorName && normalizeName(survivorName) !== normalizeName(accountName)
        ? `${survivorName} / ${accountName}` : accountName;
      const searchable = `${displayName} ${server.name} ${server.id}`;
      const tokens = normalizeName(query).split(/\s+/u).filter(Boolean);
      if (!tokens.every((token) => normalizeName(searchable).includes(token))) continue;
      const score = tokens.length ? choiceScore(searchable, query) : 3;
      const identity = { eosId: player.id, playerName: player.name, characterName: mapping?.characterName };
      const mute = this.state.getMute(this.state.gameMuteKeys(identity));
      const playtime = this.state.getPlaytime?.(player.id);
      choices.push({
        selection: this.playerChoiceToken(server, player, userId, String(purpose)),
        name: accountName,
        survivorName: survivorName && normalizeName(survivorName) !== normalizeName(accountName) ? survivorName : '',
        serverId: server.id,
        serverName: sanitizeIdentity(server.name, 64),
        targeting,
        linked: Boolean(this.state.getLinkByGame(identity)),
        mutedUntil: mute?.until ?? null,
        playtimeSeconds: Number.isFinite(playtime?.totalSeconds) ? Math.max(0, playtime.totalSeconds) : 0,
        notesCount: this.state.listModerationNotes?.(player.id)?.length ?? 0,
        score: Number.isFinite(score) ? score : 2,
      });
    }
    return choices
      .sort((a, b) => a.score - b.score || a.name.localeCompare(b.name) || a.serverId.localeCompare(b.serverId))
      .slice(0, maximum)
      .map(({ score: _score, ...choice }) => choice);
  }

  /**
   * Resolve a purpose-bound web player handle into a structured staff record.
   * The handle is deliberately not consumed so an administrator can use that
   * same session-bound selection for the separately authorized identifier
   * disclosure. Stable player identifiers never leave this method.
   */
  async adminPlayerStaffRecord(value, principalId, { purpose = 'player', noteLimit = 10 } = {}) {
    const invalid = (message = 'That player selection is invalid or expired; refresh the player list and try again.', code = 'PLAYER_SELECTION_INVALID') => {
      const error = new Error(message); error.code = code; throw error;
    };
    const token = String(value ?? '').trim();
    if (!/^p2:[A-Za-z0-9_-]{24}$/.test(token)) return invalid();
    const record = this.playerChoiceTokens.get(token); const initialNow = this.now();
    if (!record || record.expiresAt <= initialNow) {
      if (record) this.deletePlayerChoiceToken(token);
      return invalid();
    }
    if (!principalId || record.discordUserId !== String(principalId) || record.scope !== String(purpose)) return invalid();
    const server = this.serverMap.get(record.serverId);
    if (!server || typeof server.refreshPlayers !== 'function') return invalid();

    let connectedPlayers;
    try { connectedPlayers = await server.refreshPlayers(); }
    catch {
      return invalid('Connected-player status could not be refreshed. Try again shortly.', 'PLAYER_STATUS_UNAVAILABLE');
    }
    const now = this.now(); const currentRecord = this.playerChoiceTokens.get(token);
    if (currentRecord !== record || record.expiresAt <= now || record.discordUserId !== String(principalId)
      || record.scope !== String(purpose)) {
      if (currentRecord === record && record.expiresAt <= now) this.deletePlayerChoiceToken(token);
      return invalid();
    }
    const matches = (connectedPlayers ?? []).filter((player) => String(player.id ?? '') === record.eosId);
    if (matches.length !== 1) {
      return invalid('That player is no longer connected; refresh the player list and try again.');
    }

    const player = matches[0]; const mapping = this.profileMapping(server, player);
    const source = this.profileSource(server); const key = this.profileKey(server, player);
    const validatedAt = this.profileValidatedAt.get(key);
    const verified = Boolean(source && validatedAt != null
      && now - validatedAt < (source.config?.revalidateIntervalMs ?? 300_000));
    const failed = Boolean(source && (this.activeProfileSourceFailure(server, source, now)
      || this.profileFailureDetails.has(key)));
    const targeting = mapping
      ? (source ? (verified ? 'ready (profile verified)' : failed ? 'cached; profile recheck failed' : 'cached; verification pending') : 'ready (manual mapping)')
      : (source ? (failed ? 'profile lookup unavailable' : 'profile lookup pending') : 'numeric ID needed');
    const staffRedactionSecrets = [
      ...this.redactionSecrets,
      String(player.id ?? '').trim(),
      String(mapping?.playerDataId ?? '').trim(),
    ].filter(Boolean);
    const survivorName = mapping?.characterName
      ? sanitizeIdentity(redactText(mapping.characterName, staffRedactionSecrets), 96) : '';
    const name = sanitizeIdentity(redactText(player.name, staffRedactionSecrets), 96);
    const identity = { eosId: player.id, playerName: player.name, characterName: mapping?.characterName };
    const link = this.state.getLinkByGame(identity);
    const discordDisplayName = link?.discordDisplayName
      ? sanitizeIdentity(redactText(link.discordDisplayName, staffRedactionSecrets), 96) : '';
    const mute = this.state.getMute(this.state.gameMuteKeys(identity));
    const playtime = this.state.getPlaytime?.(player.id);
    const requestedNoteLimit = Math.min(10, Math.max(1, Number.isSafeInteger(noteLimit) ? noteLimit : 10));
    const storedNotes = typeof this.state.listModerationNotesWithIds === 'function'
      ? this.state.listModerationNotesWithIds(player.id, 100)
      : this.state.listModerationNotes?.(player.id, 100);
    const availableNotes = Array.isArray(storedNotes) ? storedNotes.slice(0, 100) : [];
    const notes = availableNotes.slice(0, requestedNoteLimit).map((note = {}) => ({
      id: typeof note.id === 'string' ? note.id : '',
      type: typeof note.type === 'string' ? note.type : 'note',
      text: sanitizeForGame(redactText(note.text, staffRedactionSecrets), 1_000),
      at: Number.isFinite(note.at) && note.at >= 0 ? note.at : null,
      actor: sanitizeIdentity(redactText(note.actor, staffRedactionSecrets), 96),
    }));
    return Object.freeze({
      name,
      survivorName: survivorName && normalizeName(survivorName) !== normalizeName(name) ? survivorName : '',
      serverId: sanitizeIdentity(server.id, 32),
      serverName: sanitizeIdentity(server.name, 64),
      targeting,
      linked: Boolean(link),
      discordDisplayName,
      mutedUntil: Number.isFinite(mute?.until) && mute.until > now ? mute.until : null,
      playtimeSeconds: Number.isFinite(playtime?.totalSeconds) ? Math.max(0, playtime.totalSeconds) : 0,
      notesCount: availableNotes.length,
      notes,
    });
  }

  async adminDeleteModerationNote(value, principalId, noteId, { purpose = 'player' } = {}) {
    const token = String(value ?? '').trim(); const principal = String(principalId ?? '').trim();
    const record = this.playerChoiceTokens.get(token); const now = this.now();
    if (!/^p2:[A-Za-z0-9_-]{24}$/.test(token) || !record || record.expiresAt <= now
      || !principal || record.discordUserId !== principal || record.scope !== String(purpose)) {
      if (record?.expiresAt <= now) this.deletePlayerChoiceToken(token);
      const error = new Error('That player selection is invalid or expired; refresh the player list and try again.');
      error.code = 'PLAYER_SELECTION_INVALID'; throw error;
    }
    if (typeof this.state.removeModerationNote !== 'function') {
      const error = new Error('Moderation note deletion is unavailable.'); error.code = 'NOTE_DELETE_UNAVAILABLE'; throw error;
    }
    return this.state.removeModerationNote(record.eosId, noteId);
  }

  /**
   * Resolve a web-console player handle for a deliberately separate,
   * administrator-authorized identifier disclosure response. This method
   * never logs identifiers and never adds them to the ordinary player
   * projection. The caller remains responsible for authorization and for
   * recording the disclosure before returning these values.
   */
  adminPlayerIdentifiers(value, principalId, { purpose = 'player' } = {}) {
    const invalid = () => { throw new Error('That player selection is invalid or expired; refresh the player list and try again.'); };
    const token = String(value ?? '').trim();
    if (!/^p2:[A-Za-z0-9_-]{24}$/.test(token)) return invalid();
    const record = this.playerChoiceTokens.get(token);
    const now = this.now();
    if (!record || record.expiresAt <= now) {
      if (record) this.deletePlayerChoiceToken(token);
      return invalid();
    }
    if (!principalId || record.discordUserId !== String(principalId) || record.scope !== String(purpose)) return invalid();
    const server = this.serverMap.get(record.serverId);
    if (!server) return invalid();
    const players = (server.players ?? []).filter((player) => String(player.id ?? '') === record.eosId);
    if (players.length !== 1) throw new Error('That player is no longer connected; refresh the player list and try again.');
    const player = players[0];
    const eosProductUserId = String(player.id ?? '').trim().toLocaleLowerCase('en-US');
    if (!/^[a-f0-9]{32}$/u.test(eosProductUserId)) {
      throw new Error('An EOS Product User ID is unavailable for this connected player.');
    }
    const mapping = this.profileMapping(server, player);
    const playerDataId = mapping?.playerDataId == null ? null : String(mapping.playerDataId).trim();
    if (playerDataId !== null && (!/^[1-9]\d{0,9}$/u.test(playerDataId) || Number(playerDataId) > 4_294_967_295)) {
      throw new Error('The ASA PlayerDataID is unavailable in a safe format.');
    }
    const accountName = sanitizeIdentity(player.name, 96);
    const survivorName = mapping?.characterName ? sanitizeIdentity(mapping.characterName, 96) : '';
    const result = Object.freeze({
      name: accountName,
      survivorName: survivorName && normalizeName(survivorName) !== normalizeName(accountName) ? survivorName : '',
      serverId: sanitizeIdentity(server.id, 32),
      serverName: sanitizeIdentity(server.name, 64),
      eosProductUserId,
      playerDataId,
    });
    // Identifier disclosure handles are one-use. Other guided actions obtain
    // their own purpose-bound handle from the player endpoint.
    this.deletePlayerChoiceToken(token);
    return result;
  }

  validateMuteMinutes(value) {
    const minutes = Number(value);
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > this.config.moderation.maxMuteMinutes) {
      throw new Error(`Mute duration must be 1-${this.config.moderation.maxMuteMinutes} minutes.`);
    }
    return minutes;
  }

  async executeStaffCommand({ command, options = {}, level = PermissionLevel.NONE, principalId, actor } = {}) {
    const name = String(command ?? '').trim();
    const userId = String(principalId ?? '').trim();
    if (!name || !userId) throw new Error('A staff command and authenticated principal are required.');
    return this.executeInteraction(null, {
      command: name,
      options,
      level,
      principalId: userId,
      actor: sanitizeIdentity(actor || 'staff', 64),
      root: 'asa-admin',
    });
  }

  async executeInteraction(interaction, staffContext = null) {
    const subcommand = staffContext ? null : interaction.data?.options?.[0];
    const command = staffContext?.command ?? subcommand?.name ?? 'status';
    const options = staffContext?.options ?? optionMap(subcommand);
    const level = staffContext?.level ?? getPermissionLevel(interaction.member, this.config.discord);
    const user = staffContext ? { id: staffContext.principalId } : interactionUser(interaction);
    const actor = staffContext?.actor ?? `discord:${interactionDisplayName(interaction)}`;
    const requireLevel = (required) => {
      if (level < required) {
        this.logger?.security?.('access.authorization_denied', {
          component: 'bridge', surface: staffContext ? 'dashboard' : 'discord', command,
          requiredLevel: required, grantedLevel: level, outcome: 'denied',
        });
        throw new Error('You do not have permission to use this command.');
      }
    };

    const root = staffContext?.root ?? interaction.data?.name;
    if (STAFF_COMMAND_ROOTS.has(root)) {
      requireLevel(PermissionLevel.MODERATOR);
      if (this.logger?.healthy === false) throw new Error('Security audit logging is unavailable; privileged commands are temporarily disabled.');
      if (root === 'asa-ops' && !OPS_COMMANDS.has(command)) throw new Error(`Unknown /asa-ops subcommand ${command}.`);
    } else if (!['link', 'unlink', 'players', 'leaderboard'].includes(command)) {
      throw new Error('This command is restricted to /asa-admin or /asa-ops.');
    }
    this.assertPlayerChoiceScope(options.player, user.id, command);

    if (command === 'status') return this.statusText();
    if (command === 'link') {
      if (staffContext) throw new Error('This command is available only through Discord.');
      const code = await this.state.createLinkCode(user.id, interactionDisplayName(interaction));
      return `In ARK global chat, enter: ${this.config.chat.commandPrefix} link ${code}\nThe code expires in 10 minutes.`;
    }
    if (command === 'unlink') {
      const removed = await this.state.unlinkDiscord(user.id); if (removed) await this.audit(`UNLINK by ${actor}`);
      return removed ? 'Your ARK character link was removed.' : 'Your Discord account is not linked.';
    }
    if (command === 'players') { requireLevel(PermissionLevel.RELAY); return this.playersText(options.server); }
    if (command === 'leaderboard') {
      requireLevel(PermissionLevel.RELAY);
      const limit = Math.min(25, Math.max(1, Number.isInteger(Number(options.limit)) ? Number(options.limit) : 10));
      return this.leaderboardText(limit);
    }
    if (command === 'say') {
      if (staffContext) throw new Error('This command is available only through Discord.');
      requireLevel(PermissionLevel.RELAY);
      const link = this.state.getLinkByDiscord(user.id);
      if (!link && !this.config.discord.allowUnlinkedChat) throw new Error('Link your ARK character with /asa link first.');
      const mute = this.state.getMute(this.state.discordMuteKeys(user.id));
      if (mute) throw new Error(`You are relay-muted for ${formatDuration(mute.until - this.now())}.`);
      const rate = this.rateLimiter.consume(`discord:${user.id}`);
      if (!rate.allowed) throw new Error(`Slow down; retry in ${Math.ceil(rate.retryAfterMs / 1_000)}s.`);
      const message = String(options.message ?? '').trim();
      if (!message) throw new Error('Message cannot be empty.');
      const inspection = this.filter.inspect(message); if (!inspection.allowed) throw new Error('That message was blocked by the Cluster Chat filter.');
      const display = sanitizeIdentity(link?.characterName || interactionDisplayName(interaction));
      const result = await this.relayGameText(`${this.config.chat.gamePrefix}${this.config.chat.discordPrefix} ${display}: `, toGameEmoji(message, this.config.chat.emojiMode), this.servers);
      await this.state.addHistory({ source: 'discord-command', displayName: display, text: redactText(message, this.redactionSecrets),
        deliveredServers: result.delivered, deliveredServerIds: result.deliveredServerIds, deliveryCount: result.deliveries });
      return `Relayed to ${result.delivered} server delivery target${result.delivered === 1 ? '' : 's'}.`;
    }
    if (command === 'restart') {
      const minutes = Number(options.minutes);
      if (!Number.isInteger(minutes) || minutes < 1 || minutes > RESTART_MAX_DELAY_MINUTES) {
        throw new Error(`Restart delay must be 1-${RESTART_MAX_DELAY_MINUTES} minutes.`);
      }
      const scheduled = await this.scheduleRestart(minutes, actor, options.server, options.reason ?? '');
      return `Restart window scheduled for ${scheduled} server${scheduled === 1 ? '' : 's'} in ${minutes} minute${minutes === 1 ? '' : 's'}.`;
    }
    if (command === 'cancel-restart') {
      const cancelled = await this.cancelRestart(options.server, actor);
      return cancelled ? `Scheduled restart cancelled for ${cancelled} server${cancelled === 1 ? '' : 's'}.` : 'No scheduled restart matched that server.';
    }
    if (command === 'save-world') {
      requireLevel(PermissionLevel.ADMIN);
      const servers = this.selectedServers(options.server);
      const results = await Promise.allSettled(servers.map((server) => server.saveWorld()));
      const failures = results.filter((result) => result.status === 'rejected').length;
      if (failures) throw new Error(`SaveWorld failed on ${failures} server(s).`);
      await this.audit(`SAVEWORLD by ${actor} target=${options.server ?? 'cluster'}`);
      return `World save sent to ${servers.length} server${servers.length === 1 ? '' : 's'}.`;
    }
    if (command === 'give-item') {
      requireLevel(PermissionLevel.ADMIN);
      return this.executeItemGrant(options, actor, user.id);
    }
    if (command === 'give-package') {
      requireLevel(PermissionLevel.ADMIN);
      return this.executePackageGrant(options, actor, user.id);
    }
    if (command === 'give-item-num') {
      requireLevel(PermissionLevel.ADMIN);
      const server = this.resolveRequiredServer(options.server);
      const playerId = options['player-id']; const itemNumber = options['item-number'];
      const quantity = options.quantity ?? 1; const quality = options.quality ?? 0;
      const forceBlueprint = options.blueprint ?? false;
      await server.giveItemNumToPlayer(playerId, itemNumber, quantity, quality, forceBlueprint);
      await this.audit(`GIVEITEMNUM target=manual item=${itemNumber} on ${server.id} by ${actor} quantity=${quantity} quality=${quality} blueprint=${forceBlueprint}`);
      return `GiveItemNumToPlayer sent to the manually selected player on ${server.name} (item ${itemNumber}, quantity ${quantity}${forceBlueprint ? ', blueprint' : ''}).`;
    }
    if (command === 'remember-player-id') {
      requireLevel(PermissionLevel.ADMIN);
      const match = this.requireSinglePlayer(options.player, options.server, user.id);
      if (typeof this.state.setPlayerDataId !== 'function') throw new Error('This state store cannot save player IDs.');
      await this.state.setPlayerDataId(match.server.id, match.player.id, options['player-data-id'], {
        displayName: match.player.name, actor, replace: options.replace ?? false,
      });
      await this.audit(`PLAYERDATAID saved for ${match.player.name} on ${match.server.id} by ${actor}`);
      return `Saved ${match.player.name}'s numeric PlayerDataID for ${match.server.name}. Future item and XP grants are automatic.`;
    }
    if (command === 'refresh-player-id') {
      requireLevel(PermissionLevel.ADMIN);
      const match = this.requireSinglePlayer(options.player, options.server, user.id);
      if (!this.profileSource(match.server)) throw new Error(`Automatic player ID import is not configured for ${match.server.name}.`);
      let playerDataId;
      try { playerDataId = await this.importPlayerProfile(match.server, match.player, { force: true }); }
      catch (error) {
        const code = error?.sourceCode ?? profileErrorCode(error);
        throw new Error(`PlayerDataID refresh failed on ${match.server.name} (${code}). No RCON command was sent.`);
      }
      if (!playerDataId) throw new Error('The player disconnected before their profile could be verified. Choose them again.');
      const mapping = this.profileMapping(match.server, match.player);
      const survivor = mapping?.characterName && normalizeName(mapping.characterName) !== normalizeName(match.player.name)
        ? `${sanitizeIdentity(mapping.characterName, 48)} / ` : '';
      await this.audit(`PLAYERDATAID REFRESH verified ${match.player.name} on ${match.server.id} by ${actor}`);
      return `Verified ${survivor}${sanitizeIdentity(match.player.name, 48)} on ${sanitizeIdentity(match.server.name, 32)}. The numeric ID was stored privately; no RCON command was sent.`;
    }
    if (command === 'give-xp') {
      requireLevel(PermissionLevel.ADMIN);
      let target = await this.resolveGrantTarget(options, user.id); const amount = options.amount;
      const fromTribe = options['from-tribe'] ?? false; const shareWithTribe = options['share-with-tribe'] ?? false;
      target = await this.confirmGrantTargetOnline(target);
      await target.server.giveExperienceToPlayer(target.playerDataId, amount, fromTribe, shareWithTribe);
      await this.audit(`GIVEXP target=${target.player?.name ?? 'manual'} on ${target.server.id} by ${actor} amount=${amount} fromTribe=${fromTribe} shareWithTribe=${shareWithTribe}`);
      return `Gave ${amount} XP to ${target.player?.name ?? 'the manually selected player'} on ${target.server.name}.`;
    }
    if (command === 'favorite-item') {
      requireLevel(PermissionLevel.ADMIN);
      const item = resolveItemInput(options.item);
      if (!item) throw new Error('Choose one unique item from the built-in catalog.');
      if (typeof this.state.addItemFavorite !== 'function') throw new Error('Item favorites are unavailable in this state store.');
      await this.state.addItemFavorite(user.id, item.key);
      return `${item.name} is now one of your item autocomplete favorites.`;
    }
    if (command === 'unfavorite-item') {
      requireLevel(PermissionLevel.ADMIN);
      const item = resolveItemInput(options.item);
      if (!item) throw new Error('Choose one of your item favorites.');
      const removed = await this.state.removeItemFavorite?.(user.id, item.key);
      return removed ? `${item.name} was removed from your item favorites.` : `${item.name} was not in your item favorites.`;
    }
    if (command === 'save-item-preset') {
      requireLevel(PermissionLevel.ADMIN);
      const item = resolveItemInput(options.item);
      if (!item) throw new Error('Choose one unique item from the built-in catalog.');
      if (typeof this.state.setItemPreset !== 'function') throw new Error('Item presets are unavailable in this state store.');
      const preset = await this.state.setItemPreset(user.id, {
        name: options.name, itemKey: item.key, quantity: options.quantity ?? 1,
        quality: options.quality ?? 0, blueprint: options.blueprint ?? false,
      }, { replace: options.replace ?? false });
      return `Saved item preset ${preset.name}: ${item.name} x${preset.quantity}, quality ${preset.quality}${preset.blueprint ? ', blueprint' : ''}.`;
    }
    if (command === 'delete-item-preset') {
      requireLevel(PermissionLevel.ADMIN);
      const removed = await this.state.removeItemPreset?.(user.id, options.preset);
      return removed ? `Deleted item preset ${sanitizeIdentity(options.preset, 32)}.` : 'That item preset does not exist.';
    }
    if (command === 'give-item-preset') {
      requireLevel(PermissionLevel.ADMIN);
      if (!String(options.player ?? '').startsWith(PLAYER_CHOICE_PREFIX)) {
        throw new Error('Choose a currently connected player from autocomplete for preset grants.');
      }
      const preset = (this.state.listItemPresets?.(user.id) ?? [])
        .find((candidate) => normalizeName(candidate.name) === normalizeName(options.preset));
      if (!preset || !getItem(preset.itemKey)) throw new Error('Choose one of your current item presets.');
      const result = await this.executeItemGrant({
        player: options.player, item: preset.itemKey, quantity: preset.quantity,
        quality: preset.quality, blueprint: preset.blueprint,
      }, actor, user.id);
      return `${preset.name}: ${result}`;
    }
    if (command === 'whitelist' || command === 'unwhitelist') {
      requireLevel(PermissionLevel.ADMIN);
      const target = this.resolveAccountTarget(options.player ?? options['player-id'], options.server, user.id);
      if (command === 'whitelist') await target.server.allowPlayer(target.eosId);
      else await target.server.disallowPlayer(target.eosId);
      await this.audit(`${command === 'whitelist' ? 'WHITELIST' : 'UNWHITELIST'} target=${target.player?.name ?? 'manual'} on ${target.server.id} by ${actor}`);
      return `${target.player?.name ?? target.eosId} was ${command === 'whitelist' ? 'added to' : 'removed from'} the no-check join list on ${target.server.name}.`;
    }
    if (command === 'destroy-wild-dinos') {
      requireLevel(PermissionLevel.ADMIN);
      if (options.confirm !== true) throw new Error('Set confirm to true to run DestroyWildDinos.');
      const server = this.resolveRequiredServer(options.server);
      await server.destroyWildDinos();
      await this.audit(`DESTROYWILDDINOS on ${server.id} by ${actor}`);
      return `DestroyWildDinos sent to ${server.name}. Wild creatures will repopulate over time.`;
    }
    if (command === 'player') { return this.playerLookupText(options.player, options.server, user.id); }
    if (command === 'warn') {
      const match = this.requireSinglePlayer(options.player, options.server, user.id);
      const message = sanitizeForGame(options.message, 400); if (!message) throw new Error('Warning message is empty.');
      await this.replyToPlayer(
        match.server,
        { eosId: match.player.id, playerName: match.player.name, characterName: match.player.name },
        `Staff warning: ${message}`,
        { retries: 0 },
      );
      await this.state.addModerationNote(match.player.id, { text: message, actor, type: 'warning' });
      await this.audit(`WARN ${match.player.name} on ${match.server.id} by ${actor} reason=${message}`);
      return `Warned ${match.player.name} on ${match.server.name}.`;
    }
    if (command === 'note') {
      const match = this.requireSinglePlayer(options.player, options.server, user.id);
      const note = await this.state.addModerationNote(match.player.id, { text: options.note, actor, type: options.type ?? 'note' });
      await this.audit(`NOTE ${match.player.name} on ${match.server.id} by ${actor}`);
      return `Saved moderation note for ${match.player.name}: ${note.text}`;
    }
    if (command === 'announce-template') {
      const name = String(options.template ?? '').trim().toLocaleLowerCase('en-US');
      const templates = this.config.moderation.announcementTemplates ?? {};
      const template = Object.entries(templates).find(([key]) => key.toLocaleLowerCase('en-US') === name)?.[1];
      if (typeof template !== 'string' || !template.trim()) throw new Error('Unknown announcement template.');
      const maximum = announcementMessageMaxLength(this.config.chat.gameMaxLength);
      if (codePointLength(template.trim()) > maximum) {
        throw new Error(`Announcement template ${name} exceeds the ${maximum}-character limit. Shorten it in Settings before sending.`);
      }
      await this.broadcastAnnouncement(template, actor, options.server);
      return `Announcement template ${name} sent.`;
    }
    if (command === 'announce') {
      requireLevel(PermissionLevel.MODERATOR); await this.broadcastAnnouncement(options.message, actor, options.server);
      return options.server ? `Announcement sent to ${options.server}.` : 'Announcement sent to the cluster.';
    }
    if (command === 'mute-player') {
      requireLevel(PermissionLevel.MODERATOR);
      const minutes = this.validateMuteMinutes(options.minutes ?? this.config.moderation.defaultMuteMinutes);
      return (await this.muteGamePlayer(options.player, minutes, options.reason ?? '', actor, options.server, user.id)).message;
    }
    if (command === 'unmute-player') {
      requireLevel(PermissionLevel.MODERATOR); return (await this.unmuteGamePlayer(options.player, actor, options.server, user.id)).message;
    }
    if (command === 'mute-discord') {
      requireLevel(PermissionLevel.MODERATOR);
      const minutes = this.validateMuteMinutes(options.minutes ?? this.config.moderation.defaultMuteMinutes);
      const until = await this.state.setMute(this.state.discordMuteKeys(options.user), { minutes, reason: options.reason ?? '', actor });
      await this.audit(`MUTE Discord member by ${actor} until ${new Date(until).toISOString()} reason=${options.reason ?? ''}`);
      return `The selected Discord user's relay access was muted for ${minutes} minute${minutes === 1 ? '' : 's'}.`;
    }
    if (command === 'unmute-discord') {
      requireLevel(PermissionLevel.MODERATOR); const removed = await this.state.clearMute(this.state.discordMuteKeys(options.user));
      if (removed) await this.audit(`UNMUTE Discord member by ${actor}`);
      return removed ? `Discord user <@${options.user}> was unmuted.` : 'That Discord user had no active relay mute.';
    }
    if (command === 'kick') { requireLevel(PermissionLevel.MODERATOR); return (await this.runPlayerAction('kick', options.player, options.server, actor, options.reason ?? '', user.id)).message; }
    if (command === 'ban') { requireLevel(PermissionLevel.ADMIN); return (await this.runPlayerAction('ban', options.player, options.server, actor, options.reason ?? '', user.id)).message; }
    if (command === 'unban') {
      requireLevel(PermissionLevel.ADMIN); const server = this.resolveServer(options.server);
      await server.unban(options['player-id']); await this.audit(`UNBAN manual account on ${server.id} by ${actor} reason=${options.reason ?? ''}`);
      return `Unban command sent for the supplied account on ${server.name}.`;
    }
    if (command === 'rcon') {
      requireLevel(PermissionLevel.ADMIN);
      if (!this.config.moderation.allowRawRcon) throw new Error('Raw RCON is disabled in configuration.');
      const raw = String(options.command ?? '');
      if (/[\u0000-\u001F\u007F;|&]/u.test(raw)) throw new Error('RCON command contains prohibited separators or control characters.');
      const clean = sanitizeForGame(raw, 1_000); const verb = clean.split(/\s+/, 1)[0].toLocaleLowerCase('en-US');
      const allowlist = new Set(this.config.moderation.rawRconAllowlist.map((item) => item.toLocaleLowerCase('en-US')));
      if (!allowlist.has(verb)) throw new Error(`RCON command ${verb || '(empty)'} is not allowlisted.`);
      const server = this.resolveServer(options.server); await server.execute(clean, { retries: 0 });
      await this.audit(`RCON ${verb} on ${server.id} by ${actor}`);
      return `RCON ${verb} completed on ${server.name}. The raw response was suppressed to protect credentials and player identifiers.`;
    }
    throw new Error(`Unknown subcommand ${command}.`);
  }

  resolveServer(serverId) {
    if (serverId) {
      const query = String(serverId).trim(); const exact = this.serverMap.get(query);
      if (exact) return exact;
      const matches = this.servers.filter((server) => normalizeName(server.name) === normalizeName(query));
      if (matches.length === 1) return matches[0];
      if (matches.length > 1) throw new Error(`Server name ${query} is ambiguous; use the server ID.`);
      throw new Error(`Unknown server ID or name ${query}.`);
    }
    if (this.servers.length === 1) return this.servers[0];
    throw new Error('Choose a server for this command.');
  }
  resolveRequiredServer(serverId) {
    if (!String(serverId ?? '').trim()) throw new Error('Choose a server for this command.');
    return this.resolveServer(serverId);
  }
  selectedServers(serverId) { return serverId ? [this.resolveServer(serverId)] : this.servers; }
  locatePlayers(query, serverId, discordUserId) {
    const selected = this.resolvePlayerChoice(query, discordUserId);
    if (selected) {
      if (serverId && this.resolveServer(serverId) !== selected.server) throw new Error('The selected player is on a different server.');
      return [selected];
    }
    const server = this.resolveRequiredServer(serverId);
    const normalized = normalizeName(query);
    if (!normalized) return [];
    const results = (server.players ?? [])
      .filter((player) => normalizeName(player.id) === normalized || normalizeName(player.name) === normalized)
      .map((player) => ({ server, player }));
    return [...new Map(results.map((item) => [`${item.server.id}:${item.player.id}`, item])).values()];
  }

  requireSinglePlayer(query, serverId, discordUserId) {
    const matches = this.locatePlayers(query, serverId, discordUserId);
    if (!matches.length) throw new Error('The selected player is not connected.');
    if (matches.length > 1) throw new Error(`Player name is ambiguous: ${matches.map((item) => item.player.name).join(', ')}`);
    return matches[0];
  }

  async executeItemGrant(options, actor, discordUserId) {
    const quantity = options.quantity ?? 1; const quality = options.quality ?? 0;
    const forceBlueprint = options.blueprint ?? false;
    const item = options.item ? resolveItemInput(options.item) : null;
    if (options.item && !item) {
      throw new Error('Choose an item from the built-in autocomplete list, or enter one unique exact name, GFI code, or item number.');
    }
    const blueprintPath = item?.blueprintPath ?? options['blueprint-path'];
    const itemNumber = item?.itemNumber ?? options['item-number'];
    let target = await this.resolveGrantTarget(options, discordUserId);
    target = await this.confirmGrantTargetOnline(target);
    if (blueprintPath) await target.server.giveItemToPlayer(target.playerDataId, blueprintPath, quantity, quality, forceBlueprint);
    else if (itemNumber != null) await target.server.giveItemNumToPlayer(target.playerDataId, itemNumber, quantity, quality, forceBlueprint);
    else throw new Error('The selected catalog item has no usable blueprint path or item number.');
    const itemLabel = item?.name ?? (itemNumber != null ? `item #${itemNumber}` : 'the requested item');
    await this.audit(`GIVEITEM target=${target.player?.name ?? 'manual'} item=${item?.key ?? itemNumber ?? 'legacy-path'} on ${target.server.id} by ${actor} quantity=${quantity} quality=${quality} blueprint=${forceBlueprint}`);
    if (item && discordUserId && typeof this.state.recordRecentItem === 'function') {
      try { await this.state.recordRecentItem(discordUserId, item.key); }
      catch (error) {
        // The RCON mutation already succeeded. Preference persistence is
        // deliberately best-effort so it cannot turn success into a retryable
        // failure and tempt an administrator to duplicate the grant.
        this.logger?.warn?.('Recent item preference persistence failed after successful grant', { error: error.message });
        this.metrics.increment('errors_total', { context: 'item_recent_persist' });
      }
    }
    return `Gave ${quantity}x ${itemLabel}${item?.itemNumber != null ? ` (#${item.itemNumber})` : ''} to ${target.player?.name ?? 'the manually selected player'} on ${target.server.name}${forceBlueprint ? ' as a blueprint' : ''}.`;
  }

  async executePackageGrant(options, actor, principalId) {
    const itemPackage = this.state.getItemPackage?.(options.package);
    if (!itemPackage?.enabled || itemPackage.revision !== options.packageRevision) {
      throw new Error('That item package is disabled, missing, or changed. Refresh and review it again.');
    }
    let target = await this.resolveGrantTarget(options, principalId);
    target = await this.confirmGrantTargetOnline(target);
    let completed = 0;
    for (const entry of itemPackage.items) {
      try {
        await this.sendPackageItem(target.server, target.playerDataId, entry);
        completed += 1;
      } catch (error) {
        const failure = new Error(`Package ${itemPackage.name} stopped after ${completed} of ${itemPackage.items.length} item types. The latest grant outcome may be uncertain; do not resend the whole package. Grant any known missing items individually.`);
        failure.cause = error; failure.operationOutcome = 'uncertain'; throw failure;
      }
    }
    await this.audit(`GIVEPACKAGE target=${target.player?.name ?? 'manual'} package=${itemPackage.id} revision=${itemPackage.revision} on ${target.server.id} by ${actor} items=${itemPackage.items.length}`);
    return `Gave ${itemPackage.name} (${itemPackage.items.length} item types) to ${target.player?.name ?? 'the selected player'} on ${target.server.name}.`;
  }

  async resolveGrantTarget(options, discordUserId) {
    const raw = String(options.player ?? options['player-id'] ?? '').trim();
    if (/^\d{1,20}$/.test(raw)) {
      return { server: this.resolveRequiredServer(options.server), player: null, playerDataId: raw };
    }
    const match = this.requireSinglePlayer(raw, options.server, discordUserId);
    const source = this.profileSource(match.server); const key = this.profileKey(match.server, match.player);
    let playerDataId = String(this.profileMapping(match.server, match.player)?.playerDataId ?? '').trim();
    let lookupFailureCode = null;
    if (source) {
      try {
        const verifiedId = await this.importPlayerProfile(match.server, match.player, { force: true });
        const validatedAt = this.profileValidatedAt.get(key);
        const fresh = validatedAt != null && this.now() - validatedAt < (source.config?.revalidateIntervalMs ?? 300_000);
        playerDataId = fresh ? String(verifiedId ?? '').trim() : '';
      }
      catch (error) {
        lookupFailureCode = error?.sourceCode ?? profileErrorCode(error); playerDataId = '';
        this.logger?.warn?.('On-demand player ID import failed', {
          event: 'sftp.profile_read_failed', component: 'profile-import', server: match.server.id,
          outcome: 'failed', reasonCode: lookupFailureCode,
        });
      }
    }
    if (!playerDataId) {
      lookupFailureCode ??= this.profileFailureDetails.get(key)?.code ?? this.profileLastErrors.get(match.server.id)?.code ?? null;
      const hostKeyHelp = lookupFailureCode === 'HOST_KEY_REJECTED'
        ? ` The configured SSH host key for ${match.server.name} does not match. In Settings, scan and apply that map's current key, or explicitly disable host identity verification only if its private network is trusted.`
        : '';
      const automatic = source ? ` Automatic read-only profile lookup did not return it${lookupFailureCode ? ` (${lookupFailureCode})` : ''}; check that map's SFTP access.${hostKeyHelp}` : '';
      throw determinateOperationError(
        `${match.player.name} is connected and their EOS ID was detected automatically, but ASA item/XP commands require a different numeric PlayerDataID.${automatic} No item or XP command was sent.`,
        'PLAYER_ID_LOOKUP_FAILED',
      );
    }
    return { ...match, playerDataId };
  }

  async confirmGrantTargetOnline(target) {
    // A manually supplied numeric PlayerDataID has no EOS identity that
    // ListPlayers can correlate. Connected-player selections do, so refresh
    // that map immediately before the mutating grant and fail closed if the
    // snapshot is unavailable or the account transferred/disconnected.
    if (!target?.player) return target;
    const eosId = String(target.player.id ?? '').trim();
    if (!eosId || typeof target.server?.refreshPlayers !== 'function') {
      throw new Error('The selected player cannot be rechecked safely. No item or XP command was sent.');
    }
    let players;
    try { players = await target.server.refreshPlayers(); }
    catch (error) {
      this.logger?.warn?.('Grant preflight player refresh failed', {
        event: 'rcon.grant_preflight_failed', component: 'bridge', server: target.server.id,
        outcome: 'failed', reasonCode: error?.code ?? error?.name ?? 'refresh_failed',
      });
      this.metrics.increment('grant_preflight_total', { server: target.server.id, result: 'error' });
      throw new Error(`Could not refresh connected players on ${sanitizeIdentity(target.server.name, 32)}. No item or XP command was sent.`);
    }
    const current = (players ?? []).filter((player) => String(player.id ?? '').toLocaleLowerCase('en-US') === eosId.toLocaleLowerCase('en-US'));
    if (current.length !== 1) {
      this.metrics.increment('grant_preflight_total', { server: target.server.id, result: 'offline' });
      throw new Error(`${sanitizeIdentity(target.player.name, 48)} is no longer connected to ${sanitizeIdentity(target.server.name, 32)}. No item or XP command was sent.`);
    }
    this.metrics.increment('grant_preflight_total', { server: target.server.id, result: 'ready' });
    return { ...target, player: current[0] };
  }

  resolveAccountTarget(query, serverId, discordUserId) {
    const selected = this.resolvePlayerChoice(query, discordUserId);
    if (selected) {
      if (serverId && this.resolveServer(serverId) !== selected.server) throw new Error('The selected player is on a different server.');
      return { ...selected, eosId: selected.player.id };
    }
    const server = this.resolveRequiredServer(serverId); const value = String(query ?? '').trim();
    const matches = this.locatePlayers(value, server.id, discordUserId);
    if (matches.length === 1) return { ...matches[0], eosId: matches[0].player.id };
    if (matches.length > 1) throw new Error(`Player name is ambiguous: ${matches.map(({ player }) => player.name).join(', ')}`);
    if (!/^[A-Za-z0-9:_-]{1,128}$/.test(value)) throw new Error('Choose a connected player or enter a valid EOS/ARK account ID.');
    return { server, player: null, eosId: value };
  }

  playerLookupText(query, serverId, discordUserId) {
    const match = this.requireSinglePlayer(query, serverId, discordUserId); const { player, server } = match;
    const link = this.state.getLinkByGame({ eosId: player.id, playerName: player.name });
    const mute = this.state.getMute(this.state.gameMuteKeys({ eosId: player.id, playerName: player.name }));
    const notes = this.state.listModerationNotes(player.id);
    const playtime = this.state.getPlaytime?.(player.id); const mapping = this.profileMapping(server, player);
    const key = this.profileKey(server, player); const source = this.profileSource(server);
    const validatedAt = this.profileValidatedAt.get(key);
    const verified = source && validatedAt != null && this.now() - validatedAt < (source.config?.revalidateIntervalMs ?? 300_000);
    const failed = source && (this.activeProfileSourceFailure(server, source) || this.profileFailureDetails.has(key));
    const targeting = mapping
      ? (source ? (verified ? 'ready (profile verified)' : failed ? 'cached; profile recheck failed' : 'cached; verification pending') : 'ready (manual mapping)')
      : (source ? (failed ? 'profile lookup unavailable' : 'profile lookup pending') : 'numeric ID needed');
    const lines = [`${player.name} on ${server.name}`];
    if (mapping?.characterName && normalizeName(mapping.characterName) !== normalizeName(player.name)) lines.push(`Survivor: ${sanitizeIdentity(mapping.characterName, 64)}`);
    lines.push(`Account identifier: protected`, `Admin targeting: ${targeting}`, `Discord: ${link?.discordDisplayName ?? 'not linked'}`, `Relay mute: ${mute ? `until ${new Date(mute.until).toISOString()}` : 'none'}`, `Total playtime: ${playtime ? formatDuration(playtime.totalSeconds * 1_000) : 'no completed sessions yet'}`);
    if (notes.length) lines.push(`Recent notes: ${notes.map((note) => `${new Date(note.at).toISOString().slice(0, 10)} ${note.text}`).join(' | ')}`);
    return lines.join('\n').slice(0, 1_900);
  }

  leaderboardText(limit = 10) {
    const rows = this.state.listPlaytimeLeaderboard?.(limit) ?? [];
    if (!rows.length) return 'No playtime recorded yet.';
    const lines = rows.map((row, index) => `${index + 1}. ${sanitizeIdentity(row.displayName || 'Protected account', 32)} — ${formatDuration(row.totalSeconds * 1_000)}`);
    return ['Playtime leaderboard:', ...lines].join('\n').slice(0, 1_900);
  }

  async scheduleRestart(minutes, actor, serverId, reason) {
    const deadline = this.now() + minutes * 60_000; const servers = this.selectedServers(serverId);
    const maximum = restartReasonMaxLength(this.config.chat.gameMaxLength);
    const safeReason = sanitizeForGame(redactText(reason, this.redactionSecrets), 20_000);
    if (codePointLength(safeReason) > maximum) {
      const error = new Error(`Restart reason exceeds the ${maximum}-character limit. Shorten it and try again.`);
      error.code = 'RESTART_REASON_TOO_LONG';
      throw error;
    }
    const notice = restartNotice('scheduled', { minutes, reason: safeReason }, this.config.chat.gameMaxLength);
    for (const server of servers) {
      const warningMinutes = new Set((this.config.operations.restartWarningMinutes ?? []).filter((warning) => warning >= minutes));
      const restart = { deadline, actor, reason: safeReason, warningMinutes };
      this.scheduledRestarts.set(server.id, restart);
      await this.state.setScheduledRestart?.(server.id, { ...restart, warningMinutes: [...warningMinutes] });
      await server.announce(notice);
    }
    if (this.config.discord.enabled) await this.audit(`RESTART scheduled by ${actor} target=${serverId ?? 'cluster'} in=${minutes}m reason=${safeReason}`);
    return servers.length;
  }

  async cancelRestart(serverId, actor) {
    const servers = this.selectedServers(serverId); let cancelled = 0;
    for (const server of servers) if (this.scheduledRestarts.delete(server.id)) {
      cancelled += 1; await this.state.clearScheduledRestart?.(server.id);
      await server.announce(restartNotice('cancelled', {}, this.config.chat.gameMaxLength));
    }
    if (cancelled) await this.audit(`RESTART cancelled by ${actor} target=${serverId ?? 'cluster'}`);
    return cancelled;
  }

  async processScheduledRestarts() {
    const warnings = this.config.operations.restartWarningMinutes ?? [];
    for (const [serverId, scheduled] of this.scheduledRestarts) {
      const server = this.serverMap.get(serverId); if (!server) { this.scheduledRestarts.delete(serverId); continue; }
      const remaining = scheduled.deadline - this.now();
      for (const minutes of warnings) if (remaining > 0 && remaining <= minutes * 60_000 && !scheduled.warningMinutes.has(minutes)) {
        const notice = restartNotice('warning', { minutes, reason: scheduled.reason }, this.config.chat.gameMaxLength);
        scheduled.warningMinutes.add(minutes); await this.state.setScheduledRestart?.(serverId, { ...scheduled, warningMinutes: [...scheduled.warningMinutes] }); await server.announce(notice);
        if (this.config.discord.enabled) await this.audit(`RESTART warning ${server.name} in ${minutes}m`);
      }
      if (remaining <= 0) {
        // Claim the deadline synchronously, before the first await. The timer may
        // overlap when RCON is slow, so leaving the entry visible here could send
        // the same non-idempotent command once per tick after an ambiguous error.
        this.scheduledRestarts.delete(serverId);
        const operationId = this.randomBytesFn(12).toString('base64url');
        const safeServerId = sanitizeIdentity(server.id, 32);
        const auditBase = {
          component: 'bridge', action: 'scheduled_restart', operationId, server: safeServerId,
          targetScope: 'single_server',
        };
        let startAudited = false;
        try {
          startAudited = this.logger?.healthy !== false
            && typeof this.logger?.audit === 'function'
            && this.logger.audit('restart.deadline_started', { ...auditBase, stage: 'claim', outcome: 'started' }) === true;
        } catch { startAudited = false; }
        if (!startAudited) {
          this.metrics.increment('errors_total', { context: 'scheduled_restart_audit_start' });
          try { await this.state.clearScheduledRestart?.(serverId); }
          catch {
            this.metrics.increment('errors_total', { context: 'scheduled_restart_blocked_state_clear' });
            try {
              this.logger?.error?.('Blocked scheduled restart could not be removed from durable state', {
                event: 'restart.deadline_cleanup_failed', component: 'bridge', action: 'scheduled_restart',
                server: safeServerId, stage: 'state_clear', outcome: 'failed', reasonCode: 'state_clear_failed',
              });
            } catch { /* Diagnostics must not revive or block an expired schedule. */ }
          }
          try {
            this.logger?.error?.('Scheduled restart deadline blocked because its audit start could not be committed', {
              event: 'restart.deadline_blocked', component: 'bridge', action: 'scheduled_restart',
              server: safeServerId, stage: 'audit_start', outcome: 'failed', reasonCode: 'audit_unavailable',
            });
          } catch { /* The one-shot claim is already consumed. */ }
          continue;
        }

        let terminalAttempted = false;
        const terminalAudit = (outcome, stage, reasonCode = '') => {
          if (terminalAttempted) return;
          terminalAttempted = true;
          const event = `restart.deadline_${outcome}`;
          try {
            const recorded = this.logger.audit(event, {
              ...auditBase, stage, outcome, ...(reasonCode ? { reasonCode } : {}),
            });
            if (recorded !== true) this.metrics.increment('errors_total', { context: 'scheduled_restart_terminal_audit' });
          } catch {
            // The state or RCON outcome may already be final. Never convert an
            // audit-write failure into a retryable scheduled-restart failure.
            this.metrics.increment('errors_total', { context: 'scheduled_restart_terminal_audit' });
          }
        };
        try {
          // Clear durable intent before touching RCON. If this fails, no command
          // is sent and the in-memory claim remains consumed. On a later process
          // start the existing stale-deadline cleanup will clear the residue
          // without executing it.
          await this.state.clearScheduledRestart?.(serverId);
        } catch {
          terminalAudit('failed', 'state_clear', 'state_clear_failed');
          try {
            this.logger?.error?.('Scheduled restart deadline could not be durably claimed; no RCON command was sent', {
              event: 'restart.deadline_failed', component: 'bridge', action: 'scheduled_restart',
              server: safeServerId, stage: 'state_clear', outcome: 'failed', reasonCode: 'state_clear_failed',
            });
          } catch { /* The terminal audit was already attempted. */ }
          this.metrics.increment('errors_total', { context: 'scheduled_restart_state_clear' });
          continue;
        }

        let stage = 'save_world';
        try {
          await server.saveWorld();
          stage = 'announcement';
          await server.announce(restartNotice('deadline', {}, this.config.chat.gameMaxLength));
        } catch {
          const reasonCode = stage === 'save_world' ? 'save_world_failed' : 'announcement_failed';
          terminalAudit('uncertain', stage, reasonCode);
          try {
            this.logger?.warn?.('Scheduled restart deadline was consumed; verify the result before any manual retry', {
              event: 'restart.deadline_uncertain', component: 'bridge', action: 'scheduled_restart',
              server: safeServerId, stage, outcome: 'uncertain', reasonCode,
            });
          } catch { /* The terminal audit was already attempted. */ }
          this.metrics.increment('errors_total', { context: `scheduled_restart_${stage}` });
          continue;
        }

        terminalAudit('succeeded', 'complete');
        try {
          this.logger?.info?.('Scheduled restart deadline completed', {
            event: 'restart.deadline_succeeded', component: 'bridge', action: 'scheduled_restart',
            server: safeServerId, stage: 'complete', outcome: 'succeeded',
          });
          await this.audit(`RESTART window reached on ${server.name}; world save and final player notice sent`);
        } catch {
          this.metrics.increment('errors_total', { context: 'scheduled_restart_auxiliary_audit' });
        }
      }
    }
  }

  async muteGamePlayer(query, minutes, reason, actor, serverId, discordUserId) {
    minutes = this.validateMuteMinutes(minutes);
    const matches = this.locatePlayers(query, serverId, discordUserId); const keys = [];
    if (matches.length) for (const { player } of matches) keys.push(...this.state.gameMuteKeys({ eosId: player.id, playerName: player.name }));
    else if (looksLikePlayerId(query)) keys.push(...this.state.gameMuteKeys({ eosId: String(query).trim() }));
    else keys.push(...this.state.gameMuteKeys({ playerName: query }));
    const until = await this.state.setMute(keys, { minutes, reason, actor });
    const targetLabel = matches.length === 1 ? sanitizeIdentity(matches[0].player.name, 48) : visiblePlayerTarget(query);
    for (const { player } of matches) {
      await this.state.addModerationNote(player.id, {
        type: 'mute', actor,
        text: `Cluster Chat muted for ${minutes} minute${minutes === 1 ? '' : 's'}${reason ? `: ${reason}` : '.'}`,
      });
    }
    await this.audit(`MUTE ARK ${targetLabel} by ${actor} until ${new Date(until).toISOString()} reason=${reason}`);
    return { ok: true, message: `${targetLabel} relay-muted for ${minutes} minute${minutes === 1 ? '' : 's'}${matches.length ? ` (${matches.length} online match${matches.length === 1 ? '' : 'es'})` : ''}.` };
  }

  async unmuteGamePlayer(query, actor, serverId, discordUserId) {
    const matches = this.locatePlayers(query, serverId, discordUserId); const keys = [];
    for (const { player } of matches) keys.push(...this.state.gameMuteKeys({ eosId: player.id, playerName: player.name }));
    if (looksLikePlayerId(query)) keys.push(...this.state.gameMuteKeys({ eosId: String(query).trim() }));
    else keys.push(...this.state.gameMuteKeys({ playerName: query }));
    const targetLabel = matches.length === 1 ? sanitizeIdentity(matches[0].player.name, 48) : visiblePlayerTarget(query);
    const removed = await this.state.clearMute(keys);
    if (removed) {
      for (const { player } of matches) {
        await this.state.addModerationNote(player.id, { type: 'unmute', actor, text: 'Cluster Chat mute removed.' });
      }
      await this.audit(`UNMUTE ARK ${targetLabel} by ${actor}`);
    }
    return { ok: removed, message: removed ? `${targetLabel} was unmuted.` : `No active relay mute found for ${targetLabel}.` };
  }

  async runPlayerAction(action, query, serverId, actor, reason, discordUserId) {
    const { server, player } = this.requireSinglePlayer(query, serverId, discordUserId);
    await server[action](player.id);
    await this.state.addModerationNote(player.id, {
      type: action, actor,
      text: `${action === 'kick' ? 'Kicked from' : 'Banned on'} ${server.name}${reason ? `: ${reason}` : '.'}`,
    });
    await this.audit(`${action.toLocaleUpperCase('en-US')} ${player.name} on ${server.id} by ${actor} reason=${reason}`);
    return { ok: true, message: `${player.name} ${action === 'kick' ? 'was kicked from' : 'was banned on'} ${server.name}.` };
  }

  async broadcastAnnouncement(message, actor, serverId) {
    const maximum = announcementMessageMaxLength(this.config.chat.gameMaxLength);
    const clean = sanitizeForGame(redactText(message, this.redactionSecrets), 20_000);
    if (!clean) throw new Error('Announcement message is empty.');
    if (codePointLength(clean) > maximum) {
      const error = new Error(`Announcement message exceeds the ${maximum}-character limit. Shorten it and try again.`);
      error.code = 'ANNOUNCEMENT_TOO_LONG';
      throw error;
    }
    const servers = this.selectedServers(serverId);
    const operationId = this.randomBytesFn(12).toString('base64url');
    const source = String(actor ?? '') === 'http-api' ? 'automation'
      : String(actor ?? '').startsWith('http:') ? 'dashboard'
        : String(actor ?? '').startsWith('discord:') ? 'discord'
        : String(actor ?? '').startsWith('game:') ? 'game' : 'internal';
    const target = serverId ? sanitizeIdentity(servers[0]?.id, 32) : 'cluster';
    const auditFields = {
      component: 'bridge', operationId, source, target,
      targetScope: serverId ? 'server' : 'cluster', targetServerCount: servers.length,
      messageLength: codePointLength(clean),
    };
    let startAudited = false;
    try {
      startAudited = this.logger?.healthy !== false
        && typeof this.logger?.audit === 'function'
        && this.logger.audit('announcement.delivery_started', { ...auditFields, outcome: 'started' }) === true;
    } catch { startAudited = false; }
    if (!startAudited) {
      const error = new Error('Security audit logging is unavailable; no announcement was sent.');
      error.code = 'AUDIT_UNAVAILABLE';
      throw error;
    }

    const results = await Promise.allSettled(servers.map((server) => server.announce(`${ANNOUNCEMENT_PREFIX}${clean}`)));
    const failedServerCount = results.filter((item) => item.status === 'rejected').length;
    const deliveredServerCount = results.length - failedServerCount;
    let discordOutcome = 'skipped';
    if (this.config.discord.enabled) {
      if (failedServerCount === 0) {
        try { await this.discord.sendChat(`📢 **ADMIN:** ${toDiscordEmoji(clean)}`); discordOutcome = 'succeeded'; }
        catch (error) { discordOutcome = 'failed'; this.logger?.warn?.('Discord announcement delivery failed', { error: error.message }); this.metrics.increment('relay_failures_total', { destination: 'discord' }); }
      }
    }
    const outcome = failedServerCount === 0 ? 'succeeded'
      : deliveredServerCount === 0 ? 'failed' : 'partial';
    try {
      const terminalAudited = this.logger.audit(`announcement.delivery_${outcome}`, {
        ...auditFields, outcome, deliveredServerCount, failedServerCount, discordOutcome,
      });
      if (terminalAudited !== true) {
        this.metrics.increment('errors_total', { context: 'announcement_terminal_audit' });
      }
    } catch {
      // The RCON result is already final. Never surface an audit-write failure
      // as a retryable announcement failure after a server may have displayed it.
      this.metrics.increment('errors_total', { context: 'announcement_terminal_audit' });
    }
    if (failedServerCount) {
      const error = deliveredServerCount
        ? new Error(`Announcement partially delivered to ${deliveredServerCount} of ${servers.length} servers; do not retry blindly.`)
        : new Error(`Announcement failed on ${failedServerCount} server(s); no target confirmed delivery.`);
      error.code = deliveredServerCount ? 'ANNOUNCEMENT_PARTIAL' : 'ANNOUNCEMENT_FAILED';
      throw error;
    }
    try { await this.audit(`ANNOUNCE by ${actor} target=${serverId ?? 'cluster'} message=${clean}`); }
    catch {
      // Delivery succeeded and its terminal audit was already attempted. An
      // auxiliary Discord-audit failure must not invite a duplicate send.
      this.metrics.increment('errors_total', { context: 'announcement_auxiliary_audit' });
    }
  }

  playersText(serverId) {
    const lines = [];
    for (const server of this.selectedServers(serverId)) {
      lines.push(`${server.name} (${server.players.length}):`);
      if (!server.players.length) lines.push('  no players connected');
      else for (const player of server.players) lines.push(`  ${sanitizeIdentity(player.name, 64)}`);
    }
    return lines.join('\n').slice(0, 1_900);
  }

  statusText() {
    const status = this.status();
    const now = this.now();
    const totalPlayers = status.servers.reduce((count, server) => count + server.playerCount, 0);
    const lines = [
      `${status.clusterName} — ${status.ready ? 'ready' : 'degraded'}`,
      `Bridge: ${status.started ? 'running' : 'stopped'} | Uptime: ${formatDuration(status.uptimeSeconds * 1_000)} | Players: ${totalPlayers}`,
    ];
    for (const server of status.servers) {
      const details = [
        server.connected ? 'connected' : 'offline',
        server.polling ? 'polling' : 'not polling',
        `${server.playerCount} player${server.playerCount === 1 ? '' : 's'}`,
        `latency ${server.lastLatencyMs == null ? 'unknown' : `${server.lastLatencyMs}ms`}`,
        `connected ${server.connected ? formatAge(server.connectedSinceAt, now).replace(' ago', '') : 'n/a'}`,
        `last success ${formatAge(server.lastSuccessAt, now)}`,
        `players refreshed ${formatAge(server.lastPlayerRefreshAt, now)}`,
      ];
      const profile = server.profileImport;
      if (profile?.enabled) {
        details.push(`profile IDs ${profile.verifiedPlayers}/${profile.eligiblePlayers} verified (${profile.state})`);
        if (profile.lastErrorCode) details.push(`profile error ${profile.lastErrorCode}`);
      } else details.push('profile IDs disabled');
      if (server.consecutiveFailures) details.push(`${server.consecutiveFailures} consecutive failure${server.consecutiveFailures === 1 ? '' : 's'}`);
      if (server.lastError) details.push(`error: ${redactText(server.lastError, this.redactionSecrets)}`);
      lines.push(`${server.serverName} [${server.serverId}]: ${details.join(' | ')}`);
      lines.push(server.players.length
        ? `  Players: ${server.players.map((player) => sanitizeIdentity(player.name, 64)).join(', ')}`
        : '  Players: none connected');
    }
    if (this.config.discord.enabled) lines.push(`Discord: ${status.discord.ready ? 'connected' : 'offline'} | Client: ${status.discord.user ?? 'unknown'}`);
    lines.push(`Links: ${status.linkedAccounts} | Active relay mutes: ${status.activeMutes}`);
    if (status.scheduledRestarts.length) lines.push(`Scheduled restarts: ${status.scheduledRestarts.map((restart) => `${restart.serverId} in ${formatDuration(Math.max(0, restart.deadline - now))}${restart.reason ? ` (${restart.reason})` : ''}`).join(', ')}`);
    return lines.join('\n').slice(0, 1_900);
  }

  async audit(message) {
    const safeMessage = redactText(message, this.redactionSecrets);
    const action = String(safeMessage).trim().split(/\s+/, 1)[0].replace(/[^a-z0-9_-]/giu, '').toLocaleLowerCase('en-US').slice(0, 48) || 'event';
    this.logger?.audit?.('bridge.audit', { component: 'bridge', action, outcome: 'recorded' });
    if (this.config.discord.enabled) {
      try { await this.discord.sendAudit(`\`${new Date(this.now()).toISOString()}\` ${sanitizeForDiscord(safeMessage, 1_700)}`); }
      catch (error) { this.logger?.warn?.('Discord audit delivery failed', { error: error.message }); }
    }
  }
}
