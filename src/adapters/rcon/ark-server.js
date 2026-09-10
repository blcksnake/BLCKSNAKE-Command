import { EventEmitter } from 'node:events';
import { SourceRconClient } from './source-rcon.js';
import { parseChatResponse } from '../../core/chat-parser.js';
import { parsePlayerList } from '../../core/player-parser.js';
import { assertGameNoticeFits, gameMessageMaxLength } from '../../core/announcement-policy.js';
import { quoteRconArgument, sanitizeForGame } from '../../core/sanitize.js';
import { redactText } from '../../core/redaction.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function safeId(value) {
  const id = String(value ?? '').trim();
  if (!/^[A-Za-z0-9:_-]{1,128}$/.test(id)) throw new Error('A valid player ID is required');
  return id;
}

function safeInteger(value, field, minimum, maximum) {
  const text = String(value ?? '').trim();
  if (!/^\d+$/.test(text)) throw new Error(`${field} must be an integer from ${minimum} to ${maximum}`);
  const number = Number(text);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) {
    throw new Error(`${field} must be an integer from ${minimum} to ${maximum}`);
  }
  return String(number);
}

function safeNumber(value, field, minimum, maximum, { exclusiveMinimum = false } = {}) {
  const text = String(value ?? '').trim();
  if (!/^(?:\d+(?:\.\d+)?|\.\d+)$/.test(text)) throw new Error(`${field} must be a finite number from ${minimum} to ${maximum}`);
  const number = Number(text);
  const belowMinimum = exclusiveMinimum ? number <= minimum : number < minimum;
  if (!Number.isFinite(number) || belowMinimum || number > maximum) {
    throw new Error(`${field} must be a finite number ${exclusiveMinimum ? 'greater than ' : 'from '}${minimum}${exclusiveMinimum ? ` and at most ${maximum}` : ` to ${maximum}`}`);
  }
  return String(number);
}

function safeBoolean(value, field) {
  if (typeof value !== 'boolean') throw new Error(`${field} must be a boolean`);
  return value;
}

function safeBlueprint(value) {
  let blueprint = String(value ?? '').trim();
  if (blueprint.startsWith('"') && blueprint.endsWith('"') && blueprint.length >= 2) blueprint = blueprint.slice(1, -1);
  if (blueprint.length > 512 || !/^Blueprint'\/Game\/[A-Za-z0-9_./-]+'$/.test(blueprint)) {
    throw new Error("Blueprint must be a full Blueprint'/Game/...' path");
  }
  return `"${blueprint}"`;
}

function safePlayerName(value) {
  const name = sanitizeForGame(value, 96).replace(/[;|]/g, '');
  if (!name) throw new Error('A valid player name is required');
  return name;
}

function safeChatMessage(value, maxLength, secrets = []) {
  // ASA consoles can treat ASCII semicolons and pipes as command separators.
  // Preserve readable punctuation without allowing player text to append
  // another RCON command. Newlines/control bytes are already removed.
  return sanitizeForGame(redactText(value, secrets), maxLength).replace(/[;|]/g, ',');
}

function safeOneShotNotice(value, maxLength, secrets = []) {
  const maximum = gameMessageMaxLength(maxLength);
  const clean = sanitizeForGame(redactText(value, secrets), maximum + 1).replace(/[;|]/g, ',');
  return assertGameNoticeFits(clean, maximum);
}

export class ArkServer extends EventEmitter {
  constructor(config, { clientFactory, logger = null, metrics = null, now = () => Date.now() } = {}) {
    super();
    this.config = config; this.id = config.id; this.name = config.name;
    this.logger = logger; this.metrics = metrics; this.now = now;
    this.clientFactory = clientFactory ?? (() => new SourceRconClient(config));
    this.commandQueue = Promise.resolve(); this.pollTimer = null; this.running = false; this.players = []; this.hasPlayerSnapshot = false;
    this.status = {
      serverId: this.id, serverName: this.name, connected: false, polling: false, playerCount: 0,
      consecutiveFailures: 0, lastSuccessAt: null, lastErrorAt: null, lastError: null,
      connectedSinceAt: null, lastLatencyMs: null, lastPlayerRefreshAt: null,
    };
  }

  snapshot() { return { ...this.status, playerCount: this.players.length }; }

  execute(command, { retries = this.config.retries ?? 2 } = {}) {
    const operation = async () => {
      let lastError;
      for (let attempt = 0; attempt <= retries; attempt += 1) {
        const started = this.now();
        try {
          const result = await this.clientFactory().execute(command);
          if (!this.status.connected) { this.status.connectedSinceAt = this.now(); this.emit('connected', this); }
          this.status.connected = true; this.status.lastSuccessAt = this.now();
          this.status.lastLatencyMs = Math.max(0, this.now() - started);
          this.status.lastError = null; this.status.consecutiveFailures = 0;
          this.metrics?.increment('rcon_commands_total', { server: this.id, result: 'success' });
          return result;
        } catch (error) {
          lastError = error;
          if (this.status.connected) this.emit('disconnected', this, error);
          this.status.connected = false; this.status.lastErrorAt = this.now();
          this.status.connectedSinceAt = null; this.status.lastError = error.message; this.status.consecutiveFailures += 1;
          this.metrics?.increment('rcon_commands_total', { server: this.id, result: 'error' });
          if (attempt < retries) await sleep(Math.min(2_000, 100 * 2 ** attempt));
        }
      }
      this.logger?.warn?.('RCON command failed', {
        event: 'rcon.command_failed', component: 'rcon', server: this.id,
        commandVerb: String(command).split(/\s/, 1)[0], outcome: 'failed',
        reasonCode: lastError?.code ?? lastError?.name ?? 'command_failed',
      });
      throw lastError;
    };
    const queued = this.commandQueue.then(operation, operation);
    this.commandQueue = queued.catch(() => undefined);
    return queued;
  }

  async getChat() {
    try {
      return parseChatResponse(await this.execute('GetChat'), { playerNames: this.players.map((player) => player.name) });
    } catch (error) {
      if (this.status.lastSuccessAt && error?.message?.startsWith('RCON command timed out')) {
        this.status.connected = true; this.status.lastError = null; this.status.consecutiveFailures = 0;
        return [];
      }
      throw error;
    }
  }

  async refreshPlayers() {
    const previous = new Map(this.players.map((player) => [player.id || player.name, player]));
    const players = parsePlayerList(await this.execute('ListPlayers'));
    const current = new Map(players.map((player) => [player.id || player.name, player]));
    if (this.hasPlayerSnapshot) {
      for (const [key, player] of current) if (!previous.has(key)) this.emit('playerJoined', player, this);
      for (const [key, player] of previous) if (!current.has(key)) this.emit('playerLeft', player, this);
    }
    this.players = players;
    this.hasPlayerSnapshot = true;
    this.status.playerCount = this.players.length; this.status.lastPlayerRefreshAt = this.now();
    this.metrics?.setGauge('players', { server: this.id }, this.players.length);
    this.emit('players', this.players); return this.players;
  }

  async sendChat(message, { retries = this.config.retries ?? 2 } = {}) {
    const clean = safeChatMessage(message, this.config.gameMaxLength ?? 420, [this.config.password]);
    return clean ? this.execute(`ServerChat ${clean}`, { retries }) : '';
  }
  async sendPrivateById(playerId, message, { retries = this.config.retries ?? 2 } = {}) {
    const clean = safeChatMessage(message, this.config.gameMaxLength ?? 420, [this.config.password]);
    return clean ? this.execute(`ServerChatTo ${quoteRconArgument(safeId(playerId))} ${clean}`, { retries }) : '';
  }
  async sendPrivateByName(playerName, message, { retries = this.config.retries ?? 2 } = {}) {
    const clean = safeChatMessage(message, this.config.gameMaxLength ?? 420, [this.config.password]);
    return clean ? this.execute(`ServerChatToPlayer ${quoteRconArgument(safePlayerName(playerName))} ${clean}`, { retries }) : '';
  }
  async sendPrivate(playerId, message, options) { return this.sendPrivateById(playerId, message, options); }
  async broadcast(message, { retries = this.config.retries ?? 2 } = {}) {
    const clean = safeChatMessage(message, this.config.gameMaxLength ?? 420, [this.config.password]);
    return clean ? this.execute(`Broadcast ${clean}`, { retries }) : '';
  }
  async announce(message) {
    const clean = safeOneShotNotice(message, this.config.gameMaxLength, [this.config.password]);
    // ASA can accept Broadcast over RCON while displaying nothing to connected
    // clients. ServerChat is the reliable all-player RCON delivery mechanism
    // and leaves the notice visible in the in-game chat history.
    return clean ? this.execute(`ServerChat ${clean}`, { retries: 0 }) : '';
  }
  // Administrative mutations are deliberately sent once. A timeout can mean
  // the server applied the command but the response was lost; retrying could
  // duplicate grants, messages, or other visible effects.
  saveWorld() { return this.execute('SaveWorld', { retries: 0 }); }
  async kick(playerId) { return this.execute(`KickPlayer ${safeId(playerId)}`, { retries: 0 }); }
  async ban(playerId) { return this.execute(`BanPlayer ${safeId(playerId)}`, { retries: 0 }); }
  async unban(playerId) { return this.execute(`UnbanPlayer ${safeId(playerId)}`, { retries: 0 }); }
  giveItemToPlayer(playerId, blueprint, quantity, quality, forceBlueprint) {
    const command = [
      'GiveItemToPlayer',
      safeInteger(playerId, 'Player ID', 1, 4_294_967_295),
      safeBlueprint(blueprint),
      safeInteger(quantity, 'Quantity', 1, 10_000),
      safeNumber(quality, 'Quality', 0, 100),
      safeBoolean(forceBlueprint, 'Force blueprint'),
    ].join(' ');
    return this.execute(command, { retries: 0 });
  }
  giveItemNumToPlayer(playerId, itemNumber, quantity, quality, forceBlueprint) {
    const command = [
      'GiveItemNumToPlayer',
      safeInteger(playerId, 'Player ID', 1, 4_294_967_295),
      safeInteger(itemNumber, 'Item number', 0, 2_147_483_647),
      safeInteger(quantity, 'Quantity', 1, 10_000),
      safeNumber(quality, 'Quality', 0, 100),
      safeBoolean(forceBlueprint, 'Force blueprint'),
    ].join(' ');
    return this.execute(command, { retries: 0 });
  }
  giveExperienceToPlayer(playerId, experience, fromTribe, shareWithTribe) {
    const command = [
      'GiveExpToPlayer',
      safeInteger(playerId, 'Player ID', 1, 4_294_967_295),
      safeNumber(experience, 'Experience', 0, 1_000_000_000, { exclusiveMinimum: true }),
      safeBoolean(fromTribe, 'From tribe'),
      !safeBoolean(shareWithTribe, 'Share with tribe'),
    ].join(' ');
    return this.execute(command, { retries: 0 });
  }
  allowPlayer(playerId) { return this.execute(`AllowPlayerToJoinNoCheck ${safeId(playerId)}`, { retries: 0 }); }
  disallowPlayer(playerId) { return this.execute(`DisallowPlayerToJoinNoCheck ${safeId(playerId)}`, { retries: 0 }); }
  destroyWildDinos() { return this.execute('DestroyWildDinos', { retries: 0 }); }

  startPolling() {
    if (this.running || this.config.enabled === false) return;
    this.running = true; this.status.polling = true;
    const poll = async () => {
      if (!this.running) return;
      try {
        const at = this.now();
        if (!this.status.lastPlayerRefreshAt || at - this.status.lastPlayerRefreshAt >= this.config.playerRefreshIntervalMs) await this.refreshPlayers();
        for (const message of await this.getChat()) this.emit('chat', message, this);
      } catch (error) { this.emit('pollError', error, this); }
      finally { if (this.running) this.pollTimer = setTimeout(poll, this.config.pollIntervalMs); }
    };
    void poll();
  }

  stopPolling() {
    this.running = false; this.status.polling = false; clearTimeout(this.pollTimer); this.pollTimer = null;
  }
}
