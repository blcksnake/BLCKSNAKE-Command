import { EventEmitter } from 'node:events';

const FATAL_CLOSE_CODES = new Set([4004, 4010, 4011, 4013, 4014]);
const DEFAULT_INTENTS = 1 | 512 | 32_768;
const DEFAULT_GATEWAY_URL = 'wss://gateway.discord.gg';

function secureDiscordGatewayUrl(value) {
  try {
    const url = new URL(String(value ?? ''));
    const discordHost = url.hostname === 'discord.gg' || url.hostname.endsWith('.discord.gg');
    if (url.protocol !== 'wss:' || !discordHost || url.username || url.password) return null;
    url.hash = '';
    return url.toString().replace(/\/$/u, '');
  } catch {
    // An invalid resume URL fails closed to Discord's pinned gateway origin.
    return null;
  }
}

function addListener(socket, event, handler) {
  if (typeof socket.addEventListener === 'function') socket.addEventListener(event, handler);
  else if (typeof socket.on === 'function') socket.on(event, handler);
}

function eventData(event) {
  if (event?.data != null) return event.data;
  return event;
}

export class DiscordGateway extends EventEmitter {
  constructor(config, {
    webSocketFactory = (url) => new WebSocket(url), logger = null,
    setTimeoutFn = setTimeout, clearTimeoutFn = clearTimeout,
    setIntervalFn = setInterval, clearIntervalFn = clearInterval,
    random = Math.random,
  } = {}) {
    super();
    this.config = config; this.webSocketFactory = webSocketFactory; this.logger = logger;
    this.setTimeoutFn = setTimeoutFn; this.clearTimeoutFn = clearTimeoutFn;
    this.setIntervalFn = setIntervalFn; this.clearIntervalFn = clearIntervalFn; this.random = random;
    this.started = false; this.ready = false; this.socket = null; this.sequence = null;
    this.sessionId = null; this.resumeGatewayUrl = null; this.user = null;
    this.heartbeatTimer = null; this.initialHeartbeatTimer = null; this.reconnectTimer = null;
    this.awaitingHeartbeatAck = false; this.reconnectAttempts = 0; this.startPromise = null;
  }

  snapshot() {
    return { enabled: true, started: this.started, ready: this.ready, user: this.user?.username ?? null, sessionId: this.sessionId };
  }

  start() {
    if (this.startPromise) return this.startPromise;
    this.started = true;
    this.startPromise = new Promise((resolve, reject) => {
      this.once('_startupReady', resolve); this.once('_startupFatal', reject);
      this.connect();
      const timeout = this.setTimeoutFn(() => {
        if (!this.ready && this.started) this.emit('_startupFatal', new Error('Discord Gateway READY timed out'));
      }, this.config.gatewayReadyTimeoutMs ?? 20_000);
      this.once('_startupReady', () => this.clearTimeoutFn(timeout));
      this.once('_startupFatal', () => this.clearTimeoutFn(timeout));
    });
    return this.startPromise;
  }

  connect() {
    if (!this.started) return;
    this.clearReconnect(); this.clearHeartbeat(); this.ready = false;
    const base = secureDiscordGatewayUrl(this.resumeGatewayUrl) || DEFAULT_GATEWAY_URL;
    const separator = base.includes('?') ? '&' : '?';
    const socket = this.webSocketFactory(`${base}${separator}v=10&encoding=json`);
    this.socket = socket;
    addListener(socket, 'message', (event) => this.handleMessage(eventData(event)));
    addListener(socket, 'error', (event) => this.logger?.warn?.('Discord Gateway socket error', {
      event: 'discord.gateway_socket_error', component: 'discord', outcome: 'failed',
      reasonCode: event?.code ?? 'socket_error',
    }));
    addListener(socket, 'close', (event = {}) => this.handleClose(event.code ?? 1006, event.reason ?? ''));
  }

  send(payload) {
    if (this.socket?.readyState !== 1) return false;
    this.socket.send(JSON.stringify(payload)); return true;
  }

  handleMessage(raw) {
    let payload;
    try { payload = JSON.parse(Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw)); }
    catch {
      // Malformed gateway frames are untrusted input and must not trigger state changes.
      return;
    }
    if (payload.s != null) this.sequence = payload.s;
    switch (payload.op) {
      case 10: this.startHeartbeat(payload.d?.heartbeat_interval ?? 45_000); this.identifyOrResume(); break;
      case 11: this.awaitingHeartbeatAck = false; break;
      case 1: this.sendHeartbeat(); break;
      case 7: this.reconnect('server requested reconnect'); break;
      case 9:
        if (!payload.d) { this.sessionId = null; this.sequence = null; this.resumeGatewayUrl = null; }
        this.scheduleReconnect('invalid session', 1_000 + Math.floor(this.random() * 4_000));
        break;
      case 0: this.handleDispatch(payload.t, payload.d); break;
      default: break;
    }
  }

  identifyOrResume() {
    if (this.sessionId && this.sequence != null) {
      this.send({ op: 6, d: { token: this.config.token, session_id: this.sessionId, seq: this.sequence } });
      return;
    }
    this.send({ op: 2, d: {
      token: this.config.token,
      intents: this.config.intents ?? DEFAULT_INTENTS,
      properties: { os: process.platform, browser: 'asa-crosschat', device: 'asa-crosschat' },
    } });
  }

  handleDispatch(type, data) {
    if (type === 'READY') {
      this.sessionId = data.session_id;
      this.resumeGatewayUrl = secureDiscordGatewayUrl(data.resume_gateway_url);
      if (data.resume_gateway_url && !this.resumeGatewayUrl) {
        // RESUME carries the bot token. Fail closed to Discord's pinned default
        // origin rather than sending it to an arbitrary or plaintext URL.
        this.logger?.security?.('discord.gateway_url_rejected', { component: 'discord', outcome: 'denied', reasonCode: 'insecure_resume_url' });
      }
      this.user = data.user;
      this.ready = true; this.reconnectAttempts = 0; this.emit('ready', data); this.emit('_startupReady');
      this.logger?.info?.('Discord Gateway ready', { event: 'discord.gateway_ready', component: 'discord', outcome: 'succeeded' });
    } else if (type === 'RESUMED') {
      this.ready = true; this.reconnectAttempts = 0; this.emit('resumed', data); this.emit('_startupReady');
      this.logger?.info?.('Discord Gateway resumed', { event: 'discord.gateway_resumed', component: 'discord', outcome: 'succeeded' });
    } else if (type === 'MESSAGE_CREATE') this.emit('messageCreate', data);
    else if (type === 'INTERACTION_CREATE') this.emit('interactionCreate', data);
  }

  startHeartbeat(interval) {
    this.clearHeartbeat();
    this.initialHeartbeatTimer = this.setTimeoutFn(() => {
      this.sendHeartbeat();
      this.heartbeatTimer = this.setIntervalFn(() => {
        if (this.awaitingHeartbeatAck) this.reconnect('heartbeat ACK missed');
        else this.sendHeartbeat();
      }, interval);
    }, Math.floor(this.random() * interval));
  }

  sendHeartbeat() {
    if (this.send({ op: 1, d: this.sequence })) this.awaitingHeartbeatAck = true;
  }

  clearHeartbeat() {
    this.clearTimeoutFn(this.initialHeartbeatTimer); this.clearIntervalFn(this.heartbeatTimer);
    this.initialHeartbeatTimer = null; this.heartbeatTimer = null; this.awaitingHeartbeatAck = false;
  }

  clearReconnect() { this.clearTimeoutFn(this.reconnectTimer); this.reconnectTimer = null; }

  reconnect(reason) {
    if (!this.started) return;
    const expected = reason === 'server requested reconnect';
    this.logger?.[expected ? 'info' : 'warn']?.(expected
      ? 'Discord Gateway is honoring a server-requested reconnect'
      : 'Discord Gateway reconnecting', {
      event: 'discord.gateway_reconnecting', component: 'discord', outcome: 'retrying', reasonCode: reason,
    });
    const socket = this.socket; this.socket = null; this.ready = false; this.clearHeartbeat();
    try { socket?.close?.(4000, 'reconnect'); }
    catch { /* Socket teardown is best effort; reconnect scheduling must continue. */ }
    this.scheduleReconnect(reason);
  }

  scheduleReconnect(reason, fixedDelay) {
    if (!this.started || this.reconnectTimer) return;
    const delay = fixedDelay ?? Math.min(30_000, 500 * 2 ** Math.min(this.reconnectAttempts, 6)) + Math.floor(this.random() * 250);
    this.reconnectAttempts += 1;
    this.reconnectTimer = this.setTimeoutFn(() => { this.reconnectTimer = null; this.connect(); }, delay);
    this.emit('reconnecting', { reason, delay });
  }

  handleClose(code, reason) {
    if (this.socket) this.socket = null;
    this.ready = false; this.clearHeartbeat();
    if (!this.started) return;
    if (FATAL_CLOSE_CODES.has(code)) {
      const error = new Error(`Discord Gateway closed fatally (${code}): ${reason || 'configuration or intent error'}`);
      this.logger?.security?.('discord.gateway_fatal', { component: 'discord', outcome: 'failed', reasonCode: `close_${code}` }, 'error');
      this.started = false; this.emit('fatal', error); this.emit('_startupFatal', error); return;
    }
    this.scheduleReconnect(`socket closed ${code}`);
  }

  stop() {
    this.started = false; this.ready = false; this.clearHeartbeat(); this.clearReconnect();
    const socket = this.socket; this.socket = null;
    try { socket?.close?.(1000, 'shutdown'); }
    catch { /* Socket teardown is best effort so shutdown remains idempotent. */ }
    this.startPromise = null;
  }
}
