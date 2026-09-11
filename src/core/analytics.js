import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';

const APP_NAME = 'BLCKSNAKE Command';
const APP_VERSION = '1.1.1';
const SCHEMA_VERSION = 1;
const HEARTBEAT_INTERVAL_MS = 24 * 60 * 60 * 1_000;
const REQUEST_TIMEOUT_MS = 5_000;
const ALLOWED_EVENTS = new Set(['analytics_enabled', 'app_started', 'app_heartbeat', 'app_stopped']);

function boundedCount(value) {
  return Number.isInteger(value) && value >= 0 ? Math.min(value, 10_000) : 0;
}

function safeContext(value = {}) {
  return Object.freeze({
    serverCount: boundedCount(value.serverCount),
    discordEnabled: value.discordEnabled === true,
    managed: value.managed === true,
  });
}

export function createAnalyticsPayload({ event, installationId, context, now = new Date(), uptimeSeconds = 0 }) {
  if (!ALLOWED_EVENTS.has(event)) throw new Error('Unsupported analytics event');
  return {
    schemaVersion: SCHEMA_VERSION,
    event,
    eventId: crypto.randomUUID(),
    sentAt: now.toISOString(),
    application: { name: APP_NAME, version: APP_VERSION },
    installation: { id: String(installationId ?? '').slice(0, 128) },
    system: { platform: os.platform(), architecture: os.arch(), node: process.versions.node },
    properties: {
      ...safeContext(context),
      ...(event === 'app_stopped' ? { uptimeSeconds: boundedCount(Math.floor(uptimeSeconds)) } : {}),
    },
  };
}

export class AnalyticsClient {
  constructor(config = {}, {
    fetchImplementation = globalThis.fetch,
    logger = null,
    now = () => new Date(),
    setIntervalImplementation = setInterval,
    clearIntervalImplementation = clearInterval,
  } = {}) {
    this.enabled = config.enabled === true;
    this.endpoint = String(config.endpoint ?? '');
    this.token = String(config.token ?? '');
    if (!this.token && config.tokenFile) {
      try { this.token = fs.readFileSync(config.tokenFile, 'utf8').trim(); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    this.installationId = String(config.installationId ?? '');
    this.fetch = fetchImplementation;
    this.logger = logger;
    this.now = now;
    this.setInterval = setIntervalImplementation;
    this.clearInterval = clearIntervalImplementation;
    this.timer = null;
    this.startedAt = null;
    this.context = safeContext();
    this.lastDeliveryReason = '';
  }

  get active() {
    return this.enabled && Boolean(this.endpoint && this.token && this.installationId)
      && typeof this.fetch === 'function';
  }

  async send(event, { uptimeSeconds = 0, attempts = 1 } = {}) {
    if (!this.active) { this.lastDeliveryReason = 'collector_not_configured'; return false; }
    const payload = createAnalyticsPayload({
      event, installationId: this.installationId, context: this.context, now: this.now(), uptimeSeconds,
    });
    const body = JSON.stringify(payload);
    const maximumAttempts = attempts === 2 ? 2 : 1;
    let lastReason = 'request_failed';
    for (let attempt = 1; attempt <= maximumAttempts; attempt += 1) {
      try {
        const response = await this.fetch(this.endpoint, {
          method: 'POST',
          headers: {
            accept: 'application/json',
            authorization: `Bearer ${this.token}`,
            'content-type': 'application/json',
            'user-agent': `${APP_NAME.replaceAll(' ', '-')}/${APP_VERSION}`,
          },
          body,
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });
        if (response.ok) {
          this.lastDeliveryReason = '';
          this.logger?.info?.('Optional analytics delivered', {
            event: 'analytics.delivery_succeeded', analyticsEvent: event, outcome: 'succeeded',
          });
          return true;
        }
        lastReason = response.status === 403 && response.headers?.get?.('cf-mitigated') === 'challenge'
          ? 'collector_browser_challenge' : `collector_http_${response.status}`;
        // A Cloudflare browser challenge cannot be completed by a server process,
        // so retrying it only duplicates the same rejected initial contact.
        const retryable = (response.status === 403 && lastReason !== 'collector_browser_challenge')
          || response.status === 408 || response.status === 429
          || response.status >= 500;
        if (!retryable) break;
      } catch (error) {
        lastReason = String(error?.message ?? 'request_failed').slice(0, 96);
      }
    }
    this.logger?.warn?.('Optional analytics delivery failed', {
      event: 'analytics.delivery_failed', reasonCode: lastReason,
    });
    this.lastDeliveryReason = lastReason;
    return false;
  }

  scheduleHeartbeat() {
    if (this.timer || !this.active) return;
    this.timer = this.setInterval(() => { void this.send('app_heartbeat'); }, HEARTBEAT_INTERVAL_MS);
    this.timer?.unref?.();
  }

  start(context = {}) {
    if (this.startedAt) return;
    this.context = safeContext(context);
    this.startedAt = this.now();
    if (!this.active) return;
    void this.send('app_started');
    this.scheduleHeartbeat();
  }

  async setConsent(enabled, context = this.context) {
    const nextEnabled = enabled === true;
    const changed = this.enabled !== nextEnabled;
    this.enabled = nextEnabled;
    this.context = safeContext(context);
    if (!nextEnabled) {
      if (this.timer) this.clearInterval(this.timer);
      this.timer = null;
      return { attempted: false, delivered: false };
    }
    if (!this.startedAt) this.startedAt = this.now();
    this.scheduleHeartbeat();
    if (!changed) return { attempted: false, delivered: false };
    if (!this.active) return { attempted: false, delivered: false };
    const delivered = await this.send('analytics_enabled', { attempts: 2 });
    return {
      attempted: true, delivered,
      ...(!delivered && this.lastDeliveryReason ? { reasonCode: this.lastDeliveryReason } : {}),
    };
  }

  async stop() {
    if (!this.startedAt) return;
    if (this.timer) this.clearInterval(this.timer);
    this.timer = null;
    const uptimeSeconds = Math.max(0, (this.now().getTime() - this.startedAt.getTime()) / 1_000);
    this.startedAt = null;
    await this.send('app_stopped', { uptimeSeconds });
  }
}
