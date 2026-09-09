import {
  chunkText, normalizeWhitespace, sanitizeForDiscord, truncateCodePoints,
} from '../../core/sanitize.js';
import { redactText } from '../../core/redaction.js';

const sleepDefault = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function safeDiscordResource(resource, secrets = []) {
  const value = String(resource ?? '');
  return redactText(value, secrets).replace(
    /(\/(?:interactions|webhooks)\/[^/\s?#]+\/)[^/\s?#]+/gi,
    '$1[REDACTED]',
  );
}

function safeDiscordErrorDetails(data, statusText, secrets = []) {
  const candidate = typeof data === 'string' ? data : data?.message;
  const text = redactText(candidate || statusText || 'request rejected', secrets).replace(/[\r\n]+/g, ' ').trim();
  return Array.from(text).slice(0, 300).join('');
}

function autocompleteChoices(choices) {
  const safe = [];
  for (const choice of Array.isArray(choices) ? choices : []) {
    if (safe.length >= 25) break;
    if (!choice) continue;
    const name = truncateCodePoints(sanitizeForDiscord(normalizeWhitespace(choice.name), 6_000), 100, '');
    let value;
    if (typeof choice.value === 'string') {
      value = truncateCodePoints(normalizeWhitespace(choice.value), 100, '');
      if (!value) continue;
    } else if (typeof choice.value === 'number' && Number.isFinite(choice.value)) value = choice.value;
    else continue;
    if (!name) continue;
    safe.push({ name, value });
  }
  return safe;
}

export class DiscordRest {
  constructor(config, { fetchImpl = globalThis.fetch, sleep = sleepDefault, logger = null } = {}) {
    if (typeof fetchImpl !== 'function') throw new Error('A Fetch API implementation is required');
    this.config = config; this.fetch = fetchImpl; this.sleep = sleep; this.logger = logger;
    this.baseUrl = 'https://discord.com/api/v10';
  }

  async request(method, resource, { body, auth = true, retries = 3 } = {}) {
    let lastError;
    const secrets = this.config.redactionSecrets ?? [];
    for (let attempt = 0; attempt <= retries; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.config.restTimeoutMs ?? 10_000);
      try {
        const headers = { 'Content-Type': 'application/json', 'User-Agent': 'BLCKSNAKE-Command/1.0' };
        if (auth) headers.Authorization = `Bot ${this.config.token}`;
        const response = await this.fetch(`${this.baseUrl}${resource}`, {
          method, headers, signal: controller.signal, redirect: 'error',
          body: body === undefined ? undefined : JSON.stringify(body),
        });
        const text = await response.text();
        let data = null;
        if (text) { try { data = JSON.parse(text); } catch { data = text; } }
        if (response.ok) return data;
        if (response.status === 429 && attempt < retries) {
          const delay = Math.max(50, Math.ceil(Number(data?.retry_after ?? 1) * 1_000));
          this.logger?.warn?.('Discord REST rate limited', {
            event: 'discord.rest_rate_limited', component: 'discord', outcome: 'retrying',
            method, statusCode: 429, attempt: attempt + 1, retryAfterMs: delay,
          });
          await this.sleep(delay); continue;
        }
        if (response.status >= 500 && attempt < retries) {
          await this.sleep(Math.min(2_000, 100 * 2 ** attempt)); continue;
        }
        const details = safeDiscordErrorDetails(data, response.statusText, secrets);
        throw new Error(`Discord REST ${method} ${safeDiscordResource(resource, secrets)} failed (${response.status}): ${details}`);
      } catch (error) {
        const responseError = /^Discord REST/.test(String(error?.message ?? ''));
        if (error?.name === 'AbortError') {
          lastError = new Error(`Discord REST request timed out: ${method} ${safeDiscordResource(resource, secrets)}`);
        } else if (responseError) lastError = error;
        else {
          const details = redactText(error?.message ?? 'network request failed', secrets).replace(/[\r\n]+/g, ' ').trim();
          lastError = new Error(`Discord REST ${method} ${safeDiscordResource(resource, secrets)} request failed: ${Array.from(details).slice(0, 300).join('')}`);
        }
        if (attempt >= retries || responseError) {
          this.logger?.warn?.('Discord REST request failed', {
            event: 'discord.rest_failed', component: 'discord', outcome: 'failed', method,
            reasonCode: error?.name ?? 'request_failed', attempt: attempt + 1,
          });
          throw lastError;
        }
        await this.sleep(Math.min(2_000, 100 * 2 ** attempt));
      } finally { clearTimeout(timer); }
    }
    throw lastError;
  }

  async sendMessage(channelId, content) {
    const safe = sanitizeForDiscord(redactText(content, this.config.redactionSecrets), 20_000);
    const chunks = chunkText('', safe, this.config.maxMessageLength ?? 1_900);
    const results = [];
    for (const chunk of chunks) {
      results.push(await this.request('POST', `/channels/${channelId}/messages`, {
        body: { content: chunk, allowed_mentions: { parse: [] } },
      }));
    }
    return results;
  }

  registerGuildCommands(commands) {
    return this.request('PUT', `/applications/${this.config.applicationId}/guilds/${this.config.guildId}/commands`, { body: commands });
  }

  deferInteraction(interaction, { ephemeral = true } = {}) {
    return this.request('POST', `/interactions/${interaction.id}/${interaction.token}/callback`, {
      auth: false, body: { type: 5, data: ephemeral ? { flags: 64 } : {} },
    });
  }

  autocompleteInteraction(interaction, choices) {
    const redactedChoices = (Array.isArray(choices) ? choices : []).map((choice) => ({
      ...choice, name: redactText(choice?.name, this.config.redactionSecrets),
    }));
    return this.request('POST', `/interactions/${interaction.id}/${interaction.token}/callback`, {
      auth: false, retries: 0, body: { type: 8, data: { choices: autocompleteChoices(redactedChoices) } },
    });
  }

  editInteraction(interaction, content) {
    return this.request('PATCH', `/webhooks/${this.config.applicationId}/${interaction.token}/messages/@original`, {
      auth: false, body: { content: sanitizeForDiscord(redactText(content, this.config.redactionSecrets), 1_900), allowed_mentions: { parse: [] } },
    });
  }
}
