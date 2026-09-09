import crypto from 'node:crypto';
import { isSensitiveKey, redactText } from './core/redaction.js';
import { SecureLogSink } from './logging/secure-log-sink.js';

const LEVELS = Object.freeze({ debug: 10, info: 20, warn: 30, error: 40 });
const CHANNELS = new Set(['application', 'audit', 'security']);
const EVENT_PATTERN = /^[a-z][a-z0-9_.-]{0,95}$/u;
const MAX_DEPTH = 12;
const MAX_NODES = 2_000;
const MAX_STRING_CODE_POINTS = 8_192;
const DEFAULT_MEMORY_RECORDS = 500;
const DEFAULT_MAX_RECORD_BYTES = 64 * 1024;
const MAX_MEMORY_BUFFER_BYTES = 8 * 1024 * 1024;

function boundedText(value, maximum = MAX_STRING_CODE_POINTS) {
  const text = String(value ?? '');
  if (text.length <= maximum) return text;
  const points = [];
  for (const point of text) {
    if (points.length === maximum) return `${points.join('')}...[TRUNCATED]`;
    points.push(point);
  }
  return text;
}

function consoleText(value) { return String(value).replace(/[\r\n\u2028\u2029]/gu, (character) => JSON.stringify(character).slice(1, -1)); }

function eventName(value, fallback = 'application.message') {
  const normalized = String(value ?? '').trim().toLocaleLowerCase('en-US');
  return EVENT_PATTERN.test(normalized) ? normalized : fallback;
}

export function redact(value, seen = new WeakSet(), secrets = [], depth = 0, budget = { nodes: 0 }) {
  budget.nodes += 1;
  if (budget.nodes > MAX_NODES || depth > MAX_DEPTH) return '[TRUNCATED]';
  if (typeof value === 'string') return redactText(boundedText(value), secrets);
  if (typeof value === 'bigint') return value.toString(10);
  if (typeof value === 'symbol' || typeof value === 'function') return `[${typeof value}]`;
  if (!value || typeof value !== 'object') return value;
  if (Buffer.isBuffer(value) || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    const bytes = value.byteLength ?? value.length ?? 0;
    return `[BINARY REDACTED: ${bytes} byte${bytes === 1 ? '' : 's'}]`;
  }
  if (seen.has(value)) return '[Circular]';
  seen.add(value);
  if (Array.isArray(value)) return value.slice(0, MAX_NODES).map((item) => redact(item, seen, secrets, depth + 1, budget));
  if (value instanceof Error) {
    return {
      name: boundedText(value.name, 128),
      message: redactText(boundedText(value.message), secrets),
      ...(value.code == null ? {} : { code: redactText(boundedText(value.code, 256), secrets) }),
      ...(value.stack == null ? {} : { stack: redactText(boundedText(value.stack, 16_384), secrets) }),
    };
  }
  return Object.fromEntries(Object.entries(value).slice(0, MAX_NODES).map(([key, item]) => [
    redactText(boundedText(key, 256), secrets),
    isSensitiveKey(key) ? '[REDACTED]' : redact(item, seen, secrets, depth + 1, budget),
  ]));
}

export class Logger {
  #secrets;

  constructor({
    level = 'info', pretty = false, sink = console, secrets = [], consoleEnabled = true,
    fileEnabled = false, fileSink = null, memoryRecords = DEFAULT_MEMORY_RECORDS,
    now = () => new Date(), instanceId = crypto.randomUUID(), ...fileOptions
  } = {}) {
    if (!Number.isInteger(memoryRecords) || memoryRecords < 100 || memoryRecords > 10_000) {
      throw new Error('Logger memoryRecords must be an integer from 100 to 10000');
    }
    this.level = LEVELS[level] ?? LEVELS.info;
    this.pretty = Boolean(pretty); this.sink = sink; this.consoleEnabled = Boolean(consoleEnabled);
    this.now = now; this.instanceId = instanceId; this.fileFailureReported = false;
    this.memoryRecordLimit = memoryRecords; this.memoryRecordLines = []; this.memoryRecordBytes = 0;
    this.memoryMaxRecordBytes = Number.isInteger(fileOptions.maxRecordBytes) ? fileOptions.maxRecordBytes : DEFAULT_MAX_RECORD_BYTES;
    this.fileOptions = Object.freeze({ ...fileOptions }); this.ownsFileSink = !fileSink && fileEnabled;
    this.fileSink = fileSink ?? (fileEnabled ? new SecureLogSink(fileOptions) : null);
    this.#secrets = Object.freeze([...new Set((Array.isArray(secrets) ? secrets : [])
      .filter((secret) => typeof secret === 'string' && secret.length > 0))]);
  }

  start() {
    if (this.ownsFileSink && this.fileSink?.closed) this.fileSink = new SecureLogSink(this.fileOptions);
    this.fileSink?.open(); this.fileFailureReported = false; return this;
  }

  remember(record) {
    let retained = record; let line = JSON.stringify(retained);
    if (Buffer.byteLength(line) > this.memoryMaxRecordBytes) {
      retained = {
        schemaVersion: record.schemaVersion,
        time: record.time,
        level: 'warn',
        channel: record.channel,
        event: 'logging.record_truncated',
        message: 'A structured log record exceeded the configured limit and its details were omitted.',
        details: { originalEvent: record.event },
      };
      line = JSON.stringify(retained);
    }
    const bytes = Buffer.byteLength(line); this.memoryRecordLines.push({ line, bytes }); this.memoryRecordBytes += bytes;
    while (this.memoryRecordLines.length > this.memoryRecordLimit || this.memoryRecordBytes > MAX_MEMORY_BUFFER_BYTES) {
      this.memoryRecordBytes -= this.memoryRecordLines.shift().bytes;
    }
  }

  recentRecords({ channel = '', minLevel = '', query = '', limit = 100 } = {}) {
    if (channel && !CHANNELS.has(channel)) throw new Error('Diagnostic channel must be application, audit, or security');
    if (minLevel && !Object.hasOwn(LEVELS, minLevel)) throw new Error('Diagnostic level must be debug, info, warn, or error');
    if (typeof query !== 'string' || Array.from(query).length > 128 || /[\u0000-\u001F\u007F]/u.test(query)) {
      throw new Error('Diagnostic search must be at most 128 characters without control characters');
    }
    if (!Number.isInteger(limit) || limit < 1 || limit > 250) throw new Error('Diagnostic limit must be an integer from 1 to 250');
    const needle = query.trim().toLocaleLowerCase('en-US'); const threshold = minLevel ? LEVELS[minLevel] : 0;
    const records = [];
    for (let index = this.memoryRecordLines.length - 1; index >= 0 && records.length < limit; index -= 1) {
      const line = this.memoryRecordLines[index].line; const record = JSON.parse(line);
      if (channel && record.channel !== channel) continue;
      if ((LEVELS[record.level] ?? 0) < threshold) continue;
      if (needle && !line.toLocaleLowerCase('en-US').includes(needle)) continue;
      records.push(record);
    }
    return records;
  }

  write(level, message, fields = {}, { channel = 'application', force = false, event = '' } = {}) {
    if (!force && (LEVELS[level] ?? 100) < this.level) return true;
    const input = fields && typeof fields === 'object' && !Array.isArray(fields) ? fields : { value: fields };
    const selectedEvent = eventName(event || input.event, channel === 'application' ? 'application.message' : `${channel}.event`);
    const { event: ignoredEvent, ...details } = input;
    const record = redact({
      schemaVersion: 1,
      time: this.now().toISOString(),
      eventId: crypto.randomUUID(),
      instanceId: this.instanceId,
      level,
      channel,
      event: selectedEvent,
      message: boundedText(message, 2_048),
      details,
    }, new WeakSet(), this.#secrets);
    const text = this.pretty
      ? `${record.time} ${level.toLocaleUpperCase('en-US').padEnd(5)} ${consoleText(record.event)} ${consoleText(record.message)}${Object.keys(record.details).length ? ` ${consoleText(JSON.stringify(record.details))}` : ''}`
      : JSON.stringify(record);
    this.remember(record);
    const method = level === 'error' ? 'error' : level === 'warn' ? 'warn' : 'log';
    if (this.consoleEnabled) (this.sink[method] ?? this.sink.log).call(this.sink, text);
    try { this.fileSink?.writeRecord(record); }
    catch {
      if (!this.fileFailureReported) {
        this.fileFailureReported = true;
        (this.sink.error ?? this.sink.log).call(this.sink, `${new Date().toISOString()} ERROR secure file logging became unavailable; readiness will fail`);
      }
      return false;
    }
    return true;
  }

  debug(message, fields) { this.write('debug', message, fields); }
  info(message, fields) { this.write('info', message, fields); }
  warn(message, fields) { this.write('warn', message, fields); }
  error(message, fields) { this.write('error', message, fields); }
  audit(event, fields = {}, message = 'Privileged or operational audit event') {
    return this.write('info', message, fields, { channel: 'audit', force: true, event });
  }
  security(event, fields = {}, level = 'warn', message = 'Security-relevant event') {
    return this.write(LEVELS[level] ? level : 'warn', message, fields, { channel: 'security', force: true, event });
  }
  close() { this.fileSink?.close(); this.memoryRecordLines.length = 0; this.memoryRecordBytes = 0; }
  get healthy() { return !this.fileSink || this.fileSink.healthy; }
}
