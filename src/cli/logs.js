import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { configuredRedactionSecrets, redactText } from '../core/redaction.js';
import { readVerifiedLogSnapshot } from '../logging/secure-log-sink.js';
import { openRuntimeContext } from '../managed-instance.js';

const CHANNELS = Object.freeze(['application', 'audit', 'security']);
const LEVELS = Object.freeze(['debug', 'info', 'warn', 'error']);
const LEVEL_RANK = Object.freeze(Object.fromEntries(LEVELS.map((level, index) => [level, index])));
const FORMATS = Object.freeze(['json', 'pretty']);
const EVENT_PATTERN = /^[a-z][a-z0-9_.-]{0,95}$/u;
const SERVER_PATTERN = /^[A-Za-z0-9_-]{1,32}$/u;
const OPERATION_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/u;
const ISO_TIMESTAMP_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(?:Z|([+-])(\d{2}):(\d{2}))$/u;
const DURATION_PATTERN = /^([1-9]\d*)(s|m|h|d|w)$/iu;
const DURATION_MULTIPLIERS = Object.freeze({ s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000 });
const MAX_SINCE_MS = 3_650 * 86_400_000;
const TERMINAL_CONTROL_PATTERN = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]/gu;
const ERROR_REDACTION_SECRETS = Symbol('logCliRedactionSecrets');

export const LOG_HELP = `Usage:
  npm run logs:verify
  npm run logs:read -- [options]

Read options:
  --channel <application|audit|security>  Include one exact channel
  --level <debug|info|warn|error>         Include one exact level
  --min-level <debug|info|warn|error>     Include this level and above
  --since <duration|ISO timestamp>        Include records at or after this time (for example 15m, 24h, 7d)
  --event <event-name>                    Include one exact event name
  --server <server-id>                    Include one exact details.server value
  --operation-id <id>                     Include one exact details.operationId value
  --format <json|pretty>                  Output format (default: json)
  --limit <1-10000>                       Newest matching records (default: 100)
  -h, --help                              Show this help without loading configuration or keys`;

export class LogCliUsageError extends Error {
  constructor(message) { super(message); this.name = 'LogCliUsageError'; this.code = 'LOG_CLI_USAGE'; }
}

function usageError(message) { throw new LogCliUsageError(message); }

function enumValue(name, value, values) {
  if (!values.includes(value)) usageError(`${name} must be ${values.slice(0, -1).join(', ')}, or ${values.at(-1)}`);
  return value;
}

function positiveLimit(value) {
  if (!/^[1-9]\d*$/u.test(value)) usageError('--limit must be an integer from 1 to 10000');
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed > 10_000) usageError('--limit must be an integer from 1 to 10000');
  return parsed;
}

function parseSince(value, now) {
  const duration = value.match(DURATION_PATTERN);
  if (duration) {
    const amount = Number(duration[1]);
    const milliseconds = amount * DURATION_MULTIPLIERS[duration[2].toLocaleLowerCase('en-US')];
    if (!Number.isSafeInteger(milliseconds) || milliseconds > MAX_SINCE_MS) {
      usageError('--since duration must be from 1 second through 3650 days');
    }
    const current = now();
    const currentMs = current instanceof Date ? current.getTime() : Number.NaN;
    if (!Number.isFinite(currentMs)) throw new Error('The log reader clock returned an invalid time');
    return currentMs - milliseconds;
  }
  const iso = value.match(ISO_TIMESTAMP_PATTERN);
  if (!iso) {
    usageError('--since must be a duration such as 15m, 24h, or 7d, or a complete ISO timestamp');
  }
  const year = Number(iso[1]); const month = Number(iso[2]); const day = Number(iso[3]);
  const hour = Number(iso[4]); const minute = Number(iso[5]); const second = Number(iso[6]);
  const offsetHour = iso[8] ? Number(iso[9]) : 0; const offsetMinute = iso[8] ? Number(iso[10]) : 0;
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1]
    || hour > 23 || minute > 59 || second > 59 || offsetHour > 23 || offsetMinute > 59) {
    usageError('--since must contain a valid ISO timestamp');
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) usageError('--since must contain a valid ISO timestamp');
  return timestamp;
}

function optionValue(args, index, token) {
  const equals = token.indexOf('=');
  if (equals >= 0) {
    const name = token.slice(0, equals); const value = token.slice(equals + 1);
    if (!value) usageError(`${name} requires a value`);
    return { name, value, nextIndex: index };
  }
  const name = token;
  const value = args[index + 1];
  if (value == null || value.startsWith('-')) usageError(`${name} requires a value`);
  return { name, value, nextIndex: index + 1 };
}

export function parseLogArguments(argv = [], { now = () => new Date() } = {}) {
  if (!Array.isArray(argv)) throw new TypeError('Log arguments must be an array');
  const args = argv.map((value) => String(value));
  let mode = 'verify'; let index = 0;
  if (args[0] && !args[0].startsWith('-')) { mode = args[0]; index = 1; }
  if (!['verify', 'read'].includes(mode)) usageError('Unknown log command');

  const raw = new Map(); let help = false;
  for (; index < args.length; index += 1) {
    const token = args[index];
    if (token === '-h' || token === '--help') {
      if (help) usageError(`${token} may be specified only once`);
      help = true; continue;
    }
    if (!token.startsWith('--')) usageError('Unexpected positional argument');
    const parsed = optionValue(args, index, token); index = parsed.nextIndex;
    const supported = ['--channel', '--level', '--min-level', '--since', '--event', '--server', '--operation-id', '--format', '--limit'];
    if (!supported.includes(parsed.name)) usageError(`Unknown option: ${parsed.name}`);
    if (raw.has(parsed.name)) usageError(`${parsed.name} may be specified only once`);
    raw.set(parsed.name, parsed.value);
  }

  if (mode === 'verify' && raw.size) usageError('The verify command does not accept read filters');
  if (raw.has('--level') && raw.has('--min-level')) usageError('--level and --min-level cannot be used together');

  const options = {
    mode,
    help,
    channel: raw.has('--channel') ? enumValue('--channel', raw.get('--channel'), CHANNELS) : '',
    level: raw.has('--level') ? enumValue('--level', raw.get('--level'), LEVELS) : '',
    minLevel: raw.has('--min-level') ? enumValue('--min-level', raw.get('--min-level'), LEVELS) : '',
    sinceMs: raw.has('--since') ? parseSince(raw.get('--since'), now) : null,
    event: raw.get('--event') ?? '',
    server: raw.get('--server') ?? '',
    operationId: raw.get('--operation-id') ?? '',
    format: raw.has('--format') ? enumValue('--format', raw.get('--format'), FORMATS) : 'json',
    limit: raw.has('--limit') ? positiveLimit(raw.get('--limit')) : 100,
  };
  if (options.event && !EVENT_PATTERN.test(options.event)) usageError('--event must be a controlled event name of at most 96 characters');
  if (options.server && !SERVER_PATTERN.test(options.server)) usageError('--server must be a 1-32 character server ID');
  if (options.operationId && !OPERATION_ID_PATTERN.test(options.operationId)) usageError('--operation-id must contain 1-128 letters, numbers, underscores, or hyphens');
  return Object.freeze(options);
}

function recordTime(record) {
  const timestamp = Date.parse(String(record?.time ?? ''));
  return Number.isFinite(timestamp) ? timestamp : Number.NEGATIVE_INFINITY;
}

export function selectLogRecords(snapshot, options) {
  const records = [];
  for (const file of snapshot?.files ?? []) {
    for (const record of file?.records ?? []) {
      const details = record?.details && typeof record.details === 'object' && !Array.isArray(record.details) ? record.details : {};
      if (options.channel && record.channel !== options.channel) continue;
      if (options.level && record.level !== options.level) continue;
      const recordRank = Object.hasOwn(LEVEL_RANK, record.level) ? LEVEL_RANK[record.level] : -1;
      if (options.minLevel && recordRank < LEVEL_RANK[options.minLevel]) continue;
      if (options.sinceMs != null && recordTime(record) < options.sinceMs) continue;
      if (options.event && record.event !== options.event) continue;
      if (options.server && details.server !== options.server) continue;
      if (options.operationId && details.operationId !== options.operationId) continue;
      records.push(record);
    }
  }
  records.sort((left, right) => String(left.time ?? '').localeCompare(String(right.time ?? ''), 'en-US')
    || String(left.eventId ?? '').localeCompare(String(right.eventId ?? ''), 'en-US'));
  return records.slice(-options.limit);
}

function escapeTerminalControls(value) {
  return String(value).replace(TERMINAL_CONTROL_PATTERN, (character) => {
    const code = character.codePointAt(0);
    return code <= 0xffff ? `\\u${code.toString(16).padStart(4, '0')}` : `\\u{${code.toString(16)}}`;
  });
}

export function formatLogRecord(record, format = 'json') {
  const details = record?.details && typeof record.details === 'object' && !Array.isArray(record.details) ? record.details : {};
  if (format === 'json') return escapeTerminalControls(JSON.stringify(record));
  if (format !== 'pretty') usageError('--format must be json or pretty');
  const level = String(record?.level ?? 'unknown').toLocaleUpperCase('en-US').padEnd(5);
  const main = `${record?.time ?? 'unknown-time'} ${level} [${record?.channel ?? 'unknown'}] ${record?.event ?? 'unknown.event'} - ${record?.message ?? ''}`;
  const detailText = Object.keys(details).length ? ` ${JSON.stringify(details)}` : '';
  return escapeTerminalControls(`${main}${detailText}`);
}

export async function runLogCommand(argv = process.argv.slice(2), dependencies = {}) {
  const {
    openContext = openRuntimeContext,
    loadConfiguration,
    environment = process.env,
    readSnapshot = readVerifiedLogSnapshot,
    stdout = (line) => console.log(line),
    stderr = (line) => console.error(line),
    now = () => new Date(),
  } = dependencies;
  const options = parseLogArguments(argv, { now });
  if (options.help) { stdout(LOG_HELP); return; }

  let context = null; let secrets = [];
  try {
    context = loadConfiguration
      ? { managed: false, config: await loadConfiguration() }
      : await openContext({ environment, initialize: false });
    const { config } = context; const logging = config.logging;
    secrets = configuredRedactionSecrets(config);
    if (!logging.fileEnabled) throw new Error('Encrypted file logging is disabled');
    const snapshot = readSnapshot({ ...logging, generateEncryptionKey: false });
    if (options.mode === 'verify') {
      const files = Object.values(snapshot.summary).reduce((total, value) => total + value.files, 0);
      const records = Object.values(snapshot.summary).reduce((total, value) => total + value.records, 0);
      stdout(`Encrypted log verification passed: ${files} file(s), ${records} authenticated record(s).`);
      return;
    }

    const selected = selectLogRecords(snapshot, options);
    const lines = selected.map((record) => formatLogRecord(record, options.format));
    if (!lines.length) { stderr('No matching authenticated log records.'); return; }
    for (const line of lines) stdout(line);
  } catch (error) {
    if (error && typeof error === 'object') {
      Object.defineProperty(error, ERROR_REDACTION_SECRETS, {
        value: context?.config ? secrets : null, configurable: true,
      });
    }
    throw error;
  } finally {
    await context?.close?.().catch(() => undefined);
  }
}

export async function main(argv = process.argv.slice(2)) {
  try { await runLogCommand(argv); return 0; }
  catch (error) {
    if (error instanceof LogCliUsageError) console.error(redactText(error.message));
    else if (Array.isArray(error?.[ERROR_REDACTION_SECRETS])) {
      console.error(redactText(error?.message ?? 'Encrypted log command failed', error[ERROR_REDACTION_SECRETS]));
    } else console.error('Encrypted log command failed safely; no sensitive value was printed.');
    return 1;
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));
if (isMain) process.exitCode = await main();
