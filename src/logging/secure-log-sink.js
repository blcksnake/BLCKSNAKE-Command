import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { isPathWithin } from '../core/filesystem.js';

const FORMAT = 'asa-crosschat-encrypted-log';
const FORMAT_VERSION = 1;
const CIPHER = 'aes-256-gcm';
const CHANNELS = Object.freeze(['application', 'audit', 'security']);
const CHANNEL_SET = new Set(CHANNELS);
const ARCHIVE_PATTERN = /^(application|audit|security)\.(\d{8}T\d{9}Z)\.([A-Za-z0-9_-]{22})\.jsonl\.enc$/u;
const CURRENT_PATTERN = /^(application|audit|security)\.jsonl\.enc$/u;
const ZERO_CHAIN = Buffer.alloc(32).toString('base64url');
const CHECKPOINT_FILE = 'integrity.checkpoint.json';
const SNAPSHOT_ATTEMPTS = 4;
const SNAPSHOT_RETRY_DELAYS_MS = Object.freeze([10, 25, 50]);

function fail(message) { throw new Error(`Secure logging error: ${message}`); }

function boundedInteger(value, name, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    fail(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

function decodeKey(value) {
  const encoded = String(value ?? '').trim();
  let key;
  if (/^(?:hex:)?[a-f0-9]{64}$/iu.test(encoded)) key = Buffer.from(encoded.replace(/^hex:/iu, ''), 'hex');
  else if (/^(?:base64:)?[A-Za-z0-9+/]{43}=$/u.test(encoded)) key = Buffer.from(encoded.replace(/^base64:/u, ''), 'base64');
  else fail('the encryption key must be exactly 32 bytes encoded as hexadecimal or base64');
  if (key.length !== 32) fail('the decoded encryption key must contain exactly 32 bytes');
  return key;
}

function secureDirectory(directory) {
  const absolute = path.resolve(directory);
  try {
    const current = fs.lstatSync(absolute);
    if (current.isSymbolicLink() || !current.isDirectory()) fail('the log directory must be a real directory, not a link or special file');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    fs.mkdirSync(absolute, { recursive: true, mode: 0o700 });
  }
  if (process.platform !== 'win32') {
    fs.chmodSync(absolute, 0o700);
    if ((fs.statSync(absolute).mode & 0o077) !== 0) fail('the log directory permissions must be 0700');
  }
  return absolute;
}

function assertRegularFile(file, maximumBytes, label) {
  const details = fs.lstatSync(file);
  if (details.isSymbolicLink() || !details.isFile()) fail(`${label} must be a real regular file`);
  if (details.size < 1 || details.size > maximumBytes) fail(`${label} is empty or exceeds its configured size limit`);
  if (process.platform !== 'win32' && (details.mode & 0o077) !== 0) fail(`${label} permissions must be 0600`);
  return details;
}

export function loadLogEncryptionKey({ encryptionKey = '', encryptionKeyFile = '', generateEncryptionKey = false, directory = '' } = {}) {
  if (encryptionKey && encryptionKeyFile) fail('configure only one encryption-key source');
  if (generateEncryptionKey && !encryptionKeyFile) fail('automatic key generation requires encryptionKeyFile');
  if (encryptionKey) return decodeKey(encryptionKey);
  if (!encryptionKeyFile) fail('an encryption key is required');
  const file = path.resolve(encryptionKeyFile);
  if (directory && isPathWithin(directory, file)) fail('the encryption key must be stored outside the log directory');
  try {
    assertRegularFile(file, 256, 'the log encryption key file');
    return decodeKey(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT' || !generateEncryptionKey) throw error;
  }
  const parent = path.dirname(file);
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const parentDetails = fs.lstatSync(parent);
  if (parentDetails.isSymbolicLink() || !parentDetails.isDirectory()) fail('the log-key directory must be a real directory');
  const generated = crypto.randomBytes(32);
  const content = `base64:${generated.toString('base64')}\n`;
  try { fs.writeFileSync(file, content, { encoding: 'utf8', mode: 0o600, flag: 'wx' }); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    assertRegularFile(file, 256, 'the log encryption key file');
    return decodeKey(fs.readFileSync(file, 'utf8'));
  }
  if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
  return generated;
}

function derive(masterKey, fileId, channel, purpose) {
  const salt = Buffer.from(fileId, 'base64url');
  return Buffer.from(crypto.hkdfSync('sha256', masterKey, salt, Buffer.from(`${FORMAT}\u001f${FORMAT_VERSION}\u001f${channel}\u001f${purpose}`), 32));
}

function headerPayload(header) {
  return JSON.stringify({
    format: FORMAT,
    version: FORMAT_VERSION,
    channel: header.channel,
    fileId: header.fileId,
    createdAt: header.createdAt,
    previousFileChain: header.previousFileChain,
  });
}

function headerMac(masterKey, header) {
  return crypto.createHmac('sha256', derive(masterKey, header.fileId, header.channel, 'header'))
    .update(headerPayload(header)).digest('base64url');
}

function checkpointPayload(checkpoint) {
  return JSON.stringify({
    format: `${FORMAT}-checkpoint`,
    version: FORMAT_VERSION,
    updatedAt: checkpoint.updatedAt,
    channels: Object.fromEntries(CHANNELS.map((channel) => [channel, checkpoint.channels[channel]])),
  });
}

function checkpointMac(masterKey, checkpoint) {
  return crypto.createHmac('sha256', masterKey).update(`${FORMAT}\u001fcheckpoint\u001f`).update(checkpointPayload(checkpoint)).digest('base64url');
}

function checkpointFromStates(states, masterKey, now) {
  const checkpoint = {
    format: `${FORMAT}-checkpoint`, version: FORMAT_VERSION, updatedAt: now().toISOString(),
    channels: Object.fromEntries(CHANNELS.map((channel) => {
      const state = states.get(channel);
      return [channel, { fileId: state.header.fileId, sequence: state.sequence, lastChain: state.lastChain }];
    })),
  };
  return { ...checkpoint, mac: checkpointMac(masterKey, checkpoint) };
}

function validateCheckpoint(checkpoint, states, masterKey) {
  if (!checkpoint || checkpoint.format !== `${FORMAT}-checkpoint` || checkpoint.version !== FORMAT_VERSION
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(checkpoint.updatedAt ?? '')
    || !/^[A-Za-z0-9_-]{43}$/u.test(checkpoint.mac ?? '') || !checkpoint.channels) {
    fail('the encrypted log checkpoint is invalid or unsupported');
  }
  if (!safeEqualEncoded(checkpoint.mac, checkpointMac(masterKey, checkpoint))) fail('the encrypted log checkpoint failed authentication');
  for (const channel of CHANNELS) {
    const expected = states.get(channel); const actual = checkpoint.channels[channel];
    if (!expected || !actual || actual.fileId !== expected.header.fileId || actual.sequence !== expected.sequence || actual.lastChain !== expected.lastChain) {
      fail('the encrypted log checkpoint does not match the current log tail');
    }
  }
}

function safeEqualEncoded(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left); const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function validateHeader(header, masterKey, expectedChannel = '') {
  if (!header || header.format !== FORMAT || header.version !== FORMAT_VERSION || !CHANNEL_SET.has(header.channel)) {
    fail('an encrypted log header is invalid or unsupported');
  }
  if (expectedChannel && header.channel !== expectedChannel) fail('the encrypted log channel does not match its filename');
  if (!/^[A-Za-z0-9_-]{22}$/u.test(header.fileId ?? '') || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(header.createdAt ?? '')) {
    fail('an encrypted log header contains malformed metadata');
  }
  if (!/^[A-Za-z0-9_-]{43}$/u.test(header.previousFileChain ?? '') || !/^[A-Za-z0-9_-]{43}$/u.test(header.headerMac ?? '')) {
    fail('an encrypted log header contains malformed integrity data');
  }
  if (!safeEqualEncoded(header.headerMac, headerMac(masterKey, header))) fail('an encrypted log header failed authentication');
  return header;
}

function recordAad(header, sequence, previousChain) {
  return Buffer.from(`${FORMAT}\u001f${FORMAT_VERSION}\u001f${header.channel}\u001f${header.fileId}\u001f${sequence}\u001f${previousChain}`);
}

function sealRecord(record, masterKey, header, sequence, previousChain, randomBytes) {
  const nonce = randomBytes(12);
  if (!Buffer.isBuffer(nonce) || nonce.length !== 12) fail('the nonce generator must return exactly 12 bytes');
  const aad = recordAad(header, sequence, previousChain);
  const cipher = crypto.createCipheriv(CIPHER, derive(masterKey, header.fileId, header.channel, 'encryption'), nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(record), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const chain = crypto.createHmac('sha256', derive(masterKey, header.fileId, header.channel, 'chain'))
    .update(aad).update(nonce).update(ciphertext).update(tag).digest('base64url');
  return {
    v: FORMAT_VERSION,
    seq: sequence,
    nonce: nonce.toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
    tag: tag.toString('base64url'),
    chain,
  };
}

function openRecord(envelope, masterKey, header, expectedSequence, previousChain) {
  if (!envelope || envelope.v !== FORMAT_VERSION || envelope.seq !== expectedSequence
    || !/^[A-Za-z0-9_-]{16}$/u.test(envelope.nonce ?? '') || !/^[A-Za-z0-9_-]{22}$/u.test(envelope.tag ?? '')
    || !/^[A-Za-z0-9_-]+$/u.test(envelope.ciphertext ?? '') || !/^[A-Za-z0-9_-]{43}$/u.test(envelope.chain ?? '')) {
    fail('an encrypted log record is malformed or out of sequence');
  }
  const aad = recordAad(header, expectedSequence, previousChain);
  const nonce = Buffer.from(envelope.nonce, 'base64url');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64url');
  const tag = Buffer.from(envelope.tag, 'base64url');
  const expectedChain = crypto.createHmac('sha256', derive(masterKey, header.fileId, header.channel, 'chain'))
    .update(aad).update(nonce).update(ciphertext).update(tag).digest('base64url');
  if (!safeEqualEncoded(envelope.chain, expectedChain)) fail('an encrypted log record failed its integrity-chain check');
  try {
    const decipher = crypto.createDecipheriv(CIPHER, derive(masterKey, header.fileId, header.channel, 'encryption'), nonce);
    decipher.setAAD(aad); decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    const record = JSON.parse(plaintext);
    if (!record || record.channel !== header.channel) fail('a decrypted log record has the wrong channel');
    return record;
  } catch (error) {
    if (String(error.message).startsWith('Secure logging error:')) throw error;
    fail('an encrypted log record could not be authenticated');
  }
}

function readLines(raw, maximumBytes) {
  if (!Buffer.isBuffer(raw) || raw.length < 1 || raw.length > maximumBytes) {
    fail('an encrypted log file is empty or exceeds its configured size limit');
  }
  const text = raw.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(raw)) fail('an encrypted log file is not valid UTF-8');
  if (!text.endsWith('\n')) fail('an encrypted log file is truncated');
  const lines = text.slice(0, -1).split('\n');
  if (lines.length < 1 || lines.some((line) => !line)) fail('an encrypted log file contains an invalid line');
  return lines;
}

function parseEncryptedLogBytes(raw, masterKey, { expectedChannel = '', maximumBytes = 1024 * 1024 * 1024 } = {}) {
  const lines = readLines(raw, maximumBytes);
  let header;
  try { header = JSON.parse(lines[0]); } catch { fail('an encrypted log header is not valid JSON'); }
  validateHeader(header, masterKey, expectedChannel);
  const records = []; const nonces = new Set(); let previousChain = header.previousFileChain; let sequence = 0;
  for (const line of lines.slice(1)) {
    let envelope;
    try { envelope = JSON.parse(line); } catch { fail('an encrypted log record envelope is not valid JSON'); }
    sequence += 1;
    if (nonces.has(envelope.nonce)) fail('an encrypted log file reuses an AES-GCM nonce');
    nonces.add(envelope.nonce);
    records.push(openRecord(envelope, masterKey, header, sequence, previousChain));
    previousChain = envelope.chain;
  }
  return { header, records, sequence, lastChain: previousChain, nonces, bytes: raw.length };
}

export function readEncryptedLogFile(file, masterKey, { expectedChannel = '', maximumBytes = 1024 * 1024 * 1024 } = {}) {
  const absolute = path.resolve(file);
  const details = assertRegularFile(absolute, maximumBytes, 'an encrypted log file');
  const raw = fs.readFileSync(absolute);
  if (raw.length !== details.size) fail('an encrypted log file changed while it was being read');
  return parseEncryptedLogBytes(raw, masterKey, { expectedChannel, maximumBytes });
}

function archiveTimestamp(date) { return date.toISOString().replace(/[-:.]/gu, ''); }
function currentName(channel) { return `${channel}.jsonl.enc`; }

function recognizedFiles(directory, channel) {
  const current = currentName(channel);
  const archives = [];
  for (const name of fs.readdirSync(directory)) {
    if (name === current) continue;
    const match = name.match(ARCHIVE_PATTERN);
    if (!match || match[1] !== channel) continue;
    const file = path.join(directory, name); const details = fs.lstatSync(file);
    if (details.isSymbolicLink() || !details.isFile()) fail('a recognized archived log path is not a regular file');
    archives.push({ name, file, details });
  }
  archives.sort((left, right) => left.name.localeCompare(right.name, 'en-US'));
  return { current: path.join(directory, current), archives };
}

function chainOrder(items) {
  if (items.length < 2) return items;
  const lastChains = new Set(items.map(({ parsed }) => parsed.lastChain));
  const heads = items.filter(({ parsed }) => !lastChains.has(parsed.header.previousFileChain));
  if (heads.length !== 1) fail('the archived log files do not form one unambiguous integrity chain');
  const ordered = []; const unused = new Set(items); let current = heads[0];
  while (current) {
    ordered.push(current); unused.delete(current);
    const next = [...unused].filter(({ parsed }) => parsed.header.previousFileChain === current.parsed.lastChain);
    if (next.length > 1) fail('the archived log-file integrity chain contains a branch');
    current = next[0];
  }
  if (unused.size) fail('the archived log-file integrity chain is disconnected');
  return ordered;
}

function authenticatedArchives(directory, channel, masterKey, maximumBytes) {
  const { archives } = recognizedFiles(directory, channel);
  return chainOrder(archives.map((archive) => ({
    ...archive,
    parsed: readEncryptedLogFile(archive.file, masterKey, { expectedChannel: channel, maximumBytes }),
  })));
}

function createHeader(channel, previousFileChain, now, randomBytes, masterKey) {
  const fileIdBytes = randomBytes(16);
  if (!Buffer.isBuffer(fileIdBytes) || fileIdBytes.length !== 16) fail('the file-ID generator must return exactly 16 bytes');
  const header = {
    format: FORMAT,
    version: FORMAT_VERSION,
    channel,
    fileId: fileIdBytes.toString('base64url'),
    createdAt: now().toISOString(),
    previousFileChain,
  };
  return { ...header, headerMac: headerMac(masterKey, header) };
}

function writeExclusive(file, content) {
  const descriptor = fs.openSync(file, 'wx', 0o600);
  try { fs.writeFileSync(descriptor, content, 'utf8'); fs.fsyncSync(descriptor); }
  finally { fs.closeSync(descriptor); }
  if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
}

function writeAtomic(file, content) {
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  try {
    writeExclusive(temporary, content);
    fs.renameSync(temporary, file);
    if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
  } catch (error) {
    try { fs.unlinkSync(temporary); } catch { /* best-effort cleanup of an unpublished checkpoint */ }
    throw error;
  }
}

export class SecureLogSink {
  constructor({
    directory = './logs', encryptionKey = '', encryptionKeyFile = '', generateEncryptionKey = false,
    encryptionRequired = true, maxFileBytes = 10 * 1024 * 1024, maxFiles = 10, retentionDays = 30,
    auditRetentionDays = 180, securityRetentionDays = 180, maxRecordBytes = 64 * 1024,
    now = () => new Date(), randomBytes = crypto.randomBytes,
  } = {}) {
    if (encryptionRequired !== true) fail('file logging requires encryptionRequired=true');
    this.directory = path.resolve(directory);
    this.encryptionKey = encryptionKey; this.encryptionKeyFile = encryptionKeyFile ? path.resolve(encryptionKeyFile) : '';
    this.generateEncryptionKey = generateEncryptionKey;
    this.maxFileBytes = boundedInteger(maxFileBytes, 'maxFileBytes', 512, 1024 * 1024 * 1024);
    this.maxFiles = boundedInteger(maxFiles, 'maxFiles', 2, 1000);
    this.retentionDays = Object.freeze({
      application: boundedInteger(retentionDays, 'retentionDays', 1, 3650),
      audit: boundedInteger(auditRetentionDays, 'auditRetentionDays', 1, 3650),
      security: boundedInteger(securityRetentionDays, 'securityRetentionDays', 1, 3650),
    });
    this.maxRecordBytes = boundedInteger(maxRecordBytes, 'maxRecordBytes', 1024, 1024 * 1024);
    this.now = now; this.randomBytes = randomBytes; this.masterKey = null; this.states = new Map();
    this.opened = false; this.closed = false; this.failed = false;
  }

  open() {
    if (this.opened) return this;
    if (this.closed) fail('the log sink is closed');
    secureDirectory(this.directory);
    this.masterKey = loadLogEncryptionKey({
      encryptionKey: this.encryptionKey,
      encryptionKeyFile: this.encryptionKeyFile,
      generateEncryptionKey: this.generateEncryptionKey,
      directory: this.directory,
    });
    for (const channel of CHANNELS) this.openChannel(channel);
    this.openCheckpoint();
    for (const channel of CHANNELS) this.prune(channel);
    this.opened = true;
    return this;
  }

  openCheckpoint() {
    const file = path.join(this.directory, CHECKPOINT_FILE);
    try {
      assertRegularFile(file, 16_384, 'the encrypted log checkpoint');
      let checkpoint;
      try { checkpoint = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { fail('the encrypted log checkpoint is not valid JSON'); }
      validateCheckpoint(checkpoint, this.states, this.masterKey);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      const hasHistory = CHANNELS.some((channel) => this.states.get(channel).sequence > 0
        || recognizedFiles(this.directory, channel).archives.length > 0);
      if (hasHistory) fail('the encrypted log checkpoint is missing for an existing log history');
      this.writeCheckpoint();
    }
  }

  writeCheckpoint() {
    const checkpoint = checkpointFromStates(this.states, this.masterKey, this.now);
    writeAtomic(path.join(this.directory, CHECKPOINT_FILE), `${JSON.stringify(checkpoint)}\n`);
  }

  openChannel(channel) {
    const files = recognizedFiles(this.directory, channel); let prior = null;
    const archives = authenticatedArchives(this.directory, channel, this.masterKey, this.maxFileBytes + this.maxRecordBytes + 16_384);
    for (const archive of archives) {
      const { parsed } = archive;
      if (prior && parsed.header.previousFileChain !== prior.lastChain) fail('the archived log-file chain is discontinuous');
      prior = parsed;
    }
    let parsed;
    try {
      parsed = readEncryptedLogFile(files.current, this.masterKey, { expectedChannel: channel, maximumBytes: this.maxFileBytes + this.maxRecordBytes + 16_384 });
      if (prior && parsed.header.previousFileChain !== prior.lastChain) fail('the current log file is disconnected from its archive chain');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      const header = createHeader(channel, prior?.lastChain ?? ZERO_CHAIN, this.now, this.randomBytes, this.masterKey);
      writeExclusive(files.current, `${JSON.stringify(header)}\n`);
      parsed = { header, records: [], sequence: 0, lastChain: header.previousFileChain, nonces: new Set(), bytes: Buffer.byteLength(JSON.stringify(header)) + 1 };
    }
    this.states.set(channel, { file: files.current, ...parsed });
  }

  rotate(channel) {
    const state = this.states.get(channel); const stamp = archiveTimestamp(this.now());
    const archive = path.join(this.directory, `${channel}.${stamp}.${state.header.fileId}.jsonl.enc`);
    if (fs.existsSync(archive)) fail('an encrypted log archive name collision was refused');
    fs.renameSync(state.file, archive);
    const header = createHeader(channel, state.lastChain, this.now, this.randomBytes, this.masterKey);
    try { writeExclusive(state.file, `${JSON.stringify(header)}\n`); }
    catch (error) {
      try { fs.renameSync(archive, state.file); } catch { /* preserve the original error */ }
      throw error;
    }
    this.states.set(channel, {
      file: state.file, header, records: [], sequence: 0, lastChain: header.previousFileChain,
      nonces: new Set(), bytes: Buffer.byteLength(JSON.stringify(header)) + 1,
    });
    this.prune(channel);
  }

  prune(channel) {
    const archives = authenticatedArchives(this.directory, channel, this.masterKey, this.maxFileBytes + this.maxRecordBytes + 16_384);
    const cutoff = this.now().getTime() - this.retentionDays[channel] * 86_400_000;
    let removeCount = 0;
    while (removeCount < archives.length && Date.parse(archives[removeCount].parsed.header.createdAt) < cutoff) removeCount += 1;
    const keepArchives = this.maxFiles - 1;
    removeCount = Math.max(removeCount, archives.length - keepArchives);
    const remove = new Set(archives.slice(0, removeCount).map(({ file }) => file));
    for (const file of remove) {
      const details = fs.lstatSync(file);
      if (details.isSymbolicLink() || !details.isFile()) fail('log retention refused a non-regular archive path');
      fs.unlinkSync(file);
    }
  }

  writeRecord(record) {
    if (!this.opened || this.closed || !this.masterKey) fail('the log sink is not open');
    if (this.failed) fail('the log sink previously failed and is no longer writable');
    const channel = record?.channel;
    if (!CHANNEL_SET.has(channel)) fail('the record channel is unsupported');
    let safeRecord = record; let serialized = JSON.stringify(safeRecord);
    if (Buffer.byteLength(serialized) > this.maxRecordBytes) {
      safeRecord = {
        schemaVersion: record.schemaVersion,
        time: record.time,
        level: 'warn',
        channel,
        event: 'logging.record_truncated',
        message: 'A structured log record exceeded the configured limit and its details were omitted.',
        details: { originalEvent: record.event },
      };
      serialized = JSON.stringify(safeRecord);
    }
    if (Buffer.byteLength(serialized) > this.maxRecordBytes) fail('the bounded fallback log record exceeds maxRecordBytes');
    try {
      let state = this.states.get(channel); const at = this.now();
      const sequence = state.sequence + 1;
      let envelope = sealRecord(safeRecord, this.masterKey, state.header, sequence, state.lastChain, this.randomBytes);
      if (state.nonces.has(envelope.nonce)) fail('AES-GCM nonce reuse was refused');
      let line = `${JSON.stringify(envelope)}\n`;
      const rotationRequired = state.sequence > 0 && (state.header.createdAt.slice(0, 10) !== at.toISOString().slice(0, 10)
        || state.bytes + Buffer.byteLength(line) > this.maxFileBytes);
      if (rotationRequired) {
        this.rotate(channel); state = this.states.get(channel);
        envelope = sealRecord(safeRecord, this.masterKey, state.header, 1, state.lastChain, this.randomBytes);
        if (state.nonces.has(envelope.nonce)) fail('AES-GCM nonce reuse was refused');
        line = `${JSON.stringify(envelope)}\n`;
      }
      const descriptor = fs.openSync(state.file, 'a', 0o600);
      try {
        fs.writeFileSync(descriptor, line, 'utf8');
        if (channel !== 'application') fs.fsyncSync(descriptor);
      } finally { fs.closeSync(descriptor); }
      state.sequence = envelope.seq; state.lastChain = envelope.chain; state.nonces.add(envelope.nonce); state.bytes += Buffer.byteLength(line);
      this.writeCheckpoint();
      return true;
    } catch (error) {
      this.failed = true;
      throw error;
    }
  }

  close() { this.closed = true; this.opened = false; this.masterKey?.fill(0); this.masterKey = null; }
  get healthy() { return this.opened && !this.closed && !this.failed; }
}

function checkpointBytes(directory) {
  const file = path.join(directory, CHECKPOINT_FILE);
  const details = assertRegularFile(file, 16_384, 'the encrypted log checkpoint');
  const raw = fs.readFileSync(file);
  if (raw.length !== details.size) fail('the encrypted log checkpoint changed while it was being read');
  return raw;
}

function recognizedManifest(directory, maximumBytes) {
  const manifest = [];
  for (const name of fs.readdirSync(directory).sort((left, right) => left.localeCompare(right, 'en-US'))) {
    const current = name.match(CURRENT_PATTERN); const archive = name.match(ARCHIVE_PATTERN); const match = current ?? archive;
    if (!match) continue;
    const file = path.join(directory, name); const details = fs.lstatSync(file, { bigint: true });
    if (details.isSymbolicLink() || !details.isFile()) fail('a recognized encrypted log path is not a regular file');
    if (details.size < 1n || details.size > BigInt(maximumBytes)) {
      fail('an encrypted log file is empty or exceeds its configured size limit');
    }
    manifest.push({
      file, name, channel: match[1], archived: Boolean(archive), size: Number(details.size),
      metadata: [details.dev, details.ino, details.mode, details.nlink, details.size, details.mtimeNs, details.ctimeNs]
        .map((value) => value.toString()),
    });
  }
  return manifest;
}

function manifestToken(manifest) {
  return JSON.stringify(manifest.map(({ name, metadata }) => [name, ...metadata]));
}

function snapshotSleep(milliseconds) {
  if (milliseconds > 0) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function captureVerifiedLogSnapshot(options, masterKey, maximumBytes, attempt, captureHook) {
  const directory = path.resolve(options.directory ?? './logs');
  const checkpointBefore = checkpointBytes(directory); const manifestBefore = recognizedManifest(directory, maximumBytes);
  captureHook?.({ phase: 'after-pre-fence', attempt, directory });
  const captures = manifestBefore.map((entry) => {
    const raw = fs.readFileSync(entry.file);
    if (raw.length !== entry.size) fail('an encrypted log file changed while it was being captured');
    return { ...entry, raw };
  });
  const manifestAfter = recognizedManifest(directory, maximumBytes); const checkpointAfter = checkpointBytes(directory);
  if (!checkpointBefore.equals(checkpointAfter)) fail('the encrypted log checkpoint changed during snapshot capture');
  if (manifestToken(manifestBefore) !== manifestToken(manifestAfter)) fail('the encrypted log file set changed during snapshot capture');

  const parsedFiles = captures.map((entry) => ({
    ...entry, parsed: parseEncryptedLogBytes(entry.raw, masterKey, { expectedChannel: entry.channel, maximumBytes }),
  }));
  const summary = {}; const states = new Map(); const files = [];
  for (const channel of CHANNELS) {
    const channelFiles = parsedFiles.filter((entry) => entry.channel === channel);
    const archives = chainOrder(channelFiles.filter((entry) => entry.archived));
    const current = channelFiles.filter((entry) => !entry.archived);
    if (current.length !== 1) fail(`the ${channel} log set must contain exactly one current file`);
    const ordered = [...archives, ...current]; let prior = null; let records = 0;
    for (const entry of ordered) {
      if (prior && entry.parsed.header.previousFileChain !== prior.lastChain) fail(`the ${channel} log-file chain is discontinuous`);
      prior = entry.parsed; records += entry.parsed.records.length;
      files.push({
        file: entry.file, name: entry.name, channel, raw: entry.raw,
        header: entry.parsed.header, records: entry.parsed.records,
        sequence: entry.parsed.sequence, lastChain: entry.parsed.lastChain,
      });
    }
    if (prior) states.set(channel, { header: prior.header, sequence: prior.sequence, lastChain: prior.lastChain });
    summary[channel] = { files: ordered.length, records };
  }
  let checkpoint;
  try { checkpoint = JSON.parse(checkpointAfter.toString('utf8')); } catch { fail('the encrypted log checkpoint is not valid JSON'); }
  validateCheckpoint(checkpoint, states, masterKey);
  return { summary, files };
}

export function readVerifiedLogSnapshot(options = {}, controls = {}) {
  const directory = path.resolve(options.directory ?? './logs');
  const maxAttempts = boundedInteger(controls.maxAttempts ?? SNAPSHOT_ATTEMPTS, 'snapshot maxAttempts', 1, 10);
  const retryDelaysMs = controls.retryDelaysMs ?? SNAPSHOT_RETRY_DELAYS_MS;
  if (!Array.isArray(retryDelaysMs) || retryDelaysMs.some((delay) => !Number.isInteger(delay) || delay < 0 || delay > 1_000)) {
    fail('snapshot retryDelaysMs must contain millisecond integers from 0 to 1000');
  }
  if (controls.captureHook != null && typeof controls.captureHook !== 'function') fail('snapshot captureHook must be a function');
  const maxFileBytes = boundedInteger(options.maxFileBytes ?? 10 * 1024 * 1024, 'maxFileBytes', 512, 1024 * 1024 * 1024);
  const maxRecordBytes = boundedInteger(options.maxRecordBytes ?? 64 * 1024, 'maxRecordBytes', 1024, 1024 * 1024);
  const maximumBytes = maxFileBytes + maxRecordBytes + 16_384;
  const masterKey = loadLogEncryptionKey({ ...options, directory });
  try {
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try { return captureVerifiedLogSnapshot(options, masterKey, maximumBytes, attempt, controls.captureHook); }
      catch (error) {
        if (attempt === maxAttempts) throw error;
        const delay = retryDelaysMs[Math.min(attempt - 1, Math.max(0, retryDelaysMs.length - 1))] ?? 0;
        snapshotSleep(delay);
      }
    }
    fail('the encrypted log snapshot retry budget was exhausted');
  } finally { masterKey.fill(0); }
}

export function verifyLogDirectory(options = {}, controls = {}) {
  return readVerifiedLogSnapshot(options, controls).summary;
}

export function listEncryptedLogFiles(directory) {
  const absolute = path.resolve(directory); const output = [];
  for (const name of fs.readdirSync(absolute)) {
    if (!CURRENT_PATTERN.test(name) && !ARCHIVE_PATTERN.test(name)) continue;
    const file = path.join(absolute, name); const details = fs.lstatSync(file);
    if (details.isSymbolicLink() || !details.isFile()) fail('a recognized encrypted log path is not a regular file');
    output.push(file);
  }
  return output.sort((left, right) => path.basename(left).localeCompare(path.basename(right), 'en-US'));
}

export const LOG_CHANNELS = CHANNELS;
