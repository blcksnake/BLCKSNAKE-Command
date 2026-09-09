import crypto from 'node:crypto';
import path from 'node:path';
import { Writable } from 'node:stream';
import { finished } from 'node:stream/promises';
import SftpClient from 'ssh2-sftp-client';
import { MAX_ASA_PROFILE_BYTES, parseAsaProfile } from './asa-profile-parser.js';

const EOS_ID_PATTERN = /^[a-f0-9]{32}$/i;
const HOST_KEY_HEX_PATTERN = /^[a-f0-9]{64}$/i;
const SERVER_ID_PATTERN = /^[a-z0-9_-]{1,32}$/i;
const MODERN_SSH_ALGORITHMS = Object.freeze({
  kex: Object.freeze([
    'curve25519-sha256', 'curve25519-sha256@libssh.org',
    'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521',
    'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group14-sha256',
    'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512',
  ]),
  cipher: Object.freeze([
    'chacha20-poly1305@openssh.com',
    'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com',
    'aes256-ctr', 'aes192-ctr', 'aes128-ctr',
  ]),
  hmac: Object.freeze([
    'hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com',
    'hmac-sha2-512', 'hmac-sha2-256',
  ]),
  serverHostKey: Object.freeze([
    'ssh-ed25519',
    'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
    'rsa-sha2-512', 'rsa-sha2-256',
  ]),
  compress: Object.freeze(['none']),
});

export class SftpProfileSourceError extends Error {
  constructor(message, code, options) {
    super(message, options);
    this.name = 'SftpProfileSourceError';
    this.code = code;
  }
}

function fail(message, code = 'INVALID_CONFIG', options) {
  throw new SftpProfileSourceError(message, code, options);
}

function requiredText(value, field, maximum = 512) {
  const text = String(value ?? '').trim();
  if (!text || text.length > maximum || /[\0\r\n]/u.test(text)) fail(`${field} is required and must not contain control characters`);
  return text;
}

function requiredSecret(value, field, maximum = 4_096) {
  if (typeof value !== 'string' || !value || value.length > maximum || /[\0\r\n]/u.test(value)) {
    fail(`${field} is required and must not contain control characters`);
  }
  return value;
}

function positiveInteger(value, field, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${field} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

function normalizeHostKeyFingerprint(value) {
  const fingerprint = requiredText(value, 'SFTP host-key SHA-256 fingerprint', 128);
  if (HOST_KEY_HEX_PATTERN.test(fingerprint)) return fingerprint.toLocaleLowerCase('en-US');
  const match = fingerprint.match(/^SHA256:([A-Za-z0-9+/]{43}=?)$/);
  if (!match) fail('SFTP host-key SHA-256 fingerprint must be 64 hexadecimal characters or OpenSSH SHA256:base64 form');
  const bytes = Buffer.from(match[1], 'base64');
  if (bytes.length !== 32) fail('SFTP host-key SHA-256 fingerprint is invalid');
  return bytes.toString('hex');
}

function normalizeDirectory(value) {
  const raw = requiredText(value, 'SFTP profile directory');
  if (!raw.startsWith('/') || raw.includes('\\') || /[*?[\]{}]/u.test(raw)) {
    fail('SFTP profile directories must be absolute POSIX paths without backslashes or wildcard characters');
  }
  const directory = raw === '/' ? raw : raw.replace(/\/+$/u, '');
  if (directory === '/') return directory;
  const segments = directory.slice(1).split('/');
  if (segments.some((segment) => !segment || segment === '.' || segment === '..') || path.posix.normalize(directory) !== directory) {
    fail('SFTP profile directories must be canonical paths without empty, dot, or parent segments');
  }
  return directory;
}

function normalizeDirectories({ directory, directories }) {
  const values = [directory, ...(Array.isArray(directories) ? directories : directories == null ? [] : [directories])]
    .filter((value) => value != null && String(value).trim());
  if (!values.length) fail('At least one SFTP profile directory is required');
  return [...new Set(values.map(normalizeDirectory))];
}

function hostKeyMatches(actual, expected) {
  if (typeof actual !== 'string' || !HOST_KEY_HEX_PATTERN.test(actual)) return false;
  const left = Buffer.from(actual, 'hex');
  const right = Buffer.from(expected, 'hex');
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function isNotFound(error) {
  return error?.code === 2 || error?.code === 'ENOENT' || error?.code === 'NO_SUCH_FILE';
}

function timeoutError(serverId, operation) {
  return new SftpProfileSourceError(`Read-only SFTP ${operation} timed out on ${serverId}`, 'SFTP_TIMEOUT');
}

function terminateConnection(client) {
  try { client?.destroy?.(); } catch { /* Best-effort cancellation for injected clients. */ }
  try { client?.client?.destroy?.(); } catch { /* ssh2-sftp-client exposes its underlying SSH client. */ }
}

function withDeadline(operation, timeoutMs, serverId, label, onTimeout) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      const error = timeoutError(serverId, label);
      try { onTimeout?.(error); } catch { /* Cancellation must not replace the timeout result. */ }
      reject(error);
    }, timeoutMs);
    Promise.resolve()
      .then(operation)
      .then((value) => {
        if (settled) return;
        settled = true; clearTimeout(timer); resolve(value);
      }, (error) => {
        if (settled) return;
        settled = true; clearTimeout(timer); reject(error);
      });
  });
}

class BoundedProfileSink extends Writable {
  constructor(expectedSize, maximumSize) {
    super();
    this.expectedSize = expectedSize;
    this.maximumSize = maximumSize;
    this.bytes = 0;
    this.buffer = Buffer.allocUnsafe(expectedSize);
  }

  _write(chunk, encoding, callback) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
    const nextSize = this.bytes + bytes.length;
    if (!Number.isSafeInteger(nextSize) || nextSize > this.maximumSize) {
      callback(new SftpProfileSourceError('Remote ARK profile exceeds the configured size limit during download', 'PROFILE_TOO_LARGE'));
      return;
    }
    if (nextSize > this.expectedSize) {
      callback(new SftpProfileSourceError('Remote ARK profile grew during download', 'PROFILE_CHANGED'));
      return;
    }
    bytes.copy(this.buffer, this.bytes); this.bytes = nextSize; callback();
  }

  profileBuffer() { return this.buffer.subarray(0, this.bytes); }
}

function inspectStat(stat, maximum) {
  if (!stat || typeof stat !== 'object' || stat.isDirectory === true || stat.isFile === false) {
    fail('Remote ARK profile path is not a regular file', 'INVALID_REMOTE_PROFILE');
  }
  const size = Number(stat.size);
  if (!Number.isSafeInteger(size) || size < 1) fail('Remote ARK profile has an invalid size', 'INVALID_REMOTE_PROFILE');
  if (size > maximum) fail('Remote ARK profile exceeds the configured size limit', 'PROFILE_TOO_LARGE');
  const modifiedAt = Number(stat.modifyTime);
  if (!Number.isFinite(modifiedAt) || modifiedAt < 0) {
    fail('Remote ARK profile has an invalid modification time', 'INVALID_REMOTE_PROFILE');
  }
  return { size, modifiedAt };
}

function safeAccessError(error, serverId) {
  if (error instanceof SftpProfileSourceError) return error;
  const message = String(error?.message ?? '');
  let code = 'SFTP_READ_FAILED';
  if (/authenticat/i.test(message) || error?.level === 'client-authentication') code = 'SFTP_AUTH_FAILED';
  else if (/host.?key/i.test(message) || error?.code === 'HOST_KEY_REJECTED') code = 'HOST_KEY_REJECTED';
  else if (/timed?\s*out/i.test(message) || error?.code === 'ETIMEDOUT') code = 'SFTP_TIMEOUT';
  else if (typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{1,63}$/.test(error.code)) code = error.code;
  return new SftpProfileSourceError(`Read-only SFTP profile access failed on ${serverId}`, code, { cause: error });
}

/**
 * Read the exact connected player's ASA profile from one map's SFTP endpoint.
 *
 * The adapter intentionally exposes no listing or write operation. Each lookup
 * uses a fresh client, and candidate directories are explicit configuration;
 * callers cannot supply any part of the remote path except a validated EOS ID.
 */
export class SftpProfileSource {
  constructor(config = {}, {
    // Suppress the client's optional console callbacks; operation failures are
    // surfaced by the awaited SFTP methods below.
    clientFactory = () => new SftpClient(`asa-profile-${config.serverId ?? 'server'}`, {}),
    parser = parseAsaProfile,
  } = {}) {
    this.serverId = requiredText(config.serverId, 'Profile source server ID', 32);
    if (!SERVER_ID_PATTERN.test(this.serverId)) fail('Profile source server ID is invalid');
    this.host = requiredText(config.host, 'SFTP host', 253);
    this.port = positiveInteger(config.port, 'SFTP port', 1, 65_535);
    this.username = requiredText(config.username, 'SFTP username', 256);
    this.password = requiredSecret(config.password, 'SFTP password');
    this.hostKeySha256 = normalizeHostKeyFingerprint(config.hostKeySha256);
    this.directories = normalizeDirectories(config);
    this.connectTimeoutMs = positiveInteger(config.connectTimeoutMs ?? 5_000, 'SFTP connect timeout', 100, 120_000);
    this.operationTimeoutMs = positiveInteger(config.operationTimeoutMs ?? 15_000, 'SFTP operation timeout', 100, 300_000);
    this.maxFileBytes = positiveInteger(config.maxFileBytes ?? MAX_ASA_PROFILE_BYTES, 'Maximum ARK profile size', 1, 64 * 1024 * 1024);
    this.config = Object.freeze({
      retryIntervalMs: positiveInteger(config.retryIntervalMs ?? 60_000, 'SFTP retry interval', 1_000, 86_400_000),
      revalidateIntervalMs: positiveInteger(config.revalidateIntervalMs ?? 300_000, 'SFTP revalidation interval', 10_000, 86_400_000),
    });
    if (typeof clientFactory !== 'function') fail('SFTP client factory must be a function');
    if (typeof parser !== 'function') fail('ASA profile parser must be a function');
    this.clientFactory = clientFactory;
    this.parser = parser;
  }

  connectionOptions() {
    return {
      host: this.host,
      port: this.port,
      username: this.username,
      password: this.password,
      readyTimeout: this.connectTimeoutMs,
      hostHash: 'sha256',
      hostVerifier: (fingerprint) => hostKeyMatches(fingerprint, this.hostKeySha256),
      algorithms: MODERN_SSH_ALGORITHMS,
    };
  }

  async getProfile(eosId) {
    const expectedEosId = String(eosId ?? '').trim().toLocaleLowerCase('en-US');
    if (!EOS_ID_PATTERN.test(expectedEosId)) fail('A 32-character hexadecimal EOS ID is required', 'INVALID_EOS_ID');
    const filename = `${expectedEosId}.arkprofile`;
    const client = this.clientFactory();
    if (!client || typeof client.connect !== 'function' || typeof client.stat !== 'function'
      || typeof client.get !== 'function' || typeof client.end !== 'function') {
      fail('SFTP client factory returned an invalid client', 'INVALID_CLIENT');
    }

    try {
      await withDeadline(
        () => client.connect(this.connectionOptions()), this.connectTimeoutMs, this.serverId, 'connection',
        () => terminateConnection(client),
      );
      for (const directory of this.directories) {
        const remotePath = path.posix.join(directory, filename);
        let beforeRaw;
        try {
          beforeRaw = await withDeadline(
            () => client.stat(remotePath), this.operationTimeoutMs, this.serverId, 'initial profile stat',
            () => terminateConnection(client),
          );
        }
        catch (error) {
          if (isNotFound(error)) continue;
          throw error;
        }
        const before = inspectStat(beforeRaw, this.maxFileBytes);
        const sink = new BoundedProfileSink(before.size, this.maxFileBytes);
        await withDeadline(
          () => Promise.all([
            client.get(remotePath, sink),
            finished(sink, { cleanup: true }),
          ]),
          this.operationTimeoutMs,
          this.serverId,
          'profile download',
          (error) => { sink.destroy(error); terminateConnection(client); },
        );
        const buffer = sink.profileBuffer();
        if (buffer.length !== before.size) fail('Remote ARK profile changed or was truncated during download', 'PROFILE_CHANGED');
        let afterRaw;
        try {
          afterRaw = await withDeadline(
            () => client.stat(remotePath), this.operationTimeoutMs, this.serverId, 'final profile stat',
            () => terminateConnection(client),
          );
        }
        catch (error) {
          if (isNotFound(error)) fail('Remote ARK profile disappeared during download', 'PROFILE_CHANGED', { cause: error });
          throw error;
        }
        const after = inspectStat(afterRaw, this.maxFileBytes);
        if (after.size !== before.size || after.modifiedAt !== before.modifiedAt) {
          fail('Remote ARK profile changed during download', 'PROFILE_CHANGED');
        }
        const profile = this.parser(buffer, { expectedEosId, maxBytes: this.maxFileBytes });
        return Object.freeze({
          ...profile,
          serverId: this.serverId,
          remoteDirectory: directory,
          size: after.size,
          modifiedAt: after.modifiedAt,
        });
      }
      fail(`No current ARK profile exists for the connected account on ${this.serverId}`, 'PROFILE_NOT_FOUND');
    } catch (error) {
      throw safeAccessError(error, this.serverId);
    } finally {
      try {
        await withDeadline(
          () => client.end(), this.operationTimeoutMs, this.serverId, 'connection close',
          () => terminateConnection(client),
        );
      }
      catch { /* A close failure must not hide the read or validation result. */ }
    }
  }
}
