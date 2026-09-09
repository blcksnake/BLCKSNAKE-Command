import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import { JsonStateStore } from './json-state-store.js';

const APPLICATION_ID = 0x41534343;
const SCHEMA_VERSION = 1;
const CIPHER = 'aes-256-gcm';
const FORMAT = 'asa-crosschat-sqlite-state';
const STATE_NAMESPACES = Object.freeze([
  'linksByDiscord', 'linksByGame', 'linkCodes', 'mutes', 'moderationNotes',
  'scheduledRestarts', 'playtimeByEos', 'seenPlayers', 'playerDataIds',
  'itemPreferencesByDiscord', 'history',
]);
const ROOT_NAMESPACE = '__root__';
const NAMESPACES = Object.freeze([...STATE_NAMESPACES, ROOT_NAMESPACE]);
const NAMESPACE_SET = new Set(NAMESPACES);
const MIN_DATABASE_BYTES = 1024 * 1024;
const DEFAULT_DATABASE_BYTES = 64 * 1024 * 1024;

function recordKey(masterKey, storeId) {
  return Buffer.from(crypto.hkdfSync('sha256', masterKey, storeId, Buffer.from(`${FORMAT}:record-key:v1`, 'utf8'), 32));
}

function aad(storeId, namespace, revision) {
  return Buffer.from(`${FORMAT}:v${SCHEMA_VERSION}:${storeId.toString('hex')}:${namespace}:r${revision}`, 'utf8');
}

function sealRecord(serialized, key, storeId, namespace, revision, randomBytes) {
  const nonce = randomBytes(12);
  if (!Buffer.isBuffer(nonce) || nonce.length !== 12) throw new Error('State encryption IV generator must return 12 bytes');
  const cipher = crypto.createCipheriv(CIPHER, key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad(storeId, namespace, revision));
  const ciphertext = Buffer.concat([cipher.update(serialized, 'utf8'), cipher.final()]);
  return { nonce, tag: cipher.getAuthTag(), ciphertext };
}

function openRecord(row, key, storeId) {
  if (!row || typeof row.namespace !== 'string' || !NAMESPACE_SET.has(row.namespace)
    || !Number.isSafeInteger(row.revision) || row.revision < 1
    || !Buffer.isBuffer(row.nonce) || row.nonce.length !== 12
    || !Buffer.isBuffer(row.tag) || row.tag.length !== 16
    || !Buffer.isBuffer(row.ciphertext)) {
    throw new Error('Encrypted SQLite state record is malformed');
  }
  try {
    const decipher = crypto.createDecipheriv(CIPHER, key, row.nonce, { authTagLength: 16 });
    decipher.setAAD(aad(storeId, row.namespace, row.revision));
    decipher.setAuthTag(row.tag);
    return JSON.parse(Buffer.concat([decipher.update(row.ciphertext), decipher.final()]).toString('utf8'));
  } catch {
    throw new Error('Encrypted SQLite state could not be authenticated; verify the configured key and database integrity');
  }
}

function stateDigest(state, key) {
  return crypto.createHmac('sha256', key).update(JSON.stringify(state)).digest();
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort((left, right) => left.localeCompare(right, 'en-US'))
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

async function regularFileState(file, maximum, label) {
  try {
    const metadata = await fs.lstat(file);
    if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error(`${label} path must be a regular file, not a symbolic link`);
    if (metadata.size > maximum) throw new Error(`${label} exceeds the ${maximum}-byte safety limit`);
    if (process.platform !== 'win32' && (metadata.mode & 0o077) !== 0) {
      throw new Error(`${label} file permissions must be 0600 or stricter`);
    }
    return metadata;
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function databaseSchemaObjects(database) {
  return database.prepare("SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name").all();
}

function applyConnectionHardening(database, maxDatabaseBytes, busyTimeoutMs) {
  database.pragma('foreign_keys = ON');
  database.pragma('journal_mode = DELETE');
  database.pragma('synchronous = FULL');
  database.pragma('temp_store = MEMORY');
  database.pragma('trusted_schema = OFF');
  database.pragma('secure_delete = ON');
  database.pragma(`busy_timeout = ${busyTimeoutMs}`);
  const pageSize = database.pragma('page_size', { simple: true });
  const pageCount = database.pragma('page_count', { simple: true });
  const maximumPages = Math.floor(maxDatabaseBytes / pageSize);
  if (pageCount > maximumPages) throw new Error('SQLite state database exceeds its configured size limit');
  const appliedPages = database.pragma(`max_page_count = ${maximumPages}`, { simple: true });
  if (appliedPages < pageCount || appliedPages * pageSize > maxDatabaseBytes) {
    throw new Error('SQLite database size limit could not be applied safely');
  }
}

function createSchema(database) {
  database.exec(`
    CREATE TABLE IF NOT EXISTS state_meta (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      schema_version INTEGER NOT NULL CHECK (schema_version > 0),
      revision INTEGER NOT NULL CHECK (revision >= 0),
      store_id BLOB NOT NULL CHECK (length(store_id) = 16)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS state_records (
      namespace TEXT PRIMARY KEY CHECK (length(namespace) BETWEEN 1 AND 64),
      revision INTEGER NOT NULL CHECK (revision > 0),
      nonce BLOB NOT NULL CHECK (length(nonce) = 12),
      tag BLOB NOT NULL CHECK (length(tag) = 16),
      ciphertext BLOB NOT NULL
    ) STRICT, WITHOUT ROWID;
  `);
}

function assertDatabaseIntegrity(database) {
  const quickCheck = database.pragma('quick_check');
  if (quickCheck.length !== 1 || quickCheck[0].quick_check !== 'ok') throw new Error('SQLite state database failed its integrity check');
  if (database.pragma('foreign_key_check').length) throw new Error('SQLite state database failed its foreign-key check');
}

function assertDatabaseLogicalSize(database, maximum) {
  const pageSize = database.pragma('page_size', { simple: true });
  const pageCount = database.pragma('page_count', { simple: true });
  if (!Number.isSafeInteger(pageSize) || pageSize < 1
    || !Number.isSafeInteger(pageCount) || pageCount < 0
    || pageCount * pageSize > maximum) {
    throw new Error(`SQLite state database exceeds the ${maximum}-byte safety limit`);
  }
}

export class SqliteStateStore extends JsonStateStore {
  constructor({
    file, legacyJsonFile = '', migrateLegacyJson = true,
    maxDatabaseBytes = DEFAULT_DATABASE_BYTES, busyTimeoutMs = 5_000,
    encryptionRequired = true, ...options
  } = {}) {
    if (encryptionRequired !== true) throw new Error('SQLite state encryption is mandatory');
    if (!Number.isInteger(maxDatabaseBytes) || maxDatabaseBytes < MIN_DATABASE_BYTES || maxDatabaseBytes > 1024 * 1024 * 1024) {
      throw new Error('SQLite database maximum size must be 1048576-1073741824 bytes');
    }
    if (!Number.isInteger(busyTimeoutMs) || busyTimeoutMs < 100 || busyTimeoutMs > 60_000) {
      throw new Error('SQLite busy timeout must be 100-60000 milliseconds');
    }
    super({ file, encryptionRequired: true, ...options });
    this.legacyJsonFile = legacyJsonFile ? path.resolve(legacyJsonFile) : '';
    if (this.legacyJsonFile && this.legacyJsonFile === this.file) throw new Error('SQLite and legacy JSON state files must be different');
    if (this.legacyJsonFile && this.legacyJsonFile === this.encryptionKeyFile) throw new Error('Legacy state and encryption key files must be different');
    this.migrateLegacyJson = Boolean(migrateLegacyJson);
    this.maxDatabaseBytes = maxDatabaseBytes;
    this.busyTimeoutMs = busyTimeoutMs;
    this.database = null;
    this.loaded = false;
    this.closed = false;
    this.closing = false;
    this.closePromise = null;
    this.migratedLegacyJson = false;
  }

  async openDatabase({ existed = false, allowEmptyExisting = false } = {}) {
    const metadata = await regularFileState(this.file, this.maxDatabaseBytes, 'SQLite state database');
    if (metadata && metadata.size === 0 && !allowEmptyExisting) throw new Error('SQLite state database is empty and was refused');
    const database = new Database(this.file, { timeout: this.busyTimeoutMs });
    try {
      database.pragma('trusted_schema = OFF');
      const schemaObjects = databaseSchemaObjects(database);
      const tables = schemaObjects.filter((entry) => entry.type === 'table').map((entry) => entry.name);
      const applicationId = database.pragma('application_id', { simple: true });
      const userVersion = database.pragma('user_version', { simple: true });
      if (tables.length && applicationId !== APPLICATION_ID) throw new Error('SQLite file is not a BLCKSNAKE Command state database');
      if (applicationId === APPLICATION_ID && userVersion > SCHEMA_VERSION) {
        throw new Error(`SQLite state schema version ${userVersion} is newer than supported version ${SCHEMA_VERSION}`);
      }
      if (tables.length && userVersion !== SCHEMA_VERSION) throw new Error(`SQLite state schema version ${userVersion} is unsupported`);
      if (tables.length && (schemaObjects.length !== 2
        || schemaObjects[0]?.type !== 'table' || schemaObjects[0]?.name !== 'state_meta'
        || schemaObjects[1]?.type !== 'table' || schemaObjects[1]?.name !== 'state_records')) {
        throw new Error('SQLite state database contains an unexpected schema object');
      }
      if (!tables.length && existed && metadata?.size && !allowEmptyExisting) throw new Error('Existing SQLite state database has no application schema');
      applyConnectionHardening(database, this.maxDatabaseBytes, this.busyTimeoutMs);
      if (!tables.length) {
        database.pragma(`application_id = ${APPLICATION_ID}`);
        database.pragma(`user_version = ${SCHEMA_VERSION}`);
        createSchema(database);
      }
      assertDatabaseIntegrity(database);
      await fs.chmod(this.file, 0o600).catch((error) => { if (process.platform !== 'win32') throw error; });
      this.database = database;
    } catch (error) {
      database.close();
      throw error;
    }
  }

  async migrateLegacyFile(encryptionKey) {
    if (!this.legacyJsonFile || !this.migrateLegacyJson) return false;
    const legacyMetadata = await regularFileState(this.legacyJsonFile, this.maxFileBytes, 'Legacy JSON state');
    if (!legacyMetadata) return false;
    const sourceBefore = await fs.readFile(this.legacyJsonFile);
    if (sourceBefore.length !== legacyMetadata.size) throw new Error('Legacy JSON state changed while migration was starting');
    const sourceDigestBefore = crypto.createHash('sha256').update(sourceBefore).digest();
    const legacy = await new JsonStateStore({
      file: this.legacyJsonFile,
      historyLimit: this.historyLimit,
      maxFileBytes: this.maxFileBytes,
      encryptionKey: this.encryptionKey ? `base64:${this.encryptionKey.toString('base64')}` : '',
      encryptionRequired: true,
      generateEncryptionKey: false,
      allowPlaintextMigration: false,
      now: this.now,
      randomBytes: this.randomBytes,
      encryptionRandomBytes: this.encryptionRandomBytes,
    }).load();
    const sourceState = structuredClone(legacy.state);
    const expectedDigest = stateDigest(sourceState, encryptionKey);
    const temporary = `${this.file}.${process.pid}.${crypto.randomBytes(12).toString('hex')}.migrating`;
    let published = false;
    try {
      const reservation = await fs.open(temporary, 'wx', 0o600);
      await reservation.close();
      const candidate = new SqliteStateStore({
        file: temporary,
        historyLimit: this.historyLimit,
        maxFileBytes: this.maxFileBytes,
        maxDatabaseBytes: this.maxDatabaseBytes,
        busyTimeoutMs: this.busyTimeoutMs,
        encryptionKey: `base64:${encryptionKey.toString('base64')}`,
        encryptionRequired: true,
        generateEncryptionKey: false,
        legacyJsonFile: '',
        migrateLegacyJson: false,
        now: this.now,
        randomBytes: this.randomBytes,
        encryptionRandomBytes: this.encryptionRandomBytes,
      });
      await candidate.load({ allowEmptyExisting: true });
      candidate.state = sourceState;
      await candidate.save();
      await candidate.close();
      const verified = await new SqliteStateStore({
        file: temporary,
        historyLimit: this.historyLimit,
        maxFileBytes: this.maxFileBytes,
        maxDatabaseBytes: this.maxDatabaseBytes,
        busyTimeoutMs: this.busyTimeoutMs,
        encryptionKey: `base64:${encryptionKey.toString('base64')}`,
        encryptionRequired: true,
        generateEncryptionKey: false,
        legacyJsonFile: '',
        migrateLegacyJson: false,
      }).load();
      const actualDigest = stateDigest(verified.state, encryptionKey);
      await verified.close();
      if (!crypto.timingSafeEqual(expectedDigest, actualDigest)) throw new Error('Legacy JSON migration verification failed');
      const legacyAfter = await regularFileState(this.legacyJsonFile, this.maxFileBytes, 'Legacy JSON state');
      const sourceAfter = await fs.readFile(this.legacyJsonFile);
      const sourceDigestAfter = crypto.createHash('sha256').update(sourceAfter).digest();
      if (!legacyAfter || legacyAfter.size !== legacyMetadata.size
        || legacyAfter.mtimeMs !== legacyMetadata.mtimeMs || legacyAfter.ctimeMs !== legacyMetadata.ctimeMs
        || !crypto.timingSafeEqual(sourceDigestBefore, sourceDigestAfter)) {
        throw new Error('Legacy JSON state changed during migration; SQLite destination was not published');
      }
      await fs.link(temporary, this.file);
      published = true;
      await fs.unlink(temporary);
      this.migratedLegacyJson = true;
      return true;
    } catch (error) {
      if (error.code === 'EEXIST') throw new Error('SQLite migration destination appeared while migration was running');
      throw error;
    } finally {
      if (!published) await fs.unlink(temporary).catch(() => undefined);
    }
  }

  async load({ allowEmptyExisting = false, pruneExpired = true } = {}) {
    if (this.loaded && this.database) return this;
    if (this.closed) throw new Error('SQLite state store is closed');
    await fs.mkdir(path.dirname(this.file), { recursive: true, mode: 0o700 });
    const encryptionKey = await this.ensureEncryptionKey();
    if (!encryptionKey) throw new Error('SQLite state encryption key is unavailable');
    const existing = await regularFileState(this.file, this.maxDatabaseBytes, 'SQLite state database');
    if (!existing) await this.migrateLegacyFile(encryptionKey);
    const current = await regularFileState(this.file, this.maxDatabaseBytes, 'SQLite state database');
    await this.openDatabase({ existed: Boolean(current), allowEmptyExisting });
    try {
      const meta = this.database.prepare('SELECT schema_version, revision, store_id FROM state_meta WHERE singleton = 1').get();
      if (!meta) {
        const recordCount = this.database.prepare('SELECT COUNT(*) AS count FROM state_records').get()?.count;
        if (current?.size && (!allowEmptyExisting || recordCount !== 0)) {
          throw new Error('SQLite state metadata is missing');
        }
        this.loaded = true;
        await this.save();
      } else {
        if (meta.schema_version !== SCHEMA_VERSION || !Number.isSafeInteger(meta.revision) || meta.revision < 1
          || !Buffer.isBuffer(meta.store_id) || meta.store_id.length !== 16) {
          throw new Error('SQLite state metadata is invalid or unsupported');
        }
        const rows = this.database.prepare('SELECT namespace, revision, nonce, tag, ciphertext FROM state_records ORDER BY namespace').all();
        if (rows.length !== NAMESPACES.length || rows.some((row) => row.revision !== meta.revision)
          || new Set(rows.map((row) => row.namespace)).size !== NAMESPACES.length) {
          throw new Error('SQLite state record set is incomplete or inconsistent');
        }
        const parsed = {}; const key = recordKey(encryptionKey, meta.store_id);
        for (const row of rows) {
          const value = openRecord(row, key, meta.store_id);
          if (row.namespace === ROOT_NAMESPACE) Object.assign(parsed, value);
          else parsed[row.namespace] = value;
        }
        this.hydrateState(parsed);
        this.loaded = true;
      }
      if (pruneExpired) this.pruneExpired();
      return this;
    } catch (error) {
      await this.close();
      throw error;
    }
  }

  save(snapshot = this.state) {
    let snapshots; let totalBytes = 0;
    try {
      const root = Object.fromEntries(Object.entries(snapshot)
        .filter(([key]) => !STATE_NAMESPACES.includes(key)));
      snapshots = NAMESPACES.map((namespace) => {
        const serialized = JSON.stringify(namespace === ROOT_NAMESPACE ? root : snapshot[namespace]);
        totalBytes += Buffer.byteLength(serialized);
        return [namespace, serialized];
      });
    } catch (error) {
      return Promise.reject(error);
    }
    if (totalBytes > this.maxFileBytes) {
      return Promise.reject(new Error(`State payload exceeds the ${this.maxFileBytes}-byte safety limit`));
    }
    const operation = async () => {
      if (!this.database || this.closed) throw new Error('SQLite state store is not open');
      const encryptionKey = await this.ensureEncryptionKey();
      if (!encryptionKey) throw new Error('SQLite state encryption key is unavailable');
      const meta = this.database.prepare('SELECT revision, store_id FROM state_meta WHERE singleton = 1').get();
      const revision = (meta?.revision ?? 0) + 1;
      if (!Number.isSafeInteger(revision)) throw new Error('SQLite state revision limit reached');
      const storeId = meta?.store_id ?? this.encryptionRandomBytes(16);
      if (!Buffer.isBuffer(storeId) || storeId.length !== 16) throw new Error('SQLite store ID generator must return 16 bytes');
      const key = recordKey(encryptionKey, storeId);
      const sealed = snapshots.map(([namespace, serialized]) => [namespace, sealRecord(
        serialized, key, storeId, namespace, revision, this.encryptionRandomBytes,
      )]);
      const nonceSet = new Set(this.database.prepare('SELECT nonce FROM state_records').all()
        .map((row) => row.nonce.toString('hex')));
      for (const [, record] of sealed) {
        const encodedNonce = record.nonce.toString('hex');
        if (nonceSet.has(encodedNonce)) throw new Error('SQLite state encryption refused a repeated nonce');
        nonceSet.add(encodedNonce);
      }
      const replace = this.database.prepare(`
        INSERT INTO state_records(namespace, revision, nonce, tag, ciphertext)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(namespace) DO UPDATE SET
          revision = excluded.revision, nonce = excluded.nonce,
          tag = excluded.tag, ciphertext = excluded.ciphertext
      `);
      const setMeta = this.database.prepare(`
        INSERT INTO state_meta(singleton, schema_version, revision, store_id)
        VALUES (1, ?, ?, ?)
        ON CONFLICT(singleton) DO UPDATE SET
          schema_version = excluded.schema_version, revision = excluded.revision
      `);
      this.database.transaction(() => {
        for (const [namespace, record] of sealed) replace.run(namespace, revision, record.nonce, record.tag, record.ciphertext);
        setMeta.run(SCHEMA_VERSION, revision, storeId);
        // These checks must run before COMMIT. A rejected save means callers
        // may safely retain their previous in-memory snapshot; no newer state
        // or revision may already be durable on disk.
        assertDatabaseIntegrity(this.database);
        assertDatabaseLogicalSize(this.database, this.maxDatabaseBytes);
      }).immediate();
    };
    const pending = this.writeChain.catch(() => undefined).then(operation);
    this.writeChain = pending;
    return pending;
  }

  countLinkedAccounts() { return Object.keys(this.state.linksByDiscord).length; }

  health() {
    if (!this.database || this.closed) throw new Error('SQLite state store is not open');
    assertDatabaseIntegrity(this.database);
    return {
      applicationId: this.database.pragma('application_id', { simple: true }),
      schemaVersion: this.database.pragma('user_version', { simple: true }),
      foreignKeys: this.database.pragma('foreign_keys', { simple: true }),
      journalMode: this.database.pragma('journal_mode', { simple: true }),
      synchronous: this.database.pragma('synchronous', { simple: true }),
      trustedSchema: this.database.pragma('trusted_schema', { simple: true }),
      secureDelete: this.database.pragma('secure_delete', { simple: true }),
    };
  }

  authenticatedMigrationDigest() {
    if (!this.database || this.closed || !this.loaded || !Buffer.isBuffer(this.encryptionKey)) {
      throw new Error('SQLite state store is not open');
    }
    const meta = this.database.prepare('SELECT revision, store_id FROM state_meta WHERE singleton = 1').get();
    if (!Number.isSafeInteger(meta?.revision) || meta.revision < 1
      || !Buffer.isBuffer(meta?.store_id) || meta.store_id.length !== 16) {
      throw new Error('SQLite state identity is unavailable');
    }
    const rows = this.database.prepare('SELECT namespace, revision, nonce, tag, ciphertext FROM state_records ORDER BY namespace').all();
    if (rows.length !== NAMESPACES.length || rows.some((row) => row.revision !== meta.revision)) {
      throw new Error('SQLite state identity record set is inconsistent');
    }
    const key = recordKey(this.encryptionKey, meta.store_id);
    try {
      const durableState = {};
      for (const row of rows) {
        const value = openRecord(row, key, meta.store_id);
        if (row.namespace === ROOT_NAMESPACE) {
          if (!value || typeof value !== 'object' || Array.isArray(value)) {
            throw new Error('SQLite root state record is invalid');
          }
          const root = { ...value };
          delete root.installationSettings;
          durableState[ROOT_NAMESPACE] = root;
        } else {
          durableState[row.namespace] = value;
        }
      }
      return crypto.createHmac('sha256', this.encryptionKey)
        .update('asa-crosschat:sqlite-migration-state:v1:', 'utf8')
        .update(meta.store_id)
        .update('\u0000', 'utf8')
        .update(canonicalJson(durableState), 'utf8')
        .digest('base64url');
    } finally { key.fill(0); }
  }

  async applyPersistenceLimits({ historyLimit, maxFileBytes, maxDatabaseBytes, busyTimeoutMs } = {}) {
    if (!this.database || this.closed || !this.loaded) throw new Error('SQLite state store is not open');
    if (!Number.isInteger(historyLimit) || historyLimit < 0 || historyLimit > 1_000_000) {
      throw new Error('SQLite history limit must be 0-1000000');
    }
    if (!Number.isInteger(maxFileBytes) || maxFileBytes < 1_024 || maxFileBytes > 64 * 1024 * 1024) {
      throw new Error('SQLite state payload limit must be 1024-67108864 bytes');
    }
    if (!Number.isInteger(maxDatabaseBytes) || maxDatabaseBytes < MIN_DATABASE_BYTES || maxDatabaseBytes > 1024 * 1024 * 1024) {
      throw new Error('SQLite database maximum size must be 1048576-1073741824 bytes');
    }
    if (!Number.isInteger(busyTimeoutMs) || busyTimeoutMs < 100 || busyTimeoutMs > 60_000) {
      throw new Error('SQLite busy timeout must be 100-60000 milliseconds');
    }
    await this.mutationChain;
    await this.writeChain;
    const metadata = await fs.stat(this.file);
    const pageSize = this.database.pragma('page_size', { simple: true });
    const pageCount = this.database.pragma('page_count', { simple: true });
    if (metadata.size > maxDatabaseBytes || pageCount * pageSize > maxDatabaseBytes) {
      throw new Error('SQLite state database exceeds its persisted size limit');
    }
    this.database.pragma(`busy_timeout = ${busyTimeoutMs}`);
    const maximumPages = Math.floor(maxDatabaseBytes / pageSize);
    const appliedPages = this.database.pragma(`max_page_count = ${maximumPages}`, { simple: true });
    if (appliedPages < pageCount || appliedPages * pageSize > maxDatabaseBytes) {
      throw new Error('SQLite persisted database size limit could not be applied');
    }
    this.historyLimit = historyLimit;
    this.maxFileBytes = maxFileBytes;
    this.maxDatabaseBytes = maxDatabaseBytes;
    this.busyTimeoutMs = busyTimeoutMs;
  }

  async close() {
    if (this.closePromise) return this.closePromise;
    this.closing = true;
    this.closePromise = (async () => {
      await this.mutationChain.catch(() => undefined);
      await this.writeChain.catch(() => undefined);
      if (this.database) {
        this.database.close();
        this.database = null;
      }
      this.loaded = false;
      this.closed = true;
    })();
    return this.closePromise;
  }
}

export const SQLITE_STATE_APPLICATION_ID = APPLICATION_ID;
export const SQLITE_STATE_SCHEMA_VERSION = SCHEMA_VERSION;
