import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import fs, { constants as fsConstants } from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import Database from 'better-sqlite3';
import { syncDirectory } from '../core/filesystem.js';

const KEY_PATTERN = /^(?:base64:)?[A-Za-z0-9+/]{43}=$|^(?:hex:)?[a-f0-9]{64}$/iu;
const MAX_KEY_FILE_BYTES = 256;
const INITIALIZATION_FORMAT = 'asa-crosschat-managed-initialization';
const MAX_INITIALIZATION_FILE_BYTES = 4 * 1024;
const INITIALIZATION_DIGEST_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const KEY_TEMP_PATTERN = /^\.instance-key-\d{1,10}-[a-f0-9]{24}\.tmp$/u;
const INITIALIZATION_TEMP_PATTERN = /^\.initialization-\d{1,10}-[a-f0-9]{24}\.tmp$/u;
const SETUP_TEMP_PATTERN = /^\.setup-\d{1,10}-[a-f0-9]{24}\.tmp$/u;
const MAX_SETUP_FILE_BYTES = 2 * 1024 * 1024;
const MAX_CA_BYTES = 512 * 1024;
const SETUP_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43,128}$/u;
const SETUP_RECORD_PATTERN = /^(?:BLCKSNAKE Command|Black\x20Snake Command|ASA CrossChat) first-run owner setup\n\nOpen the HTTPS dashboard and enter this value in the Setup token field:\n([A-Za-z0-9_-]{43,128})\n\nHTTPS CA SHA-256:\n([a-f0-9]{64}|unavailable)\n\nHTTPS CA PEM \(base64\):\n([A-Za-z0-9+/=]+|unavailable)\n\nThis file is removed after the server owner is created\.\n$/u;
const WINDOWS_ACL_FAILURE = 'Managed keystore Windows access controls could not be secured';
const WINDOWS_SYSTEM_SID = 'S-1-5-18';
const WINDOWS_ADMINISTRATORS_SID = 'S-1-5-32-544';
const WINDOWS_SID_PATTERN = /^S-\d{1,3}-\d{1,20}(?:-\d{1,10}){1,15}$/u;
const execFileAsync = promisify(execFile);
let windowsServiceSidPromise;

function windowsAclFailure() {
  return new Error(WINDOWS_ACL_FAILURE);
}

function normalizedWindowsTrustee(value) {
  const trustee = String(value ?? '').toUpperCase();
  if (trustee === 'SY') return WINDOWS_SYSTEM_SID;
  if (trustee === 'BA') return WINDOWS_ADMINISTRATORS_SID;
  return trustee;
}

function verifyWindowsDaclDescriptor(descriptor, allowedSids, kind) {
  const line = String(descriptor).split(/\r?\n/u)
    .map((entry) => entry.trim())
    .find((entry) => /^D:(?:P|AI|AR|\()/u.test(entry));
  if (!line) throw windowsAclFailure();
  let dacl = line.slice(2);
  const sacl = dacl.indexOf('S:');
  if (sacl >= 0) dacl = dacl.slice(0, sacl);
  const firstAce = dacl.indexOf('(');
  if (firstAce < 0) throw windowsAclFailure();
  const control = dacl.slice(0, firstAce);
  const controlParts = control.match(/P|AI|AR/gu) ?? [];
  if (controlParts.join('') !== control || !controlParts.includes('P')) throw windowsAclFailure();

  const expected = new Set(allowedSids);
  const observed = new Set();
  let cursor = firstAce;
  while (cursor < dacl.length) {
    if (dacl[cursor] !== '(') throw windowsAclFailure();
    const end = dacl.indexOf(')', cursor + 1);
    if (end < 0 || dacl.slice(cursor + 1, end).includes('(')) throw windowsAclFailure();
    const fields = dacl.slice(cursor + 1, end).split(';');
    if (fields.length !== 6) throw windowsAclFailure();
    const [type, flags, rights, objectType, inheritedObjectType, rawTrustee] = fields;
    const trustee = normalizedWindowsTrustee(rawTrustee);
    const expectedFlags = kind === 'directory' ? new Set(['OI', 'CI']) : new Set();
    const flagParts = flags.match(/OI|CI|NP|IO|ID|SA|FA/gu) ?? [];
    if (type !== 'A' || rights !== 'FA' || objectType || inheritedObjectType
      || flagParts.join('') !== flags || flagParts.length !== expectedFlags.size
      || flagParts.some((flag) => !expectedFlags.has(flag))
      || !expected.has(trustee) || observed.has(trustee)) {
      throw windowsAclFailure();
    }
    observed.add(trustee);
    cursor = end + 1;
  }
  if (observed.size !== expected.size) throw windowsAclFailure();
}

function windowsSystemTool(name) {
  const root = String(process.env.SystemRoot ?? process.env.WINDIR ?? '');
  if (!/^[A-Za-z]:[\\/]/u.test(root) || root.includes('\u0000')) throw windowsAclFailure();
  const systemDirectory = path.win32.resolve(root, 'System32');
  return { executable: path.win32.join(systemDirectory, name), systemDirectory };
}

async function runWindowsSystemTool(name, args, { environment = process.env } = {}) {
  const { executable, systemDirectory } = windowsSystemTool(name);
  try {
    const result = await execFileAsync(executable, args, {
      cwd: systemDirectory,
      encoding: 'utf8',
      env: environment,
      maxBuffer: 64 * 1024,
      shell: false,
      timeout: 10_000,
      windowsHide: true,
    });
    return String(result.stdout ?? '');
  } catch {
    throw windowsAclFailure();
  }
}

async function replaceWindowsAcl(target, allowedSids, kind) {
  const script = [
    "$ErrorActionPreference = 'Stop'",
    '$target = $env:ASA_CROSSCHAT_PRIVATE_TARGET',
    '$kind = $env:ASA_CROSSCHAT_PRIVATE_KIND',
    '$sids = @($env:ASA_CROSSCHAT_PRIVATE_SIDS -split ",")',
    'if ($kind -eq "directory") {',
    '  $acl = New-Object System.Security.AccessControl.DirectorySecurity',
    '  $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit',
    '} else {',
    '  $acl = New-Object System.Security.AccessControl.FileSecurity',
    '  $inheritance = [System.Security.AccessControl.InheritanceFlags]::None',
    '}',
    '$acl.SetAccessRuleProtection($true, $false)',
    'foreach ($sidText in $sids) {',
    '  $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)',
    '  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)',
    '  [void]$acl.AddAccessRule($rule)',
    '}',
    'Set-Acl -LiteralPath $target -AclObject $acl',
  ].join('; ');
  await runWindowsSystemTool('WindowsPowerShell\\v1.0\\powershell.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script,
  ], {
    environment: {
      ...process.env,
      ASA_CROSSCHAT_PRIVATE_TARGET: target,
      ASA_CROSSCHAT_PRIVATE_KIND: kind,
      ASA_CROSSCHAT_PRIVATE_SIDS: allowedSids.join(','),
    },
  });
}

async function windowsServiceSid() {
  windowsServiceSidPromise ??= (async () => {
    const output = (await runWindowsSystemTool('whoami.exe', ['/user', '/fo', 'csv', '/nh'])).trim();
    const match = output.match(/,\s*"?(S-\d+(?:-\d+)+)"?\s*$/iu);
    const sid = String(match?.[1] ?? '').toUpperCase();
    if (!WINDOWS_SID_PATTERN.test(sid)) throw windowsAclFailure();
    return sid;
  })();
  return windowsServiceSidPromise;
}

async function verifyWindowsAcl(target, allowedSids, kind) {
  const descriptorFile = path.join(path.dirname(target), `.acl-${process.pid}-${crypto.randomBytes(12).toString('hex')}.tmp`);
  let cleanupFailure = false;
  try {
    await runWindowsSystemTool('icacls.exe', [target, '/save', descriptorFile, '/L', '/Q']);
    const details = await fsp.lstat(descriptorFile);
    if (details.isSymbolicLink() || !details.isFile() || details.nlink !== 1
      || details.size < 6 || details.size > 64 * 1024) {
      throw windowsAclFailure();
    }
    const descriptor = (await fsp.readFile(descriptorFile)).toString('utf16le').replace(/^\uFEFF/u, '');
    verifyWindowsDaclDescriptor(descriptor, allowedSids, kind);
  } finally {
    try { await fsp.unlink(descriptorFile); }
    catch (error) { cleanupFailure = error.code !== 'ENOENT'; }
  }
  if (cleanupFailure) throw windowsAclFailure();
}

async function hardenWindowsAcl(target, kind) {
  if (process.platform !== 'win32') return;
  try {
    if (!path.isAbsolute(target) || target.includes('\u0000')) throw windowsAclFailure();
    const before = await fsp.lstat(target);
    const expectedType = kind === 'directory' ? before.isDirectory() : before.isFile() && before.nlink === 1;
    if (!expectedType || before.isSymbolicLink()) throw windowsAclFailure();

    const serviceSid = await windowsServiceSid();
    const allowedSids = [...new Set([serviceSid, WINDOWS_SYSTEM_SID, WINDOWS_ADMINISTRATORS_SID])];
    try {
      await verifyWindowsAcl(target, allowedSids, kind);
      const unchanged = await fsp.lstat(target);
      if (unchanged.isSymbolicLink() || unchanged.dev !== before.dev || unchanged.ino !== before.ino
        || (kind === 'directory' ? !unchanged.isDirectory() : !unchanged.isFile() || unchanged.nlink !== 1)) {
        throw windowsAclFailure();
      }
      return;
    } catch {
      // A non-canonical ACL is replaced below; exact existing ACLs remain
      // untouched so an Administrators-owned deployment can reopen unelevated.
    }
    await replaceWindowsAcl(target, allowedSids, kind);
    await verifyWindowsAcl(target, allowedSids, kind);
    const after = await fsp.lstat(target);
    if (after.isSymbolicLink() || after.dev !== before.dev || after.ino !== before.ino
      || (kind === 'directory' ? !after.isDirectory() : !after.isFile() || after.nlink !== 1)) {
      throw windowsAclFailure();
    }
  } catch {
    throw windowsAclFailure();
  }
}

function decodeKey(value) {
  const text = String(value ?? '').trim();
  if (!KEY_PATTERN.test(text)) throw new Error('Managed instance key has an invalid encoding');
  const hex = /^(?:hex:)?[a-f0-9]{64}$/iu.test(text);
  const key = Buffer.from(text.replace(hex ? /^(?:hex:)?/iu : /^(?:base64:)?/u, ''), hex ? 'hex' : 'base64');
  if (key.length !== 32) throw new Error('Managed instance key must decode to exactly 32 bytes');
  return key;
}

async function assertPrivateDirectory(directory, { create = true } = {}) {
  if (create) await fsp.mkdir(directory, { recursive: true, mode: 0o700 });
  const details = await fsp.lstat(directory);
  if (!details.isDirectory() || details.isSymbolicLink()) throw new Error('Managed keystore must be a real directory');
  if (process.platform === 'win32') {
    await hardenWindowsAcl(path.resolve(directory), 'directory');
  } else if ((details.mode & 0o077) !== 0) {
    await fsp.chmod(directory, 0o700);
    const hardened = await fsp.lstat(directory);
    if ((hardened.mode & 0o077) !== 0) throw new Error('Managed keystore permissions must be 0700');
  }
}

export async function hardenManagedPrivatePath(target, { kind = 'file' } = {}) {
  const absolute = path.resolve(target);
  if (kind === 'directory') {
    await assertPrivateDirectory(absolute);
    return absolute;
  }
  if (kind !== 'file') throw new Error('Managed private path kind is invalid');
  let details = await fsp.lstat(absolute);
  if (details.isSymbolicLink() || !details.isFile() || details.nlink !== 1) {
    throw new Error('Managed private file must be one unlinked regular file');
  }
  if (process.platform === 'win32') {
    await hardenWindowsAcl(absolute, 'file');
    details = await fsp.lstat(absolute);
  } else {
    if ((details.mode & 0o077) !== 0) await fsp.chmod(absolute, 0o600);
    const hardened = await fsp.lstat(absolute);
    if (hardened.isSymbolicLink() || !hardened.isFile() || hardened.nlink !== 1
      || hardened.dev !== details.dev || hardened.ino !== details.ino || (hardened.mode & 0o077) !== 0) {
      throw new Error('Managed private file permissions could not be secured');
    }
  }
  return absolute;
}

async function reconcilePublicationTemps(file, pattern) {
  const absolute = path.resolve(file);
  const directory = path.dirname(absolute);
  let published = null;
  try { published = await fsp.lstat(absolute); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const candidates = [];
  for (const name of await fsp.readdir(directory)) {
    if (!pattern.test(name)) continue;
    const candidate = path.join(directory, name);
    const details = await fsp.lstat(candidate);
    if (details.isSymbolicLink() || !details.isFile()) throw new Error('Managed keystore publication artifact is invalid');
    candidates.push({ candidate, details });
  }
  const linked = candidates.filter(({ details }) => published
    && details.dev === published.dev && details.ino === published.ino);
  if (published && published.nlink !== linked.length + 1) {
    throw new Error('Managed keystore publication has an unexpected hard link');
  }
  for (const { details } of candidates) {
    const linkedToPublished = published && details.dev === published.dev && details.ino === published.ino;
    if (details.nlink !== (linkedToPublished ? published.nlink : 1)) {
      throw new Error('Managed keystore publication artifact has an unexpected hard link');
    }
  }
  for (const { candidate } of candidates) await fsp.unlink(candidate);
  if (candidates.length) await syncDirectory(directory);
}

export async function readManagedKeyFile(file) {
  const absolute = path.resolve(file);
  await assertPrivateDirectory(path.dirname(absolute));
  let before = await fsp.lstat(absolute);
  if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1
    || before.size < 1 || before.size > MAX_KEY_FILE_BYTES) {
    throw new Error('Managed instance key path must be one bounded, unlinked regular file');
  }
  if (process.platform === 'win32') {
    await hardenWindowsAcl(absolute, 'file');
    before = await fsp.lstat(absolute);
  } else if ((before.mode & 0o077) !== 0) {
    throw new Error('Managed instance key permissions must be 0600 or stricter');
  }
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  const handle = await fsp.open(absolute, flags);
  let bytes;
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== before.size || opened.ino !== before.ino || opened.dev !== before.dev) {
      throw new Error('Managed instance key changed while it was being opened');
    }
    bytes = Buffer.alloc(opened.size);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    if (bytesRead !== bytes.length) throw new Error('Managed instance key could not be read completely');
    const after = await handle.stat();
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) {
      throw new Error('Managed instance key changed while it was being read');
    }
    return decodeKey(bytes.toString('utf8'));
  } finally {
    bytes?.fill(0);
    await handle.close();
  }
}

export async function createManagedKeyFile(file, { encodedKey = '', randomBytes = crypto.randomBytes } = {}) {
  const absolute = path.resolve(file);
  await assertPrivateDirectory(path.dirname(absolute));
  await reconcilePublicationTemps(absolute, KEY_TEMP_PATTERN);
  let key;
  if (encodedKey) key = decodeKey(encodedKey);
  else {
    key = randomBytes(32);
    if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('Managed key generator must return exactly 32 bytes');
  }
  const content = `base64:${key.toString('base64')}\n`;
  const temporary = path.join(path.dirname(absolute), `.instance-key-${process.pid}-${crypto.randomBytes(12).toString('hex')}.tmp`);
  let published = false;
  try {
    const handle = await fsp.open(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0), 0o600);
    try { await handle.writeFile(content, 'utf8'); await handle.sync(); }
    finally { await handle.close(); }
    if (process.platform === 'win32') await hardenWindowsAcl(temporary, 'file');
    else await fsp.chmod(temporary, 0o600);
    try {
      await fsp.link(temporary, absolute);
      published = true;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      key.fill(0);
      return readManagedKeyFile(absolute);
    }
    await syncDirectory(path.dirname(absolute));
  } catch (error) {
    key.fill(0);
    throw error;
  } finally {
    await fsp.unlink(temporary).catch((error) => { if (error.code !== 'ENOENT') throw error; });
    await syncDirectory(path.dirname(absolute));
  }
  if (!published) { key.fill(0); throw new Error('Managed instance key could not be published'); }
  return key;
}

export async function ensureManagedKeyFile(file, options = {}) {
  try { return await readManagedKeyFile(file); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return createManagedKeyFile(file, options);
  }
}

export async function removeIncompleteManagedKeyFile(file, expectedKey) {
  if (!Buffer.isBuffer(expectedKey) || expectedKey.length !== 32) {
    throw new Error('Managed recovery key must contain exactly 32 bytes');
  }
  const absolute = path.resolve(file);
  await assertPrivateDirectory(path.dirname(absolute));
  let before;
  try { before = await fsp.lstat(absolute); }
  catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  const expected = Buffer.from(`base64:${expectedKey.toString('base64')}\n`, 'utf8');
  if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1
    || before.size >= expected.length) {
    throw new Error('Managed published key conflicts with the authenticated initialization record');
  }
  if (process.platform === 'win32') {
    await hardenWindowsAcl(absolute, 'file');
    before = await fsp.lstat(absolute);
  } else if ((before.mode & 0o077) !== 0) {
    throw new Error('Managed incomplete key permissions must be 0600 or stricter');
  }
  const handle = await fsp.open(absolute, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  let bytes;
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 || opened.size !== before.size
      || opened.ino !== before.ino || opened.dev !== before.dev) {
      throw new Error('Managed incomplete key changed while it was being opened');
    }
    bytes = Buffer.alloc(opened.size);
    if (bytes.length) {
      const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
      if (bytesRead !== bytes.length) throw new Error('Managed incomplete key could not be read completely');
    }
    const after = await handle.stat();
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs
      || !expected.subarray(0, bytes.length).equals(bytes)) {
      throw new Error('Managed published key conflicts with the authenticated initialization record');
    }
  } finally {
    bytes?.fill(0);
    expected.fill(0);
    await handle.close();
  }
  const current = await fsp.lstat(absolute);
  if (current.isSymbolicLink() || !current.isFile() || current.nlink !== 1
    || current.dev !== before.dev || current.ino !== before.ino || current.size !== before.size) {
    throw new Error('Managed incomplete key changed before recovery');
  }
  await fsp.unlink(absolute);
  await syncDirectory(path.dirname(absolute));
  return true;
}

function normalizedInitializationProvenance({ mode, configurationDigest = '', stateDigest = '' } = {}) {
  if (!['fresh', 'legacy-sqlite'].includes(mode)) throw new Error('Managed initialization mode is invalid');
  if (mode === 'fresh' && (configurationDigest !== '' || stateDigest !== '')) {
    throw new Error('Fresh managed initialization cannot contain legacy provenance');
  }
  if (mode === 'legacy-sqlite' && (!INITIALIZATION_DIGEST_PATTERN.test(configurationDigest)
    || !INITIALIZATION_DIGEST_PATTERN.test(stateDigest))) {
    throw new Error('Legacy managed initialization provenance is invalid');
  }
  return { mode, configurationDigest, stateDigest };
}

function initializationPayload(key, provenance) {
  return {
    format: INITIALIZATION_FORMAT,
    version: 1,
    ...provenance,
    key: encodeManagedKey(key),
  };
}

function initializationMac(key, payload) {
  return crypto.createHmac('sha256', key)
    .update(`${INITIALIZATION_FORMAT}:v1:`, 'utf8')
    .update(JSON.stringify(payload), 'utf8')
    .digest('base64url');
}

async function readManagedInitializationBytes(file) {
  const absolute = path.resolve(file);
  await assertPrivateDirectory(path.dirname(absolute));
  let before = await fsp.lstat(absolute);
  if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1
    || before.size < 1 || before.size > MAX_INITIALIZATION_FILE_BYTES) {
    throw new Error('Managed initialization path must be one bounded, unlinked regular file');
  }
  if (process.platform === 'win32') {
    await hardenWindowsAcl(absolute, 'file');
    before = await fsp.lstat(absolute);
  } else if ((before.mode & 0o077) !== 0) {
    throw new Error('Managed initialization permissions must be 0600 or stricter');
  }
  const handle = await fsp.open(absolute, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  let bytes;
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 || opened.size !== before.size
      || opened.ino !== before.ino || opened.dev !== before.dev) {
      throw new Error('Managed initialization record changed while it was being opened');
    }
    bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (!bytesRead) throw new Error('Managed initialization record ended unexpectedly');
      offset += bytesRead;
    }
    const after = await handle.stat();
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) {
      throw new Error('Managed initialization record changed while it was being read');
    }
    const text = bytes.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(bytes)) throw new Error('Managed initialization record is not valid UTF-8');
    return text;
  } finally {
    bytes?.fill(0);
    await handle.close();
  }
}

export async function readManagedInitializationFile(file) {
  let record;
  try { record = JSON.parse(await readManagedInitializationBytes(file)); }
  catch (error) {
    if (error.code === 'ENOENT') throw error;
    throw new Error('Managed initialization record is invalid');
  }
  const keys = record && typeof record === 'object' && !Array.isArray(record) ? Object.keys(record).sort() : [];
  if (keys.join(',') !== 'configurationDigest,format,key,mac,mode,stateDigest,version'
    || record.format !== INITIALIZATION_FORMAT || record.version !== 1
    || !INITIALIZATION_DIGEST_PATTERN.test(String(record.mac ?? ''))) {
    throw new Error('Managed initialization record is invalid');
  }
  let provenance;
  let key;
  try {
    provenance = normalizedInitializationProvenance(record);
    key = decodeKey(record.key);
    const payload = initializationPayload(key, provenance);
    const expected = Buffer.from(initializationMac(key, payload), 'base64url');
    const actual = Buffer.from(record.mac, 'base64url');
    if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
      throw new Error('Managed initialization record is invalid');
    }
    return { key, ...provenance };
  } catch {
    key?.fill(0);
    throw new Error('Managed initialization record is invalid');
  }
}

export async function createManagedInitializationFile(file, {
  mode, configurationDigest = '', stateDigest = '', encodedKey = '', randomBytes = crypto.randomBytes,
} = {}) {
  const absolute = path.resolve(file);
  const provenance = normalizedInitializationProvenance({ mode, configurationDigest, stateDigest });
  await assertPrivateDirectory(path.dirname(absolute));
  await reconcilePublicationTemps(absolute, INITIALIZATION_TEMP_PATTERN);
  let key;
  if (encodedKey) key = decodeKey(encodedKey);
  else {
    key = randomBytes(32);
    if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('Managed key generator must return exactly 32 bytes');
  }
  const payload = initializationPayload(key, provenance);
  const content = `${JSON.stringify({ ...payload, mac: initializationMac(key, payload) })}\n`;
  const temporary = path.join(path.dirname(absolute), `.initialization-${process.pid}-${crypto.randomBytes(12).toString('hex')}.tmp`);
  let published = false;
  try {
    const handle = await fsp.open(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0), 0o600);
    try { await handle.writeFile(content, 'utf8'); await handle.sync(); }
    finally { await handle.close(); }
    if (process.platform === 'win32') await hardenWindowsAcl(temporary, 'file');
    else await fsp.chmod(temporary, 0o600);
    try {
      await fsp.link(temporary, absolute);
      published = true;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      key.fill(0);
      return readManagedInitializationFile(absolute);
    }
    await syncDirectory(path.dirname(absolute));
  } catch (error) {
    key.fill(0);
    throw error;
  } finally {
    await fsp.unlink(temporary).catch((error) => { if (error.code !== 'ENOENT') throw error; });
    await syncDirectory(path.dirname(absolute));
  }
  if (!published) { key.fill(0); throw new Error('Managed initialization record could not be published'); }
  return { key, ...provenance };
}

export async function removeManagedInitializationFile(file) {
  const absolute = path.resolve(file);
  try {
    const details = await fsp.lstat(absolute);
    if (details.isSymbolicLink() || !details.isFile() || details.nlink !== 1) {
      throw new Error('Managed initialization path is not one unlinked regular file');
    }
    if (process.platform === 'win32') await hardenWindowsAcl(absolute, 'file');
    else if ((details.mode & 0o077) !== 0) throw new Error('Managed initialization permissions must be 0600 or stricter');
    await fsp.unlink(absolute);
    await syncDirectory(path.dirname(absolute));
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

export function decodeManagedKey(value) {
  return decodeKey(value);
}

function setupCa(caPem) {
  const value = String(caPem ?? '');
  if (!value) return { pem: '', fingerprint: 'unavailable', encoded: 'unavailable' };
  if (Buffer.byteLength(value, 'utf8') > MAX_CA_BYTES) throw new Error('First-run HTTPS CA exceeds its safety limit');
  let certificate;
  try { certificate = new crypto.X509Certificate(value); }
  catch { throw new Error('First-run HTTPS CA is invalid'); }
  if (!certificate.ca) throw new Error('First-run HTTPS trust anchor is not a certificate authority');
  const pem = certificate.toString();
  return {
    pem,
    fingerprint: certificate.fingerprint256.replaceAll(':', '').toLocaleLowerCase('en-US'),
    encoded: Buffer.from(pem, 'utf8').toString('base64'),
  };
}

function setupRecord(token, caPem = '') {
  const value = String(token ?? '');
  if (!SETUP_TOKEN_PATTERN.test(value)) throw new Error('First-run setup token is invalid');
  const ca = setupCa(caPem);
  return {
    ca,
    content: [
      'BLCKSNAKE Command first-run owner setup',
      '',
      'Open the HTTPS dashboard and enter this value in the Setup token field:',
      value,
      '',
      'HTTPS CA SHA-256:',
      ca.fingerprint,
      '',
      'HTTPS CA PEM (base64):',
      ca.encoded,
      '',
      'This file is removed after the server owner is created.',
      '',
    ].join('\n'),
  };
}

async function readBoundedSetupRecord(file) {
  const absolute = path.resolve(file);
  await assertPrivateDirectory(path.dirname(absolute));
  let before = await fsp.lstat(absolute);
  if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1
    || before.size < 1 || before.size > MAX_SETUP_FILE_BYTES) {
    throw new Error('First-run setup path must be one bounded, unlinked regular file');
  }
  if (process.platform === 'win32') {
    await hardenWindowsAcl(absolute, 'file');
    before = await fsp.lstat(absolute);
  } else if ((before.mode & 0o077) !== 0) {
    throw new Error('First-run setup record permissions must be 0600 or stricter');
  }
  const handle = await fsp.open(absolute, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  let bytes;
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 || opened.size !== before.size
      || opened.ino !== before.ino || opened.dev !== before.dev) {
      throw new Error('First-run setup record changed while it was being opened');
    }
    bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (!result.bytesRead) throw new Error('First-run setup record ended unexpectedly');
      offset += result.bytesRead;
    }
    const after = await handle.stat();
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) {
      throw new Error('First-run setup record changed while it was being read');
    }
    const text = bytes.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(bytes)) throw new Error('First-run setup record is not valid UTF-8');
    return text;
  } finally {
    bytes?.fill(0);
    await handle.close();
  }
}

export async function readFirstRunSetupFile(file) {
  const text = await readBoundedSetupRecord(file);
  const match = text.match(SETUP_RECORD_PATTERN);
  if (!match || !SETUP_TOKEN_PATTERN.test(match[1])) throw new Error('First-run setup record is malformed');
  const [, token, fingerprint, encoded] = match;
  if ((fingerprint === 'unavailable') !== (encoded === 'unavailable')) {
    throw new Error('First-run setup record is malformed');
  }
  const ca = encoded === 'unavailable' ? setupCa('') : setupCa(Buffer.from(encoded, 'base64').toString('utf8'));
  if (ca.fingerprint !== fingerprint || (encoded !== 'unavailable' && ca.encoded !== encoded)) {
    throw new Error('First-run setup record HTTPS CA does not match its fingerprint');
  }
  return Object.freeze({ token, caPem: ca.pem, caFingerprint: ca.fingerprint === 'unavailable' ? '' : ca.fingerprint });
}

export async function writeFirstRunSetupFile(file, token, { caPem = '' } = {}) {
  const absolute = path.resolve(file);
  await assertPrivateDirectory(path.dirname(absolute));
  await reconcilePublicationTemps(absolute, SETUP_TEMP_PATTERN);
  const { content } = setupRecord(token, caPem);
  const temporary = path.join(path.dirname(absolute), `.setup-${process.pid}-${crypto.randomBytes(12).toString('hex')}.tmp`);
  let published = false;
  try {
    const handle = await fsp.open(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0), 0o600);
    try { await handle.writeFile(content, 'utf8'); await handle.sync(); } finally { await handle.close(); }
    if (process.platform === 'win32') await hardenWindowsAcl(temporary, 'file');
    else await fsp.chmod(temporary, 0o600);
    try {
      const existing = await fsp.lstat(absolute);
      if (existing.isSymbolicLink() || !existing.isFile() || existing.nlink !== 1) {
        throw new Error('First-run setup path is not one unlinked regular file');
      }
      if (process.platform === 'win32') await hardenWindowsAcl(absolute, 'file');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await fsp.rename(temporary, absolute);
    published = true;
    await syncDirectory(path.dirname(absolute));
    const persisted = await readFirstRunSetupFile(absolute);
    const expected = setupRecord(token, caPem);
    if (persisted.token !== String(token) || persisted.caFingerprint !== (expected.ca.fingerprint === 'unavailable' ? '' : expected.ca.fingerprint)) {
      throw new Error('First-run setup record could not be verified after publication');
    }
  } finally {
    if (!published) await fsp.unlink(temporary).catch((error) => { if (error.code !== 'ENOENT') throw error; });
    await syncDirectory(path.dirname(absolute));
  }
  return absolute;
}

export async function removeFirstRunSetupFile(file) {
  const absolute = path.resolve(file);
  await assertPrivateDirectory(path.dirname(absolute));
  await reconcilePublicationTemps(absolute, SETUP_TEMP_PATTERN);
  try {
    const details = await fsp.lstat(absolute);
    if (details.isSymbolicLink() || !details.isFile()) throw new Error('First-run setup path is not a regular file');
    if (process.platform === 'win32') await hardenWindowsAcl(absolute, 'file');
    await fsp.unlink(absolute);
    await syncDirectory(path.dirname(absolute));
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

export async function reconcileManagedKeystorePublications({
  keyFile, initializationFile, setupFile,
} = {}) {
  for (const [file, pattern] of [
    [keyFile, KEY_TEMP_PATTERN],
    [initializationFile, INITIALIZATION_TEMP_PATTERN],
    [setupFile, SETUP_TEMP_PATTERN],
  ]) {
    if (!file) throw new Error('Managed keystore publication path is required');
    const absolute = path.resolve(file);
    await assertPrivateDirectory(path.dirname(absolute));
    await reconcilePublicationTemps(absolute, pattern);
  }
}

export async function acquireManagedRuntimeLock(file, { requireExisting = false } = {}) {
  const absolute = path.resolve(file);
  await assertPrivateDirectory(path.dirname(absolute), { create: !requireExisting });
  let existing = null;
  try {
    existing = await fsp.lstat(absolute);
    if (existing.isSymbolicLink() || !existing.isFile() || existing.nlink !== 1) {
      throw new Error('Managed runtime lock database is invalid');
    }
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (requireExisting && !existing) throw new Error('Managed runtime lock database is unavailable');
  let database;
  try {
    database = new Database(absolute, { timeout: 250, fileMustExist: requireExisting });
    database.pragma('trusted_schema = OFF');
    if (requireExisting) {
      const lockTable = database.prepare(
        "SELECT 1 AS present FROM sqlite_schema WHERE type = 'table' AND name = 'runtime_lock'",
      ).get();
      if (!lockTable?.present) throw new Error('Managed runtime lock schema is unavailable');
    }
    database.pragma('journal_mode = DELETE');
    database.pragma('synchronous = FULL');
    database.pragma('busy_timeout = 250');
    if (!requireExisting) {
      database.exec('CREATE TABLE IF NOT EXISTS runtime_lock (singleton INTEGER PRIMARY KEY CHECK (singleton = 1)) STRICT');
    }
    const metadata = await fsp.lstat(absolute);
    if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1) {
      throw new Error('Managed runtime lock database is invalid');
    }
    if (process.platform === 'win32') await hardenWindowsAcl(absolute, 'file');
    else await fsp.chmod(absolute, 0o600);
    database.exec('BEGIN EXCLUSIVE');
    let released = false;
    return Object.freeze({
      async release() {
        if (released) return;
        released = true;
        try { database.exec('ROLLBACK'); } finally { database.close(); }
      },
    });
  } catch {
    try { database?.close(); } catch { /* Preserve the generic singleton failure. */ }
    throw new Error('Another BLCKSNAKE Command process already owns this managed instance');
  }
}

export function encodeManagedKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('Managed key must contain exactly 32 bytes');
  return `base64:${key.toString('base64')}`;
}
