import crypto from 'node:crypto';
import net from 'node:net';
import os from 'node:os';
import tls from 'node:tls';

const OIDS = Object.freeze({
  commonName: '2.5.4.3',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  extendedKeyUsage: '2.5.29.37',
  subjectAltName: '2.5.29.17',
  serverAuth: '1.3.6.1.5.5.7.3.1',
  ecdsaSha256: '1.2.840.10045.4.3.2',
});

const MAX_PRIVATE_KEY_BYTES = 128 * 1024;
const MAX_CERTIFICATE_BYTES = 256 * 1024;
const MAX_SUBJECT_ALT_NAMES = 16;

function lengthBytes(length) {
  if (!Number.isInteger(length) || length < 0) throw new Error('DER length is invalid');
  if (length < 128) return Buffer.from([length]);
  const bytes = [];
  for (let value = length; value > 0; value = Math.floor(value / 256)) bytes.unshift(value & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag, ...parts) {
  const value = Buffer.concat(parts.map((part) => Buffer.from(part)));
  return Buffer.concat([Buffer.from([tag]), lengthBytes(value.length), value]);
}

const sequence = (...parts) => der(0x30, ...parts);
const set = (...parts) => der(0x31, ...parts);
const octetString = (value) => der(0x04, value);
const boolean = (value) => der(0x01, Buffer.from([value ? 0xff : 0x00]));
const utf8String = (value) => der(0x0c, Buffer.from(String(value), 'utf8'));
const bitString = (value, unused = 0) => der(0x03, Buffer.from([unused]), value);

function integer(value) {
  let bytes = Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from([value]);
  while (bytes.length > 1 && bytes[0] === 0 && (bytes[1] & 0x80) === 0) bytes = bytes.subarray(1);
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return der(0x02, bytes);
}

function oid(value) {
  const parts = String(value).split('.').map(Number);
  if (parts.length < 2 || parts[0] > 2 || parts.some((part) => !Number.isSafeInteger(part) || part < 0)) {
    throw new Error('OID is invalid');
  }
  const output = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const encoded = [part & 0x7f];
    for (let remaining = Math.floor(part / 128); remaining > 0; remaining = Math.floor(remaining / 128)) {
      encoded.unshift(0x80 | (remaining & 0x7f));
    }
    output.push(...encoded);
  }
  return der(0x06, Buffer.from(output));
}

function utcTime(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error('Certificate time is invalid');
  const year = date.getUTCFullYear();
  if (year < 1950 || year > 2049) throw new Error('Certificate time is outside the supported UTC range');
  const stamp = `${String(year % 100).padStart(2, '0')}${String(date.getUTCMonth() + 1).padStart(2, '0')}`
    + `${String(date.getUTCDate()).padStart(2, '0')}${String(date.getUTCHours()).padStart(2, '0')}`
    + `${String(date.getUTCMinutes()).padStart(2, '0')}${String(date.getUTCSeconds()).padStart(2, '0')}Z`;
  return der(0x17, Buffer.from(stamp, 'ascii'));
}

function distinguishedName(commonName) {
  return sequence(set(sequence(oid(OIDS.commonName), utf8String(commonName))));
}

function extension(id, value, critical = false) {
  return sequence(oid(id), ...(critical ? [boolean(true)] : []), octetString(value));
}

function signatureAlgorithm() { return sequence(oid(OIDS.ecdsaSha256)); }

function serialNumber(randomBytes) {
  const serial = randomBytes(16);
  if (!Buffer.isBuffer(serial) || serial.length !== 16) throw new Error('Certificate serial generator must return 16 bytes');
  serial[0] &= 0x7f;
  if (serial.every((byte) => byte === 0)) serial[15] = 1;
  return serial;
}

function pem(label, bytes) {
  const body = Buffer.from(bytes).toString('base64').match(/.{1,64}/gu).join('\n');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

function certificate({
  subjectName, issuerName, publicKeyDer, issuerPrivateKey, serial, notBefore, notAfter, extensions,
}) {
  const algorithm = signatureAlgorithm();
  const tbs = sequence(
    der(0xa0, integer(2)),
    integer(serial),
    algorithm,
    issuerName,
    sequence(utcTime(notBefore), utcTime(notAfter)),
    subjectName,
    publicKeyDer,
    der(0xa3, sequence(...extensions)),
  );
  const signature = crypto.sign('sha256', tbs, issuerPrivateKey);
  return sequence(tbs, algorithm, bitString(signature));
}

function keyPair() {
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

function safeHostname(value) {
  const hostname = String(value ?? '').trim().toLocaleLowerCase('en-US');
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/u.test(hostname)
    ? hostname : 'localhost';
}

function ipv6Bytes(address) {
  const normalized = address.toLocaleLowerCase('en-US');
  const halves = normalized.split('::');
  if (halves.length > 2) throw new Error('HTTPS certificate IP address is invalid');
  const expand = (part) => {
    if (!part) return [];
    const words = part.split(':');
    const last = words.at(-1);
    if (last?.includes('.')) {
      const octets = last.split('.').map(Number);
      if (octets.length !== 4 || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
        throw new Error('HTTPS certificate IP address is invalid');
      }
      words.splice(-1, 1, ((octets[0] << 8) | octets[1]).toString(16), ((octets[2] << 8) | octets[3]).toString(16));
    }
    return words.map((word) => {
      const value = Number.parseInt(word, 16);
      if (!/^[a-f0-9]{1,4}$/u.test(word) || !Number.isInteger(value)) throw new Error('HTTPS certificate IP address is invalid');
      return value;
    });
  };
  const left = expand(halves[0]); const right = expand(halves[1] ?? '');
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
    throw new Error('HTTPS certificate IP address is invalid');
  }
  const words = [...left, ...Array(missing).fill(0), ...right];
  const output = Buffer.alloc(16);
  words.forEach((word, index) => output.writeUInt16BE(word, index * 2));
  return output;
}

function ipBytes(address) {
  if (net.isIP(address) === 4) return Buffer.from(address.split('.').map(Number));
  if (net.isIP(address) === 6) return ipv6Bytes(address);
  throw new Error('HTTPS certificate IP address is invalid');
}

function normalizeExplicitTlsName(value) {
  if (typeof value !== 'string' || /[\u0000-\u0020\u007f-\u009f]/u.test(value)) {
    throw new Error('HTTPS certificate name is invalid');
  }
  const raw = value.trim().toLocaleLowerCase('en-US');
  const bracketed = raw.startsWith('[') && raw.endsWith(']');
  if (raw.startsWith('[') !== raw.endsWith(']')) throw new Error('HTTPS certificate name is invalid');
  const name = bracketed ? raw.slice(1, -1) : raw;
  if (!name || name.includes('%')) throw new Error('HTTPS certificate name is invalid');
  if (net.isIP(name)) return name;
  if (safeHostname(name) !== name) throw new Error('HTTPS certificate name is invalid');
  return name;
}

export function normalizeTlsSubjectAltNames(values = [], { hostname = os.hostname() } = {}) {
  if (!Array.isArray(values) || values.length > MAX_SUBJECT_ALT_NAMES) {
    throw new Error(`HTTPS certificate names must be an array of at most ${MAX_SUBJECT_ALT_NAMES} entries`);
  }
  const host = safeHostname(hostname);
  const result = ['localhost', ...(host === 'localhost' ? [] : [host]), '127.0.0.1', '::1'];
  for (const value of values) {
    const name = normalizeExplicitTlsName(value);
    if (!result.includes(name)) result.push(name);
  }
  return Object.freeze(result);
}

function sanValue(names) {
  return sequence(...names.map((name) => net.isIP(name)
    ? der(0x87, ipBytes(name))
    : der(0x82, Buffer.from(name, 'ascii'))));
}

function certificateValidity(certificate, label, at) {
  const when = at instanceof Date ? at : new Date(at);
  const validFrom = Date.parse(certificate.validFrom); const validTo = Date.parse(certificate.validTo);
  if (!Number.isFinite(when.getTime()) || !Number.isFinite(validFrom) || !Number.isFinite(validTo)) {
    throw new Error(`TLS ${label} certificate validity is invalid`);
  }
  if (when.getTime() < validFrom) throw new Error(`TLS ${label} certificate is not valid yet`);
  if (when.getTime() > validTo) throw new Error(`TLS ${label} certificate has expired`);
}

export function inspectTlsIdentity({ keyPem, certPem, caPem = '', passphrase = '', at = new Date() }) {
  if (typeof keyPem !== 'string' || typeof certPem !== 'string' || typeof caPem !== 'string'
    || typeof passphrase !== 'string'
    || !keyPem.trim() || !certPem.trim()
    || Buffer.byteLength(keyPem, 'utf8') > MAX_PRIVATE_KEY_BYTES
    || Buffer.byteLength(certPem, 'utf8') > MAX_CERTIFICATE_BYTES
    || Buffer.byteLength(caPem, 'utf8') > MAX_CERTIFICATE_BYTES) {
    throw new Error('TLS identity material is missing or exceeds its safety limit');
  }
  let leaf; let privateKey; let authority = null;
  try {
    leaf = new crypto.X509Certificate(certPem);
    privateKey = crypto.createPrivateKey({ key: keyPem, format: 'pem', ...(passphrase ? { passphrase } : {}) });
    if (caPem) authority = new crypto.X509Certificate(caPem);
  } catch {
    throw new Error('TLS identity key or certificate could not be parsed');
  }
  if (leaf.ca) throw new Error('TLS leaf certificate must not be a certificate authority');
  if (!leaf.checkPrivateKey(privateKey)) throw new Error('TLS private key does not match the certificate');
  certificateValidity(leaf, 'leaf', at);
  if (authority) {
    certificateValidity(authority, 'authority', at);
    if (!authority.ca || !leaf.verify(authority.publicKey) || leaf.issuer !== authority.subject) {
      throw new Error('TLS leaf certificate is not signed by the supplied certificate authority');
    }
  }
  try {
    tls.createSecureContext({
      key: keyPem, cert: certPem, ...(caPem ? { ca: caPem } : {}),
      ...(passphrase ? { passphrase } : {}), minVersion: 'TLSv1.2',
    });
  } catch {
    throw new Error('TLS identity could not create a secure server context');
  }
  return Object.freeze({
    fingerprint: leaf.fingerprint256.replaceAll(':', '').toLocaleLowerCase('en-US'),
    subject: leaf.subject,
    issuer: leaf.issuer,
    validFrom: new Date(leaf.validFrom).toISOString(),
    expiresAt: new Date(leaf.validTo).toISOString(),
    subjectAltName: leaf.subjectAltName,
  });
}

export function generateInstanceTlsIdentity({
  hostname = os.hostname(), subjectAltNames = [], now = () => new Date(), randomBytes = crypto.randomBytes,
} = {}) {
  const issuedAt = now();
  if (!(issuedAt instanceof Date) || !Number.isFinite(issuedAt.getTime())) throw new Error('TLS identity clock returned an invalid date');
  const host = safeHostname(hostname);
  const defaultCertificateNames = normalizeTlsSubjectAltNames([], { hostname: host });
  const certificateNames = normalizeTlsSubjectAltNames(subjectAltNames, { hostname: host });
  const requestedCertificateNames = certificateNames.filter((name) => !defaultCertificateNames.includes(name));
  const marker = randomBytes(6);
  if (!Buffer.isBuffer(marker) || marker.length !== 6) throw new Error('TLS identity marker generator must return 6 bytes');
  const caName = distinguishedName(`BLCKSNAKE Command Local CA ${marker.toString('hex')}`);
  const leafName = distinguishedName(host);
  const ca = keyPair();
  const leaf = keyPair();
  const caNotBefore = new Date(issuedAt.getTime() - 60 * 60_000);
  const caNotAfter = new Date(issuedAt.getTime() + 10 * 365 * 86_400_000);
  const leafNotBefore = caNotBefore;
  const leafNotAfter = new Date(issuedAt.getTime() + 397 * 86_400_000);
  const caDer = certificate({
    subjectName: caName,
    issuerName: caName,
    publicKeyDer: ca.publicKey,
    issuerPrivateKey: ca.privateKey,
    serial: serialNumber(randomBytes),
    notBefore: caNotBefore,
    notAfter: caNotAfter,
    extensions: [
      extension(OIDS.basicConstraints, sequence(boolean(true)), true),
      extension(OIDS.keyUsage, bitString(Buffer.from([0x06]), 1), true),
    ],
  });
  const caPem = pem('CERTIFICATE', caDer);
  const leafDer = certificate({
    subjectName: leafName,
    issuerName: caName,
    publicKeyDer: leaf.publicKey,
    issuerPrivateKey: ca.privateKey,
    serial: serialNumber(randomBytes),
    notBefore: leafNotBefore,
    notAfter: leafNotAfter,
    extensions: [
      extension(OIDS.basicConstraints, sequence(), true),
      extension(OIDS.keyUsage, bitString(Buffer.from([0x80]), 7), true),
      extension(OIDS.extendedKeyUsage, sequence(oid(OIDS.serverAuth))),
      extension(OIDS.subjectAltName, sanValue(certificateNames)),
    ],
  });
  const leafPem = pem('CERTIFICATE', leafDer);
  const certPem = `${leafPem}${caPem}`;
  const details = inspectTlsIdentity({ keyPem: leaf.privateKey, certPem, caPem, at: issuedAt });
  return Object.freeze({
    mode: 'generated',
    keyPem: leaf.privateKey,
    certPem,
    caPem,
    subjectAltNames: certificateNames,
    requestedSubjectAltNames: Object.freeze(requestedCertificateNames),
    generatedAt: issuedAt.toISOString(),
    ...details,
  });
}
