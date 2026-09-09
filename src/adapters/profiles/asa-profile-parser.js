const EOS_ID_PATTERN = /^[a-f0-9]{32}$/i;
const PLAYER_DATA_ID_MAX = 4_294_967_295n;
const DEFAULT_MAX_PROFILE_BYTES = 16 * 1024 * 1024;
const MAX_OBJECTS = 4_096;
const MAX_NAMES_PER_OBJECT = 16_384;
const MAX_TYPE_ARGUMENTS = 16;
const MAX_STRING_BYTES = 1024 * 1024;

export const MAX_ASA_PROFILE_BYTES = DEFAULT_MAX_PROFILE_BYTES;

export class AsaProfileParseError extends Error {
  constructor(message, code = 'INVALID_PROFILE') {
    super(message);
    this.name = 'AsaProfileParseError';
    this.code = code;
  }
}

function fail(message, code) {
  throw new AsaProfileParseError(message, code);
}

class Reader {
  constructor(buffer, start = 0, end = buffer.length) {
    this.buffer = buffer;
    this.position = start;
    this.end = end;
  }

  remaining() { return this.end - this.position; }

  need(bytes) {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > this.remaining()) {
      fail('ARK profile is truncated or contains an invalid length');
    }
  }

  byte() { this.need(1); return this.buffer[this.position++]; }

  int32() {
    this.need(4);
    const value = this.buffer.readInt32LE(this.position);
    this.position += 4;
    return value;
  }

  bytes(length) {
    this.need(length);
    const value = this.buffer.subarray(this.position, this.position + length);
    this.position += length;
    return value;
  }

  ueString({ identifier = false } = {}) {
    const length = this.int32();
    if (length === 0) return '';
    const wide = length < 0;
    const units = Math.abs(length);
    const byteLength = units * (wide ? 2 : 1);
    if (!Number.isSafeInteger(byteLength) || byteLength < (wide ? 2 : 1) || byteLength > MAX_STRING_BYTES) {
      fail('ARK profile contains an invalid string length');
    }
    const raw = this.bytes(byteLength);
    if (wide) {
      if (raw.at(-1) !== 0 || raw.at(-2) !== 0) fail('ARK profile contains an unterminated UTF-16 string');
    } else if (raw.at(-1) !== 0) {
      fail('ARK profile contains an unterminated UTF-8 string');
    }
    const value = raw.toString(wide ? 'utf16le' : 'utf8', 0, raw.length - (wide ? 2 : 1));
    if (value.includes('\0')) fail('ARK profile contains an embedded string terminator');
    if (identifier && !/^[A-Za-z0-9_./'-]+$/.test(value)) fail('ARK profile contains an invalid identifier');
    return value;
  }
}

function encodedAsciiString(value) {
  const raw = Buffer.from(`${value}\0`, 'ascii');
  const length = Buffer.allocUnsafe(4);
  length.writeInt32LE(raw.length);
  return Buffer.concat([length, raw]);
}

function propertyRanges(buffer) {
  if (buffer.length < 9) fail('ARK profile is too small');
  const reader = new Reader(buffer);
  const version = reader.int32();
  let objectCount;
  if (version === 6) {
    objectCount = reader.int32();
  } else if (version >= 7 && version <= 1_000) {
    reader.int32();
    reader.int32();
    objectCount = reader.int32();
  } else {
    fail(`Unsupported ASA profile version ${version}`, 'UNSUPPORTED_VERSION');
  }
  if (objectCount < 1 || objectCount > MAX_OBJECTS || objectCount > Math.floor(buffer.length / 40)) {
    fail('ARK profile contains an invalid object count');
  }

  const objects = [];
  for (let index = 0; index < objectCount; index += 1) {
    reader.bytes(16); // object GUID
    const className = reader.ueString({ identifier: true });
    reader.int32(); // isItem
    const nameCount = reader.int32();
    if (nameCount < 0 || nameCount > MAX_NAMES_PER_OBJECT || nameCount > Math.floor(reader.remaining() / 4)) {
      fail('ARK profile contains an invalid object-name count');
    }
    for (let nameIndex = 0; nameIndex < nameCount; nameIndex += 1) reader.ueString({ identifier: true });
    reader.int32();
    reader.int32();
    reader.int32();
    const storedStart = reader.int32();
    // Version 7 stores the byte immediately before the first property tag;
    // version 6 stores the tag start. Skipping an optional lead byte is safe
    // because field discovery below searches within the bounded object block.
    objects.push({ className, storedStart, start: storedStart + (version >= 7 ? 1 : 0) });
    reader.int32();
  }

  const tableEnd = reader.position;
  const ordered = [...objects].sort((left, right) => left.start - right.start);
  const expectedFirstStarts = version >= 7 ? new Set([tableEnd, tableEnd + 1]) : new Set([tableEnd]);
  if (new Set(ordered.map(({ start }) => start)).size !== ordered.length || !expectedFirstStarts.has(ordered[0].start)) {
    fail('ARK profile contains invalid property offsets');
  }
  for (const { storedStart, start } of ordered) {
    if (!Number.isSafeInteger(storedStart) || !Number.isSafeInteger(start) || storedStart < tableEnd - 1 || start < tableEnd || start >= buffer.length) {
      fail('ARK profile contains an out-of-range property offset');
    }
  }
  const ranges = ordered.map((object, index) => ({
    className: object.className,
    start: object.start,
    end: ordered[index + 1]?.start ?? buffer.length,
  }));
  const playerRanges = ranges.filter(({ className }) => className.includes('PrimalPlayerData'));
  if (playerRanges.length !== 1) fail('ARK profile does not contain exactly one player-data object');
  return playerRanges.map((range) => ({ ...range, version }));
}

function parseVersionSixProperty(reader, type) {
  const size = reader.int32();
  reader.int32(); // position marker; not an array index in ASA profiles
  if (size < 0) fail('ARK profile contains a negative property size');
  if (type === 'StructProperty') {
    const structType = reader.ueString({ identifier: true });
    const payloadStart = reader.position;
    reader.need(size);
    return { typeArguments: [structType], payloadStart, payloadEnd: payloadStart + size };
  }
  const flags = reader.byte();
  const arrayIndex = (flags & 0x01) === 0x01 ? reader.int32() : undefined;
  const payloadStart = reader.position;
  reader.need(size);
  return { typeArguments: [], arrayIndex, payloadStart, payloadEnd: payloadStart + size };
}

function parseVersionSevenProperty(reader) {
  const typeArguments = [];
  for (;;) {
    const flag = reader.int32();
    if (flag === 0) break;
    if (flag !== 1 || typeArguments.length >= MAX_TYPE_ARGUMENTS) fail('ARK profile contains invalid property type arguments');
    typeArguments.push(reader.ueString({ identifier: true }));
  }
  const size = reader.int32();
  if (size < 0) fail('ARK profile contains a negative property size');
  const flags = reader.byte();
  const arrayIndex = (flags & 0x01) === 0x01 ? reader.int32() : undefined;
  const payloadStart = reader.position;
  reader.need(size);
  return { typeArguments, arrayIndex, payloadStart, payloadEnd: payloadStart + size };
}

function parsePropertyAt(buffer, position, rangeEnd, version) {
  const reader = new Reader(buffer, position, rangeEnd);
  const name = reader.ueString({ identifier: true });
  if (!name || name === 'None') fail('Invalid property marker');
  const type = reader.ueString({ identifier: true });
  const body = version === 6
    ? parseVersionSixProperty(reader, type)
    : parseVersionSevenProperty(reader);
  return { name, type, ...body };
}

function findProperties(buffer, ranges, name) {
  const needle = encodedAsciiString(name);
  const matches = [];
  for (const range of ranges) {
    let position = buffer.indexOf(needle, range.start);
    while (position !== -1 && position + needle.length <= range.end) {
      try {
        const property = parsePropertyAt(buffer, position, range.end, range.version);
        if (property.name === name) matches.push({ ...property, position });
      } catch (error) {
        if (!(error instanceof AsaProfileParseError)) throw error;
      }
      position = buffer.indexOf(needle, position + 1);
    }
  }
  return matches;
}

function requireSingleProperty(buffer, ranges, name) {
  const matches = findProperties(buffer, ranges, name);
  if (!matches.length) fail(`ARK profile is missing ${name}`, 'MISSING_FIELD');
  if (matches.length !== 1) fail(`ARK profile contains more than one ${name}`, 'AMBIGUOUS_FIELD');
  return matches[0];
}

function optionalSingleProperty(buffer, ranges, name) {
  const matches = findProperties(buffer, ranges, name);
  if (matches.length > 1) fail(`ARK profile contains more than one ${name}`, 'AMBIGUOUS_FIELD');
  return matches[0] ?? null;
}

function parsePlayerDataId(buffer, property) {
  const payload = buffer.subarray(property.payloadStart, property.payloadEnd);
  let value;
  if (property.type === 'UInt32Property' && payload.length === 4) value = BigInt(payload.readUInt32LE());
  else if (property.type === 'IntProperty' && payload.length === 4) value = BigInt(payload.readInt32LE());
  else if (property.type === 'UInt64Property' && payload.length === 8) value = payload.readBigUInt64LE();
  else if (property.type === 'Int64Property' && payload.length === 8) value = payload.readBigInt64LE();
  else fail('ARK profile has an unsupported PlayerDataID encoding', 'INVALID_PLAYER_DATA_ID');
  if (value < 1n || value > PLAYER_DATA_ID_MAX) {
    fail('ARK profile PlayerDataID is outside the supported range', 'INVALID_PLAYER_DATA_ID');
  }
  return value.toString();
}

function parseEosId(buffer, property) {
  if (property.type !== 'StructProperty' || !property.typeArguments.includes('UniqueNetIdRepl')) {
    fail('ARK profile has an unsupported UniqueID encoding', 'INVALID_EOS_ID');
  }
  const reader = new Reader(buffer, property.payloadStart, property.payloadEnd);
  reader.byte(); // serialized UniqueNetIdRepl flags
  const idType = reader.ueString({ identifier: true });
  const idLength = reader.byte();
  if (idType !== 'RedpointEOS' || idLength !== 16 || reader.remaining() !== idLength) {
    fail('ARK profile does not contain a valid EOS UniqueID', 'INVALID_EOS_ID');
  }
  return reader.bytes(idLength).toString('hex');
}

function parseName(buffer, property) {
  if (!property) return null;
  if (property.type !== 'StrProperty' && property.type !== 'NameProperty') {
    fail(`ARK profile has an unsupported ${property.name} encoding`);
  }
  const reader = new Reader(buffer, property.payloadStart, property.payloadEnd);
  const value = reader.ueString();
  if (reader.remaining() !== 0) fail(`ARK profile contains trailing data in ${property.name}`);
  if (Array.from(value).length > 256) fail(`ARK profile ${property.name} is too long`);
  return value || null;
}

/**
 * Extract the identity fields needed for targeted ASA admin commands.
 *
 * The connected player's EOS ID is mandatory. The parser validates it against
 * the profile's internal UniqueID; callers should separately obtain the remote
 * file using the exact `<EOS>.arkprofile` filename. No profile bytes are ever
 * modified.
 */
export function parseAsaProfile(buffer, { expectedEosId, maxBytes = DEFAULT_MAX_PROFILE_BYTES } = {}) {
  if (!Buffer.isBuffer(buffer)) fail('ARK profile input must be a Buffer', 'INVALID_INPUT');
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) fail('maxBytes must be a positive safe integer', 'INVALID_INPUT');
  if (buffer.length > maxBytes) fail('ARK profile exceeds the configured size limit', 'PROFILE_TOO_LARGE');
  const expected = String(expectedEosId ?? '').trim().toLocaleLowerCase('en-US');
  if (!EOS_ID_PATTERN.test(expected)) fail('A 32-character hexadecimal EOS ID is required', 'INVALID_INPUT');

  const ranges = propertyRanges(buffer);
  const internalEosId = parseEosId(buffer, requireSingleProperty(buffer, ranges, 'UniqueID'));
  if (internalEosId !== expected) fail('ARK profile EOS ID does not match the connected account', 'EOS_MISMATCH');
  const playerDataId = parsePlayerDataId(buffer, requireSingleProperty(buffer, ranges, 'PlayerDataID'));
  const playerName = parseName(buffer, optionalSingleProperty(buffer, ranges, 'PlayerName'));
  const characterName = parseName(buffer, optionalSingleProperty(buffer, ranges, 'PlayerCharacterName'));

  return Object.freeze({ eosId: internalEosId, playerDataId, playerName, characterName });
}
