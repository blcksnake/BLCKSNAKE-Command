const ITEM_KEY_PATTERN = /^[a-z0-9][a-z0-9-]{0,99}$/;
const PRESET_NAME_PATTERN = /^[A-Za-z0-9 _-]{1,32}$/;
const OPERATOR_ID_PATTERN = /^op_[A-Za-z0-9_-]{22}$/;
const RESERVED_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function cleanOperatorId(value) {
  if (typeof value !== 'string' || !OPERATOR_ID_PATTERN.test(value)) throw new Error('Operator account ID is invalid');
  return value;
}

export function cleanOperatorTimestamp(value, label) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new Error(`${label} must be a non-negative finite number`);
  return Object.is(value, -0) ? 0 : value;
}

export function cleanOperatorRevision(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${label} must be a positive safe integer`);
  return value;
}

export function cleanDiscordUserId(value) {
  const id = String(value ?? '').trim();
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(id) || RESERVED_OBJECT_KEYS.has(id)) {
    throw new Error('A valid Discord user ID is required');
  }
  return id;
}

export function cleanItemKey(value) {
  const key = String(value ?? '').trim();
  if (!ITEM_KEY_PATTERN.test(key)) throw new Error('Item key must be 1-100 lowercase letters, numbers, or hyphens');
  return key;
}

export function cleanPresetName(value) {
  const raw = String(value ?? '');
  if (/[\u0000-\u001F\u007F]/u.test(raw)) throw new Error('Preset name contains unsupported characters');
  const name = raw.trim().replace(/ {2,}/gu, ' ');
  if (!PRESET_NAME_PATTERN.test(name)) throw new Error('Preset name must be 1-32 letters, numbers, spaces, underscores, or hyphens');
  return name;
}
