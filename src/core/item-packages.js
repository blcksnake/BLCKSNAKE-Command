import { getItem } from './item-catalog.js';
import { normalizeWhitespace } from './sanitize.js';

export const MAX_ITEM_PACKAGES = 64;
export const MAX_PACKAGE_ITEMS = 50;
export const ITEM_PACKAGE_ID_PATTERN = /^pkg_[A-Za-z0-9_-]{22}$/u;

const PACKAGE_NAME_MAX = 64;
const PACKAGE_DESCRIPTION_MAX = 240;

function boundedText(value, label, maximum, { required = false } = {}) {
  if (typeof value !== 'string' || /[\u0000-\u001F\u007F]/u.test(value)) {
    throw new Error(`${label} must be text without control characters`);
  }
  const text = normalizeWhitespace(value);
  if ((required && !text) || Array.from(text).length > maximum) {
    throw new Error(`${label} must contain ${required ? `1-${maximum}` : `0-${maximum}`} characters`);
  }
  return text;
}

export function cleanItemPackageId(value) {
  const id = String(value ?? '').trim();
  if (!ITEM_PACKAGE_ID_PATTERN.test(id)) throw new Error('Choose a valid item package');
  return id;
}

export function normalizePackageItem(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Package items must be objects');
  for (const field of Object.keys(value)) {
    if (!['itemKey', 'quantity', 'quality', 'blueprint'].includes(field)) throw new Error(`Unsupported package item field ${field}`);
  }
  const itemKey = String(value.itemKey ?? '').trim();
  if (!getItem(itemKey)) throw new Error('Choose each package item from the trusted catalog');
  const quantity = value.quantity ?? 1;
  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 10_000) {
    throw new Error('Package item quantity must be a whole number from 1 to 10000');
  }
  const quality = value.quality ?? 0;
  if (typeof quality !== 'number' || !Number.isFinite(quality) || quality < 0 || quality > 100) {
    throw new Error('Package item quality must be a number from 0 to 100');
  }
  const blueprint = value.blueprint ?? false;
  if (typeof blueprint !== 'boolean') throw new Error('Package blueprint must be true or false');
  return { itemKey, quantity, quality: Object.is(quality, -0) ? 0 : quality, blueprint };
}

export function normalizeItemPackageInput(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Item package must be an object');
  for (const field of Object.keys(value)) {
    if (!['name', 'description', 'enabled', 'starterEnabled', 'items'].includes(field)) {
      throw new Error(`Unsupported item package field ${field}`);
    }
  }
  const name = boundedText(value.name, 'Package name', PACKAGE_NAME_MAX, { required: true });
  const description = boundedText(value.description ?? '', 'Package description', PACKAGE_DESCRIPTION_MAX);
  const enabled = value.enabled ?? true;
  const starterEnabled = value.starterEnabled ?? false;
  if (typeof enabled !== 'boolean' || typeof starterEnabled !== 'boolean') {
    throw new Error('Package toggles must be true or false');
  }
  if (starterEnabled && !enabled) throw new Error('An automatic starter package must also be enabled for staff grants');
  if (!Array.isArray(value.items) || value.items.length < 1 || value.items.length > MAX_PACKAGE_ITEMS) {
    throw new Error(`Item packages must contain 1-${MAX_PACKAGE_ITEMS} items`);
  }
  const items = value.items.map(normalizePackageItem);
  return { name, description, enabled, starterEnabled, items };
}

export function cloneItemPackage(value) {
  return value ? { ...value, items: value.items.map((item) => ({ ...item })) } : null;
}

export function normalizePersistedItemPackages(value) {
  if (value == null) return {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Persisted item packages must be an object');
  const entries = Object.entries(value);
  if (entries.length > MAX_ITEM_PACKAGES) throw new Error(`Item packages are limited to ${MAX_ITEM_PACKAGES}`);
  const output = {};
  const names = new Set();
  for (const [candidateId, candidate] of entries) {
    const id = cleanItemPackageId(candidateId);
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate) || candidate.id !== id) {
      throw new Error('Persisted item package identity is invalid');
    }
    const normalized = normalizeItemPackageInput({
      name: candidate.name,
      description: candidate.description,
      enabled: candidate.enabled,
      starterEnabled: candidate.starterEnabled,
      items: candidate.items,
    });
    const nameKey = normalized.name.toLocaleLowerCase('en-US');
    if (names.has(nameKey)) throw new Error('Item package names must be unique');
    names.add(nameKey);
    if (!Number.isSafeInteger(candidate.revision) || candidate.revision < 1
      || !Number.isSafeInteger(candidate.createdAt) || candidate.createdAt < 0
      || !Number.isSafeInteger(candidate.updatedAt) || candidate.updatedAt < candidate.createdAt) {
      throw new Error('Persisted item package metadata is invalid');
    }
    output[id] = { id, ...normalized, revision: candidate.revision, createdAt: candidate.createdAt, updatedAt: candidate.updatedAt };
  }
  return output;
}

export function publicItemPackage(value) {
  const itemPackage = cloneItemPackage(value);
  if (!itemPackage) return null;
  return {
    ...itemPackage,
    items: itemPackage.items.map((entry) => {
      const item = getItem(entry.itemKey);
      return {
        ...entry,
        name: item?.name ?? 'Unavailable catalog item',
        category: item?.category ?? 'Unavailable',
      };
    }),
  };
}
