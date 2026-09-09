import catalog from '../data/ark-items.json' with { type: 'json' };

const BLUEPRINT_PATTERN = /^Blueprint'\/Game\/[A-Za-z0-9_./-]+'$/;
const DEFAULT_ITEM_NAMES = Object.freeze([
  'Metal', 'Metal Ingot', 'Wood', 'Stone', 'Fiber', 'Thatch', 'Hide', 'Flint', 'Crystal', 'Obsidian',
  'Oil', 'Silica Pearls', 'Cementing Paste', 'Polymer', 'Organic Polymer', 'Electronics', 'Element',
  'Element Shard', 'Black Pearl', 'Narcotic', 'Sparkpowder', 'Gunpowder', 'Charcoal', 'Raw Meat', 'Cooked Meat',
]);

function normalize(value) {
  return String(value ?? '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().trim();
}

function validateItem(item) {
  if (!item || typeof item !== 'object') throw new Error('Invalid item catalog entry');
  if (!/^[a-z0-9][a-z0-9-]{0,99}$/.test(item.key)) throw new Error(`Invalid catalog key: ${item.key}`);
  if (!item.name || !item.category || !BLUEPRINT_PATTERN.test(item.blueprintPath)) {
    throw new Error(`Invalid catalog item: ${item.key}`);
  }
  const body = item.blueprintPath.slice("Blueprint'".length, -1);
  const separator = body.lastIndexOf('.');
  const packageName = body.slice(body.lastIndexOf('/', separator) + 1, separator);
  if (separator < 0 || !packageName || body.slice(separator + 1) !== packageName) {
    throw new Error(`Mismatched catalog blueprint object: ${item.key}`);
  }
  if (item.itemNumber !== null && (!Number.isSafeInteger(item.itemNumber) || item.itemNumber < 0)) {
    throw new Error(`Invalid item number: ${item.key}`);
  }
  if (item.gfi !== null && typeof item.gfi !== 'string') throw new Error(`Invalid GFI code: ${item.key}`);
  return Object.freeze({ ...item });
}

const items = Object.freeze(catalog.items.map(validateItem));
const byKey = new Map(items.map((item) => [item.key, item]));

function addIndex(index, key, item) {
  if (!key) return;
  const matches = index.get(key) ?? [];
  matches.push(item); index.set(key, matches);
}

const byName = new Map(); const byGfi = new Map(); const byNumber = new Map(); const byBlueprint = new Map();
for (const item of items) {
  addIndex(byName, normalize(item.name), item);
  addIndex(byGfi, normalize(item.gfi), item);
  addIndex(byNumber, item.itemNumber == null ? '' : String(item.itemNumber), item);
  addIndex(byBlueprint, normalize(item.blueprintPath), item);
}

// Empty Discord autocomplete queries should offer useful day-to-day resources,
// not whichever catalog labels happen to sort first. Only unique exact catalog
// names are accepted here, so a future catalog collision fails closed by
// omitting that shortcut rather than choosing an arbitrary item.
const defaultItems = Object.freeze(DEFAULT_ITEM_NAMES.flatMap((name) => {
  const matches = byName.get(normalize(name));
  return matches?.length === 1 ? matches : [];
}));

if (byKey.size !== items.length) throw new Error('Duplicate item catalog keys');
if (catalog.metadata?.itemCount !== items.length) throw new Error('Item catalog count does not match its metadata');

export const ITEM_COUNT = items.length;
export const ITEM_CATALOG_METADATA = Object.freeze({ ...catalog.metadata });

/** Return an item only for an exact, server-issued catalog key. */
export function getItem(value) {
  return typeof value === 'string' ? byKey.get(value) ?? null : null;
}

/**
 * Resolve only a unique, exact value to a trusted catalog entry. This supports
 * Discord users who type an exact name/GFI/item number instead of clicking an
 * autocomplete result, while never treating their text as an RCON path.
 */
export function resolveItemInput(value) {
  if (typeof value !== 'string') return null;
  const raw = value.trim(); const keyed = byKey.get(raw);
  if (keyed) return keyed;
  if (!raw || Array.from(raw).length > 512) return null;
  const normalized = normalize(raw); const matches = new Set();
  const collect = (entries) => { for (const item of entries ?? []) matches.add(item); };
  collect(byName.get(normalized)); collect(byGfi.get(normalized)); collect(byBlueprint.get(normalized));
  const gfi = normalized.match(/^gfi\s+(.+)$/u); if (gfi) collect(byGfi.get(gfi[1].trim()));
  const number = normalized.match(/^#?\s*(\d+)$/u); if (number) collect(byNumber.get(String(Number(number[1]))));
  return matches.size === 1 ? [...matches][0] : null;
}

/**
 * Search item names and codes for Discord autocomplete. Results are stable and
 * capped at 25 because Discord rejects more choices.
 */
export function searchItems(query, limit = 25) {
  const maximum = Math.min(25, Math.max(0, Number.isSafeInteger(limit) ? limit : 25));
  if (!maximum) return [];
  const needle = normalize(query);
  const tokens = needle.split(/\s+/).filter(Boolean);
  if (!tokens.length) return defaultItems.slice(0, maximum);

  const ranked = [];
  for (const item of items) {
    const name = normalize(item.name);
    const gfi = normalize(item.gfi);
    const category = normalize(item.category);
    const blueprint = normalize(item.blueprintPath);
    const itemNumber = item.itemNumber === null ? '' : String(item.itemNumber);
    const searchable = `${name} ${gfi} ${itemNumber} ${category} ${blueprint}`;
    if (!tokens.every((token) => searchable.includes(token))) continue;
    let score = 40;
    if (name === needle) score = 0;
    else if (gfi === needle || itemNumber === needle) score = 5;
    else if (name.startsWith(needle)) score = 10;
    else if (name.split(/[^a-z0-9]+/).some((word) => word.startsWith(needle))) score = 20;
    else if (gfi.startsWith(needle)) score = 25;
    else if (blueprint.includes(needle)) score = 28;
    else if (name.includes(needle)) score = 30;
    ranked.push({ item, score });
  }

  ranked.sort((left, right) => left.score - right.score
    || left.item.name.localeCompare(right.item.name, 'en', { sensitivity: 'base' })
    || left.item.key.localeCompare(right.item.key));
  return ranked.slice(0, maximum).map(({ item }) => item);
}
