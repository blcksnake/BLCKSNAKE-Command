import { getItemForGame } from './item-catalog.js';
import { ITEM_PACKAGE_ID_PATTERN, normalizePackageItem } from './item-packages.js';

export const MAX_GRANT_CART_LINES = 50;

function invalid(message, code = 'invalid_cart') {
  const error = new Error(message); error.code = code; error.operationOutcome = 'failed'; throw error;
}

export function normalizeGrantCart(value) {
  const items = value.items ?? []; const packages = value.packages ?? [];
  if (!Array.isArray(items) || !Array.isArray(packages)
    || items.length + packages.length < 1 || items.length + packages.length > MAX_GRANT_CART_LINES) {
    invalid(`Choose 1-${MAX_GRANT_CART_LINES} items or packages for this cart.`);
  }
  const normalizedItems = items.map((entry) => {
    try { return normalizePackageItem(entry); } catch (error) { invalid(error.message); }
  });
  const seen = new Set();
  const normalizedPackages = packages.map((entry) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
      || Object.keys(entry).some((key) => !['packageId', 'revision'].includes(key))
      || !ITEM_PACKAGE_ID_PATTERN.test(entry.packageId)
      || !Number.isSafeInteger(entry.revision) || entry.revision < 1) {
      invalid('Each package must have a valid ID and its current revision.');
    }
    if (seen.has(entry.packageId)) invalid('Each package may appear only once in a cart.');
    seen.add(entry.packageId);
    return { packageId: entry.packageId, revision: entry.revision };
  });
  return { items: normalizedItems, packages: normalizedPackages };
}

// Materialize server-owned entries for confirmation; never accept paths or names
// from a client. Repeating this before execution also checks every package revision.
export function expandGrantCart(value, state, gameContext) {
  const cart = normalizeGrantCart(value);
  const lines = cart.items.map((entry) => ({ ...entry, sourcePackageId: null, sourcePackageName: null }));
  for (const selected of cart.packages) {
    const itemPackage = state.getItemPackage?.(selected.packageId);
    if (!itemPackage?.enabled || itemPackage.revision !== selected.revision) {
      invalid('A selected package is disabled, missing, or changed. Refresh the packages and review this cart again.', 'package_changed');
    }
    for (const entry of itemPackage.items) {
      lines.push({ ...normalizePackageItem(entry), sourcePackageId: itemPackage.id, sourcePackageName: itemPackage.name });
    }
  }
  if (lines.length < 1 || lines.length > MAX_GRANT_CART_LINES) {
    invalid(`This cart expands to ${lines.length} item lines. Send at most ${MAX_GRANT_CART_LINES} item lines in one operation.`);
  }
  return lines.map((entry) => {
    const item = getItemForGame(entry.itemKey, gameContext);
    if (!item) invalid('A selected item is not compatible with the selected game edition.', 'incompatible_item');
    return Object.freeze({ ...entry, name: item.name, blueprintPath: item.blueprintPath, itemNumber: item.itemNumber });
  });
}
