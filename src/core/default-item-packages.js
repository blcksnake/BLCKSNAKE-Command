import crypto from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import bundledData from '../data/default-item-packages.json' with { type: 'json' };
import additionsData from '../data/asa-boss-package-additions.json' with { type: 'json' };
import recipeData from '../data/verified-boss-recipes.json' with { type: 'json' };
import {
  MAX_ITEM_PACKAGES,
  cloneItemPackage,
  normalizeItemPackageInput,
  normalizePersistedItemPackages,
} from './item-packages.js';

const BUNDLED_DATA_VERSION = 1;
const BUNDLED_CREATED_AT = Date.parse('2026-09-14T00:00:00.000Z');
export const BUNDLED_PACKAGE_ADDITIONS_VERSION = 1;
const verifiedRecipes = new Map(recipeData.recipes.map((recipe) => [recipe.name, recipe]));

function bundledPackageId(name) {
  const suffix = crypto.createHash('sha256')
    .update(`blcksnake:item-package:v${BUNDLED_DATA_VERSION}:${name}`, 'utf8')
    .digest('base64url')
    .slice(0, 22);
  return `pkg_${suffix}`;
}

function expandPackage(candidate) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)
    || Object.keys(candidate).some((key) => !['name', 'description', 'starter', 'items'].includes(key))) {
    throw new Error('Bundled item package data is malformed');
  }
  if (!Array.isArray(candidate.items)) throw new Error('Bundled item package items are malformed');
  return normalizeItemPackageInput({
    name: candidate.name,
    description: candidate.description,
    enabled: true,
    starterEnabled: candidate.starter === true,
    items: candidate.items.map((entry) => {
      if (!Array.isArray(entry) || entry.length !== 2) throw new Error('Bundled item package entry is malformed');
      return { itemKey: entry[0], quantity: entry[1], quality: 0, blueprint: false };
    }),
  });
}

function bundledRecord(candidate) {
  const input = expandPackage(candidate);
  return { id: bundledPackageId(input.name), ...input, revision: 1,
    createdAt: BUNDLED_CREATED_AT, updatedAt: BUNDLED_CREATED_AT };
}

function loadBundledPackages() {
  if (bundledData?.version !== BUNDLED_DATA_VERSION || !Array.isArray(bundledData.packages)
    || bundledData.packages.length < 1 || bundledData.packages.length > MAX_ITEM_PACKAGES) {
    throw new Error('Bundled item package data has an unsupported version or package count');
  }
  const packages = {};
  if (additionsData.version !== BUNDLED_PACKAGE_ADDITIONS_VERSION || !Array.isArray(additionsData.packages)) {
    throw new Error('Bundled package additions have an unsupported version');
  }
  for (const candidate of [...bundledData.packages, ...additionsData.packages]) {
    const recipe = verifiedRecipes.get(candidate.name);
    const itemPackage = bundledRecord(recipe ? { ...candidate, items: recipe.items } : candidate);
    if (packages[itemPackage.id]) throw new Error('Bundled item package identity collision');
    packages[itemPackage.id] = itemPackage;
  }
  return normalizePersistedItemPackages(packages);
}

const BUNDLED_ITEM_PACKAGES = loadBundledPackages();

export const BUNDLED_ITEM_PACKAGE_COUNT = Object.keys(BUNDLED_ITEM_PACKAGES).length;

export function createBundledItemPackages() {
  return Object.fromEntries(Object.entries(BUNDLED_ITEM_PACKAGES)
    .map(([id, itemPackage]) => [id, cloneItemPackage(itemPackage)]));
}

/** One-time additive upgrade. Keep customized/disabled identities and equivalent names intact. */
export function mergeBundledPackageAdditions(existing) {
  const itemPackages = { ...existing };
  const names = new Set(Object.values(existing).map((entry) => entry.name.toLocaleLowerCase('en-US')));
  const added = []; const skipped = [];
  for (const candidate of additionsData.packages) {
    const id = bundledPackageId(candidate.name);
    if (Object.hasOwn(itemPackages, id) || names.has(candidate.name.toLocaleLowerCase('en-US'))) continue;
    if (Object.keys(itemPackages).length >= MAX_ITEM_PACKAGES) { skipped.push(id); continue; }
    itemPackages[id] = cloneItemPackage(BUNDLED_ITEM_PACKAGES[id]);
    names.add(candidate.name.toLocaleLowerCase('en-US')); added.push(id);
  }
  return { itemPackages, added, skipped };
}

/** Correct only exact, enabled, revision-one bundled records. All local edits survive. */
export function correctUntouchedBundledPackages(existing, { now = Date.now() } = {}) {
  if (!Number.isSafeInteger(now) || now < 0) throw new Error('Package correction time must be a valid timestamp');
  const itemPackages = { ...existing }; const corrected = [];
  for (const candidate of bundledData.packages) {
    if (!recipeData.correctedBundledNames.includes(candidate.name)) continue;
    const original = bundledRecord(candidate);
    if (!isDeepStrictEqual(existing[original.id], original)) continue;
    itemPackages[original.id] = {
      ...cloneItemPackage(BUNDLED_ITEM_PACKAGES[original.id]),
      revision: 2,
      updatedAt: Math.max(now, BUNDLED_CREATED_AT),
    };
    corrected.push(original.id);
  }
  return { itemPackages, corrected };
}
