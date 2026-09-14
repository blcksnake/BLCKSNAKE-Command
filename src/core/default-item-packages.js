import crypto from 'node:crypto';
import bundledData from '../data/default-item-packages.json' with { type: 'json' };
import {
  MAX_ITEM_PACKAGES,
  cloneItemPackage,
  normalizeItemPackageInput,
  normalizePersistedItemPackages,
} from './item-packages.js';

const BUNDLED_DATA_VERSION = 1;
const BUNDLED_CREATED_AT = Date.parse('2026-09-14T00:00:00.000Z');

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

function loadBundledPackages() {
  if (bundledData?.version !== BUNDLED_DATA_VERSION || !Array.isArray(bundledData.packages)
    || bundledData.packages.length < 1 || bundledData.packages.length > MAX_ITEM_PACKAGES) {
    throw new Error('Bundled item package data has an unsupported version or package count');
  }
  const packages = {};
  for (const candidate of bundledData.packages) {
    const input = expandPackage(candidate);
    const id = bundledPackageId(input.name);
    if (packages[id]) throw new Error('Bundled item package identity collision');
    packages[id] = {
      id,
      ...input,
      revision: 1,
      createdAt: BUNDLED_CREATED_AT,
      updatedAt: BUNDLED_CREATED_AT,
    };
  }
  return normalizePersistedItemPackages(packages);
}

const BUNDLED_ITEM_PACKAGES = loadBundledPackages();

export const BUNDLED_ITEM_PACKAGE_COUNT = Object.keys(BUNDLED_ITEM_PACKAGES).length;

export function createBundledItemPackages() {
  return Object.fromEntries(Object.entries(BUNDLED_ITEM_PACKAGES)
    .map(([id, itemPackage]) => [id, cloneItemPackage(itemPackage)]));
}
