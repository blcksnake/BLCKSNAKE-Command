import { JsonStateStore } from './json-state-store.js';
import { SqliteStateStore } from './sqlite-state-store.js';

export function createStateStore(config = {}) {
  const driver = config.driver ?? (/\.json$/iu.test(String(config.file ?? '')) ? 'json' : 'sqlite');
  const options = { seedBundledItemPackages: true, ...config };
  if (driver === 'json') return new JsonStateStore(options);
  if (driver === 'sqlite') return new SqliteStateStore(options);
  throw new Error(`Unsupported state persistence driver: ${String(driver)}`);
}
