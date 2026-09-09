import { JsonStateStore } from './json-state-store.js';
import { SqliteStateStore } from './sqlite-state-store.js';

export function createStateStore(config = {}) {
  const driver = config.driver ?? (/\.json$/iu.test(String(config.file ?? '')) ? 'json' : 'sqlite');
  if (driver === 'json') return new JsonStateStore(config);
  if (driver === 'sqlite') return new SqliteStateStore(config);
  throw new Error(`Unsupported state persistence driver: ${String(driver)}`);
}
