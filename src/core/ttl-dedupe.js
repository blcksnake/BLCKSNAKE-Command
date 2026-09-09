export class TtlDedupe {
  constructor({ ttlMs = 90_000, maxEntries = 10_000, now = () => Date.now() } = {}) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.now = now;
    this.entries = new Map();
  }

  prune(at = this.now()) {
    for (const [key, expiresAt] of this.entries) if (expiresAt <= at) this.entries.delete(key);
    while (this.entries.size > this.maxEntries) this.entries.delete(this.entries.keys().next().value);
  }

  seen(key) {
    const at = this.now();
    const expiresAt = this.entries.get(key);
    if (expiresAt && expiresAt > at) return true;
    this.entries.delete(key);
    this.entries.set(key, at + this.ttlMs);
    if (this.entries.size > this.maxEntries) this.prune(at);
    return false;
  }
}
