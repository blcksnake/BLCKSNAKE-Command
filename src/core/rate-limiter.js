export class SlidingWindowRateLimiter {
  constructor({ limit = 5, windowMs = 10_000, maxKeys = 20_000, now = () => Date.now() } = {}) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.maxKeys = maxKeys;
    this.now = now;
    this.events = new Map();
    this.operations = 0;
  }

  prune(at = this.now()) {
    const cutoff = at - this.windowMs;
    for (const [key, timestamps] of this.events) {
      const active = timestamps.filter((time) => time > cutoff);
      if (active.length) this.events.set(key, active);
      else this.events.delete(key);
    }
    while (this.events.size > this.maxKeys) this.events.delete(this.events.keys().next().value);
  }

  consume(key) {
    const at = this.now();
    const cutoff = at - this.windowMs;
    const active = (this.events.get(key) ?? []).filter((time) => time > cutoff);
    this.operations += 1;
    if (this.operations % 256 === 0 || this.events.size >= this.maxKeys) this.prune(at);
    if (active.length >= this.limit) {
      this.events.set(key, active);
      return { allowed: false, remaining: 0, retryAfterMs: Math.max(1, active[0] + this.windowMs - at) };
    }
    active.push(at);
    this.events.delete(key);
    this.events.set(key, active);
    return { allowed: true, remaining: Math.max(0, this.limit - active.length), retryAfterMs: 0 };
  }
}
