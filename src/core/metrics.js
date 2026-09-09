import { isSensitiveKey, redactText, REDACTED } from './redaction.js';

function keyFor(name, labels = {}) {
  const keys = Object.keys(labels).sort();
  return `${name}\u001f${keys.map((key) => `${key}=${labels[key]}`).join('\u001f')}`;
}

function formatLabels(labels) {
  const entries = Object.entries(labels ?? {}).sort(([a], [b]) => a.localeCompare(b));
  if (!entries.length) return '';
  return `{${entries.map(([key, value]) => {
    const safe = isSensitiveKey(key) ? REDACTED : redactText(value);
    const escaped = safe.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\r/g, '\\r').replace(/\n/g, '\\n');
    return `${key}="${escaped}"`;
  }).join(',')}}`;
}

export class Metrics {
  constructor() { this.values = new Map(); }

  increment(name, labels = {}, amount = 1) {
    const key = keyFor(name, labels);
    const current = this.values.get(key) ?? { name, labels: { ...labels }, value: 0 };
    current.value += amount;
    this.values.set(key, current);
  }

  setGauge(name, labels = {}, value = 0) {
    this.values.set(keyFor(name, labels), { name, labels: { ...labels }, value: Number(value) });
  }

  get(name, labels = {}) { return this.values.get(keyFor(name, labels))?.value ?? 0; }

  toPrometheus() {
    return [...this.values.values()]
      .sort((a, b) => keyFor(a.name, a.labels).localeCompare(keyFor(b.name, b.labels)))
      .map((item) => `${item.name}${formatLabels(item.labels)} ${item.value}`)
      .join('\n') + (this.values.size ? '\n' : '');
  }
}
