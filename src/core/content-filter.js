import { normalizeName } from './sanitize.js';

export class ContentFilter {
  constructor({ blockedTerms = [], blockedRegexes = [] } = {}) {
    this.terms = blockedTerms.map(normalizeName).filter(Boolean);
    this.regexes = blockedRegexes.map((source) => {
      try { return new RegExp(source, 'iu'); }
      catch (error) { throw new Error(`Invalid blocked regex ${source}: ${error.message}`); }
    });
  }

  inspect(value) {
    const text = String(value ?? '');
    const normalized = normalizeName(text);
    const term = this.terms.find((candidate) => normalized.includes(candidate));
    if (term) return { allowed: false, reason: 'blocked_term', match: term };
    const regex = this.regexes.find((candidate) => candidate.test(text));
    if (regex) return { allowed: false, reason: 'blocked_regex', match: regex.source };
    return { allowed: true, reason: null, match: null };
  }
}
