import { createHash } from 'node:crypto';

const CONTROL_EXCEPT_NEWLINE = /[\u0000-\u0009\u000B\u000C\u000E-\u001F\u007F]/g;
const ALL_CONTROL = /[\u0000-\u001F\u007F]/g;
const RICH_TAGS = /<\/?(?:RichColor|img|Image|a|b|i|u|span)(?:\s[^>]*)?>/gi;

export function normalizeWhitespace(value) {
  return String(value ?? '')
    .replace(CONTROL_EXCEPT_NEWLINE, '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

export function truncateCodePoints(value, maxLength, suffix = '…') {
  const points = Array.from(String(value ?? ''));
  if (points.length <= maxLength) return points.join('');
  if (maxLength <= 0) return '';
  const suffixPoints = Array.from(suffix);
  if (suffixPoints.length >= maxLength) return suffixPoints.slice(0, maxLength).join('');
  return [...points.slice(0, maxLength - suffixPoints.length), ...suffixPoints].join('');
}

export function sanitizeIdentity(value, maxLength = 48) {
  const clean = normalizeWhitespace(value)
    .replace(RICH_TAGS, '')
    .replace(/[<>`]/g, '')
    .replace(/[@]/g, '')
    .trim();
  return truncateCodePoints(clean || 'Unknown', maxLength);
}

export function sanitizeForGame(value, maxLength = 420) {
  const clean = String(value ?? '')
    .replace(RICH_TAGS, '')
    .replace(ALL_CONTROL, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim();
  return truncateCodePoints(clean, maxLength);
}

export function sanitizeForDiscord(value, maxLength = 2_000) {
  const clean = String(value ?? '')
    .replace(CONTROL_EXCEPT_NEWLINE, '')
    .replace(/\r\n?/g, '\n')
    .replace(/@(everyone|here)/gi, '@\u200b$1')
    .trim();
  return truncateCodePoints(clean, maxLength);
}

export function escapeDiscordMarkdown(value) {
  return String(value ?? '').replace(/([\\`*_{}\[\]()#+\-.!|>~])/g, '\\$1');
}

export function quoteRconArgument(value) {
  const clean = String(value ?? '')
    .replace(ALL_CONTROL, '')
    .replace(/["\\]/g, '')
    .trim();
  return `"${clean}"`;
}

export function normalizeName(value) {
  return normalizeWhitespace(value).toLocaleLowerCase('en-US');
}

export function fingerprint(parts) {
  return createHash('sha256').update(parts.map((part) => String(part ?? '')).join('\u001f')).digest('hex');
}

export function chunkText(header, body, maxLength) {
  const safeHeader = String(header ?? '');
  const maxBody = Math.max(1, maxLength - Array.from(safeHeader).length);
  const points = Array.from(String(body ?? ''));
  if (!points.length) return [];
  const chunks = [];
  let start = 0;
  while (start < points.length) {
    let end = Math.min(points.length, start + maxBody);
    if (end < points.length) {
      const candidate = points.slice(start, end).join('');
      const whitespace = Math.max(candidate.lastIndexOf(' '), candidate.lastIndexOf('\n'));
      if (whitespace >= Math.floor(maxBody * 0.55)) end = start + Array.from(candidate.slice(0, whitespace)).length;
    }
    if (end <= start) end = Math.min(points.length, start + maxBody);
    const piece = points.slice(start, end).join('').trim();
    if (piece) chunks.push(`${safeHeader}${piece}`);
    start = end;
    while (start < points.length && /\s/u.test(points[start])) start += 1;
  }
  return chunks;
}
