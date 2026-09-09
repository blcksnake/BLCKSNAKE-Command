import { normalizeName, normalizeWhitespace } from './sanitize.js';

const EMPTY = /^(?:No Players Connected|Server received, but no response!{1,2})$/i;

export function parsePlayerList(response) {
  const text = String(response ?? '').replace(/\0/g, '').replace(/\r/g, '').trim();
  if (!text || EMPTY.test(text)) return [];
  return text.split('\n').map((line) => line.trim()).filter(Boolean).flatMap((line) => {
    const match = line.match(/^\s*(?:\d+\.\s*)?(.+?)\s*,\s*([^,\s]+)\s*$/);
    if (!match) return [];
    return [{ name: normalizeWhitespace(match[1]), id: normalizeWhitespace(match[2]) }];
  });
}

export function findPlayer(players, query) {
  const normalized = normalizeName(query);
  if (!normalized) return { player: null, matches: [] };
  const exact = players.find((player) => normalizeName(player.id) === normalized || normalizeName(player.name) === normalized);
  if (exact) return { player: exact, matches: [exact] };
  const matches = players.filter((player) => normalizeName(player.name).includes(normalized));
  return { player: matches.length === 1 ? matches[0] : null, matches };
}
