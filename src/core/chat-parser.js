import { normalizeWhitespace } from './sanitize.js';

const EMPTY_RESPONSES = [
  'server received, but no response!!',
  'server received, but no response!',
  'no chat messages',
  'no messages',
];
const CHANNELS = ['Global', 'Local', 'Tribe', 'Alliance'];

function titleCase(value) {
  const lower = String(value).toLocaleLowerCase('en-US');
  return CHANNELS.find((channel) => channel.toLocaleLowerCase('en-US') === lower) ?? 'Global';
}

function stripChannelPrefix(value) {
  let rest = value.trim();
  let channel = 'Global';
  const bracket = rest.match(/^\[(Global|Local|Tribe|Alliance)\]\s*/i);
  if (bracket) return { channel: titleCase(bracket[1]), rest: rest.slice(bracket[0].length) };
  const colon = rest.match(/^(Global|Local|Tribe|Alliance)\s*:\s*/i);
  if (colon) {
    channel = titleCase(colon[1]);
    rest = rest.slice(colon[0].length);
  }
  return { channel, rest };
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function recordStartRegex(playerNames = []) {
  const knownNames = [...new Set(playerNames.map(normalizeWhitespace).filter(Boolean))]
    .sort((a, b) => b.length - a.length)
    .map(escapeRegex);
  const player = knownNames.length ? `(?:${knownNames.join('|')})` : String.raw`[\p{L}\p{N}_.-]{1,96}`;
  const channel = String.raw`(?:(?:\[(?:Global|Local|Tribe|Alliance)\]|(?:Global|Local|Tribe|Alliance)\s*:)[ \t]*)?`;
  const character = String.raw`\(\s*(?:"[^"\r\n]{1,96}"|[^()\r\n]{1,96})\s*\)\s*:`;
  const chat = `${channel}${player}\\s+${character}`;
  const system = String.raw`(?:AdminCmd\s*:|SERVER\s*:|Tribe\s+[^,\r\n]{1,128},\s*ID\s+\d+\s*:)`;
  return new RegExp(`(?<!\\S)(?=(?:${system}|${chat}))`, 'giu');
}

function splitConcatenatedLine(rawLine, playerNames) {
  const line = normalizeWhitespace(rawLine);
  if (!line) return [];
  const starts = new Set([0]);
  for (const match of line.matchAll(recordStartRegex(playerNames))) {
    if (match.index > 0) starts.add(match.index);
  }
  const ordered = [...starts].sort((a, b) => a - b);
  return ordered.map((start, index) => line.slice(start, ordered[index + 1] ?? line.length).trim()).filter(Boolean);
}

export function parseChatLine(rawLine) {
  const raw = String(rawLine ?? '').replace(/\0/g, '').trim();
  if (!raw) return null;
  if (EMPTY_RESPONSES.includes(raw.toLocaleLowerCase('en-US'))) return null;
  if (/^AdminCmd\s*:/i.test(raw)) return { kind: 'admin', raw, text: raw.replace(/^AdminCmd\s*:\s*/i, '') };
  if (/^SERVER\s*:/i.test(raw)) return { kind: 'server', raw, text: raw.replace(/^SERVER\s*:\s*/i, '') };
  if (/^Tribe\s+.+?,\s*ID\s+\d+\s*:/i.test(raw)) return { kind: 'tribelog', raw, text: raw };

  const { channel, rest } = stripChannelPrefix(raw);
  let match = rest.match(/^(.+?)\s+\(\s*"([^"]+)"\s*\)\s*:\s*([\s\S]+)$/);
  if (!match) match = rest.match(/^(.+?)\s+\(\s*([^()]+?)\s*\)\s*:\s*([\s\S]+)$/);
  if (match) {
    return {
      kind: 'chat', channel,
      playerName: normalizeWhitespace(match[1]),
      characterName: normalizeWhitespace(match[2]),
      text: normalizeWhitespace(match[3]), raw,
    };
  }
  match = rest.match(/^([^:]{1,96})\s*:\s*([\s\S]+)$/);
  if (match) {
    return {
      kind: 'chat', channel,
      playerName: normalizeWhitespace(match[1]),
      characterName: normalizeWhitespace(match[1]),
      text: normalizeWhitespace(match[2]), raw,
    };
  }
  return { kind: 'unknown', raw, text: raw };
}

export function parseChatResponse(response, { playerNames = [] } = {}) {
  const text = String(response ?? '').replace(/\0/g, '').replace(/\r/g, '');
  if (!text.trim()) return [];
  return text.split('\n')
    .flatMap((line) => splitConcatenatedLine(line, playerNames))
    .map(parseChatLine)
    .filter(Boolean);
}
