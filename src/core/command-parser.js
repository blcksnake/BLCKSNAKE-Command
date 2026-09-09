export function tokenizeCommand(input) {
  const tokens = [];
  const regex = /"((?:\\.|[^"])*)"|'((?:\\.|[^'])*)'|(\S+)/g;
  for (const match of String(input ?? '').matchAll(regex)) {
    tokens.push((match[1] ?? match[2] ?? match[3]).replace(/\\([\\"'])/g, '$1'));
  }
  return tokens;
}

export function parseGameCommand(text, prefix = '!cc') {
  const value = String(text ?? '').trim();
  if (!value.toLocaleLowerCase('en-US').startsWith(prefix.toLocaleLowerCase('en-US'))) return null;
  const boundary = value.slice(prefix.length, prefix.length + 1);
  if (boundary && !/\s/.test(boundary)) return null;
  const [command = 'help', ...args] = tokenizeCommand(value.slice(prefix.length).trim());
  return { command: command.toLocaleLowerCase('en-US'), args };
}

export function parseDurationMinutes(value, fallback, maximum = Number.MAX_SAFE_INTEGER) {
  if (value == null || value === '') return fallback;
  const match = String(value).trim().match(/^(\d+)(m|h|d)?$/i);
  if (!match) return null;
  const amount = Number(match[1]);
  const multiplier = { m: 1, h: 60, d: 1_440 }[(match[2] ?? 'm').toLocaleLowerCase('en-US')];
  const minutes = amount * multiplier;
  return Number.isSafeInteger(minutes) && minutes >= 1 && minutes <= maximum ? minutes : null;
}
