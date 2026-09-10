function isWhitespace(character) {
  return /\s/u.test(character);
}

function unescapeCommandToken(value) {
  let result = '';
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    const next = value[index + 1];
    if (character === '\\' && (next === '\\' || next === '"' || next === "'")) {
      result += next;
      index += 1;
    } else result += character;
  }
  return result;
}

/** Tokenize operator commands in one pass so hostile input cannot trigger regex backtracking. */
export function tokenizeCommand(input) {
  const value = String(input ?? '');
  const tokens = [];
  let index = 0;

  while (index < value.length) {
    while (index < value.length && isWhitespace(value[index])) index += 1;
    if (index >= value.length) break;

    const quote = value[index] === '"' || value[index] === "'" ? value[index] : null;
    if (quote) {
      let cursor = index + 1;
      while (cursor < value.length) {
        if (value[cursor] === '\\' && cursor + 1 < value.length) {
          cursor += 2;
          continue;
        }
        if (value[cursor] === quote) break;
        cursor += 1;
      }
      if (cursor < value.length) {
        tokens.push(unescapeCommandToken(value.slice(index + 1, cursor)));
        index = cursor + 1;
        continue;
      }
    }

    let cursor = index;
    while (cursor < value.length && !isWhitespace(value[cursor])) cursor += 1;
    tokens.push(unescapeCommandToken(value.slice(index, cursor)));
    index = cursor;
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
