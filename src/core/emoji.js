const PAIRS = [
  ['grinning', '😀'], ['smiley', '😃'], ['smile', '😄'], ['grin', '😁'], ['laughing', '😆'],
  ['sweat_smile', '😅'], ['joy', '😂'], ['rofl', '🤣'], ['wink', '😉'], ['blush', '😊'],
  ['heart_eyes', '😍'], ['kissing_heart', '😘'], ['yum', '😋'], ['sunglasses', '😎'], ['thinking', '🤔'],
  ['neutral_face', '😐'], ['expressionless', '😑'], ['unamused', '😒'], ['sweat', '😓'], ['pensive', '😔'],
  ['confused', '😕'], ['upside_down', '🙃'], ['fearful', '😨'], ['cry', '😢'], ['sob', '😭'],
  ['angry', '😠'], ['rage', '😡'], ['skull', '💀'], ['poop', '💩'], ['clown', '🤡'],
  ['ghost', '👻'], ['alien', '👽'], ['robot', '🤖'], ['wave', '👋'], ['thumbsup', '👍'],
  ['thumbsdown', '👎'], ['ok_hand', '👌'], ['muscle', '💪'], ['pray', '🙏'], ['clap', '👏'],
  ['eyes', '👀'], ['brain', '🧠'], ['heart', '❤️'], ['broken_heart', '💔'], ['sparkles', '✨'],
  ['star', '⭐'], ['fire', '🔥'], ['boom', '💥'], ['zap', '⚡'], ['snowflake', '❄️'],
  ['sunny', '☀️'], ['cloud', '☁️'], ['umbrella', '☔'], ['coffee', '☕'], ['beer', '🍺'],
  ['pizza', '🍕'], ['meat_on_bone', '🍖'], ['egg', '🥚'], ['tada', '🎉'], ['gift', '🎁'],
  ['soccer', '⚽'], ['video_game', '🎮'], ['rocket', '🚀'], ['warning', '⚠️'], ['white_check_mark', '✅'],
  ['x', '❌'], ['question', '❓'], ['exclamation', '❗'], ['100', '💯'], ['map', '🗺️'],
  ['pick', '⛏️'], ['hammer', '🔨'], ['crossed_swords', '⚔️'], ['shield', '🛡️'], ['gem', '💎'],
  ['dino', '🦖'], ['sauropod', '🦕'], ['dragon', '🐉'], ['wolf', '🐺'], ['eagle', '🦅'],
];

export const aliases = Object.freeze(Object.fromEntries(PAIRS));
const unicodeEntries = [...PAIRS].sort((a, b) => Array.from(b[1]).length - Array.from(a[1]).length);

export function toDiscordEmoji(value) {
  let output = String(value ?? '').replace(/<a?:([A-Za-z0-9_]+):\d+>/g, ':$1:');
  output = output.replace(/:([A-Za-z0-9_+-]+):/g, (full, name) => aliases[name.toLocaleLowerCase('en-US')] ?? full);
  return output;
}

export function toGameEmoji(value, mode = 'shortcode') {
  let output = String(value ?? '').replace(/<a?:([A-Za-z0-9_]+):\d+>/g, ':$1:');
  if (mode === 'unicode') return toDiscordEmoji(output);
  for (const [name, emoji] of unicodeEntries) output = output.split(emoji).join(mode === 'strip' ? '' : `:${name}:`);
  if (mode === 'strip') output = output.replace(/:([A-Za-z0-9_+-]+):/g, '');
  return output;
}
