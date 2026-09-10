import crypto from 'node:crypto';

const NOTE_ID_PATTERN = /^mn_[A-Za-z0-9_-]{22}$/u;
export const MODERATION_NOTE_TYPES = Object.freeze(['note', 'warning', 'incident', 'positive', 'mute', 'unmute', 'kick', 'ban']);
const MODERATION_NOTE_TYPE_SET = new Set(MODERATION_NOTE_TYPES);

export function normalizeModerationNoteType(value) {
  const type = String(value ?? 'note').trim().toLocaleLowerCase('en-US');
  if (!MODERATION_NOTE_TYPE_SET.has(type)) throw new Error('Moderation note type is not supported');
  return type;
}

export function moderationNoteId(playerId, note, index) {
  const payload = JSON.stringify([
    String(playerId ?? ''),
    Number.isSafeInteger(index) && index >= 0 ? index : -1,
    Number.isFinite(note?.at) ? note.at : null,
    String(note?.actor ?? ''),
    String(note?.text ?? ''),
  ]);
  return `mn_${crypto.createHash('sha256').update(payload).digest('base64url').slice(0, 22)}`;
}

export function validModerationNoteId(value) {
  const id = String(value ?? '');
  return NOTE_ID_PATTERN.test(id) ? id : '';
}
