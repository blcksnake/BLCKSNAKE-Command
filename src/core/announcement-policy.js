export const ANNOUNCEMENT_PREFIX = '[ADMIN] ';
export const ANNOUNCEMENT_PREFIX_RESERVE = 20;
export const DEFAULT_GAME_MESSAGE_MAX_LENGTH = 420;
export const RESTART_MAX_DELAY_MINUTES = 10_080;
export const RESTART_REASON_MAX_LENGTH = 160;

const RESTART_CANCELLED_NOTICE = `${ANNOUNCEMENT_PREFIX}Restart cancelled.`;
const RESTART_DEADLINE_NOTICE = `${ANNOUNCEMENT_PREFIX}Restart due. World saved.`;
const RESTART_REASON_HEADER = `${ANNOUNCEMENT_PREFIX}Restart in ${RESTART_MAX_DELAY_MINUTES}m: `;

export function gameMessageMaxLength(gameMaxLength = DEFAULT_GAME_MESSAGE_MAX_LENGTH) {
  const configured = Number(gameMaxLength);
  return Number.isFinite(configured) ? Math.max(1, Math.floor(configured)) : DEFAULT_GAME_MESSAGE_MAX_LENGTH;
}

export function announcementMessageMaxLength(gameMaxLength = DEFAULT_GAME_MESSAGE_MAX_LENGTH) {
  return Math.max(1, gameMessageMaxLength(gameMaxLength) - ANNOUNCEMENT_PREFIX_RESERVE);
}

export function codePointLength(value) { return Array.from(String(value ?? '')).length; }

export function restartReasonMaxLength(gameMaxLength = DEFAULT_GAME_MESSAGE_MAX_LENGTH) {
  return Math.min(
    RESTART_REASON_MAX_LENGTH,
    Math.max(1, gameMessageMaxLength(gameMaxLength) - codePointLength(RESTART_REASON_HEADER)),
  );
}

export function assertGameNoticeFits(message, gameMaxLength = DEFAULT_GAME_MESSAGE_MAX_LENGTH) {
  const maximum = gameMessageMaxLength(gameMaxLength);
  if (codePointLength(message) > maximum) {
    const error = new Error(`Server notice exceeds the configured ${maximum}-character game limit.`);
    error.code = 'SERVER_NOTICE_TOO_LONG';
    throw error;
  }
  return message;
}

export function restartNotice(kind, { minutes, reason = '' } = {}, gameMaxLength = DEFAULT_GAME_MESSAGE_MAX_LENGTH) {
  let message;
  if (kind === 'scheduled' || kind === 'warning') {
    const delay = Number(minutes);
    if (!Number.isInteger(delay) || delay < 1 || delay > RESTART_MAX_DELAY_MINUTES) {
      throw new Error(`Restart delay must be 1-${RESTART_MAX_DELAY_MINUTES} minutes.`);
    }
    const cleanReason = String(reason ?? '').trim();
    const maximum = restartReasonMaxLength(gameMaxLength);
    if (codePointLength(cleanReason) > maximum) {
      const error = new Error(`Restart reason exceeds the ${maximum}-character limit. Shorten it and try again.`);
      error.code = 'RESTART_REASON_TOO_LONG';
      throw error;
    }
    message = `${ANNOUNCEMENT_PREFIX}Restart in ${delay}m${cleanReason ? `: ${cleanReason}` : '.'}`;
  } else if (kind === 'cancelled') message = RESTART_CANCELLED_NOTICE;
  else if (kind === 'deadline') message = RESTART_DEADLINE_NOTICE;
  else throw new Error('Unknown restart notice type.');
  return assertGameNoticeFits(message, gameMaxLength);
}
