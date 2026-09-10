export const MODERATOR_ACTION_GRANTS = Object.freeze([
  'save-world',
  'give-item',
  'give-xp',
  'refresh-player-id',
  'ban',
  'whitelist',
  'unwhitelist',
]);

const MODERATOR_ACTION_GRANT_SET = new Set(MODERATOR_ACTION_GRANTS);

export function normalizeOperatorActionGrants(value, { role = 'moderator' } = {}) {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length > MODERATOR_ACTION_GRANTS.length) {
    throw new Error('Operator action grants must be a bounded array');
  }
  const grants = [];
  for (const candidate of value) {
    if (typeof candidate !== 'string' || !MODERATOR_ACTION_GRANT_SET.has(candidate)) {
      throw new Error('Operator action grant is not supported');
    }
    if (!grants.includes(candidate)) grants.push(candidate);
  }
  if (role !== 'moderator' && grants.length) throw new Error('Only moderators can have individual action grants');
  return grants.sort((left, right) => MODERATOR_ACTION_GRANTS.indexOf(left) - MODERATOR_ACTION_GRANTS.indexOf(right));
}

export function hasOperatorActionGrant(account, action) {
  return account?.role === 'moderator'
    && Array.isArray(account.actionGrants)
    && account.actionGrants.includes(action)
    && MODERATOR_ACTION_GRANT_SET.has(action);
}
