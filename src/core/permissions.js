export const PermissionLevel = Object.freeze({ NONE: 0, RELAY: 1, MODERATOR: 2, ADMIN: 3 });
const ADMINISTRATOR = 0x8n;

export function hasDiscordAdministrator(member) {
  try { return (BigInt(member?.permissions ?? 0) & ADMINISTRATOR) === ADMINISTRATOR; }
  catch {
    // Discord permission payloads are untrusted; malformed permission bits fail closed.
    return false;
  }
}

export function getPermissionLevel(member, config = {}) {
  if (hasDiscordAdministrator(member)) return PermissionLevel.ADMIN;
  const roles = new Set(member?.roles ?? []);
  if ((config.adminRoleIds ?? []).some((id) => roles.has(id))) return PermissionLevel.ADMIN;
  if ((config.moderatorRoleIds ?? []).some((id) => roles.has(id))) return PermissionLevel.MODERATOR;
  const relay = config.relayRoleIds ?? [];
  if (!relay.length || relay.some((id) => roles.has(id))) return PermissionLevel.RELAY;
  return PermissionLevel.NONE;
}
