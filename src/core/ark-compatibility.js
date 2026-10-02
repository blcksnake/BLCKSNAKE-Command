import { workflowPresets } from './workflow-presets.js';

const presets = workflowPresets({}).maps;
const byLevel = new Map(presets.map((preset) => [preset.mapName, preset]));

function presetFromId(value) {
  if (typeof value !== 'string') return null;
  return byLevel.get(value) ?? byLevel.get(value.replace(/-(?:[2-9]|[1-9]\d+)$/u, '')) ?? null;
}

/** Infer from explicit configured level tokens, never a friendly server name or a port. */
export function inferServerGameContext(serverOrConfig) {
  const config = serverOrConfig?.config ?? serverOrConfig ?? {};
  const token = typeof config.profileImport?.mapName === 'string' ? config.profileImport.mapName.trim() : '';
  const profile = byLevel.get(token);
  const identity = presetFromId(config.id ?? serverOrConfig?.id);
  const unknown = (reason) => ({ game: 'unknown', mapName: null, mapId: null, source: 'unknown', reason });
  if (profile && identity && profile.mapName !== identity.mapName) {
    return unknown('Configured map ID and profile level disagree. Check the map settings.');
  }
  // An explicit unrecognized profile token can represent a custom map; do not
  // override it with a familiar-looking stable dashboard ID.
  if (token && !profile) return unknown('The configured level is not in the verified map catalog.');
  const preset = profile ?? identity;
  if (!preset) return unknown('No verified level token is configured for this server.');
  return {
    game: preset.game, mapName: preset.name, mapId: preset.mapName,
    source: profile ? 'profile-map-token' : 'server-id',
    reason: 'Inferred from the configured level token; not a live game-server probe.',
  };
}

/** Common vanilla RCON item grant syntax is shared; identity lookup remains separate. */
export function commandPresetForGame(gameContext) {
  return {
    game: gameContext?.game ?? 'unknown',
    giveItem: 'GiveItemToPlayer',
    giveItemNumber: 'GiveItemNumToPlayer',
    usesPlayerDataId: true,
  };
}
