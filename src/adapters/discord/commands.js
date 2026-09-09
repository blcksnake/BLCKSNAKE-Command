import {
  RESTART_MAX_DELAY_MINUTES, announcementMessageMaxLength, restartReasonMaxLength,
} from '../../core/announcement-policy.js';

const STRING = 3;
const INTEGER = 4;
const BOOLEAN = 5;
const USER = 6;
const NUMBER = 10;
const SUBCOMMAND = 1;
const MANAGE_GUILD = '32';

const option = (type, name, description, required = false, extra = {}) => ({ type, name, description, required, ...extra });
const sub = (name, description, options = []) => ({ type: SUBCOMMAND, name, description, options });
const serverOption = (required = false, description = 'Server ID or name') => option(STRING, 'server', description, required, { autocomplete: true });
const playerOption = (description = 'Connected player (server selected automatically)') => option(STRING, 'player', description, true, { autocomplete: true });

export function buildApplicationCommands({ maxMuteMinutes = 43_200, gameMaxLength = 420 } = {}) {
  const announcementMaxLength = announcementMessageMaxLength(gameMaxLength);
  const restartReasonMaximum = restartReasonMaxLength(gameMaxLength);
  const commands = [{
    name: 'asa',
    description: 'Link your ARK character or view players',
    dm_permission: false,
    options: [
      sub('link', 'Create a code to link your ARK character'),
      sub('unlink', 'Remove your ARK character link'),
      sub('players', 'List connected ARK players', [serverOption(false, 'Optional server ID or name')]),
      sub('leaderboard', 'Show the cluster playtime leaderboard', [option(INTEGER, 'limit', 'Number of players to show (max 25)', false, { min_value: 1, max_value: 25 })]),
    ],
  }, {
    name: 'asa-admin',
    description: 'BLCKSNAKE Command moderation and operations',
    dm_permission: false,
    default_member_permissions: MANAGE_GUILD,
    options: [
      sub('status', 'Show bridge and server status'),
      sub('say', 'Relay a message to every ARK server', [option(STRING, 'message', 'Message to send', true, { max_length: 1_500 })]),
      sub('restart', 'Schedule a save and restart countdown', [
        option(INTEGER, 'minutes', 'Minutes until the restart window', true, { min_value: 1, max_value: RESTART_MAX_DELAY_MINUTES }),
        serverOption(false, 'Optional server ID or name'),
        option(STRING, 'reason', 'Optional reason', false, { max_length: restartReasonMaximum }),
      ]),
      sub('cancel-restart', 'Cancel a scheduled restart', [serverOption(false, 'Optional server ID or name')]),
      sub('save-world', 'Save one map or the entire cluster', [serverOption(false, 'Optional server ID or name')]),
      sub('give-item', 'Give a built-in catalog item to a connected player', [
        playerOption('Connected player, or numeric PlayerDataID for manual fallback'),
        option(STRING, 'item', 'Search item name, GFI code, item number, or blueprint', true, { autocomplete: true }),
        option(INTEGER, 'quantity', 'Quantity to give (default 1)', false, { min_value: 1, max_value: 10_000 }),
        option(NUMBER, 'quality', 'Item quality from 0 to 100 (default 0)', false, { min_value: 0, max_value: 100 }),
        option(BOOLEAN, 'blueprint', 'Give a blueprint instead of a crafted item'),
        serverOption(false, 'Needed only when manually entering a numeric PlayerDataID'),
      ]),
      sub('remember-player-id', 'Save a connected survivor numeric ID for automatic grants', [
        playerOption(),
        option(STRING, 'player-data-id', 'Numeric survivor ID shown on the implant or admin manager', true, { min_length: 1, max_length: 20 }),
        option(BOOLEAN, 'replace', 'Replace another account mapping that already uses this numeric ID'),
        serverOption(false, 'Needed only when manually entering an EOS account ID'),
      ]),
      sub('refresh-player-id', 'Read and verify a connected survivor ID from this map', [
        playerOption('Connected player; the current map is selected automatically'),
      ]),
      sub('give-xp', 'Give experience to a player', [
        playerOption('Connected player, or numeric PlayerDataID for manual fallback'),
        option(NUMBER, 'amount', 'Amount of experience to give', true, { min_value: 1, max_value: 1_000_000_000 }),
        option(BOOLEAN, 'from-tribe', 'Treat the experience as a tribe share'),
        option(BOOLEAN, 'share-with-tribe', 'Share the experience with tribe members'),
        serverOption(false, 'Needed only when manually entering a numeric PlayerDataID'),
      ]),
      sub('whitelist', 'Add an ASA account to the no-check join list', [
        playerOption('Connected player, or an offline EOS/ARK account ID'),
        serverOption(false, 'Needed only when manually entering an offline account ID'),
      ]),
      sub('unwhitelist', 'Remove an ASA account from the no-check join list', [
        playerOption('Connected player, or an offline EOS/ARK account ID'),
        serverOption(false, 'Needed only when manually entering an offline account ID'),
      ]),
      sub('destroy-wild-dinos', 'Destroy every untamed creature on one server', [
        serverOption(true, 'Server ID or name'),
        option(BOOLEAN, 'confirm', 'Confirm the wild dino wipe', true),
      ]),
      sub('player', 'Look up an online player and moderation history', [
        playerOption(), serverOption(false, 'Optional when selecting a connected player'),
      ]),
      sub('warn', 'Privately warn an online player', [
        playerOption(), option(STRING, 'message', 'Warning text', true, { max_length: 500 }), serverOption(false, 'Optional when selecting a connected player'),
      ]),
      sub('note', 'Add a private moderation note to an online player', [
        playerOption(), option(STRING, 'note', 'Staff note', true, { max_length: 1_000 }), serverOption(false, 'Optional when selecting a connected player'),
      ]),
      sub('announce-template', 'Send a configured announcement template', [
        option(STRING, 'template', 'Template name', true, { autocomplete: true }), serverOption(false, 'Optional server ID or name'),
      ]),
      sub('announce', 'Send an administrator announcement', [
        option(STRING, 'message', 'Announcement text', true, { max_length: announcementMaxLength }),
        serverOption(false, 'Optional server ID or name'),
      ]),
      sub('mute-player', 'Mute an ARK player from Cluster Chat', [
        playerOption(),
        option(INTEGER, 'minutes', 'Mute length in minutes', false, { min_value: 1, max_value: maxMuteMinutes }),
        option(STRING, 'reason', 'Audit reason'), serverOption(false, 'Optional when selecting a connected player'),
      ]),
      sub('unmute-player', 'Remove an ARK Cluster Chat mute', [
        playerOption(), serverOption(false, 'Optional when selecting a connected player'),
      ]),
      sub('mute-discord', 'Mute a Discord user from Cluster Chat', [
        option(USER, 'user', 'Discord user', true),
        option(INTEGER, 'minutes', 'Mute length in minutes', false, { min_value: 1, max_value: maxMuteMinutes }),
        option(STRING, 'reason', 'Audit reason'),
      ]),
      sub('unmute-discord', 'Remove a Discord Cluster Chat mute', [option(USER, 'user', 'Discord user', true)]),
      sub('kick', 'Kick an online ARK player', [
        playerOption(), serverOption(false, 'Optional when selecting a connected player'), option(STRING, 'reason', 'Audit reason'),
      ]),
      sub('ban', 'Ban an online ARK player', [
        playerOption(), serverOption(false, 'Optional when selecting a connected player'), option(STRING, 'reason', 'Audit reason'),
      ]),
      sub('unban', 'Unban an ARK EOS player ID', [
        option(STRING, 'player-id', 'EOS player ID', true), serverOption(true, 'Server ID or name'), option(STRING, 'reason', 'Audit reason'),
      ]),
      sub('rcon', 'Run an allowlisted RCON command', [
        option(STRING, 'command', 'Allowlisted command', true), serverOption(true, 'Server ID or name'),
      ]),
    ],
  }];

  const adminCommand = commands[1];
  const operationalAliases = [
    'status', 'restart', 'cancel-restart', 'save-world', 'give-item', 'remember-player-id',
    'refresh-player-id', 'give-xp', 'whitelist', 'unwhitelist', 'destroy-wild-dinos',
    'announce-template', 'announce', 'rcon',
  ].map((name) => structuredClone(adminCommand.options.find((command) => command.name === name)));

  commands.push({
    name: 'asa-ops',
    description: 'BLCKSNAKE Command server and item operations',
    dm_permission: false,
    default_member_permissions: MANAGE_GUILD,
    options: [
      ...operationalAliases,
      sub('favorite-item', 'Pin a catalog item at the top of your suggestions', [
        option(STRING, 'item', 'Search item name, GFI code, item number, or blueprint', true, { autocomplete: true }),
      ]),
      sub('unfavorite-item', 'Remove an item from your favorites', [
        option(STRING, 'item', 'Favorite catalog item', true, { autocomplete: true }),
      ]),
      sub('save-item-preset', 'Save one catalog item and its grant settings', [
        option(STRING, 'name', 'Preset name', true, { min_length: 1, max_length: 32 }),
        option(STRING, 'item', 'Search item name, GFI code, item number, or blueprint', true, { autocomplete: true }),
        option(INTEGER, 'quantity', 'Quantity to give (default 1)', false, { min_value: 1, max_value: 10_000 }),
        option(NUMBER, 'quality', 'Item quality from 0 to 100 (default 0)', false, { min_value: 0, max_value: 100 }),
        option(BOOLEAN, 'blueprint', 'Give a blueprint instead of a crafted item'),
        option(BOOLEAN, 'replace', 'Replace an existing preset with the same name'),
      ]),
      sub('delete-item-preset', 'Delete one of your saved item presets', [
        option(STRING, 'preset', 'Saved item preset', true, { autocomplete: true }),
      ]),
      sub('give-item-preset', 'Give a saved item preset to a connected player', [
        playerOption('Connected player; the current map is selected automatically'),
        option(STRING, 'preset', 'Saved item preset', true, { autocomplete: true }),
      ]),
    ],
  });
  return commands;
}
