import net from 'node:net';

export const TEMPLATE_CATEGORIES = Object.freeze([
  { id: 'general', label: 'General' },
  { id: 'maintenance', label: 'Maintenance' },
  { id: 'events', label: 'Events' },
  { id: 'community', label: 'Community' },
  { id: 'rules', label: 'Rules' },
].map(Object.freeze));

export const DEFAULT_TEMPLATE_CATEGORIES = Object.freeze({
  Welcome: 'community', 'Maintenance soon': 'maintenance', 'World save': 'maintenance',
  'Event starting': 'events', 'Rules reminder': 'rules',
});

// Exact server level names, not display-name slugs. Existing IDs are never rewritten.
// Sources: https://github.com/CubeCoders/AMPTemplates/blob/main/ark-sa-minconfig.json
// https://github.com/CubeCoders/AMPTemplates/blob/main/ark-se-minconfig.json
// https://www.curseforge.com/ark-survival-ascended/mods/club-ark
const MAP_PRESETS = Object.freeze([
  ['ASA', 'The Island', 'TheIsland_WP'],
  ['ASA', 'Scorched Earth', 'ScorchedEarth_WP'],
  ['ASA', 'The Center', 'TheCenter_WP'],
  ['ASA', 'Aberration', 'Aberration_WP'],
  ['ASA', 'Extinction', 'Extinction_WP'],
  ['ASA', 'Astraeos', 'Astraeos_WP'],
  ['ASA', 'Ragnarok', 'Ragnarok_WP'],
  ['ASA', 'Valguero', 'Valguero_WP'],
  ['ASA', 'Lost Colony', 'LostColony_WP'],
  ['ASA', 'Genesis: Part 1', 'Genesis_WP'],
  ['ASA', 'Club ARK', 'BobsMissions_WP'],
  ['ASE', 'The Island', 'TheIsland'],
  ['ASE', 'Scorched Earth', 'ScorchedEarth_P'],
  ['ASE', 'The Center', 'TheCenter'],
  ['ASE', 'Aberration', 'Aberration_P'],
  ['ASE', 'Extinction', 'Extinction'],
  ['ASE', 'Ragnarok', 'Ragnarok'],
  ['ASE', 'Valguero', 'Valguero_P'],
  ['ASE', 'Genesis: Part 1', 'Genesis'],
  ['ASE', 'Crystal Isles', 'CrystalIsles'],
  ['ASE', 'Genesis: Part 2', 'Gen2'],
  ['ASE', 'Lost Island', 'LostIsland'],
  ['ASE', 'Fjordur', 'Fjordur'],
  ['ASE', 'Aquatica', 'Aquatica'],
].map(([game, name, mapName]) => Object.freeze({ game, id: mapName, name, mapName })));

export function workflowPresets(templates) {
  return {
    maps: MAP_PRESETS.map((preset) => ({ ...preset })),
    templateCategories: TEMPLATE_CATEGORIES.map((category) => ({ ...category })),
    announcementTemplates: Object.entries(templates).map(([name, message]) => ({
      name, message, category: DEFAULT_TEMPLATE_CATEGORIES[name] ?? 'general',
    })),
    rconPort: { minimum: 1, maximum: 65_535, default: 27_020, step: 1 },
  };
}

// Compare equivalent IPv6 spellings and IPv4-mapped IPv6 with their IPv4 peer.
// Keep link-local scope IDs: separate interfaces can reach separate endpoints.
export function canonicalRconHost(value) {
  const host = String(value ?? '').trim().toLowerCase();
  const [address, scope] = host.split('%');
  if (net.isIPv4(address)) return address;
  if (!net.isIPv6(address)) return host;
  const normalized = new URL(`http://[${address}]/`).hostname.slice(1, -1);
  const mapped = /^::ffff:([a-f0-9]+):([a-f0-9]+)$/u.exec(normalized);
  if (mapped) {
    const high = parseInt(mapped[1], 16); const low = parseInt(mapped[2], 16);
    return `${high >>> 8}.${high & 255}.${low >>> 8}.${low & 255}`;
  }
  return `${normalized}${scope ? `%${scope}` : ''}`;
}

export function duplicateRconEndpoint(servers) {
  const endpoints = new Set();
  for (const server of servers) {
    const endpoint = `${canonicalRconHost(server.host)}|${server.port}`;
    if (endpoints.has(endpoint)) return true;
    endpoints.add(endpoint);
  }
  return false;
}

// A configuration suggestion only: this does not probe or reserve a socket.
// Scan upward without wrapping into unexpectedly low privileged ports.
export function suggestRconPort(servers, host, { start = 27_020, step = 1 } = {}) {
  if (!Number.isInteger(start) || start < 1 || start > 65_535
    || !Number.isInteger(step) || step < 1 || step > 65_535) {
    throw new RangeError('Port start and step must be integers from 1 to 65535');
  }
  const canonical = canonicalRconHost(host);
  const used = new Set(servers.filter((server) => canonicalRconHost(server.host) === canonical)
    .map((server) => Number(server.port)));
  for (let port = start; port <= 65_535; port += step) if (!used.has(port)) return port;
  return null;
}
