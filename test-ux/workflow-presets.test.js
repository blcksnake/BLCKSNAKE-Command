import test from 'node:test';
import assert from 'node:assert/strict';
import { applyDefaults, validateConfig } from '../src/config.js';
import { ManagedSettingsService } from '../src/core/managed-settings.js';
import { canonicalRconHost, duplicateRconEndpoint, suggestRconPort, workflowPresets } from '../src/core/workflow-presets.js';

function fixture() {
  const runtime = applyDefaults({
    clusterName: 'Test cluster', servers: [],
    moderation: { announcementTemplates: { Welcome: 'Welcome survivors.' } },
  });
  const context = { installation: {
    revision: 1, configured: false,
    configuration: { runtime, instance: { id: 'test-instance' }, secrets: { tls: {} } },
  } };
  const service = new ManagedSettingsService({ context });
  // Exercise validation and projections without touching production state or TLS.
  service.saveConfiguration = async (current, configuration, { configured }) => {
    context.installation = { ...current, configuration, configured, revision: current.revision + 1 };
    return context.installation;
  };
  const payload = () => {
    const settings = structuredClone(service.current().settings);
    delete settings.discord.tokenConfigured;
    return { expectedRevision: context.installation.revision, settings };
  };
  return { service, context, payload };
}

function server(id, host = '127.0.0.1', port = 27020) {
  const source = applyDefaults({ servers: [{ id, name: id, host, port, password: `unique-test-password-${id}` }] }).servers[0];
  delete source.allowPublicRcon;
  delete source.profileImport.directory;
  delete source.profileImport.password;
  return source;
}

test('map presets distinguish verified ASE/ASA identifiers and accept every token without changing existing IDs', async () => {
  const maps = workflowPresets({}).maps;
  assert.deepEqual(maps.filter(map => map.game === 'ASA').map(map => map.id), [
    'TheIsland_WP', 'ScorchedEarth_WP', 'TheCenter_WP', 'Aberration_WP', 'Extinction_WP',
    'Astraeos_WP', 'Ragnarok_WP', 'Valguero_WP', 'LostColony_WP', 'Genesis_WP', 'BobsMissions_WP',
  ]);
  assert.deepEqual(maps.filter(map => map.game === 'ASE').map(map => map.id), [
    'TheIsland', 'ScorchedEarth_P', 'TheCenter', 'Aberration_P', 'Extinction', 'Ragnarok',
    'Valguero_P', 'Genesis', 'CrystalIsles', 'Gen2', 'LostIsland', 'Fjordur', 'Aquatica',
  ]);
  assert.equal(new Set(maps.map(map => map.id)).size, maps.length);
  const { service, payload } = fixture();
  const input = payload();
  input.settings.servers = [server('island'), ...maps.map((map, index) => {
    assert.equal(map.id, map.mapName);
    const value = server(map.id, '127.0.0.1', 27021 + index);
    value.profileImport.mapName = map.mapName;
    return value;
  })];
  const result = await service.update(input);
  assert.equal(result.settings.servers[0].id, 'island');
  for (const [index, map] of maps.entries()) {
    assert.equal(result.settings.servers[index + 1].id, map.id);
    assert.equal(result.settings.servers[index + 1].profileImport.mapName, map.mapName);
  }
});

test('port suggestions skip configured endpoints, preserve host scope, and never overflow', () => {
  const servers = [server('one'), server('two', '127.0.0.1', 27021), server('three', '127.0.0.2', 27022)];
  assert.equal(suggestRconPort(servers, '127.0.0.1'), 27022);
  assert.equal(suggestRconPort(servers, '127.0.0.3'), 27020);
  assert.equal(suggestRconPort(servers, '127.0.0.1', { step: 2 }), 27022);
  assert.equal(suggestRconPort([server('last', '127.0.0.1', 65535)], '127.0.0.1', { start: 65535 }), null);
  assert.throws(() => suggestRconPort([], '127.0.0.1', { start: 65536 }), RangeError);
  assert.throws(() => suggestRconPort([], '127.0.0.1', { step: 0 }), RangeError);
});

test('canonical endpoints recognize equivalent IPv6 and mapped IPv4 without merging scoped interfaces', () => {
  assert.equal(canonicalRconHost('FD00:0000::1'), 'fd00::1');
  assert.equal(canonicalRconHost('::ffff:127.0.0.1'), '127.0.0.1');
  assert.equal(canonicalRconHost('::ffff:7f00:1'), '127.0.0.1');
  assert.equal(duplicateRconEndpoint([server('one'), server('two', '::ffff:127.0.0.1')]), true);
  assert.equal(duplicateRconEndpoint([server('one', 'fe80::1%2'), server('two', 'fe80::1%3')]), false);
  assert.equal(suggestRconPort([server('one', 'FD00:0000::1')], 'fd00::1'), 27021);
});

test('map settings reject duplicate endpoints even for disabled maps and accept distinct hosts', async () => {
  const { service, payload } = fixture();
  const input = payload();
  input.settings.servers = [server('one'), { ...server('two'), enabled: false }];
  await assert.rejects(service.update(input), (error) => error.code === 'duplicate_rcon_endpoint');
  input.settings.servers[1].host = '127.0.0.2';
  const result = await service.update(input);
  assert.equal(result.settings.servers.length, 2);
  assert.equal(result.settings.servers[0].passwordConfigured, true);
  assert.equal(JSON.stringify(result).includes('unique-test-password'), false);
});

test('template categories survive edits, tolerate older clients, and clean removed template metadata', async () => {
  const { service, payload } = fixture();
  let input = payload();
  input.settings.moderation.announcementTemplateCategories = { Welcome: 'events' };
  let result = await service.update(input);
  assert.equal(result.settings.moderation.announcementTemplates.Welcome, 'Welcome survivors.');
  assert.equal(result.settings.moderation.announcementTemplateCategories.Welcome, 'events');
  input = payload();
  delete input.settings.moderation.announcementTemplateCategories;
  input.settings.moderation.announcementTemplates.Welcome = 'Updated welcome.';
  result = await service.update(input);
  assert.equal(result.settings.moderation.announcementTemplateCategories.Welcome, 'events');
  input = payload();
  delete input.settings.moderation.announcementTemplateCategories;
  input.settings.moderation.announcementTemplates = {};
  result = await service.update(input);
  assert.deepEqual(result.settings.moderation.announcementTemplateCategories, {});
  assert.deepEqual(result.settings.moderation.announcementTemplates, {});
});

test('template category validation rejects unknown names, categories and malformed objects', async () => {
  const { service, payload } = fixture();
  for (const categories of [{ Missing: 'general' }, { Welcome: 'unknown' }, [], null, 'events']) {
    const input = payload();
    input.settings.moderation.announcementTemplateCategories = categories;
    await assert.rejects(service.update(input), (error) => error.code === 'invalid_settings');
  }
  const config = applyDefaults({ servers: [server('one')], moderation: {
    announcementTemplates: { Welcome: 'Hello.' }, announcementTemplateCategories: { Welcome: 'unknown' },
  } });
  assert.throws(() => validateConfig(config), /supported category/u);
});

test('workflow presets are isolated metadata and do not populate intentionally empty templates', async () => {
  const { service, payload } = fixture();
  const input = payload();
  input.settings.moderation.announcementTemplates = {};
  input.settings.moderation.announcementTemplateCategories = {};
  const result = await service.update(input);
  assert.equal(result.workflowPresets.maps.length, 24);
  assert.equal(result.workflowPresets.announcementTemplates.length, 5);
  assert.deepEqual(result.settings.moderation.announcementTemplates, {});
  result.workflowPresets.maps[0].name = 'Mutated';
  assert.equal(service.current().workflowPresets.maps[0].name, 'The Island');
});
