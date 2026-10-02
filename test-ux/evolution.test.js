import test from 'node:test';
import assert from 'node:assert/strict';
import { applyDefaults } from '../src/config.js';
import { ManagedSettingsService } from '../src/core/managed-settings.js';
import { createBundledItemPackages } from '../src/core/default-item-packages.js';
import { itemPackageGrouping, publicItemPackage, normalizeItemPackageInput } from '../src/core/item-packages.js';

function fixture() {
  const runtime = applyDefaults({
    clusterName: 'Evolution test',
    servers: [1, 2, 3].map((number) => ({
      id: `map-${number}`, name: `Map ${number}`, host: '127.0.0.1', port: 27019 + number,
      password: `evolution-test-private-${number}`, enabled: true,
    })),
    moderation: {
      announcementTemplates: { Welcome: 'Welcome.', Event: 'Event tonight.', Rules: 'Be kind.' },
      announcementTemplateCategories: { Welcome: 'general', Event: 'events', Rules: 'rules' },
    },
  });
  const context = { installation: { revision: 1, configured: true,
    configuration: { runtime, instance: { id: 'test-instance' }, secrets: { tls: {} } } } };
  const service = new ManagedSettingsService({ context });
  let saves = 0;
  service.saveConfiguration = async (current, configuration, { configured }) => {
    saves += 1;
    context.installation = { ...current, configuration, configured, revision: current.revision + 1 };
    return context.installation;
  };
  const payload = () => {
    const settings = structuredClone(service.current().settings);
    delete settings.discord.tokenConfigured;
    settings.servers.forEach((server) => {
      delete server.passwordConfigured;
      delete server.profileImport.passwordConfigured;
    });
    return { expectedRevision: context.installation.revision, settings };
  };
  return { service, context, payload, saves: () => saves };
}

test('all bundled boss packages expose grouping without changing stored records', () => {
  const packages = Object.values(createBundledItemPackages());
  const before = structuredClone(packages);
  const bosses = packages.filter((entry) => entry.name.startsWith('Boss: '));
  assert.equal(bosses.length, 68);
  for (const entry of bosses) {
    const projected = publicItemPackage(entry);
    assert.equal(projected.grouping.category, 'boss');
    assert.ok(projected.grouping.map);
    assert.ok(projected.grouping.boss);
    assert.ok(['alpha', 'beta', 'gamma', 'standard'].includes(projected.grouping.tier));
    assert.equal(`Boss: ${projected.grouping.map} - ${projected.grouping.boss} - ${projected.grouping.tier[0].toUpperCase()}${projected.grouping.tier.slice(1)}`, entry.name);
  }
  assert.deepEqual(packages, before);
  assert.equal(publicItemPackage(null), null);
});

test('grouping handles Unicode names and does not infer bosses from descriptions or partial names', () => {
  assert.deepEqual(itemPackageGrouping({ name: 'Boss: Fjordur - Hati + Sköll - Standard' }),
    { category: 'boss', map: 'Fjordur', boss: 'Hati + Sköll', tier: 'standard' });
  for (const name of ['Boss supplies', 'Boss: Island - Dragon', 'Boss: Island - Dragon - Unknown', 'Custom']) {
    assert.deepEqual(itemPackageGrouping({ name, description: 'Boss: Island - Dragon - Alpha' }),
      { category: 'custom', map: null, boss: null, tier: null });
  }
  assert.equal(itemPackageGrouping({ name: 'Starter: Survival Essentials' }).category, 'starter');
  assert.equal(itemPackageGrouping({ name: 'Freebie: Community Weekend' }).category, 'freebie');
  assert.equal(itemPackageGrouping({ name: 'My Freebie: Community Weekend' }).category, 'custom');
  const entry = Object.values(createBundledItemPackages())[0];
  const { id, revision, createdAt, updatedAt, ...input } = entry;
  assert.throws(() => normalizeItemPackageInput({ ...input, grouping: { category: 'boss' } }), /Unsupported item package field grouping/u);
});

test('bulk map enable changes commit once and preserve credentials, unrelated maps and categories', async () => {
  const { service, context, payload, saves } = fixture();
  const input = payload();
  input.settings.servers[0].enabled = false;
  input.settings.servers[1].enabled = false;
  const result = await service.update(input);
  assert.equal(saves(), 1);
  assert.equal(result.revision, 2);
  assert.equal(result.restartRequired, true);
  assert.deepEqual(result.settings.servers.map((entry) => entry.enabled), [false, false, true]);
  assert.deepEqual(context.installation.configuration.runtime.servers.map((entry) => entry.password),
    [1, 2, 3].map((number) => `evolution-test-private-${number}`));
  assert.equal(JSON.stringify(result).includes('evolution-test-private'), false);
  assert.deepEqual(result.settings.moderation.announcementTemplateCategories, input.settings.moderation.announcementTemplateCategories);
});

test('bulk template category and removal changes remain one atomic settings revision', async () => {
  const { service, payload, saves } = fixture();
  const input = payload();
  input.settings.moderation.announcementTemplateCategories.Welcome = 'events';
  input.settings.moderation.announcementTemplateCategories.Rules = 'events';
  delete input.settings.moderation.announcementTemplates.Event;
  delete input.settings.moderation.announcementTemplateCategories.Event;
  const result = await service.update(input);
  assert.equal(result.revision, 2);
  assert.equal(saves(), 1);
  assert.deepEqual(result.settings.moderation.announcementTemplates, { Welcome: 'Welcome.', Rules: 'Be kind.' });
  assert.deepEqual(result.settings.moderation.announcementTemplateCategories, { Welcome: 'events', Rules: 'events' });
  assert.deepEqual(result.settings.servers.map((entry) => entry.enabled), [true, true, true]);
});

test('invalid member rejects the entire bulk change before persistence', async () => {
  const { service, context, payload, saves } = fixture();
  const before = structuredClone(context.installation);
  const input = payload();
  input.settings.servers[0].enabled = false;
  input.settings.servers[1].enabled = 'disabled';
  input.settings.moderation.announcementTemplateCategories.Welcome = 'events';
  await assert.rejects(service.update(input), (error) => error.code === 'invalid_settings');
  assert.equal(saves(), 0);
  assert.deepEqual(context.installation, before);
});

test('stale bulk drafts cannot overwrite a newer revision', async () => {
  const { service, context, payload, saves } = fixture();
  const stale = payload();
  const current = payload();
  current.settings.moderation.announcementTemplateCategories.Welcome = 'events';
  await service.update(current);
  stale.settings.servers.forEach((entry) => { entry.enabled = false; });
  await assert.rejects(service.update(stale), (error) => error.status === 409 && error.code === 'settings_conflict');
  assert.equal(saves(), 1);
  assert.equal(context.installation.revision, 2);
  assert.deepEqual(context.installation.configuration.runtime.servers.map((entry) => entry.enabled), [true, true, true]);
});
