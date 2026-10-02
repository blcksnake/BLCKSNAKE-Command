import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { chromium, expect } from '@playwright/test';
import { DASHBOARD_HTML } from '../src/http/dashboard.js';
import { workflowPresets } from '../src/core/workflow-presets.js';

// Exercise the real DOM, stylesheet and client in Chromium. All HTTP requests are
// intercepted; these fixtures cannot contact a real instance, RCON or SFTP host.
const client = await fs.readFile(new URL('../src/http/dashboard-client.js', import.meta.url), 'utf8');
const css = await fs.readFile(new URL('../src/http/dashboard.css', import.meta.url), 'utf8');
const brand = await fs.readFile(new URL('../src/http/assets/blcksnake-mark.png', import.meta.url));
let browser;
before(async () => { browser = await chromium.launch({ headless: true }); });
after(async () => { await browser?.close(); });

function projectionFixture() {
  return {
    managed: true, revision: 1, restartRequired: false,
    workflowPresets: workflowPresets({ Welcome: 'Welcome survivors!', Maintenance: 'Maintenance begins in ten minutes.' }),
    instance: {
      instanceId: 'browser-test-instance', keystore: 'managed',
      tls: { mode: 'Managed HTTPS', trustUpdateRequired: false, rotationRequiresExplicitNames: false, subjectAltNames: ['localhost'], additionalSubjectAltNames: [] },
      automationToken: { configured: true, activationPending: false, deliveryPending: false, activationReceipt: '' },
    },
    settings: {
      clusterName: 'Browser test cluster',
      servers: [
        { id: 'island', name: 'The Island', enabled: true, host: '127.0.0.1', port: 27020, passwordConfigured: true, profileImport: { enabled: false } },
        { id: 'scorched', name: 'Scorched Earth', enabled: false, host: '127.0.0.1', port: 27021, passwordConfigured: true, profileImport: { enabled: false } },
      ],
      discord: { enabled: false }, analytics: { enabled: false },
      moderation: {
        announcementTemplates: { Welcome: 'Welcome survivors!', Maintenance: 'Maintenance begins in ten minutes.' },
        announcementTemplateCategories: { Welcome: 'community', Maintenance: 'maintenance' },
        recurringAnnouncements: [], rawRconAllowlist: [], allowRawRcon: false,
      },
    },
  };
}

function packageFixtures() {
  return [
    { id: 'starter', name: 'Starter supplies', description: 'First join supplies', enabled: true, starterEnabled: true, revision: 1, items: [{ itemKey: 'gfi:Stone', name: 'Stone', quantity: 10, quality: 0, blueprint: false }] },
    { id: 'boss', name: 'Boss battle supplies', description: 'Boss encounter equipment', enabled: true, starterEnabled: false, revision: 1, items: [{ itemKey: 'gfi:Stone', name: 'Stone', quantity: 20, quality: 0, blueprint: false }] },
  ];
}

async function dashboard(t, options = {}) {
  const context = await browser.newContext({ viewport: options.viewport || { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
  t.after(() => context.close());
  const page = await context.newPage();
  page.setDefaultTimeout(7000);
  const errors = [];
  const requests = [];
  const unexpected = [];
  let projection = projectionFixture();
  if (options.largeCollection) {
    projection.settings.servers = Array.from({ length: 64 }, (_, index) => ({
      ...projection.settings.servers[0], id: `map-${index}`, name: `Map ${String(index).padStart(2, '0')}`, port: 27020 + index,
    }));
    projection.settings.moderation.announcementTemplates = Object.fromEntries(Array.from({ length: 32 }, (_, index) => [`Template ${index}`, `Message number ${index}`]));
    projection.settings.moderation.announcementTemplateCategories = {};
  }
  let packages = packageFixtures();
  const status = {
    ready: true, clusterName: 'Browser test cluster', discord: { enabled: false, ready: false },
    servers: projection.settings.servers.map((server) => ({ serverId: server.id, serverName: server.name, connected: server.enabled, playerCount: 0, players: [], lastLatencyMs: 3, lastSuccessAt: Date.now(), profileImport: { enabled: false } })),
  };
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error' && /not focusable/i.test(message.text())) errors.push(message.text()); });
  await page.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    const json = (body, statusCode = 200) => route.fulfill({ status: statusCode, contentType: 'application/json', body: JSON.stringify(body) });
    if (url.pathname === '/dashboard') return route.fulfill({ contentType: 'text/html', body: DASHBOARD_HTML });
    if (url.pathname === '/dashboard-client.js') return route.fulfill({ contentType: 'text/javascript', body: client });
    if (url.pathname === '/dashboard.css') return route.fulfill({ contentType: 'text/css', body: css });
    if (url.pathname === '/brand/blcksnake-mark.png') return route.fulfill({ contentType: 'image/png', body: brand });
    if (url.pathname.startsWith('/brand/') || url.pathname === '/favicon.ico') return route.fulfill({ status: 204, body: '' });
    if (url.pathname === '/admin/api/auth-mode') return json({ authenticated: true, remote: false, setupRequired: false });
    if (url.pathname === '/admin/api/bootstrap') return json({
      session: { username: 'BrowserAdmin', role: 'admin', csrfToken: 'synthetic-browser-csrf', mustChangePassword: false, recentAuthenticationExpiresAt: Date.now() + 60_000 },
      status, capabilities: { actions: ['announce', 'save-world', 'restart'], packages, announcementMaxLength: 400 },
    });
    if (url.pathname === '/admin/api/settings' && request.method() === 'GET') return json(projection);
    if (url.pathname === '/admin/api/settings' && request.method() === 'PUT') {
      const body = request.postDataJSON(); requests.push({ path: url.pathname, method: request.method(), body });
      projection = { ...projection, revision: projection.revision + 1, restartRequired: true, settings: body.settings || body };
      projection.settings.servers = projection.settings.servers.map(server => ({ ...server, passwordConfigured: true }));
      return json(projection);
    }
    if (url.pathname.startsWith('/admin/api/packages/') && request.method() === 'PUT') {
      const body = request.postDataJSON(); requests.push({ path: url.pathname, method: request.method(), body });
      if (options.failPackageSave) return json({ message: 'Synthetic save failure', code: 'TEST_FAILURE' }, 503);
      const id = url.pathname.split('/').at(-1);
      const saved = { ...packages.find(item => item.id === id), ...body, revision: 2 };
      packages = packages.map(item => item.id === id ? saved : item);
      return json({ ok: true, package: saved });
    }
    if (url.pathname === '/admin/api/players') return json({ players: [] });
    if (url.pathname === '/admin/api/activity') return json({ activity: [] });
    unexpected.push(`${request.method()} ${url.pathname}`);
    return json({ message: 'Unexpected fixture request' }, 404);
  });
  await page.goto('http://127.0.0.1/dashboard#settings');
  await expect(page.locator('#settings-cluster-name')).toHaveValue('Browser test cluster');
  t.after(() => {
    assert.deepEqual(errors, [], 'browser must not raise runtime errors or focus hidden invalid fields');
    assert.deepEqual(unexpected, [], 'all API requests must be deliberate fixture interactions');
  });
  return { page, requests, errors };
}

async function selectSection(page, name) {
  await page.locator(`[data-settings-jump="settings-${name}"]`).click();
  await expect(page.locator(`#settings-${name}`)).toBeVisible();
}

test('settings sections, map disclosure, and combined filters preserve drafts', async t => {
  const { page, requests } = await dashboard(t);
  await selectSection(page, 'maps');
  await expect(page.locator('.settings-sections > .settings-card:visible')).toHaveCount(1);
  const maps = page.locator('[data-settings-server]');
  await expect(maps).toHaveCount(2);
  const first = maps.first();
  await expect(first.locator('.settings-server-body')).toBeHidden();
  await first.locator('.settings-editor-toggle').click();
  await first.locator('[data-setting-field="name"]').fill('Island draft name');
  await first.locator('.settings-editor-toggle').click();
  await page.locator('#settings-map-search').fill('scorched');
  await expect(page.locator('[data-settings-server]:visible')).toHaveCount(1);
  await page.locator('#settings-map-filter').selectOption('enabled');
  await expect(page.locator('[data-settings-server]:visible')).toHaveCount(0);
  await page.locator('#settings-map-search').fill('');
  await expect(page.locator('[data-settings-server]:visible')).toHaveCount(1);
  await page.locator('#settings-map-clear').click();
  await expect(page.locator('[data-settings-server]:visible')).toHaveCount(2);
  await selectSection(page, 'general');
  await selectSection(page, 'maps');
  await first.locator('.settings-editor-toggle').click();
  await expect(first.locator('[data-setting-field="name"]')).toHaveValue('Island draft name');
  assert.equal(requests.length, 0, 'draft edits must not mutate the backend');
});

test('HTML constraint patterns compile under the browser Unicode-set rules', async t => {
  const { page } = await dashboard(t);
  const errors = await page.locator('input[pattern]').evaluateAll(inputs => inputs.flatMap(input => {
    try { new RegExp(input.pattern, 'v'); return []; }
    catch (error) { return [{ field: input.id || input.dataset.settingField || input.dataset.templateField, pattern: input.pattern, message: error.message }]; }
  }));
  assert.deepEqual(errors, [], 'invalid HTML patterns are ignored by modern browsers and must be fixed');
});

test('all ASE and ASA presets fill exact map IDs and keep duplicate server suffixes out of the save token', async t => {
  const { page, requests } = await dashboard(t);
  await selectSection(page, 'maps');
  const ids = page.locator('#settings-server-list [data-setting-field="id"]');
  assert.deepEqual(await ids.evaluateAll(inputs => inputs.map(input => input.value)), ['island', 'scorched']);
  await page.locator('#settings-add-server').click();
  const wizard = page.locator('#settings-map-wizard');
  const preset = page.locator('#settings-map-preset');
  await expect(preset.locator('optgroup')).toHaveCount(2);
  for (const entry of workflowPresets({}).maps) {
    await preset.selectOption(entry.mapName);
    await expect(wizard.locator('[data-setting-field="id"]')).toHaveValue(entry.mapName);
    await expect(wizard.locator('[data-setting-field="name"]')).toHaveValue(entry.name);
    await expect(wizard.locator('[data-setting-field="profile.mapName"]')).toHaveValue(entry.mapName);
  }
  await preset.selectOption('TheIsland');
  await wizard.locator('[data-setting-field="name"]').fill('ASE Island renamed');
  await expect(wizard.locator('[data-setting-field="profile.mapName"]')).toHaveValue('TheIsland');
  await page.locator('#settings-map-wizard-cancel').click();
  const rows = page.locator('[data-settings-server]');
  await rows.nth(0).locator('.settings-editor-toggle').click();
  await rows.nth(1).locator('.settings-editor-toggle').click();
  await ids.nth(0).fill('TheIsland_WP');
  await ids.nth(1).fill('TheIsland_WP-2');
  await page.locator('#settings-add-server').click();
  await preset.selectOption('TheIsland_WP');
  await expect(wizard.locator('[data-setting-field="id"]')).toHaveValue('TheIsland_WP-3');
  await expect(wizard.locator('[data-setting-field="profile.mapName"]')).toHaveValue('TheIsland_WP');
  await preset.selectOption('');
  await wizard.locator('[data-setting-field="id"]').fill('MyCustomMap');
  await expect(wizard.locator('[data-setting-field="id"]')).toHaveValue('MyCustomMap');
  await page.locator('#settings-map-wizard-cancel').click();
  assert.equal(requests.length, 0);
});

test('Add Map wizard validates, suggests a free port, stages a map, and restores visible focus', async t => {
  const { page, requests } = await dashboard(t);
  await selectSection(page, 'maps');
  await page.locator('#settings-map-search').fill('no map matches');
  await page.locator('#settings-add-server').click();
  const wizard = page.locator('#settings-map-wizard');
  await expect(wizard).toBeVisible();
  const field = name => wizard.locator(`[data-setting-field="${name}"]`);
  await page.locator('#settings-map-preset').selectOption('Aberration_WP');
  await expect(field('id')).toHaveValue('Aberration_WP');
  await expect(field('name')).toHaveValue('Aberration');
  await field('name').fill('Aberration test');
  await page.locator('#settings-map-wizard-next').click();
  await expect(field('password')).toBeVisible();
  assert.ok(![27020, 27021].includes(Number(await field('port').inputValue())), 'new map port must avoid occupied host/port pairs');
  await page.locator('#settings-map-wizard-next').click();
  await expect(field('password')).toBeFocused();
  await field('password').fill('Synthetic test password 123!');
  await page.locator('#settings-map-wizard-next').click();
  await expect(field('profile.enabled')).toBeVisible();
  await page.locator('#settings-map-wizard-next').click();
  await expect(wizard).not.toContainText('Synthetic test password 123!');
  await page.locator('#settings-map-wizard-next').click();
  await expect(wizard).toBeHidden();
  await expect(page.locator('[data-settings-server]')).toHaveCount(3);
  await expect(page.locator('#settings-change-bar')).toBeVisible();
  assert.equal(await page.locator('#settings-server-list [data-setting-field="id"]').evaluateAll(inputs => inputs.filter(input => input.value === 'Aberration_WP').length), 1);
  assert.equal(requests.length, 0, 'wizard completion must only stage a draft');
  assert.equal(await page.evaluate(() => Boolean(document.activeElement?.closest('[data-settings-server]'))), true);
});

test('wizard cancellation preserves collection and returns focus to Add map', async t => {
  const { page } = await dashboard(t);
  await selectSection(page, 'maps');
  await page.locator('#settings-add-server').click();
  for (let index = 0; index < 8; index += 1) {
    await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(() => document.activeElement === document.body || Boolean(document.activeElement?.closest('#settings-map-wizard'))), true, 'Tab must not focus inert background controls; native dialogs may also yield focus to browser chrome');
  }
  await page.keyboard.press('Escape');
  await expect(page.locator('#settings-map-wizard')).toBeHidden();
  await expect(page.locator('[data-settings-server]')).toHaveCount(2);
  await expect(page.locator('#settings-add-server')).toBeFocused();
});

test('Add Map rejects public RCON hosts and validates optional SFTP before review', async t => {
  const { page, requests } = await dashboard(t);
  await selectSection(page, 'maps');
  await page.locator('#settings-add-server').click();
  const wizard = page.locator('#settings-map-wizard');
  const field = name => wizard.locator(`[data-setting-field="${name}"]`);
  await page.locator('#settings-map-preset').selectOption('TheCenter_WP');
  await field('id').fill('invalid map id');
  await page.locator('#settings-map-wizard-next').click();
  await expect(field('id')).toBeFocused();
  await field('id').fill('center');
  await page.locator('#settings-map-wizard-next').click();
  await field('host').fill('8.8.8.8');
  await field('password').fill('Synthetic RCON password 123!');
  await page.locator('#settings-map-wizard-next').click();
  await expect(field('host')).toBeFocused();
  await field('host').fill('fe80::1%eth0');
  await page.locator('#settings-map-wizard-next').click();
  await expect(field('profile.enabled')).toBeVisible();
  await page.locator('#settings-map-wizard-back').click();
  await field('host').fill('127.0.0.2');
  await page.locator('#settings-map-wizard-next').click();
  await field('profile.enabled').check();
  await expect(field('profile.host')).toHaveValue('127.0.0.2');
  await page.locator('#settings-map-wizard-next').click();
  await expect(field('profile.username')).toBeFocused();
  await field('profile.username').fill('readonly');
  await field('profile.password').fill('Synthetic SFTP password 456!');
  await field('profile.hostKeySha256').fill('invalid-fingerprint');
  await page.locator('#settings-map-wizard-next').click();
  await expect(field('profile.hostKeySha256')).toBeFocused();
  await field('profile.verifyHostKey').uncheck();
  await expect(field('profile.hostKeySha256')).toBeDisabled();
  await field('profile.verifyHostKey').check();
  await expect(field('profile.hostKeySha256')).toBeEnabled();
  await field('profile.hostKeySha256').fill('SHA256:' + 'A'.repeat(43));
  await page.locator('#settings-map-wizard-next').click();
  await expect(wizard.locator('.wizard-review')).toContainText('TheCenter_WP');
  await expect(wizard.locator('.wizard-review')).not.toContainText('Synthetic');
  assert.equal(requests.length, 0);
  await page.keyboard.press('Escape');
});

test('template category search and duplication retain message and stage changes', async t => {
  const { page, requests } = await dashboard(t);
  await selectSection(page, 'templates');
  await page.locator('#settings-template-category').selectOption('maintenance');
  await expect(page.locator('[data-settings-template]:visible')).toHaveCount(1);
  await page.locator('#settings-template-search').fill('ten minutes');
  await expect(page.locator('[data-settings-template]:visible')).toHaveCount(1);
  await page.locator('[data-settings-template]:visible .settings-template-duplicate').click();
  await expect(page.locator('[data-settings-template]')).toHaveCount(3);
  const active = page.locator('[data-template-field="name"]:focus');
  await expect(active).toHaveCount(1);
  const row = page.locator('[data-settings-template]').filter({ has: active });
  const duplicateName = await active.inputValue();
  await active.fill('@invalid-name');
  assert.equal(await active.evaluate(input => input.validity.patternMismatch), true, 'invalid template names must fail the native constraint');
  await active.fill(duplicateName);
  await expect(row.locator('[data-template-field="message"]')).toHaveValue('Maintenance begins in ten minutes.');
  await expect(row.locator('[data-template-field="category"]')).toHaveValue('maintenance');
  const names = await page.locator('[data-template-field="name"]').evaluateAll(inputs => inputs.map(input => input.value));
  assert.equal(new Set(names.map(name => name.toLowerCase())).size, names.length);
  await expect(page.locator('#settings-change-bar')).toBeVisible();
  assert.equal(requests.length, 0);
});

test('Review reveals invalid fields hidden by a section, card, and filter', async t => {
  const { page } = await dashboard(t);
  await selectSection(page, 'maps');
  const first = page.locator('[data-settings-server]').first();
  await first.locator('.settings-editor-toggle').click();
  await first.locator('[data-setting-field="name"]').fill('');
  await first.locator('.settings-editor-toggle').click();
  await page.locator('#settings-map-search').fill('scorched');
  await selectSection(page, 'general');
  await page.locator('#settings-review').click();
  await expect(first.locator('[data-setting-field="name"]')).toBeVisible();
  await expect(first.locator('[data-setting-field="name"]')).toBeFocused();
  await expect(page.locator('#settings-review-dialog')).toBeHidden();
});

test('template category changes survive revision-checked settings save and reload', async t => {
  const { page, requests } = await dashboard(t);
  await selectSection(page, 'templates');
  const row = page.locator('[data-settings-template]').first();
  await row.locator('.settings-editor-toggle').click();
  await row.locator('[data-template-field="category"]').selectOption('events');
  await row.locator('[data-template-field="message"]').fill('Community event starts tomorrow.');
  await page.locator('#settings-review').click();
  await expect(page.locator('#settings-review-dialog')).toBeVisible();
  await page.locator('#settings-apply').click();
  await expect(page.locator('#settings-review-dialog')).toBeHidden();
  await expect(page.locator('#settings-restart-banner')).toBeVisible();
  assert.equal(requests.length, 1);
  assert.equal(requests[0].body.expectedRevision, 1);
  assert.equal(requests[0].body.settings.moderation.announcementTemplateCategories.Welcome, 'events');
  await page.reload();
  await expect(page.locator('#settings-cluster-name')).toHaveValue('Browser test cluster');
  await selectSection(page, 'templates');
  await page.locator('[data-settings-template]').first().locator('.settings-editor-toggle').click();
  await expect(page.locator('[data-settings-template]').first().locator('[data-template-field="category"]')).toHaveValue('events');
});

test('package filtering and immediate editor save retain failures and submit real drafts', async t => {
  const { page, requests } = await dashboard(t, { failPackageSave: true });
  await selectSection(page, 'packages');
  await page.locator('#settings-package-filter').selectOption('shared');
  await expect(page.locator('.settings-package-row:visible')).toHaveCount(2);
  await page.locator('#settings-package-filter').selectOption('boss');
  await expect(page.locator('.settings-package-row:visible')).toHaveCount(1);
  await page.locator('#settings-package-search').fill('equipment');
  await expect(page.locator('.settings-package-row:visible')).toHaveCount(1);
  await page.locator('.settings-package-row:visible [data-edit-package]').click();
  await expect(page.locator('#item-package-dialog')).toBeVisible();
  await page.locator('#item-package-name').fill('Boss revised draft');
  await page.locator('#item-package-save').click();
  await expect(page.locator('#item-package-error')).toContainText('Synthetic save failure');
  await expect(page.locator('#item-package-name')).toHaveValue('Boss revised draft');
  assert.equal(requests.length, 1);
  assert.equal(requests[0].body.name, 'Boss revised draft');
  assert.equal(requests[0].body.expectedRevision, 1);
});

test('successful package save updates the list without staged settings changes', async t => {
  const { page, requests } = await dashboard(t);
  await selectSection(page, 'packages');
  await page.locator('[data-edit-package="boss"]').click();
  await page.locator('#item-package-name').fill('Boss updated supplies');
  await page.locator('#item-package-save').click();
  await expect(page.locator('#item-package-dialog')).toBeHidden();
  await expect(page.locator('.settings-package-list')).toContainText('Boss updated supplies');
  await expect(page.locator('#settings-change-bar')).toBeHidden();
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'PUT');
  assert.equal(requests[0].path, '/admin/api/packages/boss');
});

test('overview map disclosures retain open state and keyboard focus across refresh', async t => {
  const { page } = await dashboard(t);
  await page.locator('[data-tab="overview"]').click();
  const card = page.locator('[data-overview-map="island"]');
  const details = card.locator('.map-diagnostics');
  await details.locator('summary').click();
  await expect(details).toHaveAttribute('open', '');
  await details.evaluate(node => { node.dataset.testInstance = 'original'; });
  const scrollBefore = await page.evaluate(() => window.scrollY);
  const refresh = page.waitForResponse(response => new URL(response.url()).pathname === '/admin/api/bootstrap');
  await page.evaluate(() => document.querySelector('#refresh-button').click());
  await refresh;
  await expect(details).toHaveAttribute('data-test-instance', 'original');
  await expect(details).toHaveAttribute('open', '');
  await expect(details.locator('summary')).toBeFocused();
  assert.ok(Math.abs((await page.evaluate(() => window.scrollY)) - scrollBefore) <= 1, 'refresh must not scroll the page');
});

test('maximum map and template collections remain filterable without losing drafts', async t => {
  const started = performance.now();
  const { page } = await dashboard(t, { largeCollection: true });
  await selectSection(page, 'maps');
  await expect(page.locator('[data-settings-server]')).toHaveCount(64);
  const elapsed = await page.locator('#settings-map-search').evaluate(input => {
    const start = performance.now();
    input.value = 'Map 63'; input.dispatchEvent(new Event('input', { bubbles: true }));
    return performance.now() - start;
  });
  await expect(page.locator('[data-settings-server]:visible')).toHaveCount(1);
  assert.ok(elapsed < 1000, `filter event should complete within 1 second, measured ${elapsed.toFixed(1)} ms`);
  await selectSection(page, 'templates');
  await expect(page.locator('[data-settings-template]')).toHaveCount(32);
  await page.locator('#settings-template-search').fill('Message number 31');
  await expect(page.locator('[data-settings-template]:visible')).toHaveCount(1);
  t.diagnostic(`64-map filter event: ${elapsed.toFixed(1)} ms; complete large-collection browser scenario: ${(performance.now() - started).toFixed(1)} ms`);
});

test('mobile settings and floating wizard fit 320, 390, 768, and 1440 pixel viewports', async t => {
  const { page } = await dashboard(t);
  await selectSection(page, 'maps');
  await fs.mkdir(new URL('../reports/ux/', import.meta.url), { recursive: true });
  for (const width of [320, 390, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    assert.ok(overflow <= 1, `settings must not overflow horizontally at ${width}px (overflow ${overflow}px)`);
    if ([390, 1440].includes(width)) await page.screenshot({ path: fileURLToPath(new URL(`../reports/ux/maps-${width}.png`, import.meta.url)) });
    await page.locator('#settings-add-server').click();
    const rect = await page.locator('#settings-map-wizard').boundingBox();
    assert.ok(rect && rect.x >= -1 && rect.x + rect.width <= width + 1, `wizard must fit ${width}px viewport`);
    await expect(page.locator('#settings-map-wizard-next')).toBeInViewport();
    if ([390, 1440].includes(width)) await page.screenshot({ path: fileURLToPath(new URL(`../reports/ux/add-map-${width}.png`, import.meta.url)) });
    await page.keyboard.press('Escape');
  }
});
