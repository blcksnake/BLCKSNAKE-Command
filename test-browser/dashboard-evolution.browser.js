import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { chromium, expect } from '@playwright/test';
import { DASHBOARD_HTML } from '../src/http/dashboard.js';
import { workflowPresets } from '../src/core/workflow-presets.js';

// Real client/DOM, fully intercepted requests. These tests never reach live maps.
const client = await fs.readFile(new URL('../src/http/dashboard-client.js', import.meta.url), 'utf8');
const css = await fs.readFile(new URL('../src/http/dashboard.css', import.meta.url), 'utf8');
const brand = await fs.readFile(new URL('../src/http/assets/blcksnake-mark.png', import.meta.url));
let browser;
before(async () => { browser = await chromium.launch({ headless: true }); });
after(async () => { await browser?.close(); });

function fixtures(options) {
  const servers = [
    { id: 'island', name: 'The Island', enabled: true, host: '127.0.0.1', port: 27020, passwordConfigured: true, profileImport: { enabled: false } },
    { id: 'scorched', name: 'Scorched Earth', enabled: false, host: '127.0.0.1', port: 27021, passwordConfigured: true, profileImport: { enabled: false } },
    { id: 'center', name: 'The Center', enabled: true, host: '127.0.0.1', port: 27022, passwordConfigured: true, profileImport: { enabled: false } },
  ];
  const projection = {
    managed: true, revision: 1, restartRequired: false,
    workflowPresets: workflowPresets({ Welcome: 'Welcome survivors!', Maintenance: 'Maintenance begins in ten minutes.' }),
    instance: { instanceId: 'evolution-fixture', keystore: 'managed', tls: { mode: 'Managed HTTPS', trustUpdateRequired: false, rotationRequiresExplicitNames: false, subjectAltNames: ['localhost'], additionalSubjectAltNames: [] }, automationToken: { configured: true, activationPending: false, deliveryPending: false, activationReceipt: '' } },
    settings: {
      clusterName: 'Evolution test cluster', servers,
      discord: { enabled: false }, analytics: { enabled: false },
      moderation: { announcementTemplates: { Welcome: 'Welcome survivors!', Maintenance: 'Maintenance begins in ten minutes.' }, announcementTemplateCategories: { Welcome: 'community', Maintenance: 'maintenance' }, recurringAnnouncements: [], rawRconAllowlist: [], allowRawRcon: false },
    },
  };
  if (options.largeCollection) {
    projection.settings.servers = Array.from({ length: 64 }, (_, index) => ({ ...servers[0], id: `map-${index}`, name: `Map ${String(index).padStart(2, '0')}`, port: 27020 + index }));
    projection.settings.moderation.announcementTemplates = Object.fromEntries(Array.from({ length: 32 }, (_, index) => [`Template ${index}`, `Message number ${index}`]));
    projection.settings.moderation.announcementTemplateCategories = {};
  }
  const packages = [
    { id: 'starter', name: 'Starter supplies', description: 'First join supplies', enabled: true, starterEnabled: true, revision: 1, items: [{ itemKey: 'gfi:Stone', name: 'Stone', quantity: 10, quality: 0, blueprint: false }] },
    { id: 'boss-alpha', name: 'Island Alpha Boss', description: 'Island boss equipment', enabled: true, starterEnabled: false, revision: 1, items: [{ itemKey: 'gfi:Stone', name: 'Stone', quantity: 20, quality: 0, blueprint: false }] },
    { id: 'boss-gamma', name: 'Scorched Gamma Boss', description: 'Scorched Earth boss equipment', enabled: true, starterEnabled: false, revision: 1, items: [{ itemKey: 'gfi:Stone', name: 'Stone', quantity: 30, quality: 0, blueprint: false }] },
  ];
  const status = {
    ready: true, clusterName: 'Evolution test cluster', discord: { enabled: false, ready: false },
    servers: projection.settings.servers.map(server => ({ serverId: server.id, serverName: server.name, connected: server.enabled, playerCount: server.enabled ? 2 : 0, players: server.enabled ? [{ name: 'River Survivor' }, { name: 'Sky Survivor' }] : [], lastLatencyMs: 3, lastSuccessAt: Date.now(), lastPlayerRefreshAt: Date.now(), profileImport: { enabled: false } })),
  };
  packages[0].grouping = { category: 'general', map: '', boss: '', tier: '' };
  packages[1].grouping = { category: 'boss', map: 'The Island', boss: 'Broodmother', tier: 'alpha' };
  packages[2].grouping = { category: 'boss', map: 'Scorched Earth', boss: 'Manticore', tier: 'gamma' };
  if (options.statusTransform) options.statusTransform(status);
  return { projection, packages, status };
}

async function dashboard(t, options = {}) {
  const context = await browser.newContext({ viewport: options.viewport || { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
  t.after(() => context.close());
  const page = await context.newPage();
  if (options.clock) await page.clock.install();
  page.setDefaultTimeout(7000);
  const errors = []; const requests = []; const unexpected = [];
  let { projection, packages, status } = fixtures(options);
  let bootstrapCount = 0;
  let failBootstrap = false;
  page.on('pageerror', error => errors.push(error.message));
  t.after(() => { assert.deepEqual(errors, [], 'no runtime errors'); assert.deepEqual(unexpected, [], 'no unintended API access'); });
  await page.route('**/*', async route => {
    const request = route.request(); const url = new URL(request.url());
    const json = (body, code = 200) => route.fulfill({ status: code, contentType: 'application/json', body: JSON.stringify(body) });
    if (url.pathname === '/dashboard') return route.fulfill({ contentType: 'text/html', body: DASHBOARD_HTML });
    if (url.pathname === '/dashboard-client.js') return route.fulfill({ contentType: 'text/javascript', body: client });
    if (url.pathname === '/dashboard.css') return route.fulfill({ contentType: 'text/css', body: css });
    if (url.pathname === '/brand/blcksnake-mark.png') return route.fulfill({ contentType: 'image/png', body: brand });
    if (url.pathname.startsWith('/brand/') || url.pathname === '/favicon.ico') return route.fulfill({ status: 204, body: '' });
    if (url.pathname === '/admin/api/auth-mode') return json({ authenticated: true, remote: false, setupRequired: false });
    if (url.pathname === '/admin/api/bootstrap') {
      bootstrapCount += 1;
      if (failBootstrap) return json({ message: 'Status temporarily unavailable' }, 503);
      return json({ session: { username: 'EvolutionAdmin', role: options.role || 'admin', csrfToken: 'synthetic-evolution-csrf', mustChangePassword: false, recentAuthenticationExpiresAt: Date.now() + 60_000 }, status, capabilities: { actions: ['announce', 'save-world', 'restart'], packages, announcementMaxLength: 400 } });
    }
    if (url.pathname === '/admin/api/settings' && request.method() === 'GET') {
      if (options.role === 'moderator') { unexpected.push('Moderator requested settings'); return json({ message: 'Forbidden' }, 403); }
      return json(projection);
    }
    if (url.pathname === '/admin/api/settings' && request.method() === 'PUT') {
      const body = request.postDataJSON(); requests.push({ path: url.pathname, method: request.method(), body });
      if (options.failSettingsSave) return json({ message: 'Settings changed elsewhere; reload before retrying.', code: 'REVISION_CONFLICT' }, 409);
      projection = { ...projection, revision: projection.revision + 1, restartRequired: true, settings: body.settings || body };
      projection.settings.servers = projection.settings.servers.map(server => ({ ...server, passwordConfigured: true }));
      return json(projection);
    }
    if (url.pathname === '/admin/api/players') return json({ players: [] });
    if (url.pathname === '/admin/api/activity') return json({ activity: [] });
    unexpected.push(`${request.method()} ${url.pathname}`);
    return json({ message: 'Unexpected fixture request' }, 404);
  });
  await page.goto(`http://127.0.0.1/dashboard#${options.role === 'moderator' ? 'overview' : 'settings'}`);
  if (options.role !== 'moderator') {
    try { await expect(page.locator('#settings-cluster-name')).toHaveValue('Evolution test cluster'); }
    catch (error) { t.diagnostic(await page.locator('body').innerText()); throw error; }
  }
  else await expect(page.locator('#operator-name')).toHaveText('EvolutionAdmin');
  return { page, requests, status, bootstrapCount: () => bootstrapCount, failBootstrap: () => { failBootstrap = true; } };
}

async function screenshot(page, name) {
  await fs.mkdir(new URL('../reports/ux2/', import.meta.url), { recursive: true });
  await page.screenshot({ path: fileURLToPath(new URL(`../reports/ux2/${name}.png`, import.meta.url)) });
}

async function section(page, name) {
  await page.locator(`[data-settings-jump="settings-${name}"]`).click();
  await expect(page.locator(`#settings-${name}`)).toBeVisible();
  const bulk = page.locator(`#settings-${name}`).locator('details.bulk-workspace');
  if (await bulk.count() && !(await bulk.evaluate(node => node.open))) await bulk.locator('summary').click();
}

test('map bulk selection drops hidden rows and stages only the visible selection', async t => {
  const { page, requests } = await dashboard(t);
  await section(page, 'maps');
  await page.locator('#settings-map-bulk-select-visible').click();
  await expect(page.locator('[data-map-select]:checked')).toHaveCount(3);
  await screenshot(page, 'bulk-maps-desktop');
  await page.locator('#settings-map-search').fill('island');
  await expect(page.locator('[data-map-select]:checked')).toHaveCount(1);
  await page.locator('#settings-map-bulk-disable').click();
  const island = page.locator('[data-settings-server]').first();
  await expect(island.locator('[data-setting-field="enabled"]')).not.toBeChecked();
  await page.locator('#settings-map-clear').click();
  await expect(page.locator('[data-settings-server]').nth(2).locator('[data-setting-field="enabled"]')).toBeChecked();
  assert.equal(requests.length, 0, 'bulk stage must not write HTTP settings');
  await expect(page.locator('#settings-change-bar')).toBeVisible();
  await page.locator('#settings-review').click();
  await page.locator('#settings-apply').click();
  await expect(page.locator('#settings-review-dialog')).toBeHidden();
  assert.equal(requests.length, 1);
  assert.equal(requests[0].body.expectedRevision, 1);
  assert.deepEqual(requests[0].body.settings.servers.map(server => [server.id, server.enabled]), [['island', false], ['scorched', false], ['center', true]]);
});

test('map bulk removal confirms the count and retains unrelated map drafts', async t => {
  const { page, requests } = await dashboard(t);
  await section(page, 'maps');
  const center = page.locator('[data-settings-server]').nth(2);
  const removed = page.locator('[data-settings-server]').first();
  await removed.locator('.settings-editor-toggle').click();
  const removedSecret = removed.locator('[data-setting-field="password"]');
  await removedSecret.fill('Synthetic displayed secret for removal test');
  const removedSecretHandle = await removedSecret.elementHandle();
  await removed.locator('.password-toggle').first().click();
  await expect(removedSecret).toHaveAttribute('type', 'text');
  await center.locator('.settings-editor-toggle').click();
  await center.locator('[data-setting-field="name"]').fill('Center retained draft');
  await page.locator('[data-map-select]').first().check();
  page.once('dialog', async dialog => { assert.match(dialog.message(), /1/); await dialog.dismiss(); });
  await page.locator('#settings-map-bulk-remove').click();
  await expect(page.locator('[data-settings-server]')).toHaveCount(3);
  page.once('dialog', async dialog => { assert.match(dialog.message(), /1/); await dialog.accept(); });
  await page.locator('#settings-map-bulk-remove').click();
  await expect(page.locator('[data-settings-server]')).toHaveCount(2);
  assert.equal(await removedSecretHandle.evaluate(input => input.value), '', 'detached visible-password input must be cleared');
  assert.equal(await removedSecretHandle.evaluate(input => input.type), 'password', 'removed secret must revert to password type');
  await expect(page.locator('[data-settings-server]').last().locator('[data-setting-field="name"]')).toHaveValue('Center retained draft');
  assert.equal(requests.length, 0);
});

test('template bulk categories preserve messages and clear filtered-out selections', async t => {
  const { page, requests } = await dashboard(t);
  await section(page, 'templates');
  await page.locator('#settings-template-bulk-select-visible').click();
  await page.locator('#settings-template-category').selectOption('community');
  await expect(page.locator('[data-template-select]:checked')).toHaveCount(1);
  await page.locator('#settings-template-bulk-category').selectOption('events');
  await page.locator('#settings-template-bulk-apply').click();
  await expect(page.locator('[data-template-select]:checked')).toHaveCount(0);
  await page.locator('#settings-template-clear').click();
  const rows = page.locator('[data-settings-template]');
  await expect(rows.first().locator('[data-template-field="message"]')).toHaveValue('Welcome survivors!');
  await expect(rows.first().locator('[data-template-field="category"]')).toHaveValue('events');
  await expect(rows.last().locator('[data-template-field="category"]')).toHaveValue('maintenance');
  assert.equal(requests.length, 0);
});

test('template bulk deletion can be canceled and confirms before removing drafts', async t => {
  const { page, requests } = await dashboard(t);
  await section(page, 'templates');
  await page.locator('#settings-template-bulk-select-visible').click();
  page.once('dialog', async dialog => { assert.match(dialog.message(), /2/); await dialog.dismiss(); });
  await page.locator('#settings-template-bulk-delete').click();
  await expect(page.locator('[data-settings-template]')).toHaveCount(2);
  page.once('dialog', async dialog => { assert.match(dialog.message(), /2/); await dialog.accept(); });
  await page.locator('#settings-template-bulk-delete').click();
  await expect(page.locator('[data-settings-template]')).toHaveCount(0);
  await expect(page.locator('#settings-template-bulk-delete')).toBeDisabled();
  assert.equal(requests.length, 0);
});

test('cross-section search reveals matching draft templates and restores focus on Escape', async t => {
  const { page, requests } = await dashboard(t);
  await section(page, 'templates');
  const first = page.locator('[data-settings-template]').first();
  await first.locator('.settings-editor-toggle').click();
  await first.locator('[data-template-field="message"]').fill('Unique comet celebration draft');
  await page.locator('#settings-template-category').selectOption('maintenance');
  await section(page, 'general');
  await page.locator('#command-search-open').click();
  await expect(page.locator('#command-search-input')).toBeFocused();
  await page.locator('#command-search-input').fill('comet celebration');
  await expect(page.locator('#command-search-results')).toContainText('Welcome');
  await page.locator('#command-search-results button').filter({ hasText: 'Welcome' }).click();
  await expect(page.locator('#command-search-dialog')).toBeHidden();
  await expect(first).toBeVisible();
  await expect(first.locator('[data-template-field="message"]')).toHaveValue('Unique comet celebration draft');
  assert.equal(requests.length, 0);
  await page.locator('#command-search-open').click();
  await page.locator('#command-search-input').fill('Discord');
  await page.locator('#command-search-results button').filter({ hasText: 'Discord' }).first().click();
  await expect(page.locator('#settings-discord')).toBeVisible();
  await expect(first.locator('[data-template-field="message"]')).toHaveValue('Unique comet celebration draft');
  await page.locator('#command-search-open').click();
  await screenshot(page, 'search-desktop');
  await page.setViewportSize({ width: 390, height: 900 });
  await screenshot(page, 'search-mobile-390');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.keyboard.press('Escape');
  await expect(page.locator('#command-search-open')).toBeFocused();
  await page.keyboard.press('Control+k');
  await expect(page.locator('#command-search-dialog')).toBeVisible();
  await page.keyboard.press('Escape');
});

test('moderator search excludes private settings destinations and private fields', async t => {
  const { page, requests } = await dashboard(t, { role: 'moderator' });
  await page.locator('#command-search-open').click();
  await expect(page.locator('#command-search-results')).not.toContainText('Map servers');
  await expect(page.locator('#command-search-results')).not.toContainText('Broadcast templates');
  await expect(page.locator('#command-search-results')).not.toContainText('Discord');
  await expect(page.locator('#command-search-results')).not.toContainText('Security');
  await page.locator('#command-search-input').fill('127.0.0.1');
  await expect(page.locator('#command-search-results button')).toHaveCount(0);
  await page.locator('#command-search-input').fill('synthetic-evolution-csrf');
  await expect(page.locator('#command-search-results button')).toHaveCount(0);
  await page.keyboard.press('Escape');
  await page.setViewportSize({ width: 390, height: 900 });
  await expect(page.locator('[data-quick-action="maps"]')).toBeHidden();
  assert.equal(requests.length, 0);
});

test('mobile quick actions coexist with dirty drafts without horizontal overflow', async t => {
  const { page, requests } = await dashboard(t);
  await section(page, 'maps');
  await page.locator('[data-map-select]').first().check();
  await page.locator('#settings-map-bulk-disable').click();
  for (const width of [320, 390, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    const overflow = await page.evaluate(() => ({
      viewport: innerWidth, document: document.documentElement.scrollWidth,
      elements: Array.from(document.body.querySelectorAll('*')).filter(node => {
        const rect = node.getBoundingClientRect();
        return rect.width && rect.right > innerWidth + 1;
      }).slice(0, 12).map(node => ({ tag: node.tagName, id: node.id, className: node.className, right: node.getBoundingClientRect().right })),
    }));
    assert.ok(overflow.document <= overflow.viewport + 1, `no horizontal overflow at ${width}px: ${JSON.stringify(overflow)}`);
    assert.ok(await page.locator('#settings-review').evaluate(node => {
      const button = node.getBoundingClientRect();
      const bar = node.closest('#settings-change-bar').getBoundingClientRect();
      return button.right <= bar.right && node.scrollWidth <= node.clientWidth + 1;
    }), 'review label wraps inside its action bar without clipping');
    if (width <= 390) {
      const quick = page.locator('#mobile-quick-actions');
      await expect(quick).toBeVisible();
      await expect.poll(async () => {
        const quickBounds = await quick.boundingBox(); const dirtyBounds = await page.locator('#settings-change-bar').boundingBox();
        return Boolean(quickBounds && dirtyBounds && (quickBounds.y + quickBounds.height <= dirtyBounds.y + 1 || dirtyBounds.y + dirtyBounds.height <= quickBounds.y + 1));
      }, { message: 'quick actions and dirty bar settle without overlap after viewport resize' }).toBe(true);
      const quickRect = await quick.boundingBox(); const dirtyRect = await page.locator('#settings-change-bar').boundingBox();
      const separated = quickRect && dirtyRect && (quickRect.y + quickRect.height <= dirtyRect.y + 1 || dirtyRect.y + dirtyRect.height <= quickRect.y + 1);
      if (!separated) {
        await fs.mkdir(new URL('../reports/ux2/', import.meta.url), { recursive: true });
        await page.screenshot({ path: fileURLToPath(new URL(`../reports/ux2/overlap-${width}.png`, import.meta.url)) });
        t.diagnostic(JSON.stringify({ quickRect, dirtyRect, styles: await page.locator('#settings-change-bar').evaluate(node => ({ bottom: getComputedStyle(node).bottom, position: getComputedStyle(node).position })) }));
      }
      assert.ok(separated, 'quick actions and dirty bar must not overlap');
      if (await page.locator('.toast-region .toast').count()) {
        await expect.poll(async () => {
          const toast = await page.locator('.toast-region').boundingBox(); const dirty = await page.locator('#settings-change-bar').boundingBox();
          return Boolean(toast && dirty && toast.y + toast.height <= dirty.y + 1);
        }, { message: 'status toast must appear above dirty actions on mobile' }).toBe(true);
      }
      await page.locator('[data-quick-action="search"]').click();
      await expect(page.locator('#command-search-dialog')).toBeVisible();
      const rect = await page.locator('#command-search-dialog').boundingBox();
      assert.ok(rect && rect.x >= -1 && rect.x + rect.width <= width + 1);
      await page.keyboard.press('Escape');
      await page.locator('[data-quick-action="maps"]').click();
      await expect(page.locator('#settings-maps')).toBeVisible();
      await screenshot(page, `bulk-maps-mobile-${width}`);
    }
  }
  assert.equal(requests.length, 0);
});

test('maximum collections support bulk selection and cross-section search without rebuilding map drafts', async t => {
  const { page, requests } = await dashboard(t, { largeCollection: true });
  await section(page, 'maps');
  const first = page.locator('[data-settings-server]').first();
  await first.evaluate(node => { node.dataset.evolutionIdentity = 'retained'; });
  const elapsed = await page.locator('#settings-map-bulk-select-visible').evaluate(button => { const start = performance.now(); button.click(); return performance.now() - start; });
  await expect(page.locator('[data-map-select]:checked')).toHaveCount(64);
  assert.ok(elapsed < 1000, `64-map bulk selection completes within one second: ${elapsed.toFixed(1)}ms`);
  await page.locator('#command-search-open').click();
  await page.locator('#command-search-input').fill('Message number 31');
  await expect(page.locator('#command-search-results')).toContainText('Template 31');
  await page.keyboard.press('Escape');
  await expect(first).toHaveAttribute('data-evolution-identity', 'retained');
  assert.equal(requests.length, 0);
  t.diagnostic(`64-map selection event: ${elapsed.toFixed(1)}ms`);
});

test('health distinguishes recent, stale, missing, and disconnected observations', async t => {
  const { page, status, requests } = await dashboard(t, { statusTransform(status) {
    status.servers[2].lastPlayerRefreshAt = Date.now() - 180_000;
  } });
  await page.locator('[data-tab="overview"]').click();
  const island = page.locator('[data-overview-map="island"]');
  const center = page.locator('[data-overview-map="center"]');
  await expect(island.locator('.map-health-badge')).toHaveText('Healthy');
  await expect(page.locator('[data-overview-map="scorched"] .map-health-badge')).toHaveText('Offline');
  await expect(center.locator('.map-health-badge')).toHaveText('Needs attention');
  await expect(center.locator('.map-health-detail')).toContainText('stale');
  await expect(page.locator('#player-insights')).toContainText('last observed');
  await expect(page.locator('#player-insights')).toContainText('2 maps');
  await screenshot(page, 'health-desktop');
  await page.setViewportSize({ width: 390, height: 900 });
  await island.scrollIntoViewIfNeeded();
  await screenshot(page, 'health-mobile-390');
  await page.setViewportSize({ width: 1440, height: 1000 });
  status.servers[0].lastPlayerRefreshAt = null;
  status.servers[0].playerCount = null;
  status.servers[2].connected = undefined;
  const response = page.waitForResponse(response => new URL(response.url()).pathname === '/admin/api/bootstrap');
  await page.locator('#refresh-button').click(); await response;
  await expect(island.locator('.map-health-badge')).toHaveText('Unknown');
  await expect(center.locator('.map-health-badge')).toHaveText('Unknown');
  await expect(island.locator('.map-health-detail')).toContainText('unavailable');
  assert.equal(requests.length, 0);
});

test('changed telemetry refresh updates health while retaining disclosure, focus, and settings drafts', async t => {
  const { page, status } = await dashboard(t);
  await page.locator('[data-tab="overview"]').click();
  const card = page.locator('[data-overview-map="island"]');
  await card.locator('.map-diagnostics summary').click();
  const scroll = await page.evaluate(() => window.scrollY);
  status.servers[0].consecutiveFailures = 2;
  status.servers[0].playerCount = 5;
  const refresh = page.waitForResponse(response => new URL(response.url()).pathname === '/admin/api/bootstrap');
  await page.evaluate(() => document.querySelector('#refresh-button').click()); await refresh;
  await expect(card.locator('.map-health-badge')).toHaveText('Needs attention');
  await expect(card.locator('.map-health-detail')).toContainText('failures');
  await expect(card.locator('.map-diagnostics')).toHaveAttribute('open', '');
  await expect(card.locator('.map-diagnostics summary')).toBeFocused();
  assert.ok(Math.abs(await page.evaluate(() => window.scrollY) - scroll) <= 1);
  await page.locator('[data-tab="settings"]').click();
  await expect(page.locator('#settings-cluster-name')).toHaveValue('Evolution test cluster');
  await section(page, 'maps');
  const draft = page.locator('[data-settings-server]').first();
  await draft.locator('.settings-editor-toggle').click();
  await draft.locator('[data-setting-field="name"]').fill('Unsaved Island name');
  await draft.evaluate(node => { node.dataset.evolutionIdentity = 'retained-health'; });
  status.servers[0].playerCount = 8;
  const draftRefresh = page.waitForResponse(response => new URL(response.url()).pathname === '/admin/api/bootstrap');
  await page.evaluate(() => document.querySelector('#refresh-button').click()); await draftRefresh;
  await expect(draft.locator('[data-setting-field="name"]')).toHaveValue('Unsaved Island name');
  await expect(draft).toHaveAttribute('data-evolution-identity', 'retained-health');
});

test('package grouping preserves flat defaults, shared grants, disclosures, and edit navigation', async t => {
  const { page, requests } = await dashboard(t);
  await section(page, 'packages');
  await expect(page.locator('#settings-package-group')).toHaveValue('none');
  await expect(page.locator('.settings-package-row:visible')).toHaveCount(3);
  await page.locator('#settings-package-filter').selectOption('shared');
  await expect(page.locator('.settings-package-row:visible')).toHaveCount(3);
  await page.locator('#settings-package-group').selectOption('map');
  await expect(page.locator('details.package-group')).toHaveCount(3);
  const islandGroup = page.locator('details.package-group').filter({ hasText: 'Island Alpha Boss' });
  if (!(await islandGroup.evaluate(node => node.open))) await islandGroup.locator('summary').click();
  await expect(islandGroup.locator('[data-edit-package="boss-alpha"]')).toBeVisible();
  await screenshot(page, 'grouping-desktop');
  await page.setViewportSize({ width: 390, height: 900 });
  await islandGroup.scrollIntoViewIfNeeded();
  await screenshot(page, 'grouping-mobile-390');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await islandGroup.locator('summary').focus();
  await islandGroup.evaluate(node => { node.dataset.evolutionIdentity = 'package-retained'; });
  const refresh = page.waitForResponse(response => new URL(response.url()).pathname === '/admin/api/bootstrap');
  await page.evaluate(() => document.querySelector('#refresh-button').click()); await refresh;
  await expect(islandGroup).toHaveAttribute('open', '');
  await expect(islandGroup).toHaveAttribute('data-evolution-identity', 'package-retained');
  await expect(islandGroup.locator('summary')).toBeFocused();
  await page.locator('#settings-package-group').selectOption('tier');
  await expect(page.locator('details.package-group').filter({ hasText: 'Island Alpha Boss' }).locator('summary')).toContainText('Alpha');
  await page.locator('#settings-package-search').fill('Gamma');
  await expect(page.locator('.settings-package-row:visible')).toHaveCount(1);
  await page.locator('[data-edit-package="boss-gamma"]').click();
  await expect(page.locator('#item-package-dialog')).toBeVisible();
  await expect(page.locator('#item-package-name')).toHaveValue('Scorched Gamma Boss');
  await page.keyboard.press('Escape');
  assert.equal(requests.length, 0);
});

test('bulk settings retain drafts on revision conflict and reveal invalid fields before review', async t => {
  const { page, requests } = await dashboard(t, { failSettingsSave: true });
  await section(page, 'maps');
  const first = page.locator('[data-settings-server]').first();
  await first.locator('.settings-editor-toggle').click();
  await first.locator('[data-setting-field="name"]').fill('');
  await first.locator('.settings-editor-toggle').click();
  await page.locator('#settings-map-bulk-select-visible').click();
  await page.locator('#settings-map-bulk-disable').click();
  await section(page, 'general');
  await page.locator('#settings-review').click();
  await expect(first.locator('[data-setting-field="name"]')).toBeFocused();
  await expect(page.locator('#settings-review-dialog')).toBeHidden();
  await first.locator('[data-setting-field="name"]').fill('Island edited draft');
  await page.locator('#settings-review').click();
  await page.locator('#settings-apply').click();
  await expect(page.locator('#settings-review-error')).toContainText('changed elsewhere');
  await expect(first.locator('[data-setting-field="name"]')).toHaveValue('Island edited draft');
  await expect(first.locator('[data-setting-field="enabled"]')).not.toBeChecked();
  assert.equal(requests.length, 1);
  assert.equal(requests[0].body.expectedRevision, 1);
});

test('search renders draft display text safely and does not index entered credentials', async t => {
  const { page, requests } = await dashboard(t);
  await section(page, 'maps');
  const first = page.locator('[data-settings-server]').first();
  await first.locator('.settings-editor-toggle').click();
  await first.locator('[data-setting-field="password"]').fill('Private credential must remain unsearchable');
  await section(page, 'templates');
  const row = page.locator('[data-settings-template]').first();
  await row.locator('.settings-editor-toggle').click();
  await row.locator('[data-template-field="message"]').fill('<img src=x onerror="window.evolutionUnsafe=true"> safe test');
  await page.locator('#command-search-open').click();
  await page.locator('#command-search-input').fill('Private credential');
  await expect(page.locator('#command-search-results button')).toHaveCount(0);
  await page.locator('#command-search-input').fill('safe test');
  await expect(page.locator('#command-search-results')).toContainText('Welcome');
  await expect(page.locator('#command-search-results img')).toHaveCount(0);
  assert.equal(await page.evaluate(() => window.evolutionUnsafe), undefined);
  assert.equal(requests.length, 0);
});

test('status transport loss marks health unknown without replacing the inspected map', async t => {
  const fixture = await dashboard(t, { clock: true });
  const { page } = fixture;
  await page.locator('[data-tab="overview"]').click();
  const card = page.locator('[data-overview-map="island"]');
  await card.locator('.map-diagnostics summary').click();
  await card.evaluate(node => { node.dataset.evolutionIdentity = 'transport-retained'; });
  fixture.failBootstrap();
  await page.clock.fastForward(26_000);
  await expect(card.locator('.map-health-badge')).toHaveText('Unknown');
  await expect(card.locator('.map-health-detail')).toContainText('Dashboard status is stale');
  await expect(card).toHaveAttribute('data-evolution-identity', 'transport-retained');
  await expect(card.locator('.map-diagnostics')).toHaveAttribute('open', '');
  await expect(card.locator('.map-diagnostics summary')).toBeFocused();
  await expect(page.locator('#player-insights')).toContainText('stale');
});

test('map player shortcuts scope the existing view and mobile navigation protects unsaved drafts', async t => {
  const { page, requests } = await dashboard(t, { viewport: { width: 390, height: 900 } });
  await page.locator('[data-quick-action="players"]').click();
  await expect(page.locator('#panel-players')).toBeVisible();
  await page.locator('[data-quick-action="operations"]').click();
  await expect(page.locator('#panel-operations')).toBeVisible();
  await page.locator('[data-quick-action="search"]').click();
  await page.locator('#command-search-input').fill('Overview');
  await page.keyboard.press('ArrowDown');
  await expect(page.locator('#command-search-results button').first()).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#panel-overview')).toBeVisible();
  await page.locator('[data-overview-map="island"] [data-map-players]').click();
  await expect(page.locator('#panel-players')).toBeVisible();
  await expect(page.locator('#server-scope')).toHaveValue('island');
  await expect(page.locator('#player-search')).toBeFocused();
  await page.locator('[data-quick-action="maps"]').click();
  await expect(page.locator('#settings-maps')).toBeVisible();
  await expect(page.locator('[data-map-select]').first()).toHaveAccessibleName(/The Island/);
  await page.locator('[data-map-select]').first().check();
  await page.locator('#settings-map-bulk-disable').click();
  page.once('dialog', async dialog => { assert.match(dialog.message(), /unsaved settings/); await dialog.dismiss(); });
  await page.locator('[data-quick-action="players"]').click();
  await expect(page.locator('#settings-maps')).toBeVisible();
  await expect(page.locator('[data-settings-server]').first().locator('[data-setting-field="enabled"]')).not.toBeChecked();
  assert.equal(requests.length, 0);
});
