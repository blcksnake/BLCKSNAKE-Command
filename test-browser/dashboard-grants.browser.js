import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { chromium, expect } from '@playwright/test';
import { DASHBOARD_HTML } from '../src/http/dashboard.js';

// Actual shipped HTML, CSS, and client. All HTTP is intercepted; no live grants.
const client = await fs.readFile(new URL('../src/http/dashboard-client.js', import.meta.url), 'utf8');
const css = await fs.readFile(new URL('../src/http/dashboard.css', import.meta.url), 'utf8');
const brand = await fs.readFile(new URL('../src/http/assets/blcksnake-mark.png', import.meta.url));
let browser;
before(async () => { browser = await chromium.launch({ headless: true }); });
after(async () => { await browser?.close(); });

const catalog = Array.from({ length: 240 }, (_, index) => ({
  key: `gfi:Fixture${index}`, name: `Catalog supply ${String(index).padStart(3, '0')}`,
  category: index % 2 ? 'Resources' : 'Equipment', gfi: `Fixture${index}`, itemNumber: null,
  blueprintPath: `Blueprint'/Game/Test/Fixture${index}.Fixture${index}'`, editions: ['asa', 'ase'],
}));
catalog[0] = { ...catalog[0], key: 'gfi:Stone', name: 'Stone', gfi: 'Stone', category: 'Resources' };
catalog[1] = { ...catalog[1], key: 'gfi:Wood', name: 'Wood', gfi: 'Wood', category: 'Resources' };
const packageFixtures = [
  { id: 'starter', name: 'Starter: Essential supplies', grouping: { category: 'starter', map: '', boss: '', tier: '' }, gameEdition: 'both' },
  { id: 'nunatak', name: 'Boss: Ragnarok - Nunatak - Standard', grouping: { category: 'boss', map: 'Ragnarok', boss: 'Nunatak', tier: 'standard' }, gameEdition: 'asa' },
  { id: 'ragnarok-alpha', name: 'Boss: Ragnarok - Manticore - Alpha', grouping: { category: 'boss', map: 'Ragnarok', boss: 'Manticore', tier: 'alpha' }, gameEdition: 'both' },
  { id: 'island-gamma', name: 'Boss: The Island - Broodmother - Gamma', grouping: { category: 'boss', map: 'The Island', boss: 'Broodmother', tier: 'gamma' }, gameEdition: 'both' },
].map((entry, index) => ({ ...entry, description: `${entry.name} fixture supplies`, enabled: true, starterEnabled: index === 0, revision: 1,
  compatibility: { games: entry.gameEdition === 'asa' ? ['ASA'] : ['ASA', 'ASE'], mapNames: entry.grouping.map ? [entry.grouping.map] : [], verified: true, recipeVerified: index === 1 },
  items: [{ itemKey: catalog[index].key, name: catalog[index].name, quantity: 10 + index, quality: 0, blueprint: false }],
}));

async function dashboard(t, options = {}) {
  const context = await browser.newContext({ viewport: options.viewport || { width: 1280, height: 960 }, reducedMotion: 'reduce' });
  t.after(() => context.close());
  const page = await context.newPage();
  if (options.clock) await page.clock.install();
  page.setDefaultTimeout(6000);
  const errors = []; const unexpected = []; const requests = []; const itemRequests = []; const preferenceRequests = [];
  let favorites = []; let recent = options.recent || [];
  let holdQuery = ''; let heldResponse; let rejectQuery = '';
  const servers = [
    { serverId: 'Ragnarok_WP', serverName: 'Ragnarok ASA', connected: true, playerCount: 1, lastPlayerRefreshAt: Date.now(), gameContext: { game: 'ASA', mapName: 'Ragnarok', mapId: 'Ragnarok_WP', source: 'server-id' } },
    { serverId: 'TheIsland', serverName: 'The Island ASE', connected: true, playerCount: 1, lastPlayerRefreshAt: Date.now(), gameContext: { game: 'ASE', mapName: 'The Island', mapId: 'TheIsland', source: 'server-id' } },
  ];
  const players = servers.map((server, index) => ({ selection: `player-fixture-${index}`, name: index ? 'ASE Survivor' : 'ASA Survivor', survivorName: index ? 'Island Survivor' : 'Ragnarok Survivor', serverId: server.serverId, serverName: server.serverName, targeting: 'ready' }));
  page.on('pageerror', error => errors.push(error.message));
  t.after(() => { assert.deepEqual(errors, [], 'no client runtime errors'); assert.deepEqual(unexpected, [], 'no unintended API requests'); });
  await page.route('**/*', async route => {
    const request = route.request(); const url = new URL(request.url());
    const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    if (url.pathname === '/dashboard') return route.fulfill({ contentType: 'text/html', body: DASHBOARD_HTML });
    if (url.pathname === '/dashboard-client.js') return route.fulfill({ contentType: 'text/javascript', body: client });
    if (url.pathname === '/dashboard.css') return route.fulfill({ contentType: 'text/css', body: css });
    if (url.pathname === '/brand/blcksnake-mark.png') return route.fulfill({ contentType: 'image/png', body: brand });
    if (url.pathname.startsWith('/brand/') || url.pathname === '/favicon.ico') return route.fulfill({ status: 204, body: '' });
    if (url.pathname === '/admin/api/auth-mode') return json({ authenticated: true, remote: false, setupRequired: false });
    if (url.pathname === '/admin/api/bootstrap') return json({ session: { username: 'GrantTester', role: 'admin', csrfToken: 'synthetic-grant-test', mustChangePassword: false, recentAuthenticationExpiresAt: Date.now() + 60_000 }, status: { ready: true, clusterName: 'Grant QA', discord: { enabled: false }, servers }, capabilities: { actions: ['give-item', 'give-package', 'player', 'give-cart'], packages: packageFixtures } });
    if (url.pathname === '/admin/api/players') return json({ players });
    if (url.pathname === '/admin/api/activity') return json({ activity: [] });
    if (url.pathname === '/admin/api/item-preferences') {
      if (request.method() === 'PUT') {
        const body = request.postDataJSON(); preferenceRequests.push(body);
        favorites = favorites.filter(item => item.key !== body.itemKey);
        if (body.favorite) favorites.push(catalog.find(item => item.key === body.itemKey));
      }
      return json({ ok: true, favorites, recent });
    }
    if (url.pathname === '/admin/api/items') {
      const query = url.searchParams.get('q') || '';
      itemRequests.push({ query, url: url.toString() });
      if (query === holdQuery && holdQuery) await new Promise(resolve => { heldResponse = resolve; });
      if (query === rejectQuery && rejectQuery) return json({ message: 'Synthetic catalog failure' }, 503);
      const items = catalog.filter(item => !query || `${item.name} ${item.gfi} ${item.category}`.toLowerCase().includes(query.toLowerCase()));
      return json({ items, total: items.length, hasMore: false });
    }
    if (url.pathname === '/admin/api/actions/preview') {
      const body = request.postDataJSON(); requests.push({ path: url.pathname, body });
      if (options.failPreview) return json({ message: 'The target disconnected; select a current player.' }, 409);
      const grantLines = [...body.options.items.map(entry => ({ ...entry, name: catalog.find(item => item.key === entry.itemKey)?.name })), ...body.options.packages.flatMap(entry => packageFixtures.find(item => item.id === entry.packageId).items.map(item => ({ ...item, sourcePackageName: packageFixtures.find(value => value.id === entry.packageId).name })))];
      return json({ confirmationToken: 'synthetic-confirmation', expiresAt: Date.now() + 60_000, risk: 'medium', summary: { title: 'Review grant', details: [JSON.stringify(body.options)] }, grantLines });
    }
    if (url.pathname === '/admin/api/actions/execute') {
      const body = request.postDataJSON(); requests.push({ path: url.pathname, body, key: request.headers()['idempotency-key'] });
      const grantResults = body.options.items.map((entry, index) => ({ ...entry, name: catalog.find(item => item.key === entry.itemKey)?.name, outcome: options.failExecute ? (index ? 'not-sent' : 'uncertain') : 'sent' }));
      if (options.failExecute) return json({ message: 'Synthetic uncertain grant outcome', outcome: 'uncertain', grantResults }, 503);
      recent = body.options.items.map(entry => catalog.find(item => item.key === entry.itemKey));
      return json({ ok: true, outcome: 'succeeded', operationId: 'grant-fixture-operation', message: 'Fixture grant completed.', grantResults });
    }
    unexpected.push(`${request.method()} ${url.pathname}`);
    return json({ message: 'Unexpected fixture request' }, 404);
  });
  await page.goto('http://127.0.0.1/dashboard#operations');
  await expect(page.locator('#operator-name')).toHaveText('GrantTester');
  return { page, requests, itemRequests, preferenceRequests, players, hold(query) { holdQuery = query; }, release() { holdQuery = ''; heldResponse?.(); }, fail(query) { rejectQuery = query; } };
}

async function openGrant(page, action = 'give-item') {
  await page.locator(`#operation-groups [data-open-action="${action}"]`).click();
  await expect(page.locator('#action-dialog')).toBeVisible();
  await page.locator('#action-dialog [data-option="player"]').selectOption('player-fixture-0');
}

async function visibleItem(page, name) {
  const search = page.locator('#action-dialog input[role="combobox"]');
  await search.fill(name);
  await expect(page.locator('#action-dialog .combobox-results')).toHaveAttribute('aria-busy', 'false');
  const option = page.locator('#action-dialog .combobox-option').filter({ has: page.locator('strong', { hasText: new RegExp(`^${name}$`) }) });
  await expect(option).toBeVisible();
  return { search, option };
}

async function addItem(page, name, { quantity = 1, quality = 0, blueprint = false } = {}) {
  const { option } = await visibleItem(page, name); await option.click();
  await page.locator('#grant-item-quantity').fill(String(quantity));
  await page.locator('#grant-item-quality').fill(String(quality));
  await page.locator('#grant-item-blueprint').setChecked(blueprint);
  await page.locator('#grant-item-add').click();
}

async function screenshot(page, name) {
  const folder = new URL('../reports/grants/', import.meta.url);
  await fs.mkdir(folder, { recursive: true });
  const { fileURLToPath } = await import('node:url');
  await page.screenshot({ path: fileURLToPath(new URL(`${name}.png`, folder)) });
}

test('rapid item searches debounce without shrinking the modal or replacing the search field', async t => {
  const { page, itemRequests } = await dashboard(t, { clock: true });
  await openGrant(page);
  const search = page.locator('#action-dialog input[role="combobox"]');
  await expect(page.locator('#action-dialog .combobox-option').first()).toBeVisible();
  await search.focus();
  await expect(page.locator('#action-dialog .combobox-results')).toHaveAttribute('aria-busy', 'false');
  await search.evaluate(node => { node.dataset.qaIdentity = 'persistent-search'; });
  // Keep the typing cadence independent of host load and browser RPC latency.
  await page.clock.pauseAt(new Date(Date.now() + 1000));
  itemRequests.length = 0;
  await page.evaluate(() => {
    window.grantBounds = [];
    window.grantSample = setInterval(() => {
      const dialog = document.querySelector('#action-dialog').getBoundingClientRect();
      const list = document.querySelector('#action-dialog .combobox-results').getBoundingClientRect();
      window.grantBounds.push({ top: dialog.top, height: dialog.height, listHeight: list.height });
    }, 10);
  });
  for (const character of 'Stone') {
    await search.press(character);
    await page.clock.runFor(20);
  }
  assert.equal(itemRequests.length, 0, 'the catalog waits until the typing burst ends');
  await page.clock.runFor(250);
  await expect(page.locator('#action-dialog .combobox-option').filter({ hasText: 'Stone' })).toBeVisible();
  await page.clock.runFor(20);
  const bounds = await page.evaluate(() => { clearInterval(window.grantSample); return window.grantBounds; });
  assert.equal(itemRequests.length, 1, 'one catalog request after a typing burst');
  assert.equal(itemRequests[0].query, 'Stone');
  for (const key of ['top', 'height', 'listHeight']) assert.ok(Math.max(...bounds.map(entry => entry[key])) - Math.min(...bounds.map(entry => entry[key])) <= 2, `${key} remains stable during loading/results`);
  await expect(search).toHaveAttribute('data-qa-identity', 'persistent-search');
  await expect(search).toBeFocused();
});

test('an older catalog response cannot replace the current query results', async t => {
  const fixture = await dashboard(t); const { page, itemRequests } = fixture;
  await openGrant(page);
  const search = page.locator('#action-dialog input[role="combobox"]');
  fixture.hold('Stone');
  await search.fill('Stone');
  await expect.poll(() => itemRequests.some(entry => entry.query === 'Stone')).toBe(true);
  await page.evaluate(() => {
    window.staleResultRendered = false;
    const list = document.querySelector('#action-dialog .combobox-results');
    window.staleObserver = new MutationObserver(() => {
      if (document.querySelector('#action-dialog input[role="combobox"]').value === 'Wood'
        && [...list.querySelectorAll('.combobox-option strong')].some(node => node.textContent === 'Stone')) window.staleResultRendered = true;
    });
    window.staleObserver.observe(list, { subtree: true, childList: true, characterData: true });
  });
  await search.fill('Wood');
  fixture.release();
  await expect(page.locator('#action-dialog .combobox-option').filter({ hasText: 'Wood' })).toBeVisible();
  await expect(page.locator('#action-dialog .combobox-option').filter({ hasText: 'Stone' })).toHaveCount(0);
  await expect(search).toHaveValue('Wood');
  await expect(search).toBeFocused();
  assert.equal(await page.evaluate(() => { window.staleObserver.disconnect(); return window.staleResultRendered; }), false, 'an outdated response must never flash during the debounce window');
});

test('player choices and selected option retain DOM identity during unchanged polling', async t => {
  const { page } = await dashboard(t, { clock: true });
  await openGrant(page);
  const player = page.locator('#action-dialog [data-option="player"]');
  await player.focus();
  await player.evaluate(node => { node.dataset.qaIdentity = 'persistent-select'; node.selectedOptions[0].dataset.qaIdentity = 'persistent-option'; });
  const poll = page.waitForResponse(response => response.url().includes('/admin/api/bootstrap'));
  await page.clock.fastForward(16_000); await poll;
  await expect(player).toHaveValue('player-fixture-0');
  await expect(player).toBeFocused();
  await expect(player).toHaveAttribute('data-qa-identity', 'persistent-select');
  await expect(player.locator('option:checked')).toHaveAttribute('data-qa-identity', 'persistent-option');
});

test('large item catalogs mount a bounded window with keyboard access to every result', async t => {
  const { page } = await dashboard(t);
  await openGrant(page);
  const search = page.locator('#action-dialog input[role="combobox"]');
  const results = page.locator('#action-dialog .combobox-results');
  await expect(results.locator('.combobox-option').first()).toBeVisible();
  assert.ok(await results.locator('.combobox-option').count() < 60, 'catalog is virtualized');
  await search.focus();
  const dialogBefore = await page.locator('#action-dialog').boundingBox();
  await search.press('End');
  const active = page.locator('#action-dialog .combobox-option.active');
  await expect(active).toContainText('Catalog supply 239');
  await expect(active).toHaveAttribute('aria-posinset', '240');
  await expect(active).toHaveAttribute('aria-setsize', '240');
  await expect(search).toHaveAttribute('aria-activedescendant', await active.getAttribute('id'));
  await search.press('Enter');
  await expect(search).toHaveValue('Catalog supply 239');
  await expect(page.locator('#action-dialog [data-option="cart-item"]')).toHaveValue('gfi:Fixture239');
  await expect(search).toBeFocused();
  const dialogAfter = await page.locator('#action-dialog').boundingBox();
  assert.ok(Math.abs(dialogBefore.y - dialogAfter.y) <= 2, 'choosing an off-screen item does not move the modal');
  assert.ok(await results.locator('.combobox-option').count() < 60);
});

test('catalog failures show retry inside a stable result pane and recover without losing input', async t => {
  const fixture = await dashboard(t); const { page } = fixture;
  await openGrant(page);
  await expect(page.locator('#action-dialog .combobox-option').first()).toBeVisible();
  const results = page.locator('#action-dialog .combobox-results');
  const before = await results.boundingBox();
  fixture.fail('Wood');
  const search = page.locator('#action-dialog input[role="combobox"]');
  await search.fill('Wood');
  const retry = page.locator('#action-dialog .combobox-retry');
  await expect(retry).toBeVisible();
  await expect(search).toHaveValue('Wood');
  assert.ok(Math.abs(before.height - (await results.boundingBox()).height) <= 2);
  fixture.fail('');
  await retry.click();
  await expect(page.locator('#action-dialog .combobox-option').filter({ hasText: 'Wood' })).toBeVisible();
  await expect(search).toHaveValue('Wood');
});

test('repeating a search preserves virtual row identity and inner scroll position', async t => {
  const { page } = await dashboard(t);
  await openGrant(page);
  const search = page.locator('#grant-item-picker input[role="combobox"]');
  const results = page.locator('#grant-item-picker .combobox-results');
  await search.fill('Catalog'); await expect(results).toHaveAttribute('aria-busy', 'false');
  await search.press('End');
  const last = results.locator('[data-item-key="gfi:Fixture239"]');
  await last.evaluate(node => { node.dataset.qaIdentity = 'retained-result'; });
  const scroll = await results.evaluate(node => node.scrollTop);
  await search.fill('Catalog'); await expect(results).toHaveAttribute('aria-busy', 'false');
  await expect(last).toHaveAttribute('data-qa-identity', 'retained-result');
  assert.ok(Math.abs(await results.evaluate(node => node.scrollTop) - scroll) <= 1);
  await expect(search).toBeFocused();
});

test('multi-item cart retains exact selections through review and Go back without executing', async t => {
  const { page, requests } = await dashboard(t);
  await openGrant(page);
  await addItem(page, 'Stone', { quantity: 12 });
  const first = page.locator('#grant-cart-lines [data-cart-line]').first();
  await first.evaluate(node => { node.dataset.qaIdentity = 'retained-cart-line'; });
  await addItem(page, 'Wood', { quantity: 5, quality: 7, blueprint: true });
  await expect(page.locator('#grant-cart-lines [data-cart-line]')).toHaveCount(2);
  await expect(first).toHaveAttribute('data-qa-identity', 'retained-cart-line');
  await expect(page.locator('#preview-button')).toHaveText('Review cart (2)');
  const body = page.locator('#action-dialog .form-grid');
  const sourceScroll = await body.evaluate(node => { node.scrollTop = 160; return node.scrollTop; });
  assert.ok(sourceScroll > 0, 'review starts from a scrolled cart body');
  await page.locator('#preview-button').click();
  await expect(page.locator('#confirm-dialog')).toBeVisible();
  await expect(page.locator('.grant-review-lines li')).toHaveCount(2);
  assert.deepEqual(requests[0].body, { action: 'give-cart', options: { player: 'player-fixture-0', items: [
    { itemKey: 'gfi:Stone', quantity: 12, quality: 0, blueprint: false },
    { itemKey: 'gfi:Wood', quantity: 5, quality: 7, blueprint: true },
  ], packages: [] } });
  await page.locator('#confirm-dialog .dialog-footer .close-dialog').click();
  await expect(page.locator('#action-dialog')).toBeVisible();
  await expect(first).toHaveAttribute('data-qa-identity', 'retained-cart-line');
  await expect(page.locator('#grant-cart-lines [data-cart-line]')).toHaveCount(2);
  await expect(page.locator('#grant-item-picker input[role="combobox"]')).toHaveValue('Wood');
  await expect(page.locator('#action-dialog [data-option="player"]')).toHaveValue('player-fixture-0');
  await expect.poll(async () => Math.abs(await body.evaluate(node => node.scrollTop) - sourceScroll)).toBeLessThanOrEqual(1);
  await expect(page.locator('#preview-button')).toHaveText('Review cart (2)');
  assert.equal(requests.length, 1, 'review cancellation never executes');
  await screenshot(page, 'cart-desktop');
  const dialogBox = await page.locator('#action-dialog').boundingBox();
  const reviewBox = await page.locator('#preview-button').boundingBox();
  assert.ok(reviewBox.y >= dialogBox.y && reviewBox.y + reviewBox.height <= dialogBox.y + dialogBox.height, 'desktop review button is fully inside the visible modal');
});

test('multi-package cart searches and filters bosses with automatic game and map context', async t => {
  const { page, requests } = await dashboard(t);
  await openGrant(page, 'give-package');
  await expect(page.locator('#grant-context')).toContainText('ASA');
  await expect(page.locator('#grant-context')).toContainText('Ragnarok');
  await page.locator('#grant-package-category').selectOption('boss');
  await expect(page.locator('[data-grant-package]')).toHaveCount(2);
  await page.locator('#grant-package-tier').selectOption('alpha');
  await expect(page.locator('[data-grant-package]')).toHaveCount(1);
  await expect(page.locator('[data-grant-package]')).toHaveAttribute('data-grant-package', 'ragnarok-alpha');
  await expect(page.locator('[data-grant-package="ragnarok-alpha"]')).toContainText('Custom or unverified recipe');
  await page.locator('[data-grant-package="ragnarok-alpha"] button').click();
  await page.locator('#grant-package-tier').selectOption('all');
  await page.locator('#grant-package-search').fill('Nunatak');
  await expect(page.locator('[data-grant-package]')).toHaveCount(1);
  await expect(page.locator('[data-grant-package="nunatak"]')).toContainText('Verified recipe');
  await page.locator('[data-grant-package="nunatak"] button').click();
  await expect(page.locator('[data-grant-package="nunatak"] button')).toBeDisabled();
  await expect(page.locator('#grant-cart-lines [data-cart-line]')).toHaveCount(2);
  await page.locator('#preview-button').click();
  await expect(page.locator('#confirm-dialog')).toBeVisible();
  assert.deepEqual(requests[0].body.options.packages, [{ packageId: 'ragnarok-alpha', revision: 1 }, { packageId: 'nunatak', revision: 1 }]);
  await page.locator('#confirm-dialog .dialog-footer .close-dialog').click();
  await page.locator('#grant-package-search').fill('');
  await page.locator('#action-dialog [data-option="player"]').selectOption('player-fixture-1');
  await expect(page.locator('#grant-context')).toContainText('ASE');
  await expect(page.locator('[data-grant-package]')).toHaveCount(1);
  await expect(page.locator('[data-grant-package]')).toHaveAttribute('data-grant-package', 'island-gamma');
  await expect(page.locator('#grant-cart-message')).toContainText('Player changed');
  await expect(page.locator('#grant-cart-lines [data-cart-line]')).toHaveCount(2);
  await page.locator('#grant-package-map').selectOption('');
  await expect(page.locator('[data-grant-package="nunatak"]')).toHaveCount(0);
  await screenshot(page, 'packages-desktop');
});

test('cart validates quantities, merges identical selections, and can remove or clear staged lines', async t => {
  const { page, requests } = await dashboard(t);
  await openGrant(page);
  await addItem(page, 'Stone', { quantity: 10001 });
  await expect(page.locator('#grant-cart-lines [data-cart-line]')).toHaveCount(0);
  await page.locator('#grant-item-quantity').fill('2'); await page.locator('#grant-item-add').click();
  await page.locator('#grant-item-quantity').fill('3'); await page.locator('#grant-item-add').click();
  await expect(page.locator('#grant-cart-lines [data-cart-line]')).toHaveCount(1);
  await expect(page.locator('#grant-cart-lines')).toContainText('Stone × 5');
  await addItem(page, 'Wood');
  await page.locator('#grant-cart-lines button[aria-label="Remove Stone"]').click();
  await expect(page.locator('#grant-cart-lines [data-cart-line]')).toHaveCount(1);
  await expect(page.locator('#grant-cart-lines')).toContainText('Wood');
  await page.locator('#grant-cart-clear').click();
  await expect(page.locator('#grant-cart-lines [data-cart-line]')).toHaveCount(0);
  await expect(page.locator('#grant-cart-clear')).toBeDisabled();
  await page.locator('#preview-button').click();
  await expect(page.locator('#grant-cart-message')).toContainText('Add at least one');
  assert.equal(requests.length, 0);
});

test('favorite and recent shortcuts filter trusted catalog items and favorites persist across dialogs', async t => {
  const { page, preferenceRequests, requests } = await dashboard(t, { recent: [catalog[1]] });
  await openGrant(page);
  const { option, search } = await visibleItem(page, 'Stone'); await option.click();
  await page.locator('#grant-item-favorite').click();
  await expect(page.locator('#grant-item-favorite')).toHaveAttribute('aria-pressed', 'true');
  assert.deepEqual(preferenceRequests, [{ itemKey: 'gfi:Stone', favorite: true }]);
  await search.fill('');
  await page.locator('#grant-item-scope').selectOption('favorites');
  await expect(page.locator('#grant-item-picker .combobox-option')).toHaveCount(1);
  await expect(page.locator('#grant-item-picker .combobox-option')).toContainText('Stone');
  await page.locator('#grant-item-scope').selectOption('recent');
  await expect(page.locator('#grant-item-picker .combobox-option')).toHaveCount(1);
  await expect(page.locator('#grant-item-picker .combobox-option')).toContainText('Wood');
  await page.locator('#action-dialog .dialog-footer .close-dialog').click();
  await openGrant(page);
  await page.locator('#grant-item-scope').selectOption('favorites');
  await expect(page.locator('#grant-item-picker .combobox-option')).toHaveCount(1);
  await expect(page.locator('#grant-item-picker .combobox-option')).toContainText('Stone');
  assert.equal(requests.length, 0, 'shortcuts do not send game commands');
});

test('successful carts execute once and expose sent outcomes and recent grants', async t => {
  const { page, requests } = await dashboard(t);
  await openGrant(page);
  await addItem(page, 'Stone', { quantity: 3 });
  await addItem(page, 'Wood', { quantity: 4 });
  await page.locator('#preview-button').click();
  await page.locator('#execute-button').click();
  await expect(page.locator('#confirm-dialog-title')).toHaveText('Grant results');
  await expect(page.locator('#operation-summary')).toContainText('Sent: 3');
  await expect(page.locator('#operation-summary')).toContainText('Sent: 4');
  await expect(page.locator('#execute-button')).toBeDisabled();
  assert.equal(requests.length, 2);
  assert.ok(requests[1].key, 'execute has an idempotency key');
  assert.deepEqual(requests[1].body.options, requests[0].body.options);
  await page.locator('#confirm-dialog .dialog-footer .close-dialog').click();
  await openGrant(page);
  await page.locator('#grant-item-scope').selectOption('recent');
  await expect(page.locator('#grant-item-picker .combobox-option')).toHaveCount(2);
  await addItem(page, 'Stone');
  await page.locator('#preview-button').click();
  await expect(page.locator('#confirm-dialog-title')).toHaveText('Review operation');
  await expect(page.locator('#confirm-dialog .dialog-footer .close-dialog')).toHaveText('Go back');
});

test('failed preview retains the cart and an uncertain execution never automatically retries', async t => {
  const preview = await dashboard(t, { failPreview: true });
  await openGrant(preview.page); await addItem(preview.page, 'Stone');
  await preview.page.locator('#preview-button').click();
  await expect(preview.page.locator('#action-dialog .form-error')).toContainText('disconnected');
  await expect(preview.page.locator('#grant-cart-lines [data-cart-line]')).toHaveCount(1);
  assert.equal(preview.requests.length, 1);
  const execute = await dashboard(t, { failExecute: true });
  await openGrant(execute.page); await addItem(execute.page, 'Stone'); await addItem(execute.page, 'Wood');
  await execute.page.locator('#preview-button').click(); await execute.page.locator('#execute-button').click();
  await expect(execute.page.locator('#confirm-error')).toContainText('uncertain');
  await expect(execute.page.locator('#operation-summary')).toContainText('Uncertain');
  await expect(execute.page.locator('#operation-summary')).toContainText('Not sent');
  await expect(execute.page.locator('#execute-button')).toBeDisabled();
  assert.equal(execute.requests.length, 2);
});

test('review refreshes expired player tokens and preserves a cart when the target disconnects', async t => {
  const fresh = await dashboard(t);
  await openGrant(fresh.page); await addItem(fresh.page, 'Stone');
  fresh.players[0].selection = 'fresh-grant-token';
  await fresh.page.locator('#preview-button').click();
  await expect(fresh.page.locator('#confirm-dialog')).toBeVisible();
  assert.equal(fresh.requests[0].body.options.player, 'fresh-grant-token');
  const disconnected = await dashboard(t);
  await openGrant(disconnected.page); await addItem(disconnected.page, 'Wood');
  disconnected.players.splice(0, 1);
  await disconnected.page.locator('#preview-button').click();
  await expect(disconnected.page.locator('#action-dialog .form-error')).toContainText(/disconnected|changed maps|current player/i);
  await expect(disconnected.page.locator('#grant-cart-lines [data-cart-line]')).toHaveCount(1);
  assert.equal(disconnected.requests.length, 0, 'disconnected targets never reach preview or execution');
});

test('320px mobile cart stays within the viewport with keyboard search and reachable review', async t => {
  const { page, requests } = await dashboard(t, { viewport: { width: 320, height: 800 } });
  await openGrant(page);
  await addItem(page, 'Stone', { quantity: 9 });
  const dialog = page.locator('#action-dialog');
  const box = await dialog.boundingBox();
  assert.ok(box.x >= 0 && box.x + box.width <= 321 && box.y >= 0 && box.y + box.height <= 801, 'modal fits mobile viewport');
  assert.equal(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth + 1), true, 'no horizontal modal overflow');
  await screenshot(page, 'cart-mobile-320');
  await expect(page.locator('#preview-button')).toBeInViewport();
  await page.locator('#grant-packages-tab').click();
  await page.locator('#grant-package-search').fill('Nunatak');
  await expect(page.locator('[data-grant-package="nunatak"]')).toBeVisible();
  await page.locator('[data-grant-package="nunatak"] button').click();
  await page.locator('#preview-button').click();
  await expect(page.locator('#confirm-dialog')).toBeVisible();
  assert.equal(requests[0].body.options.items.length, 1);
  assert.equal(requests[0].body.options.packages.length, 1);
  await screenshot(page, 'review-mobile-320');
});
