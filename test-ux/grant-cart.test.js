import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { applyDefaults } from '../src/config.js';
import { JsonStateStore } from '../src/adapters/state/json-state-store.js';
import { AdminApi, normalizeAdminAction } from '../src/http/admin-api.js';
import { ClusterBridge } from '../src/core/bridge.js';
import { expandGrantCart } from '../src/core/grant-cart.js';
import { Metrics } from '../src/core/metrics.js';
import { OperatorPasswordService } from '../src/core/operator-credentials.js';
import { getItemForGame, searchItems, searchCatalogItems } from '../src/core/item-catalog.js';

const temporaryDirectories = [];
after(async () => {
  for (const directory of temporaryDirectories) {
    const relative = path.relative(os.tmpdir(), directory);
    if (relative.startsWith('grant-cart-fixture-') && !relative.includes(path.sep)) await fs.rm(directory, { recursive: true, force: true });
  }
});
class CartServer extends EventEmitter {
  constructor({ id, name, players }) { super(); Object.assign(this, { id, name, players, connected: true, givenItems: [] }); }
  snapshot() { return { serverId: this.id, serverName: this.name, connected: true, playerCount: this.players.length, players: this.players }; }
  async refreshPlayers() { return this.players; }
  async giveItemToPlayer(playerId, blueprintPath, quantity, quality, forceBlueprint) {
    this.givenItems.push({ playerId, blueprintPath, quantity, quality, forceBlueprint }); return 'ok';
  }
  async giveItemNumToPlayer(playerId, itemNumber, quantity, quality, forceBlueprint) {
    this.givenItems.push({ playerId, itemNumber, quantity, quality, forceBlueprint }); return 'ok';
  }
}

const username = 'CartFixtureOwner'; const password = 'Violet orbit lantern 8472!';
const metal = searchItems('Metal').find((item) => item.name === 'Metal');
const wood = searchItems('Wood').find((item) => item.name === 'Wood');
const entry = (item, quantity = 1) => ({ itemKey: item.key, quantity, quality: 0, blueprint: false });
function request(cookie = '', csrf = '', idempotency = '') {
  return { headers: { host: '127.0.0.1:8787', origin: 'https://127.0.0.1:8787', 'content-type': 'application/json',
    cookie, 'x-csrf-token': csrf, 'idempotency-key': idempotency }, socket: { remoteAddress: '127.0.0.1', encrypted: true } };
}
async function fixture() {
  const eosId = '0123456789abcdef0123456789abcdef';
  const server = new CartServer({ id: 'TheIsland_WP', name: 'The Island', players: [{ name: 'Cart Fixture Survivor', id: eosId }] });
  const config = applyDefaults({ http: { allowRemoteHttp: false, adminToken: '', tls: { enabled: true } }, servers: [] });
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'grant-cart-fixture-')); temporaryDirectories.push(directory);
  const state = new JsonStateStore({ file: path.join(directory, 'state.json'), encryptionRequired: true, encryptionKey: crypto.randomBytes(32).toString('base64') });
  await state.load();
  const metrics = new Metrics();
  const logger = { healthy: true, audit: () => true, security: () => true, warn: () => {} };
  const bridge = new ClusterBridge({ config, servers: [server], state, metrics, discord: {
    config: { enabled: false }, snapshot: () => ({ enabled: false, ready: false }), sendAudit: async () => [],
  }, logger });
  const api = new AdminApi({ config: config.http, bridge, state, metrics, logger, statusProjector: () => ({ servers: [] }),
    passwordService: new OperatorPasswordService({
      params: { N: 2, r: 1, p: 1, saltBytes: 16, keyBytes: 32, maxmem: 2 * 1024 * 1024 },
      derive: async (plain, salt) => crypto.createHash('sha256').update(plain).update(salt).digest(),
    }),
  });
  const owner = await api.setupOwner(request(), { username, password, passwordConfirmation: password });
  const cookie = owner.headers['Set-Cookie'].split(';')[0];
  const csrf = api.bootstrap(request(cookie)).session.csrfToken;
  await state.setPlayerDataId(server.id, eosId, '424242421');
  const select = () => api.players(request(cookie), new URL('https://localhost/admin/api/players?purpose=give-cart')).players[0].selection;
  const req = (key = '') => request(cookie, csrf, key);
  const itemPackage = await state.createItemPackage({ name: 'Cart fixture package', description: '', enabled: true, starterEnabled: false, items: [entry(wood, 20)] });
  const cart = () => ({ action: 'give-cart', options: { player: select(), items: [entry(metal, 10)], packages: [{ packageId: itemPackage.id, revision: itemPackage.revision }] } });
  return { api, state, server, bridge, eosId, cookie, req, select, itemPackage, cart };
}

test('cart expands catalog items and packages into immutable reviewed lines and sends once', async () => {
  const { api, req, cart, server, cookie } = await fixture();
  const input = cart(); const preview = api.preview(req(), input);
  assert.equal(preview.grantLines.length, 2);
  assert.deepEqual(preview.grantLines.map((line) => line.quantity), [10, 20]);
  const body = { ...input, confirmationToken: preview.confirmationToken };
  const first = await api.execute(req('fixture_cart_operation_1'), body);
  const replay = await api.execute(req('fixture_cart_operation_1'), body);
  assert.deepEqual(replay, first); assert.equal(first.status, 200);
  assert.deepEqual(first.body.grantResults.map((line) => line.outcome), ['sent', 'sent']);
  assert.equal(server.givenItems.length, 2);
  assert.deepEqual(api.itemPreferences(request(cookie)).recent.map((item) => item.key), [wood.key, metal.key]);
});

test('cart confirmation binds quantities, package revisions, and exact player selection', async () => {
  const { api, state, req, cart, server, itemPackage } = await fixture();
  const input = cart(); const preview = api.preview(req(), input);
  await assert.rejects(() => api.execute(req('fixture_changed_cart_1'), { ...input,
    options: { ...input.options, items: [entry(metal, 100)] }, confirmationToken: preview.confirmationToken }),
  (error) => error.code === 'confirmation_expired');
  await state.updateItemPackage(itemPackage.id, { name: itemPackage.name, description: '', enabled: true, starterEnabled: false, items: [entry(wood, 30)] }, { expectedRevision: 1 });
  await assert.rejects(() => api.execute(req('fixture_changed_cart_2'), { ...input, confirmationToken: preview.confirmationToken }),
    (error) => error.code === 'package_changed');
  assert.equal(server.givenItems.length, 0);
});

test('cart stops after first uncertain RCON response, reports every line, and never replays sends', async () => {
  const { api, req, select, server } = await fixture();
  const input = { action: 'give-cart', options: { player: select(), items: [entry(metal), entry(wood), entry(metal, 3)] } };
  const preview = api.preview(req(), input); let attempts = 0;
  server.giveItemToPlayer = async () => { attempts += 1; if (attempts === 2) throw new Error('fixture timeout'); };
  const body = { ...input, confirmationToken: preview.confirmationToken };
  const response = await api.execute(req('fixture_uncertain_cart'), body);
  assert.equal(response.status, 502); assert.equal(response.body.outcome, 'uncertain');
  assert.deepEqual(response.body.grantResults.map((line) => line.outcome), ['sent', 'uncertain', 'not-sent']);
  assert.equal(attempts, 2);
  assert.deepEqual(await api.execute(req('fixture_uncertain_cart'), body), response);
  assert.equal(attempts, 2);
});

test('cart player disconnect and package changes during target recheck send no item lines', async () => {
  for (const change of ['player', 'package']) {
    const { api, req, cart, state, server, itemPackage } = await fixture();
    const input = cart(); const preview = api.preview(req(), input);
    server.refreshPlayers = async () => {
      if (change === 'player') { server.players = []; return []; }
      await state.updateItemPackage(itemPackage.id, { name: itemPackage.name, description: '', enabled: false, starterEnabled: false, items: itemPackage.items }, { expectedRevision: 1 });
      return server.players;
    };
    const response = await api.execute(req('fixture_preflight_failure'), { ...input, confirmationToken: preview.confirmationToken });
    assert.equal(response.body.outcome, 'failed');
    assert.deepEqual(response.body.grantResults.map((line) => line.outcome), ['not-sent', 'not-sent']);
    assert.equal(server.givenItems.length, 0);
  }
});

test('cart rejects malformed items, arbitrary command paths, duplicate packages and expanded overflow', async () => {
  const { select, state, itemPackage } = await fixture(); const player = select();
  for (const items of [[], [entry(metal, 0)], [{ ...entry(metal), 'blueprint-path': 'arbitrary' }], [entry({ key: 'unknown-item' })], Array.from({ length: 51 }, () => entry(metal))]) {
    assert.throws(() => normalizeAdminAction('give-cart', { player, items }), /cart|quantity|Unsupported|trusted|Choose/i);
  }
  const selected = { packageId: itemPackage.id, revision: 1 };
  assert.throws(() => normalizeAdminAction('give-cart', { player, packages: [selected, selected] }), /once/);
  assert.throws(() => expandGrantCart({ items: Array.from({ length: 50 }, () => entry(metal)), packages: [selected] }, state), /1-50/);
  const big = await state.createItemPackage({ name: 'Overflow fixture', enabled: true, items: Array.from({ length: 50 }, () => entry(metal)) });
  assert.throws(() => expandGrantCart({ items: [entry(wood)], packages: [{ packageId: big.id, revision: 1 }] }, state), /expands to 51/);
});

test('item favorites use encrypted account preference namespace, survive sessions and require CSRF', async () => {
  const { api, req, cookie, state } = await fixture();
  await assert.rejects(() => api.updateItemPreference(request(cookie), { itemKey: metal.key, favorite: true }), (error) => error.code === 'csrf_rejected');
  const saved = await api.updateItemPreference(req(), { itemKey: metal.key, favorite: true });
  assert.deepEqual(saved.favorites.map((item) => item.key), [metal.key]);
  const serialized = await fs.readFile(state.file, 'utf8');
  assert.equal(serialized.includes(metal.key), false);
  const reopened = new JsonStateStore({ file: state.file, encryptionRequired: true, encryptionKey: state.encryptionKey.toString('base64') });
  await reopened.load();
  assert.deepEqual(reopened.listItemFavorites(`web_operator_${state.findOperatorByUsername(username).id}`), [metal.key]);
  const login = await api.createSession(request(), { username, password });
  const secondCookie = login.headers['Set-Cookie'].split(';')[0];
  assert.deepEqual(api.itemPreferences(request(secondCookie)).favorites.map((item) => item.key), [metal.key]);
  await api.updateItemPreference(req(), { itemKey: metal.key, favorite: false });
  assert.deepEqual(api.itemPreferences(request(cookie)).favorites, []);
});

test('a recent preference persistence failure cannot turn a completed cart into a failed grant', async () => {
  const { api, req, cart, state, server } = await fixture();
  state.recordRecentItem = async () => { throw new Error('fixture disk error'); };
  const input = cart(); const preview = api.preview(req(), input);
  const response = await api.execute(req('fixture_recent_failure'), { ...input, confirmationToken: preview.confirmationToken });
  assert.equal(response.body.outcome, 'succeeded'); assert.equal(server.givenItems.length, 2);
});

test('a completed cart replay remains available after a package is edited', async () => {
  const { api, req, cart, state, itemPackage, server } = await fixture();
  const input = cart(); const preview = api.preview(req(), input); const body = { ...input, confirmationToken: preview.confirmationToken };
  const result = await api.execute(req('fixture_replay_after_edit'), body);
  await state.updateItemPackage(itemPackage.id, { name: itemPackage.name, description: '', enabled: false, starterEnabled: false, items: itemPackage.items }, { expectedRevision: 1 });
  assert.deepEqual(await api.execute(req('fixture_replay_after_edit'), body), result);
  assert.equal(server.givenItems.length, 2);
  await assert.rejects(() => api.execute(req('fixture_replay_after_edit'), { ...body, options: { ...body.options, items: [entry(metal, 25)] } }), (error) => error.code === 'idempotency_conflict');
});

test('catalog paging is bounded, edition-aware, and does not change old quick suggestions', async () => {
  const { api, cookie, server } = await fixture();
  const initial = api.items(request(cookie), new URL('https://localhost/admin/api/items'));
  assert.equal(initial.items.length, 25); assert.equal(initial.items[0].name, 'Metal');
  const full = api.items(request(cookie), new URL(`https://localhost/admin/api/items?limit=2500&server=${server.id}`));
  assert.ok(full.total > 1000); assert.equal(full.items.length, full.total); assert.equal(full.context.game, 'ASA');
  server.config = { id: server.id, profileImport: { mapName: 'TheIsland' } };
  const conflicting = api.items(request(cookie), new URL(`https://localhost/admin/api/items?limit=2500&server=${server.id}`));
  assert.equal(conflicting.context.game, 'unknown');
  server.config.id = 'custom-ase-server';
  const ase = api.items(request(cookie), new URL(`https://localhost/admin/api/items?limit=2500&server=${server.id}`));
  assert.equal(ase.context.game, 'ASE'); assert.ok(ase.total < full.total);
  assert.ok(ase.items.every((item) => !item.compatibility.games.length || item.compatibility.games.includes('ASE')));
  const page = api.items(request(cookie), new URL(`https://localhost/admin/api/items?limit=10&offset=10&server=${server.id}`));
  assert.deepEqual(page.items, ase.items.slice(10, 20));
  for (const query of ['limit=2501', 'offset=-1', 'limit=1&limit=2', 'server=missing', 'limit=0']) {
    assert.throws(() => api.items(request(cookie), new URL(`https://localhost/admin/api/items?${query}`)));
  }
});

test('known incompatible carts fail before any grant, including a context change after preview', async () => {
  const { api, req, select, server } = await fixture();
  const asaItem = searchCatalogItems('', { limit: 2500 }).items.find((item) => item.compatibility.games.join(',') === 'ASA');
  assert.ok(asaItem);
  const input = { action: 'give-cart', options: { player: select(), items: [entry(asaItem)] } };
  const preview = api.preview(req(), input);
  server.config = { id: 'ase-fixture', profileImport: { mapName: 'TheIsland' } };
  assert.throws(() => api.preview(req(), input), (error) => error.code === 'incompatible_item');
  await assert.rejects(() => api.execute(req('fixture_incompatible_cart'), { ...input, confirmationToken: preview.confirmationToken }), (error) => error.code === 'incompatible_item');
  assert.equal(server.givenItems.length, 0);
});

test('moderators require the item grant permission for carts and favorites', async () => {
  const { api, req, cookie } = await fixture();
  const created = await api.createOperator(req(), { username: 'CartFixtureMod', role: 'moderator' });
  const { operator, temporaryPassword } = created.body;
  const initial = await api.createSession(request(), { username: operator.username, password: temporaryPassword });
  const initialCookie = initial.headers['Set-Cookie'].split(';')[0];
  const changed = await api.changePassword(request(initialCookie, api.bootstrap(request(initialCookie)).session.csrfToken), {
    currentPassword: temporaryPassword, newPassword: 'Copper meadow compass 5281!', passwordConfirmation: 'Copper meadow compass 5281!',
  });
  const modCookie = changed.headers['Set-Cookie'].split(';')[0];
  const mutation = request(modCookie, api.bootstrap(request(modCookie)).session.csrfToken);
  assert.throws(() => api.players(request(modCookie), new URL('https://localhost/admin/api/players?purpose=give-cart')), (error) => error.code === 'action_forbidden');
  await assert.rejects(() => api.updateItemPreference(mutation, { itemKey: metal.key, favorite: true }), (error) => error.code === 'action_forbidden');
  const current = api.operators(request(cookie)).operators.find((candidate) => candidate.id === operator.id);
  await api.updateOperator(req(), operator.id, { actionGrants: ['give-item'], expectedRevision: current.recordRevision });
  const login = await api.createSession(request(), { username: operator.username, password: 'Copper meadow compass 5281!' });
  const grantedCookie = login.headers['Set-Cookie'].split(';')[0];
  const bootstrap = api.bootstrap(request(grantedCookie));
  assert.ok(bootstrap.capabilities.actions.some((action) => action.id === 'give-cart'));
  const player = api.players(request(grantedCookie), new URL('https://localhost/admin/api/players?purpose=give-cart')).players[0];
  const grantedRequest = request(grantedCookie, bootstrap.session.csrfToken, 'fixture_mod_cart_operation');
  const input = { action: 'give-cart', options: { player: player.selection, items: [entry(metal)] } };
  const preview = api.preview(grantedRequest, input);
  assert.equal((await api.execute(grantedRequest, { ...input, confirmationToken: preview.confirmationToken })).status, 200);
  assert.deepEqual(api.itemPreferences(request(grantedCookie)).recent.map((item) => item.key), [metal.key]);
  assert.deepEqual(api.itemPreferences(request(cookie)).recent, []);
});

test('ASE grants use a saved numeric PlayerDataID without sending Steam profiles to the ASA parser', async () => {
  const { api, req, select, server, state, bridge, cookie } = await fixture();
  const steamId = '76561198012345678';
  server.config = { id: 'ase-fixture', profileImport: { mapName: 'TheIsland' } };
  server.players = [{ name: 'ASE fixture survivor', id: steamId }];
  let profileCalls = 0;
  bridge.profileSources.set(server.id, { getProfile: async () => { profileCalls += 1; throw new Error('ASA adapter must not parse Steam profile'); } });
  assert.equal(api.players(request(cookie), new URL('https://localhost/admin/api/players?purpose=give-cart')).players[0].targeting, 'id-needed');
  const missing = { action: 'give-cart', options: { player: select(), items: [entry(metal)] } };
  const firstPreview = api.preview(req(), missing);
  const first = await api.execute(req('fixture_ase_missing_id'), { ...missing, confirmationToken: firstPreview.confirmationToken });
  assert.equal(first.body.outcome, 'failed'); assert.match(first.body.message, /verified PlayerDataID/);
  assert.equal(server.givenItems.length, 0);
  await state.setPlayerDataId(server.id, steamId, '123456789', { actor: 'Fixture administrator' });
  assert.equal(api.players(request(cookie), new URL('https://localhost/admin/api/players?purpose=give-cart')).players[0].targeting, 'ready');
  const input = { action: 'give-cart', options: { player: select(), items: [entry(metal)] } };
  const preview = api.preview(req(), input);
  const response = await api.execute(req('fixture_ase_mapped_id'), { ...input, confirmationToken: preview.confirmationToken });
  assert.equal(response.body.outcome, 'succeeded'); assert.equal(server.givenItems.length, 1); assert.equal(profileCalls, 0);
});

test('ASA and ASE grants dispatch their verified edition-specific blueprint, including cart snapshots', async () => {
  const different = searchCatalogItems('', { limit: 2500 }).items.find((item) =>
    getItemForGame(item.key, 'ASA') && getItemForGame(item.key, 'ASE')
      && getItemForGame(item.key, 'ASA').blueprintPath !== getItemForGame(item.key, 'ASE').blueprintPath);
  assert.ok(different, 'Registry must contain a real edition path variant');
  for (const game of ['ASA', 'ASE']) for (const action of ['give-item', 'give-cart']) {
    const { api, req, cookie, server } = await fixture();
    server.config = { id: 'variant-fixture', profileImport: { mapName: game === 'ASA' ? 'TheIsland_WP' : 'TheIsland' } };
    const player = api.players(request(cookie), new URL(`https://localhost/admin/api/players?purpose=${action}`)).players[0].selection;
    const input = { action, options: action === 'give-cart' ? { player, items: [entry(different)] } : { player, item: different.key, quantity: 1, quality: 0, blueprint: false } };
    const preview = api.preview(req(), input); const expected = getItemForGame(different.key, game).blueprintPath;
    if (action === 'give-cart') assert.equal(preview.grantLines[0].blueprintPath, expected);
    const response = await api.execute(req('fixture_edition_path_grant'), { ...input, confirmationToken: preview.confirmationToken });
    assert.equal(response.body.outcome, 'succeeded'); assert.equal(server.givenItems[0].blueprintPath, expected);
  }
});

test('cart confirmation binds map context even for items compatible with both editions', async () => {
  for (const changeAt of ['before-execute', 'during-preflight', 'after-first-line']) {
    const { api, req, select, server } = await fixture();
    const input = { action: 'give-cart', options: { player: select(), items: [entry(metal), entry(wood)] } };
    const preview = api.preview(req(), input);
    const change = () => { server.config = { id: 'changed-fixture', profileImport: { mapName: 'TheIsland' } }; };
    if (changeAt === 'before-execute') {
      change();
      await assert.rejects(() => api.execute(req('fixture_context_change'), { ...input, confirmationToken: preview.confirmationToken }), (error) => error.code === 'confirmation_expired');
      assert.equal(server.givenItems.length, 0);
    } else {
      if (changeAt === 'during-preflight') server.refreshPlayers = async () => { change(); return server.players; };
      else {
        const original = server.giveItemToPlayer.bind(server);
        server.giveItemToPlayer = async (...args) => { const result = await original(...args); change(); return result; };
      }
      const response = await api.execute(req('fixture_context_change'), { ...input, confirmationToken: preview.confirmationToken });
      assert.equal(response.body.outcome, changeAt === 'during-preflight' ? 'failed' : 'uncertain');
      assert.deepEqual(response.body.grantResults.map((line) => line.outcome), changeAt === 'during-preflight' ? ['not-sent', 'not-sent'] : ['sent', 'not-sent']);
      assert.equal(server.givenItems.length, changeAt === 'during-preflight' ? 0 : 1);
    }
  }
});
