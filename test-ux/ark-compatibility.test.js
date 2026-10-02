import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { inferServerGameContext, commandPresetForGame } from '../src/core/ark-compatibility.js';
import { workflowPresets } from '../src/core/workflow-presets.js';
import { getItem, getItemForGame, searchCatalogItems, searchItems, ITEM_COUNT } from '../src/core/item-catalog.js';
import { createBundledItemPackages, mergeBundledPackageAdditions, correctUntouchedBundledPackages,
  BUNDLED_PACKAGE_ADDITIONS_VERSION } from '../src/core/default-item-packages.js';
import { packageCompatibleWithGame, publicItemPackage } from '../src/core/item-packages.js';
import { JsonStateStore } from '../src/adapters/state/json-state-store.js';
import compatibilityData from '../src/data/ark-item-compatibility.json' with { type: 'json' };
import recipeData from '../src/data/verified-boss-recipes.json' with { type: 'json' };
import originalPackageData from '../src/data/default-item-packages.json' with { type: 'json' };

const bundled = Object.values(createBundledItemPackages());
const find = (name) => bundled.find((entry) => entry.name === name);
const originalRecords = () => Object.fromEntries(originalPackageData.packages.map((candidate) => {
  const record = { ...find(candidate.name), items: candidate.items.map(([itemKey, quantity]) =>
    ({ itemKey, quantity, quality: 0, blueprint: false })) };
  return [record.id, record];
}));

test('game context infers all exact configured level tokens and duplicated server IDs without friendly-name guesses', () => {
  for (const preset of workflowPresets({}).maps) {
    for (const suffix of ['', '-2', '-10', '-64']) {
      const value = inferServerGameContext({ id: preset.id + suffix, name: 'Misleading ASA label' });
      assert.equal(value.game, preset.game); assert.equal(value.mapId, preset.mapName);
    }
    const profile = inferServerGameContext({ config: { id: 'stable-old-id', profileImport: { mapName: preset.mapName } } });
    assert.equal(profile.game, preset.game); assert.equal(profile.source, 'profile-map-token');
  }
  for (const config of [null, {id:'island',name:'The Island ASA'}, {id:'new_WP'}, {id:'ragnarok'},
    {id:'Ragnarok',profileImport:{mapName:'Ragnarok_WP'}}, {id:'TheIsland_WP',profileImport:{mapName:'Custom_WP'}}]) {
    assert.equal(inferServerGameContext(config).game, 'unknown');
  }
  assert.equal(commandPresetForGame({game:'ASE'}).giveItem, 'GiveItemToPlayer');
  assert.equal(commandPresetForGame({game:'ASA'}).usesPlayerDataId, true);
});

test('dashboard catalog paging is stable and edition-aware while Discord stays at 25', () => {
  const all = searchCatalogItems('', {limit:9999});
  assert.equal(all.items.length, ITEM_COUNT); assert.equal(all.total, ITEM_COUNT); assert.equal(all.limit,2500);
  const first=searchCatalogItems('stone',{limit:7}); const next=searchCatalogItems('stone',{limit:7,offset:7});
  assert.deepEqual([...first.items,...next.items],searchCatalogItems('stone',{limit:14}).items);
  assert.ok(first.total>7); assert.equal(searchItems('stone',2500).length,25);
  assert.equal(searchItems('',25)[0].name,'Metal');
  assert.ok(searchCatalogItems('Nunatak',{gameContext:{game:'ASA'}}).total>0);
  assert.equal(searchCatalogItems('Nunatak',{gameContext:{game:'ASE'}}).total,0);
  assert.ok(searchCatalogItems('Nunatak',{gameContext:{game:'unknown'}}).total>0);
  const trophy=searchCatalogItems('Alpha Nunatak Trophy').items[0];
  assert.equal(getItemForGame(trophy.key,{game:'ASE'}),null);
  assert.equal(getItemForGame(trophy.key,{game:'ASA'}).blueprintPath,getItem(trophy.key).blueprintPath);
  assert.equal(getItemForGame('forged',{game:'ASA'}),null);
});

test('Nunatak tribute packages match published ASA counts and retain ASE dual arena separately', () => {
  for (const [tier,count,basilo,other] of [['Gamma',10,0,0],['Beta',20,5,10],['Alpha',20,10,25]]) {
    const pkg=find(`Boss: Ragnarok - Nunatak - ${tier}`); assert.equal(pkg.items.length,count);
    const named = new Map(pkg.items.map((entry)=>[getItem(entry.itemKey).name,entry.quantity]));
    assert.equal([...named].filter(([name])=>name.startsWith('Artifact of the ')).length,10);
    for (const [name,qty] of named) if(name.startsWith('Artifact of the ')) assert.equal(qty,1);
    assert.equal(named.get('Basilosaurus Blubber')??0,basilo); assert.equal(named.get('Tusoteuthis Tentacle')??0,other);
    assert.equal(packageCompatibleWithGame(pkg,{game:'ASA'}),true); assert.equal(packageCompatibleWithGame(pkg,{game:'ASE'}),false);
    const projected=publicItemPackage(pkg); assert.deepEqual(projected.compatibility.mapNames,['Ragnarok']);
  }
  assert.equal(packageCompatibleWithGame(find('Boss: Ragnarok - Dragon + Manticore - Alpha'),{game:'ASA'}),false);
  assert.equal(packageCompatibleWithGame(find('Boss: Valguero - Triple Arena - Alpha'),{game:'ASA'}),false);
});

test('Grendel and Astraeos tribute sets have exact researched quantities and ASA restriction', () => {
  const expected={
    'Boss: Valguero - Grendel - Gamma': [8, 'Allosaurus Brain', 5],
    'Boss: Valguero - Grendel - Beta': [9, 'Argentavis Talon', 8],
    'Boss: Valguero - Grendel - Alpha': [10, 'Giganotosaurus Heart', 2],
    'Boss: Astraeos - Natrix The Devious - Gamma': [3, 'Artifact of the Hunter', 1],
    'Boss: Astraeos - Natrix The Devious - Beta': [7, 'Argentavis Talon', 5],
    'Boss: Astraeos - Natrix The Devious - Alpha': [7, 'Titanoboa Venom', 10],
    'Boss: Astraeos - Minotarchos - Standard': [5, 'Corrupt Heart', 2],
    'Boss: Astraeos - Hydraskos - Gamma': [4, 'Artifact of the Immune', 1],
    'Boss: Astraeos - Hydraskos - Beta': [10, 'Giganotosaurus Heart', 1],
    'Boss: Astraeos - Hydraskos - Alpha': [10, 'Tyrannosaurus Arm', 15],
    'Boss: Astraeos - Thodes the Widowmaker - Gamma': [3, 'Artifact of the Brute', 1],
    'Boss: Astraeos - Thodes the Widowmaker - Beta': [8, 'Megalania Toxin', 5],
    'Boss: Astraeos - Thodes the Widowmaker - Alpha': [8, 'Spinosaurus Sail', 10],
    'Boss: Astraeos - Manticore - Gamma': [6, 'Lightning Talon', 2],
    'Boss: Astraeos - Manticore - Beta': [6, 'Lightning Talon', 10],
    'Boss: Astraeos - Manticore - Alpha': [6, 'Lightning Talon', 20],
    'Boss: Astraeos - Kalydonios & Erymanthian - Standard': [5, 'Corrupted Nodule', 25],
  };
  for(const [name,[count,item,qty]] of Object.entries(expected)) {
    const pkg=find(name); assert.equal(pkg.items.length,count,name);
    assert.equal(pkg.items.find(entry=>getItem(entry.itemKey).name===item).quantity,qty);
    assert.equal(packageCompatibleWithGame(pkg,{game:'ASE'}),false);
    assert.equal(packageCompatibleWithGame(pkg,{game:'ASA'}),true);
  }
});

test('official registry selects exact edition paths and covers every new tribute ingredient', () => {
  assert.equal(Object.keys(compatibilityData.items).length,2215);
  const mushroom='common-mushroom-b5ffc74dd8ad';
  assert.equal(getItemForGame(mushroom,{game:'ASA'}).blueprintPath,"Blueprint'/Game/PrimalEarth/CoreBlueprints/Resources/PrimalItemResource_CommonMushroom.PrimalItemResource_CommonMushroom'");
  assert.equal(getItemForGame(mushroom,{game:'ASE'}).blueprintPath,"Blueprint'/Game/Aberration/CoreBlueprints/Items/Consumables/PrimalItemResource_CommonMushroom.PrimalItemResource_CommonMushroom'");
  const saddle=getItemForGame('shastasaurus-submarine-saddle-c5417c953e50',{game:'ASA'});
  assert.match(saddle.blueprintPath,/\/ASA\/Dinos\/Shastasaurus\/PrimalItemArmor_ShastaSaddle_Submarine\./u);
  assert.equal(getItemForGame(saddle.key,{game:'ASE'}),null);
  for(const pkg of bundled.filter(p=>/Nunatak|Grendel|Astraeos/.test(p.name))) {
    for(const entry of pkg.items) {
      const item=getItemForGame(entry.itemKey,{game:'ASA'});
      assert.ok(item,`${pkg.name}: ${entry.itemKey}`); assert.equal(item.compatibility.verified,true);
    }
  }
  const all=searchCatalogItems('mushroom',{gameContext:{game:'ASE'}}).items;
  assert.equal(all.find(item=>item.key===mushroom).blueprintPath,getItemForGame(mushroom,{game:'ASE'}).blueprintPath);
});

test('additive seed preserves customized identities, disabled packages, matching names and capacity', () => {
  const nunatak=find('Boss: Ragnarok - Nunatak - Alpha');
  const customized={...nunatak,enabled:false,description:'Locally customized',revision:4};
  const original={ [nunatak.id]: customized };
  const merged=mergeBundledPackageAdditions(original);
  assert.equal(merged.itemPackages[nunatak.id],customized); assert.equal(merged.added.length,19);
  assert.equal(Object.keys(original).length,1);
  const alias={...customized,id:'pkg_abcdefghijklmnopqrstuv',name:customized.name.toUpperCase()};
  assert.equal(mergeBundledPackageAdditions({[alias.id]:alias}).added.length,19);
  const full=Object.fromEntries(Array.from({length:128},(_,index)=>[`package-${index}`,{name:`Custom ${index}`} ]));
  const bounded=mergeBundledPackageAdditions(full); assert.equal(bounded.added.length,0); assert.equal(bounded.skipped.length,20);
  assert.equal(Object.keys(bounded.itemPackages).length,128);
});

test('persisted additive generation prevents deleted packages reappearing after upgrade', () => {
  const store=new JsonStateStore({file:'unused-test-state.json',seedBundledItemPackages:true});
  store.state.bundledItemPackagesSeeded=true;
  store.state.itemPackages={};
  assert.equal(store.seedBundledPackagesIfNeeded(),true);
  assert.equal(Object.keys(store.state.itemPackages).length,20);
  assert.equal(store.state.bundledItemPackageAdditionsVersion,BUNDLED_PACKAGE_ADDITIONS_VERSION);
  const id=Object.keys(store.state.itemPackages)[0]; delete store.state.itemPackages[id];
  assert.equal(store.seedBundledPackagesIfNeeded(),false); assert.equal(store.state.itemPackages[id],undefined);
});

test('fresh defaults correct inherited boss recipes and verify only complete unchanged tribute sets', () => {
  assert.equal(recipeData.recipes.length,65); assert.equal(recipeData.correctedBundledNames.length,27);
  assert.equal(bundled.length,74);
  for(const recipe of recipeData.recipes) {
    const pkg=find(recipe.name); const publicPackage=publicItemPackage(pkg);
    assert.equal(publicPackage.compatibility.recipeVerified,true,pkg.name);
    assert.deepEqual(publicPackage.compatibility.recipeGames,recipe.games);
    assert.equal(pkg.revision,1);
    for(const game of recipe.games) for(const line of pkg.items) {
      assert.ok(getItemForGame(line.itemKey,game),`${pkg.name}: ${game} ${line.itemKey}`);
    }
  }
  // These inherited quantities were wrong in the previous release.
  const quantities=(name)=>new Map(find(name).items.map(line=>[getItem(line.itemKey).name,line.quantity]));
  assert.equal(quantities('Boss: Aberration - Rockwell - Beta').get('Nameless Venom'),12);
  assert.equal(quantities('Boss: Aberration - Rockwell - Beta').get('Rock Drake Feather'),2);
  assert.equal(quantities('Boss: Scorched - Manticore - Gamma').get('Fire Talon'),2);
  assert.equal(quantities('Boss: Extinction - Desert Titan - Standard').get('Sarcosuchus Skin'),10);
  const good=find('Boss: Ragnarok - Nunatak - Alpha');
  const changed={...good,items:good.items.map((line,index)=>index===0?{...line,quantity:2}:line)};
  for(const candidate of [changed,{...good,items:good.items.slice(1)},
    {...good,name:'Custom Nunatak'}, {...good,items:good.items.map(line=>({...line,blueprint:true}))},
    {...good,items:good.items.map(line=>({...line,quality:1}))}]) {
    assert.equal(publicItemPackage(candidate).compatibility.recipeVerified,false);
  }
  for(const name of recipeData.unverifiedBundledNames) assert.equal(publicItemPackage(find(name)).compatibility.recipeVerified,false);
});

test('recipe correction upgrades only complete original records and preserves every local edit byte for byte', () => {
  const existing=originalRecords(); const before=JSON.stringify(existing);
  const now=Date.parse('2026-10-02T00:00:00Z');
  const result=correctUntouchedBundledPackages(existing,{now});
  assert.equal(result.corrected.length,27); assert.equal(Object.keys(result.itemPackages).length,54);
  assert.equal(JSON.stringify(existing),before);
  for(const id of result.corrected) {
    const updated=result.itemPackages[id]; assert.equal(updated.revision,2); assert.equal(updated.updatedAt,now);
    assert.equal(updated.createdAt,existing[id].createdAt);
    assert.equal(publicItemPackage(updated).compatibility.recipeVerified,true);
  }
  for(const [id,record] of Object.entries(existing)) if(!result.corrected.includes(id)) assert.equal(result.itemPackages[id],record);
  assert.equal(correctUntouchedBundledPackages(result.itemPackages,{now:now+1}).corrected.length,0);
  const base=existing[find('Boss: Scorched - Manticore - Gamma').id];
  const changes=[{enabled:false},{revision:2},{name:'Custom Manticore'}, {description:'Local recipe'},
    {starterEnabled:true},{createdAt:base.createdAt+1,updatedAt:base.updatedAt+1},{updatedAt:base.updatedAt+1},
    {items:base.items.map((line,index)=>index?line:{...line,quantity:2})},
    {items:base.items.map((line,index)=>index?line:{...line,quality:1})},
    {items:base.items.map((line,index)=>index?line:{...line,blueprint:true})}];
  for(const change of changes) {
    const record={...base,...change}; const saved=JSON.stringify(record);
    const preserved=correctUntouchedBundledPackages({[record.id]:record},{now});
    assert.equal(preserved.corrected.length,0); assert.equal(preserved.itemPackages[record.id],record);
    assert.equal(JSON.stringify(preserved.itemPackages[record.id]),saved);
  }
});

test('encrypted persisted upgrade corrects untouched defaults once while disabled and customized records survive', async(t) => {
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),'ark-recipe-upgrade-'));
  t.after(async()=>{ assert.equal(path.dirname(directory),path.resolve(os.tmpdir())); await fs.rm(directory,{recursive:true,force:true}); });
  const options={file:path.join(directory,'state.json'),encryptionKey:`hex:${'45'.repeat(32)}`,encryptionRequired:true};
  const old=await new JsonStateStore({...options,seedBundledItemPackages:false}).load();
  const records=originalRecords();
  const disabledId=find('Boss: Aberration - Rockwell - Alpha').id;
  const customId=find('Boss: Center - Dual Arena - Alpha').id;
  records[disabledId].enabled=false;
  records[customId].items[0].quantity=9; records[customId].revision=4;
  const preserved=JSON.stringify([records[disabledId],records[customId]]);
  old.state={...old.state,itemPackages:records,bundledItemPackagesSeeded:true}; await old.save();
  const upgraded=await new JsonStateStore({...options,seedBundledItemPackages:true}).load();
  assert.equal(Object.keys(upgraded.state.itemPackages).length,74);
  assert.equal(Object.values(upgraded.state.itemPackages).filter(pkg=>pkg.revision===2).length,25);
  assert.equal(JSON.stringify([upgraded.state.itemPackages[disabledId],upgraded.state.itemPackages[customId]]),preserved);
  assert.doesNotMatch(await fs.readFile(options.file,'utf8'),/Rockwell|Nunatak/);
  const removed=find('Boss: Ragnarok - Nunatak - Alpha').id;
  delete upgraded.state.itemPackages[removed]; await upgraded.save();
  const persisted=JSON.stringify(upgraded.state.itemPackages);
  const restored=await new JsonStateStore({...options,seedBundledItemPackages:true}).load();
  assert.equal(restored.state.itemPackages[removed],undefined);
  assert.equal(JSON.stringify(restored.state.itemPackages),persisted);
});
