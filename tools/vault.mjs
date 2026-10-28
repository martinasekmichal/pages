#!/usr/bin/env node
// Vault tool: init | open | seal | password | rotate | check   (Node 20+, built-in modules only)
// Reads the password from VAULT_PASSWORD (the password command, and optionally rotate, also from VAULT_NEW_PASSWORD).
// Readable files exist only in src/, which is never committed. Messages are in Czech, like everything the user reads.
import fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VAULT = path.join(ROOT, 'vault');
const BLOCKS = path.join(VAULT, 'blocks');
const LOCKS = path.join(VAULT, 'locks.json');
const CONTENTS = path.join(VAULT, 'contents.bin');
const SRC = path.join(ROOT, 'src');
const MARKER = '.vault.json';
const HOOK_MARKER = 'installed by tools/vault.mjs';
const HOOK = '#!/bin/sh\n# Vault check before every commit (' + HOOK_MARKER + ').\n' +
  'exec node "$(git rev-parse --show-toplevel)/tools/vault.mjs" check\n';
const MAX_SIZE = 95 * 1024 * 1024;
const WARN_SIZE = 20 * 1024 * 1024;
const PAGE_PATH = /^[a-z0-9][a-z0-9-]*$/;
const BLOCK_FILE = /^[0-9a-f]{16}\.bin$/;
const SKIP = new Set(['.DS_Store', 'Thumbs.db', 'desktop.ini']);
const TYPES = {
  html: 'text/html; charset=utf-8', htm: 'text/html; charset=utf-8', js: 'text/javascript; charset=utf-8',
  mjs: 'text/javascript; charset=utf-8', css: 'text/css; charset=utf-8', json: 'application/json; charset=utf-8',
  geojson: 'application/geo+json; charset=utf-8', webmanifest: 'application/manifest+json; charset=utf-8',
  txt: 'text/plain; charset=utf-8', md: 'text/markdown; charset=utf-8', csv: 'text/csv; charset=utf-8',
  xml: 'application/xml; charset=utf-8', gpx: 'application/gpx+xml; charset=utf-8',
  kml: 'application/vnd.google-earth.kml+xml; charset=utf-8', svg: 'image/svg+xml', png: 'image/png',
  jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', gif: 'image/gif', avif: 'image/avif',
  ico: 'image/x-icon', pdf: 'application/pdf', woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf',
  otf: 'font/otf', mp3: 'audio/mpeg', ogg: 'audio/ogg', wav: 'audio/wav', mp4: 'video/mp4', webm: 'video/webm',
  wasm: 'application/wasm', zip: 'application/zip'
};

const Cipher = (await import(pathToFileURL(path.join(ROOT, 'cipher.js')).href)).default;
const subtle = globalThis.crypto.subtle;
const options = new Set(process.argv.slice(3));
const force = options.has('--force');

class Stop extends Error {}
function stop(message) { throw new Stop(message); }
function git(args) {
  return execFileSync('git', ['-C', ROOT, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}
function inGitRoot() {
  try {
    return git(['rev-parse', '--is-inside-work-tree']).trim() === 'true' &&
      path.resolve(git(['rev-parse', '--show-toplevel']).trim()) === ROOT;
  } catch { return false; }
}
function typeOf(file) {
  const m = /\.([a-z0-9]+)$/i.exec(file);
  return (m && TYPES[m[1].toLowerCase()]) || 'application/octet-stream';
}
function isSafePath(p) {
  if (typeof p !== 'string' || !p || p.startsWith('/') || p.includes('\\') || /[\u0000-\u001f]/.test(p)) return false;
  return p.split('/').every((s) => s && s !== '.' && s !== '..');
}
async function writeAtomic(file, data) {
  const tmp = file + '.tmp-' + process.pid;
  await fs.writeFile(tmp, data);
  await fs.rename(tmp, file);
}
function checkStrength(password, variable) {
  const t = String(password).normalize('NFC').trim();
  if (Cipher.isRecoveryKey(t)) stop(`${variable} nesmí začínat ZK- (tak začíná záchranný klíč).`);
  if ([...t].length < 14 && !force) {
    stop(`${variable} je krátké: aspoň 14 znaků, doporučeno 12 náhodných slov (--force kontrolu přeskočí).`);
  }
}

// ---------- vault ----------
async function readLocks() {
  let locks;
  try { locks = JSON.parse(await fs.readFile(LOCKS, 'utf8')); } catch { stop('Trezor neexistuje nebo vault/locks.json nejde přečíst.'); }
  if (!locks || locks.v !== 1 || !Array.isArray(locks.locks)) stop('vault/locks.json má neznámý formát.');
  return locks;
}
async function unlockVault() {
  const password = process.env.VAULT_PASSWORD;
  if (!password) stop('Chybí proměnná VAULT_PASSWORD s heslem nebo záchranným klíčem.');
  const locks = await readLocks();
  try {
    const { key } = await Cipher.unlock(locks, password, true);
    return { key, locks };
  } catch (e) {
    if (e && e.code === 'wrong-password') stop('Špatné heslo.');
    if (e && e.code === 'typo') stop('V záchranném klíči je překlep.');
    throw e;
  }
}
async function readContents(key) {
  let data;
  try { data = await fs.readFile(CONTENTS); } catch { stop('Chybí vault/contents.bin.'); }
  try { return await Cipher.decryptContents(key, data); } catch { stop('Seznam trezoru nejde dešifrovat (poškozený soubor nebo jiný klíč).'); }
}
async function readBlock(key, entry) {
  const data = await fs.readFile(path.join(BLOCKS, entry.block + '.bin'));
  return Cipher.decryptBlock(key, entry.block, data, entry.size);
}
async function writeContents(key, contents) { await writeAtomic(CONTENTS, await Cipher.encryptContents(key, contents)); }
async function blocksOnDisk() {
  return (await fs.readdir(BLOCKS).catch(() => [])).filter((n) => BLOCK_FILE.test(n)).map((n) => n.slice(0, 16));
}
async function newDataKey() {
  const raw = Cipher.randomBytes(32);
  const key = await subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  raw.fill(0);
  return key;
}
async function newLocks(key, password) {
  const recovery = Cipher.randomBytes(32);
  const text = await Cipher.recoveryKeyText(recovery);
  const locks = { v: 1, locks: [
    await Cipher.createLock(key, 'password', Cipher.passwordInput(password)),
    await Cipher.createLock(key, 'recovery', recovery)
  ] };
  recovery.fill(0);
  return { locks, text };
}
function printRecoveryKey(text) {
  console.log('\nZÁCHRANNÝ KLÍČ (vypíše se jen teď, nikde se neukládá):\n\n    ' + text + '\n\n' +
    'Ulož ho mimo počítač (správce hesel, ideálně i papír). Odemkne trezor, když se zapomene heslo.\n');
}

// ---------- src/ ----------
async function walkSrc() {
  const found = new Map();
  async function walk(dir, prefix) {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      if (!prefix && e.name === MARKER) continue;
      if (SKIP.has(e.name)) continue;
      const rel = (prefix ? prefix + '/' : '') + e.name.normalize('NFC');
      const abs = path.join(dir, e.name);
      if (e.isSymbolicLink()) { console.warn(`Přeskakuji symbolický odkaz src/${rel}.`); continue; }
      if (e.isDirectory()) await walk(abs, rel);
      else if (e.isFile()) found.set(rel, abs);
    }
  }
  if (existsSync(SRC)) await walk(SRC, '');
  return found;
}
async function readMarker() {
  try { return JSON.parse(await fs.readFile(path.join(SRC, MARKER), 'utf8')); } catch { return null; }
}
async function writeMarker(version) {
  await fs.mkdir(SRC, { recursive: true });
  await fs.writeFile(path.join(SRC, MARKER), JSON.stringify({ version, time: new Date().toISOString() }) + '\n');
}
async function diffAgainstSrc(contents, files) {
  const diff = [];
  for (const [p, abs] of files) {
    const entry = contents.files[p];
    if (!entry) { diff.push('+ ' + p); continue; }
    if (await Cipher.sha256Hex(await fs.readFile(abs)) !== entry.hash) diff.push('~ ' + p);
  }
  for (const p of Object.keys(contents.files)) if (!files.has(p)) diff.push('- ' + p);
  return diff;
}
function parseCatalog(text) {
  if (text === null) return null;
  try { return JSON.parse(text); } catch (e) { return { error: e.message }; }
}

// No page path may collide with a public file; every tile must lead to an existing page.
function checkPaths(paths, catalog) {
  const errors = [], warnings = [];
  const set = new Set(paths);
  const roots = new Set(paths.map((p) => p.split('/')[0]));
  for (const p of paths) if (!isSafePath(p)) errors.push(`Nepovolená cesta „${p}“.`);
  for (const r of roots) if (Cipher.isReserved(r)) errors.push(`„${r}“ v kořeni trezoru koliduje s veřejným souborem nebo složkou.`);
  for (const r of roots) {
    if (r.startsWith('_') || !paths.some((p) => p.startsWith(r + '/'))) continue;
    if (!PAGE_PATH.test(r)) warnings.push(`Složka „${r}“ nemá tvar adresy (malá písmena bez diakritiky, číslice, pomlčky).`);
  }
  if (!catalog) { warnings.push('V trezoru chybí catalog.json, rozcestník bude prázdný.'); return { errors, warnings }; }
  if (catalog.error) { errors.push('catalog.json není platný JSON: ' + catalog.error); return { errors, warnings }; }
  if (!Array.isArray(catalog.tiles)) { errors.push('catalog.json nemá pole tiles.'); return { errors, warnings }; }
  const seen = new Set();
  for (const t of catalog.tiles) {
    const a = t && t.path;
    if (typeof a !== 'string' || !PAGE_PATH.test(a)) { errors.push(`Adresa dlaždice „${a}“ smí mít jen malá písmena bez diakritiky, číslice a pomlčky.`); continue; }
    if (Cipher.isReserved(a)) errors.push(`Adresa „${a}“ koliduje s veřejným souborem nebo složkou.`);
    if (seen.has(a)) errors.push(`Adresa „${a}“ je v katalogu dvakrát.`);
    seen.add(a);
    if (!set.has(a + '/index.html')) errors.push(`Dlaždice „${a}“ vede na stránku bez ${a}/index.html.`);
  }
  return { errors, warnings };
}

async function installHook() {
  if (!inGitRoot()) return;
  const dir = path.resolve(ROOT, git(['rev-parse', '--git-path', 'hooks']).trim());
  const file = path.join(dir, 'pre-commit');
  if (existsSync(file) && !(await fs.readFile(file, 'utf8')).includes(HOOK_MARKER)) {
    console.warn('Upozornění: git hook pre-commit už existuje a není od tools/vault.mjs, nechávám ho být.');
    return;
  }
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(file, HOOK);
  await fs.chmod(file, 0o755);
}

// ---------- commands ----------
async function init() {
  if (existsSync(LOCKS) || existsSync(CONTENTS)) stop('Trezor už existuje (vault/locks.json); přes existující se nový nezakládá.');
  const password = process.env.VAULT_PASSWORD;
  if (!password) stop('Chybí proměnná VAULT_PASSWORD s heslem.');
  checkStrength(password, 'VAULT_PASSWORD');
  const key = await newDataKey();
  const { locks, text } = await newLocks(key, password);
  await fs.mkdir(BLOCKS, { recursive: true });
  await writeAtomic(LOCKS, JSON.stringify(locks, null, 2) + '\n');
  await writeContents(key, { v: 1, version: 1, time: new Date().toISOString(), files: {} });
  const existing = (await walkSrc()).size;
  await writeMarker(1);
  await installHook();
  console.log('Trezor je založený (verze 1, prázdný).' +
    (existing ? ` Ve src/ už je ${existing} souborů, zašifruje je příkaz seal.` : ''));
  printRecoveryKey(text);
}

async function open() {
  const { key } = await unlockVault();
  const contents = await readContents(key);
  const existing = await walkSrc();
  if (existing.size) {
    const diff = await diffAgainstSrc(contents, existing);
    if (diff.length && !force) {
      stop(`src/ obsahuje neuložené změny (${diff.length}): ${diff.slice(0, 10).join(', ')}${diff.length > 10 ? ', …' : ''}\n` +
        'Zapečeť je (seal), nebo je zahoď volbou --force.');
    }
    if (diff.length) await fs.rm(SRC, { recursive: true, force: true });
  }
  await fs.mkdir(SRC, { recursive: true });
  let n = 0;
  for (const [p, entry] of Object.entries(contents.files)) {
    if (!isSafePath(p)) stop(`Nepovolená cesta v trezoru: ${p}`);
    const data = await readBlock(key, entry);
    if (await Cipher.sha256Hex(data) !== entry.hash) stop(`Otisk souboru ${p} nesouhlasí.`);
    const target = path.join(SRC, ...p.split('/'));
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, data);
    n++;
  }
  await writeMarker(contents.version);
  await installHook();
  console.log(`Trezor ve verzi ${contents.version} je otevřený do src/ (${n} souborů).`);
}

async function seal() {
  const { key } = await unlockVault();
  const old = await readContents(key);
  const marker = await readMarker();
  if (!marker) stop('src/ není otevřený trezor (chybí src/' + MARKER + '). Nejdřív spusť open.');
  if (marker.version !== old.version && !force) {
    stop(`Trezor se od otevření změnil (otevřená verze ${marker.version}, teď ${old.version}). Otevři ho znovu, nebo použij --force.`);
  }
  const files = await walkSrc();
  if (!files.size && Object.keys(old.files).length && !force) {
    stop('src/ je prázdný, zapečetění by smazalo celý obsah trezoru. Je-li to záměr, použij --force.');
  }
  // hashes and the path check first, only then is anything written
  const items = [];
  for (const [p, abs] of files) {
    const data = await fs.readFile(abs);
    if (data.length > MAX_SIZE) stop(`Soubor ${p} je větší než 95 MB, GitHub ho nepřijme.`);
    if (data.length > WARN_SIZE) console.warn(`Upozornění: ${p} má ${(data.length / 1048576).toFixed(0)} MB.`);
    items.push({ path: p, abs, size: data.length, hash: await Cipher.sha256Hex(data) });
  }
  const catalog = parseCatalog(files.has('catalog.json') ? await fs.readFile(files.get('catalog.json'), 'utf8') : null);
  const report = checkPaths(items.map((i) => i.path), catalog);
  report.warnings.forEach((w) => console.warn('Upozornění: ' + w));
  if (report.errors.length) {
    if (!force) stop('Zapečetění zastaveno:\n  ' + report.errors.join('\n  '));
    report.errors.forEach((e) => console.warn('Chyba (přeskočeno volbou --force): ' + e));
  }

  await fs.mkdir(BLOCKS, { recursive: true });
  const existing = new Set(await blocksOnDisk());
  const next = { v: 1, version: old.version + 1, time: new Date().toISOString(), files: {} };
  let kept = 0, added = 0;
  for (const i of items) {
    const prev = old.files[i.path];
    const type = typeOf(i.path);
    if (prev && prev.hash === i.hash && prev.size === i.size && existing.has(prev.block)) {
      next.files[i.path] = { block: prev.block, type, size: prev.size, hash: prev.hash };
      kept++;
      continue;
    }
    let id;
    do { id = Cipher.newId(); } while (existing.has(id));
    existing.add(id);
    await writeAtomic(path.join(BLOCKS, id + '.bin'), await Cipher.encryptBlock(key, id, await fs.readFile(i.abs)));
    next.files[i.path] = { block: id, type, size: i.size, hash: i.hash };
    added++;
  }
  const removed = Object.keys(old.files).filter((p) => !next.files[p]);
  const typeChanged = Object.keys(next.files).some((p) => old.files[p] && old.files[p].type !== next.files[p].type);
  const changed = added || removed.length || typeChanged;
  if (changed) await writeContents(key, next);
  const live = new Set(Object.values(changed ? next.files : old.files).map((e) => e.block));
  let deleted = 0;
  for (const b of existing) {
    if (!live.has(b)) { await fs.rm(path.join(BLOCKS, b + '.bin'), { force: true }); deleted++; }
  }
  await writeMarker(changed ? next.version : old.version);
  await installHook();
  if (!changed) { console.log(`Beze změn, trezor zůstává ve verzi ${old.version}.`); return; }
  console.log(`Zapečetěno: verze ${next.version}, ${items.length} souborů (beze změny ${kept}, ` +
    `nově zašifrovaných ${added}, odebraných ${removed.length}, smazaných bloků ${deleted}).`);
}

async function password() {
  const fresh = process.env.VAULT_NEW_PASSWORD;
  if (!fresh) stop('Chybí proměnná VAULT_NEW_PASSWORD s novým heslem.');
  checkStrength(fresh, 'VAULT_NEW_PASSWORD');
  const { key, locks } = await unlockVault();
  const lock = await Cipher.createLock(key, 'password', Cipher.passwordInput(fresh));
  const next = { v: 1, locks: [lock, ...locks.locks.filter((l) => l.kind !== 'password')] };
  await writeAtomic(LOCKS, JSON.stringify(next, null, 2) + '\n');
  console.log('Heslo je změněné. Obsah se znovu nešifroval; zařízení se zapamatovaným klíčem fungují dál, ' +
    'ostatní se zeptají na nové heslo. Záchranný klíč platí dál.');
}

async function rotate() {
  const { key: oldKey } = await unlockVault();
  const pw = process.env.VAULT_NEW_PASSWORD || process.env.VAULT_PASSWORD;
  if (Cipher.isRecoveryKey(pw)) stop('Po odemčení záchranným klíčem zadej nové heslo v proměnné VAULT_NEW_PASSWORD.');
  checkStrength(pw, process.env.VAULT_NEW_PASSWORD ? 'VAULT_NEW_PASSWORD' : 'VAULT_PASSWORD');
  const contents = await readContents(oldKey);
  const files = await walkSrc();
  if (files.size) {
    const diff = await diffAgainstSrc(contents, files);
    if (diff.length && !force) stop(`src/ obsahuje nezapečetěné změny (${diff.length}); nejdřív spusť seal.`);
  }
  const key = await newDataKey();
  const oldBlocks = await blocksOnDisk();
  const used = new Set(oldBlocks);
  const next = { v: 1, version: contents.version + 1, time: new Date().toISOString(), files: {} };
  for (const [p, entry] of Object.entries(contents.files)) {
    const data = await readBlock(oldKey, entry);
    let id;
    do { id = Cipher.newId(); } while (used.has(id));
    used.add(id);
    await writeAtomic(path.join(BLOCKS, id + '.bin'), await Cipher.encryptBlock(key, id, data));
    next.files[p] = { block: id, type: entry.type, size: entry.size, hash: entry.hash };
  }
  const { locks, text } = await newLocks(key, pw);
  await writeContents(key, next);
  await writeAtomic(LOCKS, JSON.stringify(locks, null, 2) + '\n');
  for (const b of oldBlocks) await fs.rm(path.join(BLOCKS, b + '.bin'), { force: true });
  if (await readMarker()) await writeMarker(next.version);
  console.log(`Rotace hotová: nový datový klíč, vše znovu zašifrované (verze ${next.version}, ${Object.keys(next.files).length} souborů).\n` +
    'Starý záchranný klíč přestal platit. Zařízení se zeptají na heslo znovu. Data uložená stránkami v zařízeních\n' +
    'byla zašifrovaná starým klíčem a už nepůjdou přečíst (před rotací je exportuj). Staré verze v historii gitu\n' +
    'zůstávají čitelné starým heslem; úplně pomůže jen nový repozitář.');
  printRecoveryKey(text);
}

async function check() {
  const errors = [], warnings = [], ok = [];
  let gitBlocks = null;
  if (inGitRoot()) {
    const tracked = git(['ls-files', '-z']).split('\0').filter(Boolean);
    const foreign = tracked.filter((f) => !Cipher.isPublicFile(f));
    if (foreign.length) errors.push('V gitu jsou soubory mimo seznam veřejných: ' + foreign.join(', '));
    else ok.push(`v gitu jen veřejné soubory (${tracked.length})`);
    try { git(['check-ignore', '-q', 'src/x']); } catch { errors.push('Složka src/ není v .gitignore.'); }
    const unstaged = [
      ...git(['diff', '--name-only', '-z', '--', 'vault']).split('\0'),
      ...git(['ls-files', '--others', '--exclude-standard', '-z', '--', 'vault']).split('\0')
    ].filter(Boolean);
    if (unstaged.length) errors.push('Změny ve vault/ nejsou přidané do commitu (git add vault): ' + unstaged.join(', '));
    gitBlocks = new Set(tracked.filter((f) => f.startsWith('vault/blocks/')).map((f) => f.slice(13, 29)));
  } else {
    warnings.push('Nejsem v kořeni gitového repozitáře, kontrolu gitu přeskakuji.');
  }
  const index = path.join(ROOT, 'index.html'), notFound = path.join(ROOT, '404.html');
  if (existsSync(index) && existsSync(notFound) && !(await fs.readFile(index)).equals(await fs.readFile(notFound))) {
    errors.push('404.html není kopií index.html.');
  }

  const { key, locks } = await unlockVault();
  if (!locks.locks.some((l) => l.kind === 'recovery')) warnings.push('Trezor nemá záchranný zámek.');
  const contents = await readContents(key);
  const paths = Object.keys(contents.files);
  let bad = 0;
  for (const p of paths) {
    const entry = contents.files[p];
    try {
      const data = await readBlock(key, entry);
      if (await Cipher.sha256Hex(data) !== entry.hash) throw new Error('hash');
    } catch {
      bad++;
      errors.push(`Blok ${entry.block} (${p}) chybí, nejde dešifrovat nebo nesouhlasí otisk.`);
    }
  }
  if (!bad) ok.push(`všech ${paths.length} bloků jde dešifrovat a otisky souhlasí (verze ${contents.version})`);
  const referenced = new Set(paths.map((p) => contents.files[p].block));
  const orphans = (await blocksOnDisk()).filter((b) => !referenced.has(b));
  if (orphans.length) errors.push(`Ve vault/blocks/ jsou bloky, na které nic neodkazuje: ${orphans.join(', ')}`);
  if (gitBlocks) {
    const missing = [...referenced].filter((b) => !gitBlocks.has(b));
    const extra = [...gitBlocks].filter((b) => !referenced.has(b));
    if (missing.length) errors.push('Bloky ze seznamu nejsou v gitu: ' + missing.join(', '));
    if (extra.length) errors.push('V gitu jsou bloky mimo seznam: ' + extra.join(', '));
  }
  let catalog = null;
  if (contents.files['catalog.json']) {
    try { catalog = parseCatalog(new TextDecoder().decode(await readBlock(key, contents.files['catalog.json']))); }
    catch { catalog = { error: 'nejde dešifrovat' }; }
  }
  const report = checkPaths(paths, catalog);
  errors.push(...report.errors);
  warnings.push(...report.warnings);
  if (!report.errors.length) ok.push('žádná adresa nekoliduje s veřejnými soubory');

  ok.forEach((t) => console.log('OK: ' + t));
  warnings.forEach((t) => console.warn('Upozornění: ' + t));
  if (errors.length) {
    console.error('Kontrola našla chyby:\n  ' + errors.join('\n  '));
    process.exitCode = 1;
  } else {
    console.log('Kontrola v pořádku.');
  }
}

const COMMANDS = { init, open, seal, password, rotate, check };
const HELP = `Použití: VAULT_PASSWORD=… node tools/vault.mjs <příkaz> [--force]
  init      nový trezor: datový klíč, zámek pro heslo a záchranný klíč (vypíše ho jedinkrát)
  open      dešifruje trezor do src/
  seal      zašifruje src/ (nezměněné soubory si nechají svůj blok)
  password  nové heslo z VAULT_NEW_PASSWORD (jen nové zabalení klíče)
  rotate    nový datový klíč a nové zašifrování všeho, nový záchranný klíč
  check     ověří git, adresy a dešifrování všech bloků (spouští se jako pre-commit)`;

const command = process.argv[2];
if (Number(process.versions.node.split('.')[0]) < 20) {
  console.error('Chyba: nástroj potřebuje Node 20 nebo novější.');
  process.exit(1);
}
if (!COMMANDS[command]) {
  console.log(HELP);
  process.exit(command ? 1 : 0);
}
try {
  await COMMANDS[command]();
} catch (e) {
  console.error('Chyba: ' + (e instanceof Stop ? e.message : (e && e.stack) || e));
  process.exit(1);
}
