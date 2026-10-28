/* Vault Service Worker: finds page files in the encrypted contents list, decrypts them on the fly and returns them.
   Nothing decrypted is stored; only encrypted blocks go to Cache Storage. The loader, vault/ and tools/ go to the network. */
'use strict';
importScripts('cipher.js');

var BASE = new URL(self.registration.scope);
var SCOPE = BASE.pathname;
var CACHE = Cipher.PREFIX + 'blocks';
var CONTENTS_URL = new URL('vault/contents.bin', BASE).href;
var memory = null;    // { keyId, version, files } – the decrypted contents list, in memory only
var loading = null;   // { keyId, promise }

self.addEventListener('install', function () { self.skipWaiting(); });

self.addEventListener('activate', function (e) {
  e.waitUntil(caches.keys().then(function (names) {
    return Promise.all(names.filter(function (n) { return n.indexOf(Cipher.PREFIX) === 0 && n !== CACHE; })
      .map(function (n) { return caches.delete(n); }));
  }).then(function () { return self.clients.claim(); }));
});

self.addEventListener('message', function (e) {
  var d = e.data || {};
  if (d.type !== 'lock') return;
  memory = null;
  loading = null;
  e.waitUntil(Cipher.clearCaches().catch(function () {}).then(function () {
    if (e.ports && e.ports[0]) e.ports[0].postMessage({ ok: true });
  }));
});

self.addEventListener('fetch', function (e) {
  var request = e.request;
  if (request.method !== 'GET') return;
  var url = new URL(request.url);
  if (url.origin !== self.location.origin || url.pathname.indexOf(SCOPE) !== 0) return;
  var path;
  try { path = decodeURIComponent(url.pathname.slice(SCOPE.length)).normalize('NFC'); } catch (err) { return; }
  if (Cipher.isPublicPath(path)) return;
  e.respondWith(serve(request, url, path));
});

function serve(request, url, path) {
  var navigation = request.mode === 'navigate';
  var record;
  return Cipher.loadKey().catch(function () { return null; }).then(function (r) {
    record = r;
    if (!record) return navigation ? lockScreen() : empty(401);
    return loadContents(record, navigation).then(function (contents) {
      var wanted = (path === '' || /\/$/.test(path)) ? path + 'index.html' : path;
      var entry = contents.files[wanted];
      if (!entry) {
        if (contents.files[wanted + '/index.html']) return Response.redirect(new URL(url.pathname + '/' + url.search, url).href, 301);
        return navigation ? message(404, 'Stránka nenalezena', 'Na této adrese žádná stránka není.') : empty(404);
      }
      return loadBlock(record.key, entry).then(function (data) {
        return new Response(data, { status: 200, headers: {
          'Content-Type': entry.type || 'application/octet-stream',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff'
        } });
      });
    }, function (err) {
      if (err && err.code === 'key') {
        // after a rotation the vault has a new key: forget the old one and show the lock
        return Cipher.deleteKey().catch(function () {}).then(function () { return navigation ? lockScreen() : empty(401); });
      }
      return navigation ? message(503, 'Trezor se nepodařilo načíst', 'Zkontroluj připojení k internetu a obnov stránku.') : empty(503);
    });
  }).catch(function () {
    return navigation ? message(500, 'Soubor se nepodařilo otevřít', 'Obnov stránku; když to nepomůže, zamkni a odemkni znovu.') : empty(500);
  });
}

// Contents list: fresh from the network on every navigation (its version reveals a new upload), otherwise from memory.
function loadContents(record, fresh) {
  if (memory && memory.keyId === record.id && !fresh) return Promise.resolve(memory);
  if (loading && loading.keyId === record.id) return loading.promise;
  var promise = fetch(CONTENTS_URL, { cache: 'no-store' }).then(function (r) {
    if (!r.ok) throw Cipher.error('network');
    return r.arrayBuffer().then(function (data) {
      return caches.open(CACHE).then(function (c) { return c.put(CONTENTS_URL, new Response(data)); })
        .catch(function () {}).then(function () { return data; });
    });
  }).catch(function () {
    // offline: the last known list from memory, or its encrypted copy from the cache
    if (memory && memory.keyId === record.id) return null;
    return caches.open(CACHE).then(function (c) { return c.match(CONTENTS_URL); }).then(function (r) {
      if (!r) throw Cipher.error('network');
      return r.arrayBuffer();
    });
  }).then(function (data) {
    if (data === null) return memory;
    return Cipher.decryptContents(record.key, data).then(function (c) {
      var next = { keyId: record.id, version: c.version, files: c.files };
      if (!memory || memory.version !== next.version) prune(next);
      memory = next;
      return next;
    }, function (e) {
      throw Cipher.error(e && e.name === 'OperationError' ? 'key' : 'format');
    });
  });
  loading = { keyId: record.id, promise: promise };
  var done = function () { if (loading && loading.promise === promise) loading = null; };
  promise.then(done, done);
  return promise;
}

// Block: the encrypted copy from Cache Storage first, otherwise from the network (bypassing the HTTP cache so it can be fully cleared).
function loadBlock(key, entry, again) {
  var url = new URL('vault/blocks/' + entry.block + '.bin', BASE).href;
  return caches.open(CACHE).then(function (cache) {
    return cache.match(url).then(function (cached) {
      var fromCache = !!cached && !again;
      var get = fromCache ? Promise.resolve(cached) : fetch(url, { cache: 'no-store' }).then(function (r) {
        if (!r.ok) throw Cipher.error('network');
        return r;
      });
      return get.then(function (r) { return r.arrayBuffer(); }).then(function (data) {
        return Cipher.decryptBlock(key, entry.block, data, entry.size).then(function (plain) {
          if (!fromCache) cache.put(url, new Response(data)).catch(function () {});
          return plain;
        }, function (e) {
          if (fromCache) return cache.delete(url).then(function () { return loadBlock(key, entry, true); });
          throw e;
        });
      });
    });
  });
}

// After a new upload, removes cached blocks the contents list no longer refers to.
function prune(contents) {
  var live = {};
  live[CONTENTS_URL] = true;
  Object.keys(contents.files).forEach(function (p) {
    live[new URL('vault/blocks/' + contents.files[p].block + '.bin', BASE).href] = true;
  });
  caches.open(CACHE).then(function (cache) {
    return cache.keys().then(function (requests) {
      return Promise.all(requests.filter(function (r) { return !live[r.url]; }).map(function (r) { return cache.delete(r); }));
    });
  }).catch(function () {});
}

// Without a key the page is replaced by the loader with its lock; after unlocking it opens the same address.
function lockScreen() {
  return fetch(new URL('index.html', BASE).href, { cache: 'no-store' }).then(function (r) {
    if (!r.ok) throw new Error('http ' + r.status);
    return r.text();
  }).then(function (html) {
    return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
  }).catch(function () {
    return message(503, 'Zamčeno', 'K odemčení je potřeba připojení k internetu.');
  });
}

function empty(status) {
  return new Response(null, { status: status, headers: { 'Cache-Control': 'no-store' } });
}

function message(status, title, text) {
  var html = '<!doctype html><html lang="cs"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex, nofollow">' +
    '<title>' + title + '</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;' +
    'font:16px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#eef2ef;color:#16201a}' +
    'main{max-width:380px;background:#fff;border-radius:16px;padding:22px 20px;box-shadow:0 4px 24px rgba(0,0,0,.12)}' +
    'h1{font-size:20px;margin:0 0 8px}a{display:inline-block;margin-top:14px;padding:10px 18px;border-radius:999px;' +
    'background:#1e5b40;color:#fff;text-decoration:none;font-weight:600}' +
    '@media (prefers-color-scheme:dark){body{background:#121815;color:#e6ece8}main{background:#1c2420}}</style></head>' +
    '<body><main><h1>' + title + '</h1><p>' + text + '</p><a href="' + SCOPE + '">Na rozcestník</a></main></body></html>';
  return new Response(html, { status: status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}
