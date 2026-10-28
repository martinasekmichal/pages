/* Shared vault functions (WebCrypto) for the loader, the Service Worker, pages and tools/vault.mjs.
   Format v1: block = 12-byte IV + AES-256-GCM(content zero-padded to a multiple of 4 KiB) incl. the 16-byte tag;
   the block id is authenticated as additional data. The data key is wrapped by keys derived with PBKDF2-SHA256
   from the password or from the recovery key (vault/locks.json). */
(function (g) {
  'use strict';
  var subtle = g.crypto && g.crypto.subtle;
  var encoder = new TextEncoder();
  var decoder = new TextDecoder();
  var BLOCK = 4096;
  var IV_LENGTH = 12;
  var ITERATIONS = 600000;
  var KDF = 'PBKDF2-SHA256';
  var PREFIX = 'pages-';
  var CONTENTS_AAD = 'contents';
  var ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';   // Crockford base32: no I, L, O, U
  var FORGET_AFTER_MS = 12 * 3600 * 1000;

  // Public files: the Service Worker passes them to the network and the check lets nothing else into git.
  var PUBLIC_FILES = ['index.html', '404.html', 'loader.js', 'sw.js', 'cipher.js', 'manifest.webmanifest', 'icon.png',
    'README.md', '.gitignore', '.nojekyll', 'vault/locks.json', 'vault/contents.bin', 'tools/vault.mjs'];
  var PUBLIC_PATTERNS = [/^vault\/blocks\/[0-9a-f]{16}\.bin$/];
  var PUBLIC_DIRS = ['vault/', 'tools/'];
  // Names no file or folder in the vault root may have (compared case-insensitively).
  var RESERVED = ['index.html', '404.html', 'loader.js', 'sw.js', 'cipher.js', 'manifest.webmanifest', 'icon.png',
    'readme.md', '.gitignore', '.nojekyll', 'vault', 'tools', 'src', '.git'];

  function error(code, message) {
    var e = new Error(message || code);
    e.code = code;
    return e;
  }

  // path relative to the scope, without the leading slash; '' is the hub
  function isPublicPath(path) {
    if (path === '' || PUBLIC_FILES.indexOf(path) >= 0) return true;
    for (var i = 0; i < PUBLIC_DIRS.length; i++) {
      var dir = PUBLIC_DIRS[i];
      if (path.indexOf(dir) === 0 || path + '/' === dir) return true;
    }
    return false;
  }
  function isPublicFile(path) {   // may be committed to git
    if (PUBLIC_FILES.indexOf(path) >= 0) return true;
    for (var i = 0; i < PUBLIC_PATTERNS.length; i++) if (PUBLIC_PATTERNS[i].test(path)) return true;
    return false;
  }
  function isReserved(name) { return RESERVED.indexOf(String(name).toLowerCase()) >= 0; }

  // ---------- encoding ----------
  function toBase64(data) {
    var b = new Uint8Array(data), s = '';
    for (var i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function fromBase64(text) {
    var s = atob(text), b = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
    return b;
  }
  function toHex(data) {
    var b = new Uint8Array(data), s = '';
    for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
    return s;
  }
  function randomBytes(n) { return g.crypto.getRandomValues(new Uint8Array(n)); }
  function newId() { return toHex(randomBytes(8)); }
  function base32(bytes) {
    var out = '', bits = 0, value = 0;
    for (var i = 0; i < bytes.length; i++) {
      value = ((value & 0xff) << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
    return out;
  }
  function fromBase32(text) {
    var bytes = [], bits = 0, value = 0;
    for (var i = 0; i < text.length; i++) {
      var v = ALPHABET.indexOf(text[i]);
      if (v < 0) throw error('typo');
      value = ((value & 0xff) << 5) | v;
      bits += 5;
      if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
    }
    return new Uint8Array(bytes);
  }
  function sha256(data) { return subtle.digest('SHA-256', data); }
  function sha256Hex(data) { return sha256(data).then(toHex); }

  // ---------- password and recovery key ----------
  function passwordInput(password) { return encoder.encode(String(password).normalize('NFC').trim()); }
  function isRecoveryKey(text) { return /^\s*zk[-\s]/i.test(String(text)); }

  // 32 bytes → 'ZK-XXXX-…' (14 groups of 4 characters; the last 3 bytes are a checksum against typos)
  function recoveryKeyText(key32) {
    return sha256(key32).then(function (h) {
      var all = new Uint8Array(35);
      all.set(key32);
      all.set(new Uint8Array(h).subarray(0, 3), 32);
      return 'ZK-' + base32(all).match(/.{4}/g).join('-');
    });
  }
  function parseRecoveryKey(text) {
    var t = String(text).toUpperCase().replace(/^\s*ZK[-\s]*/, '').replace(/[\s-]/g, '')
      .replace(/O/g, '0').replace(/[IL]/g, '1');
    if (t.length !== 56) return Promise.reject(error('typo'));
    var all;
    try { all = fromBase32(t); } catch (e) { return Promise.reject(e); }
    var key = all.slice(0, 32), checksum = all.subarray(32, 35);
    return sha256(key).then(function (h) {
      h = new Uint8Array(h);
      if (h[0] !== checksum[0] || h[1] !== checksum[1] || h[2] !== checksum[2]) throw error('typo');
      return key;
    });
  }

  // ---------- locks ----------
  function lockKey(input, salt, iterations) {
    return subtle.importKey('raw', input, 'PBKDF2', false, ['deriveKey']).then(function (base) {
      return subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iterations }, base,
        { name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']);
    });
  }
  // Wrapping needs an extractable data key, so it happens only in the tool; browsers only unwrap.
  function createLock(dataKey, kind, input) {
    var salt = randomBytes(16), iv = randomBytes(IV_LENGTH);
    return lockKey(input, salt, ITERATIONS).then(function (kek) {
      return subtle.wrapKey('raw', dataKey, kek, { name: 'AES-GCM', iv: iv });
    }).then(function (wrapped) {
      return { id: toHex(randomBytes(4)), kind: kind, kdf: KDF, iter: ITERATIONS, salt: toBase64(salt), iv: toBase64(iv),
        wrappedKey: toBase64(wrapped) };
    });
  }
  function unwrapDataKey(lock, kek, extractable) {
    return subtle.unwrapKey('raw', fromBase64(lock.wrappedKey), kek, { name: 'AES-GCM', iv: fromBase64(lock.iv) },
      { name: 'AES-GCM' }, !!extractable, ['encrypt', 'decrypt']);
  }
  // Text starting with ZK- is tried only on recovery locks, anything else only on password locks.
  // → { key, lock }; errors with code 'format', 'typo' or 'wrong-password'
  function unlock(locks, text, extractable) {
    if (!locks || locks.v !== 1 || !Array.isArray(locks.locks)) return Promise.reject(error('format'));
    var recovery = isRecoveryKey(text);
    var kind = recovery ? 'recovery' : 'password';
    var candidates = locks.locks.filter(function (l) { return l && l.kind === kind && l.kdf === KDF; });
    var input = recovery ? parseRecoveryKey(text) : Promise.resolve(passwordInput(text));
    return input.then(function (bytes) {
      var i = 0;
      function next() {
        if (i >= candidates.length) throw error('wrong-password');
        var lock = candidates[i++];
        return lockKey(bytes, fromBase64(lock.salt), lock.iter)
          .then(function (kek) { return unwrapDataKey(lock, kek, extractable); })
          .then(function (key) { return { key: key, lock: lock }; },
            function (e) { if (e && e.name === 'OperationError') return next(); throw e; });
      }
      return next();
    });
  }

  // ---------- encryption ----------
  function encrypt(key, aad, data) {
    var iv = randomBytes(IV_LENGTH);
    return subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: encoder.encode(aad) }, key, data).then(function (ct) {
      var out = new Uint8Array(IV_LENGTH + ct.byteLength);
      out.set(iv);
      out.set(new Uint8Array(ct), IV_LENGTH);
      return out;
    });
  }
  function decrypt(key, aad, data) {
    var b = data instanceof Uint8Array ? data : new Uint8Array(data);
    if (b.length < IV_LENGTH + 16) return Promise.reject(error('format'));
    return subtle.decrypt({ name: 'AES-GCM', iv: b.subarray(0, IV_LENGTH), additionalData: encoder.encode(aad) }, key,
      b.subarray(IV_LENGTH)).then(function (p) { return new Uint8Array(p); });
  }
  function pad(data) {
    var b = data instanceof Uint8Array ? data : new Uint8Array(data);
    var n = Math.max(BLOCK, Math.ceil(b.length / BLOCK) * BLOCK);
    if (n === b.length) return b;
    var out = new Uint8Array(n);
    out.set(b);
    return out;
  }
  function encryptBlock(key, id, data) { return encrypt(key, id, pad(data)); }
  function decryptBlock(key, id, data, size) {
    return decrypt(key, id, data).then(function (p) {
      if (typeof size !== 'number') return p;
      if (size > p.length) throw error('format');
      return p.subarray(0, size);
    });
  }
  function encryptContents(key, contents) { return encryptBlock(key, CONTENTS_AAD, encoder.encode(JSON.stringify(contents))); }
  function decryptContents(key, data) {
    return decryptBlock(key, CONTENTS_AAD, data).then(function (p) {
      var n = p.length;
      while (n > 0 && p[n - 1] === 0) n--;
      var c = JSON.parse(decoder.decode(p.subarray(0, n)));
      if (!c || c.v !== 1 || !c.files || typeof c.files !== 'object') throw error('format');
      return c;
    });
  }

  // ---------- data key remembered on the device (IndexedDB, non-extractable CryptoKey) ----------
  var KEY_DB = PREFIX + 'vault', KEY_STORE = 'key', KEY_RECORD = 'data-key';
  function openDb(name, store) {
    return new Promise(function (resolve, reject) {
      if (!g.indexedDB) { reject(error('idb')); return; }
      var r = g.indexedDB.open(name, 1);
      r.onupgradeneeded = function () { if (!r.result.objectStoreNames.contains(store)) r.result.createObjectStore(store); };
      r.onsuccess = function () { resolve(r.result); };
      r.onerror = function () { reject(r.error || error('idb')); };
      r.onblocked = function () { reject(error('idb')); };
    });
  }
  function inTransaction(name, store, mode, work) {
    return openDb(name, store).then(function (db) {
      return new Promise(function (resolve, reject) {
        var t = db.transaction(store, mode), request = work(t.objectStore(store)), result;
        if (request) request.onsuccess = function () { result = request.result; };
        t.oncomplete = function () { db.close(); resolve(result); };
        t.onerror = t.onabort = function () { db.close(); reject(t.error || error('idb')); };
      });
    });
  }
  function saveKey(key, forget) {
    var record = { key: key, expires: forget ? Date.now() + FORGET_AFTER_MS : null, saved: Date.now(), id: newId() };
    return inTransaction(KEY_DB, KEY_STORE, 'readwrite', function (s) { return s.put(record, KEY_RECORD); })
      .then(function () { return record; });
  }
  function deleteKey() {
    return inTransaction(KEY_DB, KEY_STORE, 'readwrite', function (s) { return s.delete(KEY_RECORD); });
  }
  function loadKey() {   // → record { key, expires, saved, id } or null; an expired record is deleted
    return inTransaction(KEY_DB, KEY_STORE, 'readonly', function (s) { return s.get(KEY_RECORD); }).then(function (r) {
      if (!r || !r.key) return null;
      if (r.expires && Date.now() > r.expires) return deleteKey().then(function () { return null; });
      return r;
    });
  }
  function clearCaches() {
    if (!g.caches) return Promise.resolve();
    return g.caches.keys().then(function (names) {
      return Promise.all(names.filter(function (n) { return n.indexOf(PREFIX) === 0; })
        .map(function (n) { return g.caches.delete(n); }));
    });
  }
  // Lock from a page: deletes the key from IndexedDB and from the Service Worker's memory, and the encrypted blocks from the cache.
  function lock() {
    var sw = g.navigator && g.navigator.serviceWorker;
    var notify = !sw ? Promise.resolve() : sw.getRegistration().then(function (reg) {
      var worker = (reg && reg.active) || sw.controller;
      if (!worker) return;
      return new Promise(function (resolve) {
        var channel = new MessageChannel();
        var timer = setTimeout(resolve, 3000);
        channel.port1.onmessage = function () { clearTimeout(timer); resolve(); };
        worker.postMessage({ type: 'lock' }, [channel.port2]);
      });
    }).catch(function () {});
    return deleteKey().catch(function () {})
      .then(function () { return notify; })
      .then(function () { return clearCaches().catch(function () {}); });
  }

  var Cipher = {
    VERSION: 1, BLOCK: BLOCK, ITERATIONS: ITERATIONS, KDF: KDF, PREFIX: PREFIX, FORGET_AFTER_MS: FORGET_AFTER_MS,
    PUBLIC_FILES: PUBLIC_FILES, RESERVED: RESERVED,
    isPublicPath: isPublicPath, isPublicFile: isPublicFile, isReserved: isReserved, error: error,
    toBase64: toBase64, fromBase64: fromBase64, toHex: toHex, randomBytes: randomBytes, newId: newId,
    sha256: sha256, sha256Hex: sha256Hex,
    passwordInput: passwordInput, isRecoveryKey: isRecoveryKey, recoveryKeyText: recoveryKeyText, parseRecoveryKey: parseRecoveryKey,
    lockKey: lockKey, createLock: createLock, unwrapDataKey: unwrapDataKey, unlock: unlock,
    encrypt: encrypt, decrypt: decrypt, pad: pad, encryptBlock: encryptBlock, decryptBlock: decryptBlock,
    encryptContents: encryptContents, decryptContents: decryptContents,
    openDb: openDb, inTransaction: inTransaction, saveKey: saveKey, loadKey: loadKey, deleteKey: deleteKey,
    clearCaches: clearCaches, lock: lock
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = Cipher;
  else g.Cipher = Cipher;
})(typeof globalThis !== 'undefined' ? globalThis : self);
