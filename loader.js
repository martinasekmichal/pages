/* Loader: password lock, remembering the key on the device, the hub, and returning to the address that was opened.
   Generic code without content; pages, the catalog and data are encrypted in the vault. UI texts are Czech. */
(function () {
  'use strict';
  var BASE = new URL(document.baseURI);
  var TARGET = location.href;
  var path = relativePath();
  var onHub = path === '' || path === 'index.html' || path === '404.html';
  var swSupported = 'serviceWorker' in navigator && window.isSecureContext;
  var registration = swSupported
    ? navigator.serviceWorker.register('sw.js', { scope: './', updateViaCache: 'none' }).catch(function () { return null; })
    : Promise.resolve(null);
  var ATTEMPT_KEY = 'pages.attempt';
  var $ = function (id) { return document.getElementById(id); };

  function relativePath() {
    var p = location.pathname;
    try { p = decodeURIComponent(p); } catch (e) { /* keep as is */ }
    p = p.normalize('NFC');
    return p.indexOf(BASE.pathname) === 0 ? p.slice(BASE.pathname.length) : '';
  }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function two(n) { return (n < 10 ? '0' : '') + n; }
  function clock(t) { var d = new Date(t); return d.getHours() + ':' + two(d.getMinutes()); }
  function date(t) { var d = new Date(t); return d.getDate() + '. ' + (d.getMonth() + 1) + '. ' + d.getFullYear() + ' ' + clock(t); }
  function withTimeout(promise, ms) { return Promise.race([promise, new Promise(function (r) { setTimeout(function () { r(null); }, ms); })]); }

  function show(id) {
    ['lock', 'hub', 'status'].forEach(function (s) { $(s).hidden = (s !== id); });
  }
  function showStatus(text, actions) {
    $('statusText').textContent = text;
    var box = $('statusActions');
    box.textContent = '';
    (actions || []).forEach(function (a) {
      var b = el(a.href ? 'a' : 'button', 'button' + (a.primary ? ' primary' : ''), a.text);
      if (a.href) b.href = a.href; else { b.type = 'button'; b.addEventListener('click', a.action); }
      box.appendChild(b);
    });
    show('status');
  }
  function lockMessage(text, kind) {
    var m = $('lockMessage');
    m.textContent = text || '';
    m.className = 'message' + (kind ? ' ' + kind : '');
  }
  function showLock(text, kind) {
    $('unlockButton').disabled = false;
    $('unlockButton').textContent = 'Odemknout';
    lockMessage(text, kind);
    show('lock');
    if (window.matchMedia('(pointer: fine)').matches) $('password').focus();
  }

  // ---------- vault ----------
  function download(address) {
    return fetch(address, { cache: 'no-store' }).then(function (r) {
      if (!r.ok) throw Cipher.error('network');
      return r;
    });
  }
  function loadContents(key) {
    return download('vault/contents.bin').then(function (r) { return r.arrayBuffer(); }).then(function (data) {
      return Cipher.decryptContents(key, data).catch(function (e) {
        throw Cipher.error(e && e.name === 'OperationError' ? 'key' : 'format');
      });
    });
  }
  function loadCatalog(key, contents) {
    var entry = contents.files['catalog.json'];
    if (!entry) return Promise.resolve(null);
    return download('vault/blocks/' + entry.block + '.bin').then(function (r) { return r.arrayBuffer(); })
      .then(function (data) { return Cipher.decryptBlock(key, entry.block, data, entry.size); })
      .then(function (bytes) { return JSON.parse(new TextDecoder().decode(bytes)); });
  }

  // ---------- start ----------
  function start() {
    Cipher.loadKey().catch(function () { return null; }).then(function (record) {
      if (!record) { showLock(''); return; }
      return loadContents(record.key).then(function (contents) {
        return proceed(record, contents);
      }, function (e) {
        if (e && e.code === 'key') {
          return Cipher.deleteKey().catch(function () {}).then(function () {
            showLock('Trezor má nový klíč, zadej heslo znovu.', 'warning');
          });
        }
        showStatus('Trezor se nepodařilo načíst. Zkontroluj připojení k internetu.', [
          { text: 'Zkusit znovu', primary: true, action: function () { location.reload(); } }
        ]);
      });
    });
  }

  $('lockForm').addEventListener('submit', function (e) {
    e.preventDefault();
    var text = $('password').value;
    if (!text.trim()) return;
    var forget = $('forget').checked;
    var recovery = Cipher.isRecoveryKey(text);
    $('unlockButton').disabled = true;
    $('unlockButton').textContent = 'Odemykám…';
    lockMessage('');
    var unlocked;
    download('vault/locks.json').then(function (r) { return r.json(); })
      .then(function (locks) { return Cipher.unlock(locks, text, false); })
      .then(function (u) { unlocked = u; return loadContents(u.key); })
      .then(function (contents) {
        return Cipher.saveKey(unlocked.key, forget).then(function (record) {
          $('password').value = '';
          return proceed(record, contents);
        });
      })
      .catch(function (err) {
        var code = err && err.code;
        var msg = code === 'wrong-password' ? (recovery ? 'Záchranný klíč nepasuje.' : 'Špatné heslo, zkus to znovu.')
          : code === 'typo' ? 'V záchranném klíči je překlep, zkontroluj znaky.'
          : code === 'idb' || (err && err.name === 'InvalidStateError') ? 'Prohlížeč nedovolil uložit klíč (soukromé okno?). Zkus běžné okno.'
          : code === 'key' ? 'Klíč nepasuje k obsahu trezoru. Obnov stránku a zkus to znovu.'
          : 'Trezor se nepodařilo načíst. Zkontroluj připojení k internetu.';
        showLock(msg, 'warning');
        $('password').select();
      });
  });

  function proceed(record, contents) {
    if (onHub) return renderHub(record, contents);
    var wanted = (path === '' || /\/$/.test(path)) ? path + 'index.html' : path;
    if (!contents.files[wanted] && !contents.files[wanted + '/index.html']) {
      showStatus('Na této adrese žádná stránka není.', [{ text: 'Na rozcestník', primary: true, href: BASE.href }]);
      return;
    }
    return openTarget();
  }

  // The Service Worker serves the subpage; the loader waits for it and opens the original address.
  function openTarget() {
    if (!swSupported) {
      showStatus('Tento prohlížeč neumí Service Worker, takže stránky z trezoru neotevře. Použij Chrome.', [
        { text: 'Na rozcestník', href: BASE.href }]);
      return;
    }
    showStatus('Otevírám stránku…');
    return registration.then(function (reg) {
      if (!reg) throw new Error('registration');
      return withTimeout(navigator.serviceWorker.ready, 15000);
    }).then(function (ready) {
      if (!ready) throw new Error('ready');
      if (repeatedAttempt()) {
        showStatus('Stránku se nepodařilo otevřít.', [
          { text: 'Zkusit znovu', primary: true, action: function () { forgetAttempt(); location.replace(TARGET); } },
          { text: 'Na rozcestník', href: BASE.href }]);
        return;
      }
      rememberAttempt();
      location.replace(TARGET);
    }).catch(function () {
      showStatus('Service Worker se nepodařilo spustit. Obnov stránku.', [
        { text: 'Obnovit', primary: true, action: function () { location.reload(); } }]);
    });
  }
  function repeatedAttempt() {
    try {
      var a = JSON.parse(sessionStorage.getItem(ATTEMPT_KEY) || 'null');
      return !!a && a.url === TARGET && Date.now() - a.time < 15000;
    } catch (e) { return false; }
  }
  function rememberAttempt() { try { sessionStorage.setItem(ATTEMPT_KEY, JSON.stringify({ url: TARGET, time: Date.now() })); } catch (e) { /* no storage */ } }
  function forgetAttempt() { try { sessionStorage.removeItem(ATTEMPT_KEY); } catch (e) { /* no storage */ } }

  // ---------- hub ----------
  function byOrder(a, b) {
    var oa = typeof a.order === 'number' ? a.order : 1e9, ob = typeof b.order === 'number' ? b.order : 1e9;
    return oa - ob || String(a.title || a.path || '').localeCompare(String(b.title || b.path || ''), 'cs');
  }
  function tile(t) {
    var a = el('a', 'tile');
    a.href = t.path + '/';
    if (typeof t.color === 'string' && /^#[0-9a-f]{3,8}$/i.test(t.color)) a.style.setProperty('--color', t.color);
    var icon = el('span', 'icon', t.icon || String(t.title || t.path).slice(0, 1).toUpperCase());
    icon.setAttribute('aria-hidden', 'true');
    var text = el('span', 'text');
    text.appendChild(el('b', '', t.title || t.path));
    if (t.description) text.appendChild(el('small', '', t.description));
    a.appendChild(icon);
    a.appendChild(text);
    a.addEventListener('click', function (e) {
      // first visit: wait until the Service Worker takes over the addresses
      if (!swSupported || navigator.serviceWorker.controller) return;
      e.preventDefault();
      withTimeout(navigator.serviceWorker.ready, 8000).then(function () { location.href = a.href; });
    });
    return a;
  }
  function renderHub(record, contents) {
    return loadCatalog(record.key, contents).catch(function () { return null; }).then(function (catalog) {
      var box = $('tiles');
      box.textContent = '';
      var all = catalog && Array.isArray(catalog.tiles) ? catalog.tiles : [];
      var visible = all.filter(function (t) {
        return t && typeof t.path === 'string' && /^[a-z0-9][a-z0-9-]*$/.test(t.path) && !t.hidden;
      });
      var groups = (catalog && Array.isArray(catalog.groups) ? catalog.groups : []).filter(Boolean).slice().sort(byOrder);
      var byId = {};
      groups.forEach(function (g) { byId[g.id] = { title: g.title, tiles: [] }; });
      var other = { title: groups.length ? 'Ostatní' : '', tiles: [] };
      visible.forEach(function (t) { (byId[t.group] || other).tiles.push(t); });
      groups.map(function (g) { return byId[g.id]; }).concat([other]).forEach(function (g) {
        if (!g.tiles.length) return;
        var section = el('section', 'group');
        if (g.title) section.appendChild(el('h2', '', g.title));
        var grid = el('div', 'grid');
        g.tiles.sort(byOrder).forEach(function (t) { grid.appendChild(tile(t)); });
        section.appendChild(grid);
        box.appendChild(section);
      });
      if (!visible.length) box.appendChild(el('p', 'empty', catalog ? 'V katalogu zatím nejsou žádné stránky.' : 'Katalog se nepodařilo načíst.'));
      $('memory').textContent = record.expires ? 'odemčeno do ' + clock(record.expires) : 'zapamatováno v tomto zařízení';
      $('footer').textContent = 'Trezor verze ' + contents.version + (contents.time ? ' · nahráno ' + date(contents.time) : '');
      show('hub');
    });
  }

  $('lockButton').addEventListener('click', function () {
    $('lockButton').disabled = true;
    Cipher.lock().then(function () { location.replace(BASE.href); });
  });

  start();
})();
