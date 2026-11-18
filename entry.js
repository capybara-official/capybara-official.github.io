/* Capybara entry page: find one entry that opens from the visitor's network and offer it.
 *
 * The candidate list is not in this page. It comes from entry.signed.json (several copies), an Ed25519 envelope in
 * the remote-config format (capybara-signed-config/v1, channel "entry", keys rc1/rc2 = deploy/remote-config/
 * signing_keys.json). Only a verified list is used. Candidates are probed at /_entry-check; the first that answers
 * "ok" becomes the one button on the page. Written for old in-app browsers too: no optional chaining, no
 * Promise.any; WebCrypto Ed25519 when available, else the vendored tweetnacl verify.
 */
(function (root) {
  'use strict';

  // keys:begin (generated from deploy/remote-config/signing_keys.json; scripts/entry_candidates.py check)
  var KEYS = {"rc1":"XSv1U3Jbqvru2rjm5yYRsHKx5iFLJvxUi7HqHyIWMjk=","rc2":"itHZijHNx0kd0xgInxFo3WfhwRUs8Sg3tPlddgZ0Ek8="};
  // keys:end
  var CHANNEL = 'entry';
  var SOURCES = [
    'entry.signed.json',
    'https://capybara-official.github.io/entry.signed.json',
    'https://cdn.jsdelivr.net/gh/capybara-official/capybara-official.github.io@main/entry.signed.json'
  ];
  var SOURCE_TIMEOUT_MS = 5000;
  var PROBE_TIMEOUT_MS = 4000;
  var MAX_BODY = 16384;
  var MAX_ENTRIES = 12;
  var B64 = /^[A-Za-z0-9+/]+={0,2}$/;
  var IDENT = /^[a-z0-9-]{1,32}$/;

  function b64bytes(text) {
    var bin = atob(text);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  }

  function utf8(bytes) {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  }

  // Same checks and signed message as scripts/remote_config_sign.py; returns null for anything else.
  function parseEnvelope(text) {
    if (typeof text !== 'string' || text.length > MAX_BODY) return null;
    var env;
    try { env = JSON.parse(text); } catch (e) { return null; }
    if (!env || typeof env !== 'object') return null;
    if (env.format !== 'capybara-signed-config' || env.v !== 1) return null;
    if (typeof env.kid !== 'string' || !IDENT.test(env.kid) || !Object.prototype.hasOwnProperty.call(KEYS, env.kid)) return null;
    if (env.channel !== CHANNEL) return null;
    if (typeof env.issued_at !== 'number' || env.issued_at % 1 !== 0 || env.issued_at < 0) return null;
    if (typeof env.payload !== 'string' || !B64.test(env.payload) || env.payload.length > MAX_BODY) return null;
    if (typeof env.sig !== 'string' || !B64.test(env.sig)) return null;
    var sig;
    try { sig = b64bytes(env.sig); } catch (e) { return null; }
    if (sig.length !== 64) return null;
    var message = new TextEncoder().encode('capybara-signed-config/v1\n' + env.kid + '\n' + env.channel + '\n' +
      String(env.issued_at) + '\n' + env.payload);
    return { envelope: env, sig: sig, message: message, publicKey: b64bytes(KEYS[env.kid]) };
  }

  // Candidate origins from a verified payload: https only (plain http only for local tests), no paths or credentials.
  function entriesFrom(payload) {
    var data;
    try { data = JSON.parse(utf8(b64bytes(payload))); } catch (e) { return []; }
    if (!data || data.v !== 1 || !Array.isArray(data.entries)) return [];
    var seen = {};
    var out = [];
    for (var i = 0; i < data.entries.length && out.length < MAX_ENTRIES; i += 1) {
      var url;
      try { url = new URL(String(data.entries[i])); } catch (e) { continue; }
      var local = url.protocol === 'http:' && (url.hostname === '127.0.0.1' || url.hostname === 'localhost');
      if (url.protocol !== 'https:' && !local) continue;
      if (url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) continue;
      if (seen[url.origin]) continue;
      seen[url.origin] = true;
      out.push(url.origin);
    }
    return out;
  }

  var naclLoading = null;
  function loadNacl() {
    if (root.nacl && root.nacl.sign) return Promise.resolve(root.nacl);
    if (!naclLoading) {
      naclLoading = new Promise(function (resolve, reject) {
        var script = document.createElement('script');
        script.src = 'nacl.min.js';
        script.onload = function () { root.nacl && root.nacl.sign ? resolve(root.nacl) : reject(new Error('nacl')); };
        script.onerror = function () { naclLoading = null; reject(new Error('nacl')); };
        document.head.appendChild(script);
      });
    }
    return naclLoading;
  }

  // WebCrypto when it knows Ed25519; a "false" from it is final. Only a missing algorithm falls back to tweetnacl.
  function verify(parsed, nacl) {
    var subtle = root.crypto && root.crypto.subtle;
    var webcrypto = subtle ? subtle.importKey('raw', parsed.publicKey, { name: 'Ed25519' }, false, ['verify'])
      .then(function (key) { return subtle.verify({ name: 'Ed25519' }, key, parsed.sig, parsed.message); })
      .then(function (ok) { return { ok: ok }; }, function () { return null; }) : Promise.resolve(null);
    return webcrypto.then(function (result) {
      if (result) return result.ok;
      return (nacl ? Promise.resolve(nacl) : loadNacl()).then(function (lib) {
        return lib.sign.detached.verify(parsed.message, parsed.sig, parsed.publicKey);
      });
    });
  }

  function withTimeout(ms, run) {
    var controller = typeof AbortController === 'function' ? new AbortController() : null;
    var timer = setTimeout(function () { if (controller) controller.abort(); }, ms);
    return run(controller ? controller.signal : undefined).then(function (value) {
      clearTimeout(timer);
      return value;
    }, function (error) {
      clearTimeout(timer);
      throw error;
    });
  }

  function fetchText(url, ms) {
    return withTimeout(ms, function (signal) {
      return fetch(url, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', signal: signal })
        .then(function (response) {
          if (!response.ok) throw new Error('status');
          return response.text();
        });
    });
  }

  // First source whose envelope verifies; null when none does.
  function loadCandidates(sources, fetcher) {
    var i = 0;
    function next() {
      if (i >= sources.length) return Promise.resolve(null);
      var url = sources[i];
      i += 1;
      return fetcher(url, SOURCE_TIMEOUT_MS).then(function (text) {
        var parsed = parseEnvelope(text);
        if (!parsed) return next();
        return verify(parsed).then(function (ok) {
          var entries = ok ? entriesFrom(parsed.envelope.payload) : [];
          return entries.length ? entries : next();
        });
      }, next);
    }
    return next();
  }

  function probe(origin, fetcher) {
    var nonce = Date.now().toString(36) + Math.random().toString(36).slice(2);
    return fetcher(origin + '/_entry-check?t=' + nonce, PROBE_TIMEOUT_MS).then(function (text) {
      if (String(text).trim() !== 'ok') throw new Error('body');
      return origin;
    });
  }

  // The first origin to answer; rejects only when every probe failed.
  function firstWorking(origins, fetcher) {
    return new Promise(function (resolve, reject) {
      var failed = 0;
      if (!origins.length) { reject(new Error('none')); return; }
      origins.forEach(function (origin) {
        probe(origin, fetcher).then(resolve, function () {
          failed += 1;
          if (failed === origins.length) reject(new Error('none'));
        });
      });
    });
  }

  var core = { parseEnvelope: parseEnvelope, entriesFrom: entriesFrom, verify: verify, loadCandidates: loadCandidates,
    firstWorking: firstWorking, SOURCES: SOURCES, KEYS: KEYS };

  function start() {
    var box = document.querySelector('[data-entry]');
    var message = document.querySelector('[data-message]');
    var go = document.querySelector('[data-go]');
    var retry = document.querySelector('[data-retry]');
    var note = document.querySelector('[data-note]');
    if (!box || !message || !go || !retry || !note) return;

    function show(state, text) {
      box.setAttribute('data-state', state);
      message.textContent = text;
      go.hidden = state !== 'found';
      retry.hidden = state !== 'failed';
      note.hidden = state !== 'failed';
    }

    function run() {
      show('testing', '正在找能打开的入口…');
      loadCandidates(SOURCES, fetchText).then(function (origins) {
        if (!origins) throw new Error('list');
        return firstWorking(origins, fetchText);
      }).then(function (origin) {
        go.href = origin + '/' + (location.hash || '');
        show('found', '找到了');
        go.focus();
      }, function () {
        show('failed', '暂时没找到能打开的入口');
        retry.focus();
      });
    }

    retry.addEventListener('click', run);
    run();
  }

  if (typeof module === 'object' && module.exports) {
    module.exports = core;
  } else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
}(typeof self !== 'undefined' ? self : globalThis));
