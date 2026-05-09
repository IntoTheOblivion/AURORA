/*
 * BitM-LLM Shield — settings.js
 *
 * Thin wrapper su chrome.storage.local. Stesso file usato dal background
 * service worker (via importScripts) e dal popup (via <script src>).
 * Default = mode "local": zero rete, comportamento v0.1.0 identico.
 */
(function (global) {
  "use strict";

  var KEY = "bitm-settings";

  var DEFAULTS = {
    mode: "local",                 // off | local | hybrid
    backendUrl: "",                // es. "http://localhost:8000"
    sessionId: "",                 // popolato da ensureSessionId()
    locale: "",                    // "" = segui chrome.i18n default
    blockNetRulesEnabled: false,   // toggle declarativeNetRequest dinamico
  };

  function uuidv4() {
    // Crypto-backed quando disponibile (service worker + modern Chrome),
    // altrimenti fallback Math.random che è OK: il sessionId non è segreto,
    // serve solo al backend per correlare richieste della stessa sessione.
    try {
      if (global.crypto && global.crypto.randomUUID) return global.crypto.randomUUID();
    } catch (_) { /* noop */ }
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
      var r = (Math.random() * 16) | 0;
      var v = c === "x" ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }

  function get() {
    return new Promise(function (resolve) {
      chrome.storage.local.get([KEY], function (items) {
        var raw = (items && items[KEY]) || {};
        var merged = Object.assign({}, DEFAULTS, raw);
        // Whitelist su mode per evitare valori corrotti
        if (["off", "local", "hybrid"].indexOf(merged.mode) === -1) merged.mode = "local";
        resolve(merged);
      });
    });
  }

  function set(patch) {
    return get().then(function (cur) {
      var next = Object.assign({}, cur, patch || {});
      return new Promise(function (resolve) {
        chrome.storage.local.set({ [KEY]: next }, function () { resolve(next); });
      });
    });
  }

  function ensureSessionId() {
    return get().then(function (s) {
      if (s.sessionId) return s;
      return set({ sessionId: uuidv4() });
    });
  }

  function subscribe(cb) {
    function listener(changes, area) {
      if (area === "local" && changes[KEY]) {
        var val = changes[KEY].newValue || {};
        cb(Object.assign({}, DEFAULTS, val));
      }
    }
    chrome.storage.onChanged.addListener(listener);
    return function () { chrome.storage.onChanged.removeListener(listener); };
  }

  global.BitMSettings = {
    get: get,
    set: set,
    ensureSessionId: ensureSessionId,
    subscribe: subscribe,
    DEFAULTS: DEFAULTS,
  };
})(typeof self !== "undefined" ? self : this);
