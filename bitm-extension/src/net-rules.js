/*
 * BitM Shield — net-rules.js
 *
 * Gestione delle regole declarativeNetRequest dinamiche. Blocca a livello
 * di rete (prima che il DOM parta) le richieste verso host di tunneling
 * noti per BitM+. Attivo solo quando l'utente lo abilita esplicitamente
 * da popup → Settings → "Blocca tunnel noti a livello rete".
 *
 * Il ruleset statico (src/net-rules.json) copre /websockify e /guacamole/
 * universalmente; questo file aggiunge regole dinamiche sugli host tunnel,
 * così da poter essere spento/acceso a runtime senza reinstallare.
 */
(function (global) {
  "use strict";

  // Host di tunneling comuni usati dagli scenari BitM+ (coerente con
  // TUNNEL_HOST_RE in src/detection.js e extractor.py lato backend).
  var TUNNEL_DOMAINS = [
    "ngrok.io", "ngrok-free.app", "ngrok-free.dev",
    "trycloudflare.com", "loca.lt", "localtunnel.me", "serveo.net",
  ];

  // ID iniziali alti per non collidere con net-rules.json (id 1-2)
  var FIRST_DYNAMIC_ID = 1000;

  function buildRules() {
    var rules = [];
    for (var i = 0; i < TUNNEL_DOMAINS.length; i++) {
      rules.push({
        id: FIRST_DYNAMIC_ID + i,
        priority: 2,
        action: { type: "block" },
        condition: {
          requestDomains: [TUNNEL_DOMAINS[i]],
          resourceTypes: ["websocket", "xmlhttprequest", "sub_frame", "main_frame"],
        },
      });
    }
    return rules;
  }

  async function enable() {
    try {
      var existing = await chrome.declarativeNetRequest.getDynamicRules();
      var removeIds = existing.map(function (r) { return r.id; });
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: removeIds,
        addRules: buildRules(),
      });
      return true;
    } catch (e) {
      console.warn("[BitM] net-rules enable failed", e);
      return false;
    }
  }

  async function disable() {
    try {
      var existing = await chrome.declarativeNetRequest.getDynamicRules();
      var removeIds = existing.map(function (r) { return r.id; });
      if (removeIds.length === 0) return true;
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: removeIds,
        addRules: [],
      });
      return true;
    } catch (e) {
      console.warn("[BitM] net-rules disable failed", e);
      return false;
    }
  }

  async function isActive() {
    try {
      var existing = await chrome.declarativeNetRequest.getDynamicRules();
      return existing.length > 0;
    } catch (_) { return false; }
  }

  global.BitMNetRules = {
    enable: enable,
    disable: disable,
    isActive: isActive,
    TUNNEL_DOMAINS: TUNNEL_DOMAINS,
  };
})(typeof self !== "undefined" ? self : this);
