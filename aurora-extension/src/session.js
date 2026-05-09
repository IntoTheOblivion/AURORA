/*
 * AURORA — session.js
 *
 * Traccia in sessionStorage la sequenza di pagine visitate + timing, così
 * da poterla spedire al backend /api/bitm/collect in mode=hybrid. Formato
 * identico a ciò che accumula SessionStore lato Python (pages[], timings[]).
 *
 * Gira nell'ISOLATED world del content script — ha accesso a sessionStorage
 * (per-origin) ma non al DOM della pagina.
 */
(function (global) {
  "use strict";

  var KEY = "aurora-trajectory";
  var MAX_PAGES = 40;
  var KEEP_LAST = 20;

  function load() {
    try {
      var raw = sessionStorage.getItem(KEY);
      if (!raw) return null;
      var parsed = JSON.parse(raw);
      if (!parsed || !Array.isArray(parsed.pages)) return null;
      return parsed;
    } catch (_) { return null; }
  }

  function save(state) {
    try { sessionStorage.setItem(KEY, JSON.stringify(state)); }
    catch (_) { /* quota / disabled: ignora */ }
  }

  function recordVisit(path) {
    var now = Date.now();
    var state = load() || { pages: [] };
    // Dedup: se l'ultima pagina è identica non appendiamo (refresh)
    var last = state.pages[state.pages.length - 1];
    if (last && last.path === path) return state;
    state.pages.push({ path: String(path || "/"), ts: now });
    // Sliding window: mantieni solo le ultime KEEP_LAST se supera MAX_PAGES
    if (state.pages.length > MAX_PAGES) {
      state.pages = state.pages.slice(-KEEP_LAST);
    }
    save(state);
    return state;
  }

  function snapshot() {
    var state = load();
    if (!state || state.pages.length === 0) {
      return { pages: [], timings: [], latestPage: "" };
    }
    var pages = state.pages.map(function (p) { return p.path; });
    var timings = [];
    for (var i = 1; i < state.pages.length; i++) {
      timings.push(Math.max(0, state.pages[i].ts - state.pages[i - 1].ts));
    }
    return {
      pages: pages,
      timings: timings,
      latestPage: pages[pages.length - 1],
    };
  }

  function reset() {
    try { sessionStorage.removeItem(KEY); } catch (_) { /* noop */ }
  }

  global.BitMSession = {
    recordVisit: recordVisit,
    snapshot: snapshot,
    reset: reset,
  };
})(typeof self !== "undefined" ? self : this);
