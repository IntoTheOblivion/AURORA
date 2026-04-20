/*
 * BitM Shield — content-script.js
 *
 * Gira in ISOLATED world, a document_start. Riceve via postMessage i segnali
 * grezzi raccolti da page-hook.js (MAIN world), applica BitMDetection.detect,
 * aggiorna il trajectory tracker, e:
 *   • mode=local → invia verdict locale al service worker (come v0.1)
 *   • mode=hybrid → invia verdict+fingerprint+trajectory al SW, attende il
 *     verdict mergiato col backend prima di mostrare il banner.
 *
 * Blocca submit di form con password se il verdict è block o (challenge +
 * pattern == panic_password_change).
 */
(function () {
  "use strict";

  var lastVerdict = null;
  var bannerShown = false;
  var cachedSettings = { mode: "local", backendUrl: "", sessionId: "" };

  // Carica i settings una volta all'avvio; fino a quando la prima get() non
  // risolve, i messaggi da page-hook attendono (altrimenti il primo detect
  // partirebbe con cachedSettings default e salterebbe l'hybrid path anche
  // quando l'utente ha configurato mode=hybrid).
  var settingsReady = Promise.resolve();
  try {
    if (self.BitMSettings) {
      settingsReady = self.BitMSettings.get().then(function (s) { cachedSettings = s; })
        .catch(function () { /* fallback default già impostato */ });
      self.BitMSettings.subscribe(function (s) { cachedSettings = s; });
    }
  } catch (_) { /* noop */ }

  function pathOf(url) {
    try { return new URL(url).pathname || "/"; } catch (_) { return "/"; }
  }

  // ── Fingerprint raccolto in ISOLATED world (non esposto alla pagina) ──────
  function canvasFingerprint() {
    try {
      var c = document.createElement("canvas");
      c.width = 120; c.height = 32;
      var ctx = c.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "14px Arial";
      ctx.fillStyle = "#069";
      ctx.fillText("BitMShield", 2, 2);
      ctx.fillStyle = "rgba(128,128,64,.8)";
      ctx.fillRect(60, 4, 20, 14);
      return c.toDataURL().slice(0, 80);
    } catch (_) { return ""; }
  }
  function webglRenderer() {
    try {
      var c = document.createElement("canvas");
      var gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!gl) return "";
      var ext = gl.getExtension("WEBGL_debug_renderer_info");
      if (!ext) return String(gl.getParameter(gl.RENDERER) || "");
      return String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "");
    } catch (_) { return ""; }
  }
  function pluginNames() {
    try {
      var out = [];
      var ps = navigator.plugins || [];
      for (var i = 0; i < ps.length; i++) {
        if (ps[i] && ps[i].name) out.push(String(ps[i].name));
      }
      return out;
    } catch (_) { return []; }
  }
  function languages() {
    try {
      if (navigator.languages && navigator.languages.length)
        return Array.prototype.slice.call(navigator.languages).map(String);
      if (navigator.language) return [String(navigator.language)];
      return [];
    } catch (_) { return []; }
  }
  function timezone() {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ""; }
    catch (_) { return ""; }
  }
  function screenRes() {
    try {
      return (screen && screen.width && screen.height)
        ? (screen.width + "x" + screen.height) : "";
    } catch (_) { return ""; }
  }
  function colorDepth() {
    try { return (screen && screen.colorDepth) || 24; } catch (_) { return 24; }
  }
  function enrichFingerprint(data) {
    // Parte da quanto arrivato da page-hook + aggiunge i campi sensibili
    // raccolti qui in ISOLATED world (invisibili alla pagina).
    return Object.assign({}, data, {
      platform: navigator.platform || "",
      plugins: pluginNames(),
      webgl: webglRenderer(),
      canvas: canvasFingerprint(),
      languages: languages(),
      timezone: timezone(),
      screenRes: screenRes(),
      colorDepth: colorDepth(),
    });
  }

  async function computeAndReport(data) {
    var local = self.BitMDetection.detect(data);
    // Traccia la pagina corrente nel tracker trajectory (sessionStorage)
    try {
      if (self.BitMSession) self.BitMSession.recordVisit(pathOf(location.href));
    } catch (_) { /* noop */ }

    var traj = (self.BitMSession && self.BitMSession.snapshot()) || { pages: [], timings: [], latestPage: pathOf(location.href) };

    var critical = false;
    for (var i = 0; i < local.signals.length; i++) {
      if (self.BitMDetection.CRITICAL[local.signals[i]]) { critical = true; break; }
    }

    if (cachedSettings.mode === "hybrid") {
      try {
        var merged = await sendHybridProbe({
          verdict: local.verdict,
          score: local.score,
          signals: local.signals,
          critical: critical,
          fingerprint: enrichFingerprint(data),
          trajectory: traj,
        });
        if (merged && merged.verdict) {
          lastVerdict = merged;
          maybeShowBanner(merged);
          return;
        }
      } catch (_) { /* fallback locale */ }
    }

    // Path locale (mode=off, mode=local, o hybrid senza risposta)
    lastVerdict = {
      verdict: local.verdict,
      score: local.score,
      signals: local.signals,
      explanationUser: "",
      pattern: "",
      source: "local",
    };
    try {
      chrome.runtime.sendMessage({
        type: "bitm-verdict",
        url: location.href,
        origin: location.origin,
        verdict: local.verdict,
        score: local.score,
        signals: local.signals,
      });
    } catch (_) { /* SW asleep */ }
    maybeShowBanner(lastVerdict);
  }

  function sendHybridProbe(payload) {
    return new Promise(function (resolve, reject) {
      try {
        chrome.runtime.sendMessage(
          Object.assign({ type: "bitm-hybrid-probe", url: location.href, origin: location.origin }, payload),
          function (response) {
            if (chrome.runtime.lastError) { reject(chrome.runtime.lastError); return; }
            resolve(response);
          }
        );
      } catch (e) { reject(e); }
    });
  }

  function maybeShowBanner(v) {
    if (!v) return;
    if (v.verdict === "allow") return;
    if (bannerShown) return;
    if (!self.BitMBanner) return;
    bannerShown = self.BitMBanner.show({
      verdict: v.verdict,
      signals: v.signals,
      explanationUser: v.explanationUser,
      pattern: v.pattern,
    });
  }

  // ── Listener per snapshot dal page-hook ─────────────────────────────────────
  window.addEventListener("message", function (e) {
    if (e.source !== window) return;
    var d = e.data;
    if (!d || d.source !== "bitm-hook" || !d.data) return;
    settingsReady.then(function () { computeAndReport(d.data); });
  });

  // Re-probe dopo 2s (WebSocket possono aprirsi post-load)
  setTimeout(function () {
    try { window.postMessage({ source: "bitm-content", cmd: "probe" }, "*"); }
    catch (_) { /* noop */ }
  }, 2000);

  // ── Blocco submit di form con password ─────────────────────────────────────
  function hasPasswordField(form) {
    try {
      var inputs = form.querySelectorAll("input[type=password]");
      return inputs && inputs.length > 0;
    } catch (_) { return false; }
  }

  function shouldBlockSubmit(v) {
    if (!v) return false;
    if (v.verdict === "block") return true;
    if (v.verdict === "challenge" && v.pattern === "panic_password_change") return true;
    return false;
  }

  document.addEventListener("submit", function (ev) {
    if (!shouldBlockSubmit(lastVerdict)) return;
    var form = ev.target;
    if (!form || form.tagName !== "FORM") return;
    if (!hasPasswordField(form)) return;
    ev.preventDefault();
    ev.stopImmediatePropagation();
    if (self.BitMBanner) {
      self.BitMBanner.show({
        verdict: lastVerdict.verdict,
        signals: lastVerdict.signals,
        explanationUser: lastVerdict.explanationUser,
        pattern: lastVerdict.pattern,
        submitAttempt: true,
      });
    }
  }, /*capture=*/true);

  // Il popup può chiedere lo stato corrente
  chrome.runtime.onMessage.addListener(function (msg, _sender, sendResponse) {
    if (msg && msg.type === "bitm-get-tab-verdict") {
      sendResponse(lastVerdict || { verdict: "allow", score: 0, signals: [] });
    }
    return false;
  });
})();
