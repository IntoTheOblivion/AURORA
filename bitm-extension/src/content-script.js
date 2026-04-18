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

  // Carica i settings una volta all'avvio; se cambiano (popup) li aggiorniamo
  try {
    if (self.BitMSettings) {
      self.BitMSettings.get().then(function (s) { cachedSettings = s; });
      self.BitMSettings.subscribe(function (s) { cachedSettings = s; });
    }
  } catch (_) { /* noop */ }

  function pathOf(url) {
    try { return new URL(url).pathname || "/"; } catch (_) { return "/"; }
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
          fingerprint: data,
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
    computeAndReport(d.data);
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
