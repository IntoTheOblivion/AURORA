/*
 * BitM Shield — content-script.js
 *
 * Gira in ISOLATED world, a document_start. Riceve via postMessage i segnali
 * grezzi raccolti da page-hook.js (MAIN world), applica BitMDetection.detect
 * e comunica il verdetto al service worker (background.js) + blocca i submit
 * dei form con password se il verdetto corrente è "block".
 */
(function () {
  "use strict";

  var lastVerdict = null;  // ultimo risultato inviato
  var bannerShown = false;

  function computeAndReport(data) {
    var result = self.BitMDetection.detect(data);
    lastVerdict = result;

    try {
      chrome.runtime.sendMessage({
        type: "bitm-verdict",
        url: location.href,
        origin: location.origin,
        verdict: result.verdict,
        score: result.score,
        signals: result.signals,
      });
    } catch (_) { /* service worker non raggiungibile: ignora */ }

    if (result.verdict === "block" && !bannerShown) {
      showBanner(result);
    }
  }

  // ── Listener per snapshot dal page-hook ─────────────────────────────────────
  window.addEventListener("message", function (e) {
    if (e.source !== window) return;
    var d = e.data;
    if (!d || d.source !== "bitm-hook" || !d.data) return;
    computeAndReport(d.data);
  });

  // Richiediamo una ri-probe dopo 2s (i WebSocket spesso si aprono post-load)
  setTimeout(function () {
    try { window.postMessage({ source: "bitm-content", cmd: "probe" }, "*"); }
    catch (_) { /* noop */ }
  }, 2000);

  // ── Blocco submit di form con password su pagine pericolose ────────────────
  function hasPasswordField(form) {
    try {
      var inputs = form.querySelectorAll("input[type=password]");
      return inputs && inputs.length > 0;
    } catch (_) { return false; }
  }

  document.addEventListener("submit", function (ev) {
    if (!lastVerdict || lastVerdict.verdict !== "block") return;
    var form = ev.target;
    if (!form || form.tagName !== "FORM") return;
    if (!hasPasswordField(form)) return;
    ev.preventDefault();
    ev.stopImmediatePropagation();
    showBanner(lastVerdict, /*submitAttempt=*/true);
  }, /*capture=*/true);

  // ── Banner in-page (shadow DOM per isolamento dallo stile del sito) ─────────
  function showBanner(result, submitAttempt) {
    if (bannerShown) return;
    bannerShown = true;

    try {
      var host = document.createElement("div");
      host.id = "__bitm_shield_banner__";
      host.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:2147483647;";
      var shadow = host.attachShadow({ mode: "closed" });

      var msg = submitAttempt
        ? "Invio bloccato: questa pagina mostra segnali di attacco BitM."
        : "Attenzione: segnali di Browser-in-the-Middle rilevati su questa pagina.";

      shadow.innerHTML =
        "<style>" +
        ".b{font:13px/1.4 system-ui,Arial,sans-serif;background:#c0392b;color:#fff;" +
        "padding:10px 14px;display:flex;align-items:center;gap:12px;" +
        "box-shadow:0 2px 6px rgba(0,0,0,.25)}" +
        ".t{flex:1}" +
        ".t strong{display:block;font-size:14px}" +
        ".t span{opacity:.9;font-size:12px}" +
        ".x{background:rgba(255,255,255,.18);border:0;color:#fff;border-radius:3px;" +
        "padding:4px 10px;cursor:pointer;font-size:12px}" +
        ".x:hover{background:rgba(255,255,255,.28)}" +
        "</style>" +
        "<div class='b' role='alert'>" +
        "<div class='t'><strong>BitM Shield</strong>" +
        "<span>" + escapeHtml(msg) +
        " Segnali: " + escapeHtml(result.signals.join(", ")) + "</span></div>" +
        "<button class='x' id='close'>Chiudi</button>" +
        "</div>";

      document.documentElement.appendChild(host);
      shadow.getElementById("close").addEventListener("click", function () {
        try { host.remove(); } catch (_) { /* noop */ }
      });
    } catch (_) { /* fallback: niente banner se il DOM non lo permette */ }
  }

  function escapeHtml(s) {
    return String(s || "").replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // Il popup può chiedere lo stato corrente
  chrome.runtime.onMessage.addListener(function (msg, _sender, sendResponse) {
    if (msg && msg.type === "bitm-get-tab-verdict") {
      sendResponse(lastVerdict || { verdict: "allow", score: 0, signals: [] });
    }
    return false;
  });
})();
