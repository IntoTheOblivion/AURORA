/*
 * AURORA — banner.js
 *
 * Banner condiviso (Shadow DOM mode:closed) per mostrare verdict + spiegazione
 * utente-friendly. Estratto da content-script.js v0.1.0, allineato a
 * aurora-plugin/app/static/collector.js per coerenza UX.
 */
(function (global) {
  "use strict";

  var HOST_ID = "__aurora_banner__";

  var PALETTE = {
    block:     { bg: "#c0392b", titleKey: "banner_block_title",    fallbackTitle: "Richiesta bloccata" },
    challenge: { bg: "#d68910", titleKey: "banner_challenge_title", fallbackTitle: "Richiesta sospetta" },
  };

  function i18n(key, fallback) {
    try {
      if (chrome && chrome.i18n && chrome.i18n.getMessage) {
        var v = chrome.i18n.getMessage(key);
        if (v) return v;
      }
    } catch (_) { /* noop */ }
    return fallback;
  }

  function esc(s) {
    return String(s || "").replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function fallbackMessage(signals) {
    // Se il backend non ci ha dato un explanation_user, proviamo a mapare
    // il segnale più forte in una frase italiana leggibile.
    var first = (signals && signals[0]) || "";
    var map = {
      novnc_client_marker:      "Questa pagina sembra servita tramite un tunnel noVNC.",
      guacamole_client_marker:  "Rilevato client Apache Guacamole — possibile BitM.",
      bitm_framework_ua:        "Lo user-agent contiene marker di framework BitM noti.",
      bitm_backend_port:        "La pagina è caricata da una porta tipica di BitM (:6080, :5900, :3081…).",
      xss_reflected_param:      "Rilevato payload di injection nell'URL.",
      webauthn_api_override:    "navigator.credentials.get non è nativo — possibile evilGet.",
      bitm_websocket_transport: "Una WebSocket punta a un endpoint di tunneling sospetto.",
      tunnel_host:              "Il sito è ospitato su un tunnel HTTPS (ngrok/trycloudflare/...).",
      iframe_overlay:           "Molti iframe sovrapposti: possibile clickjacking.",
    };
    return map[first] || "Segnali di Browser-in-the-Middle rilevati.";
  }

  function show(opts) {
    var verdict = opts && opts.verdict;
    if (verdict !== "block" && verdict !== "challenge") return false;

    // Se già presente, aggiorna il testo invece di duplicare
    var existing = document.getElementById(HOST_ID);
    if (existing) try { existing.remove(); } catch (_) { /* noop */ }

    var palette = PALETTE[verdict];
    var title = i18n(palette.titleKey, palette.fallbackTitle);
    var body  = (opts.explanationUser && String(opts.explanationUser).trim())
             || fallbackMessage(opts.signals);
    var pattern = opts.pattern ? " · " + opts.pattern : "";
    var subtitle = opts.submitAttempt
      ? i18n("banner_submit_blocked", "Invio del form bloccato per sicurezza.")
      : "";

    try {
      var host = document.createElement("div");
      host.id = HOST_ID;
      host.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:2147483647;";
      var shadow = host.attachShadow({ mode: "closed" });
      shadow.innerHTML =
        "<style>" +
        ".b{font:13px/1.4 system-ui,-apple-system,Segoe UI,Arial,sans-serif;" +
        "background:" + palette.bg + ";color:#fff;padding:10px 14px;" +
        "display:flex;align-items:flex-start;gap:12px;" +
        "box-shadow:0 2px 6px rgba(0,0,0,.25)}" +
        ".t{flex:1;min-width:0}" +
        ".t strong{display:block;font-size:14px;margin-bottom:2px}" +
        ".t .body{font-size:13px}" +
        ".t .meta{opacity:.8;font-size:11px;margin-top:4px}" +
        ".x{background:rgba(255,255,255,.18);border:0;color:#fff;" +
        "border-radius:3px;padding:6px 12px;cursor:pointer;font-size:12px;" +
        "flex-shrink:0}" +
        ".x:hover{background:rgba(255,255,255,.28)}" +
        "</style>" +
        "<div class='b' role='alert' aria-live='assertive'>" +
        "<div class='t'>" +
        "<strong>AURORA — " + esc(title) + "</strong>" +
        "<div class='body'>" + esc(body) + "</div>" +
        (subtitle ? "<div class='body' style='margin-top:4px'>" + esc(subtitle) + "</div>" : "") +
        "<div class='meta'>" + esc((opts.signals || []).slice(0, 3).join(", ")) +
        esc(pattern) + "</div>" +
        "</div>" +
        "<button class='x' id='close'>" +
        esc(i18n("banner_dismiss", "Chiudi")) + "</button>" +
        "</div>";
      document.documentElement.appendChild(host);
      var btn = shadow.getElementById("close");
      if (btn) btn.addEventListener("click", dismiss);
      return true;
    } catch (_) { return false; }
  }

  function dismiss() {
    try {
      var h = document.getElementById(HOST_ID);
      if (h) h.remove();
    } catch (_) { /* noop */ }
  }

  function isShown() {
    return !!document.getElementById(HOST_ID);
  }

  global.BitMBanner = { show: show, dismiss: dismiss, isShown: isShown, HOST_ID: HOST_ID };
})(typeof self !== "undefined" ? self : this);
