/*
 * BitM Shield — page-hook.js
 *
 * Gira nel MAIN world della pagina (stesso contesto dello script della pagina).
 * Raccoglie segnali che il content script (ISOLATED world) non vede:
 *   - endpoint WebSocket aperti dalla pagina (WebSocket patcher)
 *   - nativeness di navigator.credentials.get (evilGet detection)
 *   - fingerprint aggiuntivi per hybrid mode (plugins, WebGL, canvas, lingue,
 *     timezone, screen, colorDepth, platform) — tutti dati locali, nessuna
 *     richiesta di rete da qui.
 *
 * Invio via window.postMessage con envelope { source: "bitm-hook", ... }.
 */
(function () {
  "use strict";

  if (window.__bitmHookInstalled) return;
  window.__bitmHookInstalled = true;

  var wsEndpoints = [];
  var startedAt = (typeof performance !== "undefined" && performance.now)
    ? performance.now() : Date.now();

  // ── WebSocket patch ────────────────────────────────────────────────────────
  try {
    var Native = window.WebSocket;
    if (Native && !Native.__bitmPatched) {
      var Patched = function (url, protocols) {
        try { wsEndpoints.push(String(url)); } catch (_) { /* noop */ }
        return protocols !== undefined ? new Native(url, protocols) : new Native(url);
      };
      Patched.prototype = Native.prototype;
      Patched.__bitmPatched = true;
      for (var k in Native) {
        try { Patched[k] = Native[k]; } catch (_) { /* noop */ }
      }
      window.WebSocket = Patched;
    }
  } catch (_) { /* noop */ }

  // ── credentials.get nativeness ─────────────────────────────────────────────
  function credentialsGetNative() {
    try {
      if (!navigator.credentials || !navigator.credentials.get) return true;
      var src = Function.prototype.toString.call(navigator.credentials.get);
      return src.indexOf("[native code]") !== -1;
    } catch (e) {
      return true;
    }
  }

  // ── Canvas fingerprint (solo hash corto, no dati grezzi) ────────────────────
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
      return c.toDataURL().slice(0, 80); // prefisso stabile, basta al backend
    } catch (_) { return ""; }
  }

  // ── WebGL renderer ──────────────────────────────────────────────────────────
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

  function snapshot(reason) {
    var now = (typeof performance !== "undefined" && performance.now)
      ? performance.now() : Date.now();
    return {
      reason: reason,
      title: document.title || "",
      pageUrl: location.href || "",
      referrer: document.referrer || "",
      userAgent: navigator.userAgent || "",
      platform: navigator.platform || "",
      wsEndpoints: wsEndpoints.slice(),
      credentialsGetNative: credentialsGetNative(),
      iframeCount: (function () {
        try { return document.getElementsByTagName("iframe").length; }
        catch (_) { return 0; }
      })(),
      plugins: pluginNames(),
      webgl: webglRenderer(),
      canvas: canvasFingerprint(),
      languages: languages(),
      timezone: timezone(),
      screenRes: screenRes(),
      colorDepth: (function () {
        try { return (screen && screen.colorDepth) || 24; } catch (_) { return 24; }
      })(),
      timing: Math.round(now - startedAt),
    };
  }

  function emit(reason) {
    try {
      window.postMessage({ source: "bitm-hook", reason: reason, data: snapshot(reason) }, "*");
    } catch (_) { /* noop */ }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { emit("dom"); }, { once: true });
  } else {
    emit("ready");
  }

  window.addEventListener("load", function () { emit("load"); });

  window.addEventListener("message", function (e) {
    if (e.source !== window) return;
    var d = e.data;
    if (d && d.source === "bitm-content" && d.cmd === "probe") emit("probe");
  });
})();
