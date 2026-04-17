/*
 * BitM Shield — page-hook.js
 *
 * Gira nel MAIN world della pagina (stesso contesto dello script della pagina).
 * Serve solo a raccogliere segnali che il content script (ISOLATED world) non
 * può vedere direttamente:
 *   - endpoint WebSocket aperti dalla pagina (WebSocket patcher)
 *   - nativeness di navigator.credentials.get (evilGet detection)
 *
 * Manda i dati al content script via window.postMessage con un envelope
 * riconoscibile ({ source: "bitm-hook", ... }). Non fa mai rete.
 */
(function () {
  "use strict";

  if (window.__bitmHookInstalled) return;
  window.__bitmHookInstalled = true;

  var wsEndpoints = [];

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

  function snapshot() {
    return {
      title: document.title || "",
      pageUrl: location.href || "",
      referrer: document.referrer || "",
      userAgent: navigator.userAgent || "",
      wsEndpoints: wsEndpoints.slice(),
      credentialsGetNative: credentialsGetNative(),
      iframeCount: (function () {
        try { return document.getElementsByTagName("iframe").length; }
        catch (_) { return 0; }
      })(),
    };
  }

  function emit(reason) {
    try {
      window.postMessage({ source: "bitm-hook", reason: reason, data: snapshot() }, "*");
    } catch (_) { /* noop */ }
  }

  // Primo invio: appena il DOM è disponibile
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { emit("dom"); }, { once: true });
  } else {
    emit("ready");
  }

  // Invii successivi: load (WebSocket possono aprirsi dopo il primo paint)
  window.addEventListener("load", function () { emit("load"); });

  // Re-emit su richiesta esplicita del content script
  window.addEventListener("message", function (e) {
    if (e.source !== window) return;
    var d = e.data;
    if (d && d.source === "bitm-content" && d.cmd === "probe") emit("probe");
  });
})();
