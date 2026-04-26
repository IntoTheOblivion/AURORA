/*
 * BitM Shield — page-hook.js
 *
 * Gira nel MAIN world della pagina (stesso contesto dello script della pagina).
 * Raccoglie SOLO segnali che il content script (ISOLATED world) non vede:
 *   - endpoint WebSocket aperti dalla pagina (WebSocket patcher)
 *   - nativeness di navigator.credentials.get (evilGet detection)
 *
 * ATTENZIONE privacy: il canale `window.postMessage(..., "*")` è leggibile
 * da qualunque script della pagina. Per questo NON raccogliamo qui canvas,
 * plugins, WebGL renderer, lingue, timezone: quelli stanno in content-script
 * (ISOLATED world, irraggiungibile alla pagina) e vengono mergiati solo prima
 * dell'invio al backend, mai echeggiati indietro al MAIN world.
 */
(function () {
  "use strict";

  if (window.__bitmHookInstalled) return;
  window.__bitmHookInstalled = true;

  var wsEndpoints = [];

  // ── WebSocket patch ────────────────────────────────────────────────────────
  // Usiamo Proxy invece di sostituire il costruttore: il vecchio approccio
  // (function wrapper + Patched.prototype = Native.prototype) rompeva
  // `WebSocket.name`, le costanti statiche non-enumerabili (CONNECTING/OPEN/
  // CLOSING/CLOSED venivano copiate solo se enumerabili) e `WebSocket.toString()`
  // svelava il monkey-patch ad eventuali check anti-tamper della pagina.
  // Proxy con un solo trap `construct` è trasparente a tutto il resto.
  try {
    var Native = window.WebSocket;
    if (Native && !Native.__bitmPatched) {
      var Patched = new Proxy(Native, {
        construct: function (target, args) {
          try {
            if (args && args.length > 0) wsEndpoints.push(String(args[0]));
          } catch (_) { /* noop */ }
          return Reflect.construct(target, args);
        },
      });
      // Marker sul Native: idempotenza anche se un altro script applica
      // un proxy successivamente (controllo del flag prima del wrap).
      try {
        Object.defineProperty(Native, "__bitmPatched", { value: true, configurable: false });
      } catch (_) { Native.__bitmPatched = true; }
      try { window.WebSocket = Patched; } catch (_) { /* readonly: rinuncia */ }
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

  function snapshot(reason, cb) {
    var t0 = (typeof performance !== "undefined" && performance.now) ? performance.now() : Date.now();
    setTimeout(function () {
      var t1 = (typeof performance !== "undefined" && performance.now) ? performance.now() : Date.now();
      cb({
        reason: reason,
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
        timing: Math.round(t1 - t0),
      });
    }, 10);
  }

  function emit(reason) {
    try {
      snapshot(reason, function (data) {
        try {
          window.postMessage({ source: "bitm-hook", reason: reason, data: data }, "*");
        } catch (_) { /* noop */ }
      });
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
