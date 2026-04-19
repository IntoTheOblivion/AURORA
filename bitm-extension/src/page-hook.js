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

  function snapshot(reason) {
    var now = (typeof performance !== "undefined" && performance.now)
      ? performance.now() : Date.now();
    return {
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
