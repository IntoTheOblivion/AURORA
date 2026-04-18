/*
 * BitM Detection Plugin — Collector v7.3
 *
 * Integrazione one-liner:
 *   <script src="https://<host>/collector.js"
 *           data-endpoint="/api/bitm/collect"
 *           data-auto="true"></script>
 *
 * API esposta su window.BitM:
 *   BitM.classify()   → Promise<Result>   invio manuale
 *   BitM.fingerprint() → Promise<Fingerprint>
 *   BitM.onResult(fn) → registra listener sul risultato
 *
 * NOTA: i nomi dei campi nel payload (pageUrl, title, wsEndpoints, iframeCount,
 * credentialsGetNative) sono quelli letti direttamente da extractor._detect_bitm.
 * Non modificare senza aggiornare il lato Python, altrimenti i segnali BitM/BitM+
 * silenziano (vedi S15 sys_collector_payload_detects_bitm per la copertura).
 */
(function () {
  "use strict";

  var script = document.currentScript ||
               (function () {
                 var s = document.getElementsByTagName("script");
                 return s[s.length - 1];
               })();

  var ENDPOINT = (script && script.getAttribute("data-endpoint")) || "/api/bitm/collect";
  var PAGE     = (script && script.getAttribute("data-page"))     || null;
  var AUTO     = (script && script.getAttribute("data-auto"))     !== "false";
  var listeners = [];

  // Hook globale su WebSocket per tracciare endpoint effettivamente aperti
  // (serve all'extractor per fire di `bitm_websocket_transport` su websockify/tunnel).
  var _wsEndpoints = [];
  try {
    var _NativeWS = window.WebSocket;
    if (_NativeWS && !_NativeWS.__bitmPatched) {
      var _PatchedWS = function (url, protocols) {
        try { _wsEndpoints.push(String(url)); } catch (_) { /* ignore */ }
        return protocols !== undefined
          ? new _NativeWS(url, protocols)
          : new _NativeWS(url);
      };
      _PatchedWS.prototype = _NativeWS.prototype;
      _PatchedWS.__bitmPatched = true;
      // Preserva costanti statiche (CONNECTING, OPEN, ...)
      for (var k in _NativeWS) {
        try { _PatchedWS[k] = _NativeWS[k]; } catch (_) { /* ignore */ }
      }
      window.WebSocket = _PatchedWS;
    }
  } catch (_) { /* ignore hook errors */ }

  function sessionId() {
    try {
      var id = sessionStorage.getItem("bitm-sid");
      if (!id) {
        id = Math.random().toString(36).slice(2) + Date.now().toString(36);
        sessionStorage.setItem("bitm-sid", id);
      }
      return id;
    } catch (e) {
      return "anon-" + Date.now();
    }
  }

  function getWebGL() {
    try {
      var gl = document.createElement("canvas").getContext("webgl");
      return gl
        ? gl.getParameter(gl.RENDERER) + " / " + gl.getParameter(gl.VENDOR)
        : "unavailable";
    } catch (e) { return "unavailable"; }
  }

  function getCanvas() {
    try {
      var c = document.createElement("canvas");
      var ctx = c.getContext("2d");
      ctx.fillStyle = "#f60";
      ctx.fillRect(10, 1, 62, 20);
      ctx.fillStyle = "#069";
      ctx.font = "11pt Arial";
      ctx.fillText("BitM-probe", 2, 15);
      ctx.fillStyle = "rgba(102,204,0,0.7)";
      ctx.fillText("BitM-probe", 4, 17);
      return c.toDataURL().slice(-40);
    } catch (e) { return ""; }
  }

  function credentialsGetNative() {
    try {
      if (!navigator.credentials || !navigator.credentials.get) return true;
      var src = Function.prototype.toString.call(navigator.credentials.get);
      return src.indexOf("[native code]") !== -1;
    } catch (e) {
      // Se non riusciamo a ispezionare, non asseriamo override
      return true;
    }
  }

  function iframeCount() {
    try {
      return document.getElementsByTagName("iframe").length;
    } catch (e) { return 0; }
  }

  async function fingerprint() {
    var t0 = performance.now();
    await new Promise(function (r) { setTimeout(r, 10); });
    var timing = Math.round(performance.now() - t0);

    var fp = {
      sessionId:  sessionId(),
      page:       PAGE || location.pathname,
      userAgent:  navigator.userAgent,
      plugins:    [].slice.call(navigator.plugins || []).map(function (p) { return p.name; }),
      webgl:      getWebGL(),
      canvas:     getCanvas(),
      webdriver:  navigator.webdriver || false,
      languages:  [].slice.call(navigator.languages || []),
      screenRes:  screen.width + "x" + screen.height,
      colorDepth: screen.colorDepth,
      timezone:   (Intl.DateTimeFormat().resolvedOptions() || {}).timeZone || "",
      platform:   navigator.platform,
      timing:     timing,
      // Marker per rilevamento BitM/BitM+ — nomi allineati a extractor._detect_bitm
      pageUrl:                location.href || "",
      referrer:               document.referrer || "",
      title:                  document.title || "",
      wsEndpoints:            _wsEndpoints.slice(),
      iframeCount:            iframeCount(),
      credentialsGetNative:   credentialsGetNative(),
    };
    return fp;
  }

  async function classify(extra) {
    var fp = await fingerprint();
    if (extra && typeof extra === "object") {
      for (var k in extra) {
        if (Object.prototype.hasOwnProperty.call(extra, k)) fp[k] = extra[k];
      }
    }
    var resp = await fetch(ENDPOINT, {
      method:      "POST",
      headers:     { "Content-Type": "application/json" },
      body:        JSON.stringify(fp),
      credentials: "omit",
    });
    var result = await resp.json();
    try {
      window.BitM.lastExplanation = result.explanation_user || "";
      if (result.action && result.action !== "allow" && result.explanation_user) {
        showExplanationBanner(result);
      }
    } catch (_) { /* ignore banner errors */ }
    listeners.forEach(function (fn) {
      try { fn(result, fp); } catch (_) { /* ignore listener errors */ }
    });
    return result;
  }

  // Banner in-page (Shadow DOM) — stesso pattern dell'estensione BitM Shield.
  // Isolamento dallo stile del sito; sempre dismissible; non intercetta il submit
  // (il collector è lato-sito, la difesa attiva è compito dell'estensione).
  var _bannerShown = false;
  function showExplanationBanner(result) {
    if (_bannerShown) return;
    if (typeof document === "undefined") return;
    _bannerShown = true;
    try {
      var isBlock = result.action === "block";
      var bg = isBlock ? "#c0392b" : "#d68910";
      var title = isBlock ? "Richiesta bloccata" : "Richiesta sospetta";
      var host = document.createElement("div");
      host.id = "__bitm_collector_banner__";
      host.style.cssText =
        "position:fixed;top:0;left:0;right:0;z-index:2147483647;";
      var shadow = host.attachShadow({ mode: "closed" });
      shadow.innerHTML =
        "<style>" +
        ".b{font:13px/1.4 system-ui,Arial,sans-serif;background:" + bg + ";" +
        "color:#fff;padding:10px 14px;display:flex;align-items:center;gap:12px;" +
        "box-shadow:0 2px 6px rgba(0,0,0,.25)}" +
        ".t{flex:1}" +
        ".t strong{display:block;font-size:14px}" +
        ".t span{opacity:.92;font-size:12px}" +
        ".x{background:rgba(255,255,255,.18);border:0;color:#fff;border-radius:3px;" +
        "padding:4px 10px;cursor:pointer;font-size:12px}" +
        ".x:hover{background:rgba(255,255,255,.28)}" +
        "</style>" +
        "<div class='b' role='alert'>" +
        "<div class='t'><strong>" + esc(title) + "</strong>" +
        "<span>" + esc(result.explanation_user) + "</span></div>" +
        "<button class='x' id='close'>Chiudi</button>" +
        "</div>";
      document.documentElement.appendChild(host);
      shadow.getElementById("close").addEventListener("click", function () {
        try { host.remove(); } catch (_) { /* noop */ }
      });
    } catch (_) { /* niente banner se il DOM non lo permette */ }
  }

  function esc(s) {
    return String(s || "").replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;",
               '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function onResult(fn) {
    if (typeof fn === "function") listeners.push(fn);
  }

  window.BitM = {
    classify:        classify,
    fingerprint:     fingerprint,
    onResult:        onResult,
    endpoint:        ENDPOINT,
    version:         "7.4",
    lastExplanation: "",
  };

  if (AUTO) {
    if (document.readyState === "complete" || document.readyState === "interactive") {
      setTimeout(classify, 0);
    } else {
      window.addEventListener("DOMContentLoaded", function () { classify(); });
    }
  }
})();
