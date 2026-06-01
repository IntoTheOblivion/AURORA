/*
 * AURORA — detection.js
 *
 * Porting in JavaScript delle regole di extractor._detect_bitm.
 * Le regex e i pesi sono allineati con aurora-plugin/app/extractor.py: se qui
 * cambi un pattern, aggiorna anche il lato Python (e viceversa).
 */
(function () {
  "use strict";

  var TUNNEL_HOST_RE = /(?:^|[./@])([a-z0-9-]+\.(?:ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|loca\.lt|localtunnel\.me|serveo\.net))/i;
  var NOVNC_TITLE_RE = /\b(?:noVNC|Websockify)\b/i;
  var GUACAMOLE_TITLE_RE = /\bguacamole\b/i;
  // Filtro per escludere i titoli di pagine di ricerca/editoriali (es.
  // "noVNC - Ricerca Google", "guacamole recipe"). Allineato con
  // extractor._SEARCH_ENGINE_RE.
  var SEARCH_ENGINE_RE = /\b(?:Google|Bing|DuckDuckGo|Yahoo|Yandex|Baidu|Ecosia|Wikipedia|Reddit)\b|\bSearch\b|\bRicerca\b|\bBúsqueda\b|\bSuche\b|\bRecherche\b/i;
  var XSS_PAYLOAD_RE = /(?:<\s*script|onerror\s*=|javascript:|document\.createElement|appendChild|loadFromAttacker|eval\s*\(|fromCharCode)/i;
  var BITM_UA_MARKERS = ["novnc", "websockify", "guacamole", "tigervnc"];
  // Porte del backend BitM/BitM+: 3081 (Express MalSrv), 6080 (noVNC),
  // 5900 (VNC), 4822 (Guacamole Tomcat). Allineato con extractor._BITM_PORT_RE.
  var BITM_PORT_RE = /:(?:3081|6080|5900|4822)(?:\/|$)/;

  // Pesi da extractor._pre_score (devono restare sincronizzati)
  var WEIGHTS = {
    novnc_client_marker:      0.80,
    guacamole_client_marker:  0.80,
    bitm_framework_ua:        0.80,
    bitm_backend_port:        0.78,
    xss_reflected_param:      0.70,
    webauthn_api_override:    0.70,
    bitm_websocket_transport: 0.55,
    tunnel_host:              0.25,
    iframe_overlay:           0.15,
  };

  // Segnali che da soli forzano block (allineati con policy.CRITICAL_BLOCK)
  var CRITICAL = {
    novnc_client_marker:      1, guacamole_client_marker:  1,
    bitm_framework_ua:        1, bitm_backend_port:        1,
    xss_reflected_param:      1, webauthn_api_override:    1,
    bitm_websocket_transport: 1,
  };

  // Soglie [challenge, block] per contesto, allineate con policy.THRESHOLDS.
  // Senza questa mappa il verdict locale era 0.65/0.28 ovunque, quindi una
  // pagina /payment con score 0.55 (sopra block remoto) restava in challenge
  // localmente — divergenza local vs hybrid.
  var THRESHOLDS = {
    "default": [0.40, 0.75],
    "login":   [0.28, 0.62],
    "payment": [0.20, 0.55],
    "admin":   [0.22, 0.60],
    "static":  [0.70, 0.92],
  };

  // Path prefix → contesto (porting di policy.detect_page_context)
  var LOGIN_PREFIXES   = ["/login", "/signin", "/auth", "/accedi", "/logon", "/entrar"];
  var PAYMENT_PREFIXES = ["/payment", "/checkout", "/pay", "/pagamento", "/ordine", "/order"];
  var ADMIN_PREFIXES   = ["/admin", "/settings", "/account", "/profilo", "/profile", "/manage"];
  var STATIC_EXTS      = [".js", ".css", ".png", ".jpg", ".jpeg", ".svg",
                          ".ico", ".woff", ".woff2", ".ttf", ".map"];

  function _matchPrefix(p, prefixes) {
    for (var i = 0; i < prefixes.length; i++) {
      var pr = prefixes[i];
      if (p === pr || p.indexOf(pr + "/") === 0) return true;
    }
    return false;
  }

  function detectContext(pageUrl) {
    var path = "/";
    try {
      // pageUrl può essere relativo o assente: fallback a location.href.
      var base = (typeof location !== "undefined" && location.href) ? location.href : "http://x/";
      path = new URL(pageUrl || base, base).pathname || "/";
    } catch (_) { path = "/"; }
    var p = path.toLowerCase().split("?")[0].split("#")[0];
    if (_matchPrefix(p, LOGIN_PREFIXES))   return "login";
    if (_matchPrefix(p, PAYMENT_PREFIXES)) return "payment";
    if (_matchPrefix(p, ADMIN_PREFIXES))   return "admin";
    for (var j = 0; j < STATIC_EXTS.length; j++) {
      var ext = STATIC_EXTS[j];
      if (p.length >= ext.length && p.lastIndexOf(ext) === p.length - ext.length) return "static";
    }
    return "default";
  }

  function detect(input) {
    var title    = input.title || "";
    var pageUrl  = input.pageUrl || "";
    var referrer = input.referrer || "";
    var wsList   = input.wsEndpoints || [];
    var credNat  = input.credentialsGetNative;
    var iframes  = input.iframeCount || 0;
    var uaLower  = (input.userAgent || "").toLowerCase();

    var found = {};

    if (TUNNEL_HOST_RE.test(pageUrl) || TUNNEL_HOST_RE.test(referrer))
      found.tunnel_host = true;
    if (BITM_PORT_RE.test(pageUrl) || BITM_PORT_RE.test(referrer))
      found.bitm_backend_port = true;
    // Salta i marker via title se il titolo sembra una pagina di ricerca
    // (evita falsi positivi su "noVNC - Ricerca Google", "guacamole recipe").
    var titleIsSearch = !!(title && SEARCH_ENGINE_RE.test(title));
    if (title && !titleIsSearch && NOVNC_TITLE_RE.test(title))     found.novnc_client_marker = true;
    if (title && !titleIsSearch && GUACAMOLE_TITLE_RE.test(title)) found.guacamole_client_marker = true;
    if (XSS_PAYLOAD_RE.test(pageUrl) || XSS_PAYLOAD_RE.test(referrer))
      found.xss_reflected_param = true;

    for (var i = 0; i < wsList.length; i++) {
      var ws = wsList[i];
      if (typeof ws !== "string") continue;
      var wl = ws.toLowerCase();
      if (TUNNEL_HOST_RE.test(wl) || BITM_PORT_RE.test(wl)) {
        found.bitm_websocket_transport = true;
        break;
      }
      if ((wl.indexOf("ws://") === 0 || wl.indexOf("wss://") === 0) &&
          (wl.indexOf("websockify") !== -1 ||
           wl.indexOf("/vnc") !== -1 ||
           wl.indexOf("/guacamole") !== -1)) {
        found.bitm_websocket_transport = true;
        break;
      }
    }

    if (credNat === false) found.webauthn_api_override = true;

    for (var j = 0; j < BITM_UA_MARKERS.length; j++) {
      if (uaLower.indexOf(BITM_UA_MARKERS[j]) !== -1) {
        found.bitm_framework_ua = true;
        break;
      }
    }

    // Allineato con extractor._detect_bitm: soglia 5 iframe, non 3.
    if (iframes >= 5) found.iframe_overlay = true;

    // Calcolo score + verdict
    var signals = Object.keys(found);
    var score = 0;
    for (var s = 0; s < signals.length; s++) score += (WEIGHTS[signals[s]] || 0);
    score = Math.min(1, score);

    var hasCritical = false;
    for (var c = 0; c < signals.length; c++) {
      if (CRITICAL[signals[c]]) { hasCritical = true; break; }
    }

    var context = detectContext(pageUrl);
    var thresholds = THRESHOLDS[context] || THRESHOLDS["default"];
    var thChallenge = thresholds[0];
    var thBlock     = thresholds[1];

    var verdict;
    if (hasCritical || score >= thBlock)   verdict = "block";
    else if (score >= thChallenge)         verdict = "challenge";
    else                                   verdict = "allow";

    return {
      verdict: verdict,
      score: Math.round(score * 1000) / 1000,
      signals: signals,
      context: context,
    };
  }

  // Export per content-script (stessa realm ISOLATED)
  self.BitMDetection = {
    detect: detect,
    detectContext: detectContext,
    WEIGHTS: WEIGHTS,
    CRITICAL: CRITICAL,
    THRESHOLDS: THRESHOLDS,
  };
})();
