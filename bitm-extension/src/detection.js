/*
 * BitM Shield — detection.js
 *
 * Porting in JavaScript delle regole di extractor._detect_bitm.
 * Le regex e i pesi sono allineati con bitm-plugin/app/extractor.py: se qui
 * cambi un pattern, aggiorna anche il lato Python (e viceversa).
 */
(function () {
  "use strict";

  var TUNNEL_HOST_RE = /(?:^|[./@])([a-z0-9-]+\.(?:ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|loca\.lt|localtunnel\.me|serveo\.net))/i;
  var NOVNC_TITLE_RE = /\b(?:noVNC|Websockify)\b/i;
  var GUACAMOLE_TITLE_RE = /\bguacamole\b/i;
  var XSS_PAYLOAD_RE = /(?:<\s*script|onerror\s*=|javascript:|document\.createElement|appendChild|loadFromAttacker|eval\s*\(|fromCharCode)/i;
  var BITM_UA_MARKERS = ["novnc", "websockify", "guacamole", "tigervnc"];
  var BITM_PORT_RE = /:(?:3081|6080|5900|4822|8080)(?:\/|$)/;

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
    if (NOVNC_TITLE_RE.test(title))     found.novnc_client_marker = true;
    if (GUACAMOLE_TITLE_RE.test(title)) found.guacamole_client_marker = true;
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

    if (iframes >= 3) found.iframe_overlay = true;

    // Calcolo score + verdict
    var signals = Object.keys(found);
    var score = 0;
    for (var s = 0; s < signals.length; s++) score += (WEIGHTS[signals[s]] || 0);
    score = Math.min(1, score);

    var hasCritical = false;
    for (var c = 0; c < signals.length; c++) {
      if (CRITICAL[signals[c]]) { hasCritical = true; break; }
    }

    var verdict;
    if (hasCritical || score >= 0.65)      verdict = "block";
    else if (score >= 0.28)                verdict = "challenge";
    else                                   verdict = "allow";

    return { verdict: verdict, score: Math.round(score * 1000) / 1000, signals: signals };
  }

  // Export per content-script (stessa realm ISOLATED)
  self.BitMDetection = { detect: detect, WEIGHTS: WEIGHTS, CRITICAL: CRITICAL };
})();
