"""
Feature Extractor v7.2
- ip_meta arriva come parametro esplicito dal GeoIP resolver
- v7.2: rilevamento specifico degli stack BitM/BitM+ documentati in letteratura:
    * RFB variant: noVNC + WebSockify + TigerVNC  (Tommasi 2021, Tzschoppe 2023)
    * RDP variant: Apache Guacamole + FreeRDP + Tomcat   (Tzschoppe 2023)
    * BitM+      : ngrok tunnel + Puppeteer + Node/Express MalSrv + evilGet()
                   override via reflected XSS                 (Catalano 2025)
  I marker sono estratti da campi OPZIONALI del payload (pageUrl, referrer,
  title, wsEndpoints, credentialsGetNative, iframeCount) e diventano
  confirmed_signals a tutti gli effetti. Gli stessi label sono poi presenti
  in policy.CRITICAL_BLOCK / main._fast_rules per forzare BLOCK.
"""

import hashlib
import re
import statistics


# Piattaforme mobile che legittimamente non hanno plugin
_MOBILE_PLATFORMS = {"iphone", "ipad", "android", "ipod"}
_MOBILE_UA_TOKENS = ("iphone", "ipad", "android", "mobile")

# ── BitM infrastructure markers ───────────────────────────────────────────────
# Tunnel HTTPS verso localhost comunemente usati per esporre il BE BitM+
# (Catalano 2025 usa esplicitamente ngrok; trycloudflare/localtunnel sono
# sostituti funzionali noti e adottati in PoC pubbliche).
_TUNNEL_HOST_RE = re.compile(
    r"(?:^|[./@])("
    r"[a-z0-9-]+\.ngrok(?:-free)?\.(?:io|app|dev)"
    r"|[a-z0-9-]+\.trycloudflare\.com"
    r"|[a-z0-9-]+\.loca\.lt"
    r"|[a-z0-9-]+\.localtunnel\.me"
    r"|[a-z0-9-]+\.serveo\.net"
    r")", re.IGNORECASE,
)

# Marker nel document.title: i due client BitM più diffusi lasciano il proprio
# nome nel titolo quando non personalizzati (noVNC: "<sito> - noVNC";
# Guacamole: contiene "Apache Guacamole").
# NOTA: il check titolo viene saltato se la pagina è un motore di ricerca —
# altrimenti "noVNC - Ricerca Google" o "guacamole recipe" triggererebbe il marker.
_NOVNC_TITLE_RE     = re.compile(r"\b(?:noVNC|Websockify|WebSockify)\b", re.IGNORECASE)
_GUACAMOLE_TITLE_RE = re.compile(r"\bguacamole\b", re.IGNORECASE)
_SEARCH_ENGINE_RE   = re.compile(
    r"\b(?:Google|Bing|DuckDuckGo|Yahoo|Yandex|Baidu|Ecosia|Wikipedia|Reddit)\b"
    r"|\bSearch\b|\bRicerca\b|\bBúsqueda\b|\bSuche\b|\bRecherche\b",
    re.IGNORECASE,
)

# xURL di BitM+: il payload XSS viene iniettato come query-string del RP
# (es.  "?xssParam={loadFromAttacker(/xss/payload.js)}" in Catalano 2025).
_XSS_PAYLOAD_RE = re.compile(
    r"(?:<\s*script|onerror\s*=|javascript:|document\.createElement|"
    r"appendChild|loadFromAttacker|eval\s*\(|fromCharCode)",
    re.IGNORECASE,
)

# UA / marker che rivelano il framework BitM lato client (alcune PoC non
# riscrivono l'UA del viewer interno → il fingerprint trapela).
_BITM_UA_MARKERS = ("novnc", "websockify", "guacamole", "tigervnc")

# Porte di ascolto del BE BitM+ (3081=MalSrv Express, 6080=noVNC, 5900=VNC,
# 4822=Guacamole Tomcat). Se compaiono nell'URL visto dal client è
# altamente sospetto.
_BITM_PORT_RE = re.compile(r":(?:3081|6080|5900|4822)(?:/|$)")


def extract_features(raw: dict, ip: str, store: dict,
                     ip_meta: dict | None = None) -> dict:
    ua = raw.get("userAgent", "") or ""
    ua_lower = ua.lower()
    plugins = raw.get("plugins") or []
    platform = raw.get("platform", "") or ""
    ip_meta = ip_meta or {}

    # Determina se è un dispositivo mobile (Safari iOS non ha plugin — è normale)
    is_mobile = (
        platform.lower() in _MOBILE_PLATFORMS
        or any(t in ua_lower for t in _MOBILE_UA_TOKENS)
    )

    timings = store.get("timings", []) or [raw.get("timing", 0)]
    timings_pos = [t for t in timings if isinstance(t, (int, float)) and t > 0]

    avg_timing   = statistics.mean(timings_pos)             if timings_pos else 0.0
    max_timing   = max(timings_pos)                         if timings_pos else 0.0
    stdev_timing = statistics.stdev(timings_pos)            if len(timings_pos) > 1 else 0.0

    canvas_raw  = raw.get("canvas") or ""
    canvas_hash = hashlib.md5(canvas_raw.encode()).hexdigest()[:12] if canvas_raw else "empty"

    headless_signals = _detect_headless(raw, ua_lower, plugins, platform, is_mobile)
    bitm_signals     = _detect_bitm(raw, ua_lower)

    # Punteggio deterministico pre-LLM (usato nel prompt come base)
    pre_score, confirmed = _pre_score(raw, headless_signals, bitm_signals,
                                      timings_pos, avg_timing, ip_meta)

    return {
        # Identità
        "user_agent":       ua,
        "ua_browser":       _parse_browser(ua),
        "ua_os":            _parse_os(ua),
        "ip":               ip,
        "is_mobile":        is_mobile,
        # Plugin e rendering
        "plugins":          plugins,
        "plugin_count":     len(plugins),
        "webgl":            raw.get("webgl") or "unavailable",
        "webgl_swiftshader": "swiftshader" in (raw.get("webgl") or "").lower(),
        # Fingerprint
        "canvas_hash":      canvas_hash,
        "canvas_empty":     not bool(canvas_raw),
        "webdriver":        bool(raw.get("webdriver", False)),
        # Localizzazione
        "languages":        raw.get("languages") or [],
        "language_count":   len(raw.get("languages") or []),
        "screen":           raw.get("screenRes", "unknown") or "unknown",
        "color_depth":      raw.get("colorDepth", 0) or 0,
        "timezone":         raw.get("timezone", "") or "",
        "timezone_anomaly": _timezone_anomaly(raw),
        "platform":         platform or "unknown",
        # Timing
        "avg_timing_ms":    round(avg_timing, 1),
        "max_timing_ms":    round(max_timing, 1),
        "stdev_timing_ms":  round(stdev_timing, 1),
        "request_count":    len(timings),
        # Sessione
        "page_sequence":    (store.get("pages") or [])[-10:],
        # Segnali
        "headless_signals": headless_signals,
        "headless_score":   len(headless_signals),
        "bitm_signals":     bitm_signals,   # segnali specifici BitM/BitM+
        "confirmed_signals": confirmed,     # segnali certi da mostrare all'LLM
        "pre_risk_score":   round(pre_score, 3),  # score deterministico base
        # IP metadata risolti automaticamente dal GeoIP resolver
        "ip_meta":          ip_meta,
    }


def _detect_headless(raw: dict, ua_lower: str,
                     plugins: list, platform: str, is_mobile: bool) -> list[str]:
    signals = []

    # UA markers specifici di browser automatizzati
    for marker, label in [
        ("headlesschrome", "headlesschrome_ua"),
        ("phantomjs",      "phantomjs_ua"),
        ("slimerjs",       "slimerjs_ua"),
        ("jsdom",          "jsdom_ua"),
    ]:
        if marker in ua_lower:
            signals.append(label)

    # Flag webdriver (Selenium/Playwright lo impostano quasi sempre)
    if raw.get("webdriver"):
        signals.append("webdriver_true")

    # Zero plugin: normale su mobile, sospetto su desktop
    if len(plugins) == 0 and not is_mobile:
        signals.append("zero_plugins")

    # WebGL
    webgl = raw.get("webgl") or ""
    if not webgl or webgl == "unavailable":
        signals.append("no_webgl_renderer")
    elif "swiftshader" in webgl.lower():
        # SwiftShader = renderer software, usato da Chrome headless
        signals.append("swiftshader_webgl")

    # Canvas vuoto
    if not raw.get("canvas"):
        signals.append("empty_canvas")

    # Nessuna lingua: browser reali hanno sempre almeno una lingua
    if not (raw.get("languages") or []):
        signals.append("no_languages")

    # Risoluzione non standard
    screen = raw.get("screenRes", "") or ""
    if screen in ("800x600", "1024x768", "0x0", ""):
        signals.append("suspicious_resolution")

    # Color depth anomala
    if (raw.get("colorDepth") or 24) < 8:
        signals.append("low_color_depth")

    # Timezone mancante (browser reali hanno sempre un timezone)
    if not (raw.get("timezone") or "").strip():
        signals.append("no_timezone")

    return signals


def _detect_bitm(raw: dict, ua_lower: str) -> list[str]:
    """
    Rileva gli artefatti degli stack BitM e BitM+ documentati.

    Legge campi OPZIONALI del payload (il collector client può fornirli o no):
      - pageUrl / url          → window.location.href
      - referrer               → document.referrer
      - title / windowTitle    → document.title
      - wsEndpoints            → URL dei WebSocket aperti (lista)
      - credentialsGetNative   → bool: navigator.credentials.get.toString() == "[native code]"
      - iframeCount            → numero di iframe nella pagina
      - documentDomain         → document.domain

    Tutti i campi sono trattati come hint: se assenti non contribuiscono
    al risultato. Le firme e il razionale sono documentati nella docstring
    di modulo.
    """
    signals: list[str] = []

    page_url    = (raw.get("pageUrl") or raw.get("url") or "") or ""
    referrer    = raw.get("referrer") or ""
    title       = raw.get("title") or raw.get("windowTitle") or ""
    ws_list     = raw.get("wsEndpoints") or []
    iframe_n    = raw.get("iframeCount") or 0
    credget_nat = raw.get("credentialsGetNative")

    haystack = f"{page_url}\n{referrer}".lower()

    # Tunneling HTTPS verso un backend locale: tipico vettore di BitM+
    # per esporre la pagina d'attacco con certificato valido (requisito
    # WebAuthn). Su produzione non dovrebbe mai comparire un origin ngrok.
    if _TUNNEL_HOST_RE.search(page_url) or _TUNNEL_HOST_RE.search(referrer):
        signals.append("tunnel_host")

    # Porte tipiche del BE BitM+: 3081 (Express MalSrv), 6080 (noVNC),
    # 4822 (Guacamole Tomcat), 5900 (VNC). Se arrivano al client → BLOCK.
    if _BITM_PORT_RE.search(page_url) or _BITM_PORT_RE.search(referrer):
        signals.append("bitm_backend_port")

    # noVNC e Guacamole lasciano il loro nome nel document.title se non
    # stato rimosso dall'attaccante (Tzschoppe 2023 §4.1–4.2).
    # Salta il check se il titolo appartiene a una pagina di ricerca o
    # contenuto editoriale (es. "noVNC - Ricerca Google", "guacamole recipe").
    title_is_search = bool(title and _SEARCH_ENGINE_RE.search(title))
    if title and not title_is_search and _NOVNC_TITLE_RE.search(title):
        signals.append("novnc_client_marker")
    if title and not title_is_search and _GUACAMOLE_TITLE_RE.search(title):
        signals.append("guacamole_client_marker")

    # xURL con payload XSS riflesso (Catalano 2025 Fig. 11): firma tipica
    # "?xssParam={loadFromAttacker(...)}", script tag, onerror, eval, ecc.
    if _XSS_PAYLOAD_RE.search(page_url) or _XSS_PAYLOAD_RE.search(referrer):
        signals.append("xss_reflected_param")

    # Il client BitM usa WebSocket per trasportare RFB su HTTPS; se il
    # collector riporta endpoint WS esterni al dominio pagina è sospetto.
    for ws in ws_list or []:
        if not isinstance(ws, str):
            continue
        ws_l = ws.lower()
        if _TUNNEL_HOST_RE.search(ws_l) or _BITM_PORT_RE.search(ws_l):
            signals.append("bitm_websocket_transport")
            break
        if ws_l.startswith(("ws://", "wss://")) and ("websockify" in ws_l
                                                     or "/vnc" in ws_l
                                                     or "/guacamole" in ws_l):
            signals.append("bitm_websocket_transport")
            break

    # Override di navigator.credentials.get(): core di BitM+ (evilGet).
    # Il collector può verificare `navigator.credentials.get.toString()`
    # e segnalare se non è "[native code]".
    if credget_nat is False:
        signals.append("webauthn_api_override")

    # UA che rivela il framework (PoC non-stealth / operatore distratto).
    for marker in _BITM_UA_MARKERS:
        if marker in ua_lower:
            signals.append("bitm_framework_ua")
            break

    # Iframe overlay: BitM+ in Scenario 3 inietta un iframe che copre il
    # viewport per mostrare la GUI del BitM sopra il RP. Molti iframe full
    # sono anomali nelle pagine d'autenticazione reali.
    try:
        if int(iframe_n) >= 5:
            signals.append("iframe_overlay")
    except (TypeError, ValueError):
        pass

    return signals


def _pre_score(raw: dict, headless_signals: list, bitm_signals: list,
               timings_pos: list, avg_timing: float,
               ip_meta: dict | None = None) -> tuple[float, list]:
    """
    Calcola un punteggio deterministico base e una lista di segnali confermati.
    Questi vengono passati all'LLM come punto di partenza affidabile.
    """
    score = 0.0
    confirmed = []
    ip_meta = ip_meta or {}

    signal_set = set(headless_signals) | set(bitm_signals)

    weights = {
        # Headless / automation
        "headlesschrome_ua": 0.50,
        "phantomjs_ua":      0.55,
        "webdriver_true":    0.45,
        "swiftshader_webgl": 0.30,
        "no_webgl_renderer": 0.12,  # GPU disabilitata può essere legittima
        "zero_plugins":      0.07,  # Chrome moderno ha sempre 0 plugin
        "empty_canvas":      0.15,
        "no_languages":      0.15,
        "no_timezone":       0.10,
        "suspicious_resolution": 0.10,
        # BitM / BitM+ — pesi scelti per superare da soli la soglia BLOCK
        # del contesto più permissivo (default=0.75) quando il segnale è
        # intrinsecamente diagnostico (marker client, porta BE), e per
        # restare sotto quando serve coincidenza con un contesto sensibile
        # (tunnel_host, iframe_overlay).
        "novnc_client_marker":     0.80,
        "guacamole_client_marker": 0.80,
        "bitm_framework_ua":       0.80,
        "bitm_backend_port":       0.78,
        "xss_reflected_param":     0.70,
        "webauthn_api_override":   0.70,
        "bitm_websocket_transport": 0.55,
        "tunnel_host":             0.25,
        "iframe_overlay":          0.15,
    }

    for sig, w in weights.items():
        if sig in signal_set:
            score += w
            confirmed.append(sig)

    # Latenza (soglie alzate: event loop JS-heavy come YouTube può superare 500ms)
    if avg_timing > 2000:
        score += 0.32
        confirmed.append(f"extreme_latency_{int(avg_timing)}ms")
    elif avg_timing > 1000:
        score += 0.22
        confirmed.append(f"high_latency_{int(avg_timing)}ms")
    elif avg_timing > 500:
        score += 0.09
        confirmed.append(f"elevated_latency_{int(avg_timing)}ms")

    # VPN / Tor (risolti dal GeoIP)
    if ip_meta.get("is_tor"):
        score += 0.30
        confirmed.append("tor_exit_node")
    if ip_meta.get("is_vpn"):
        score += 0.12
        confirmed.append("vpn_detected")

    # Timezone anomala (UTC con lingua non-inglese)
    if _timezone_anomaly(raw):
        score += 0.10
        confirmed.append("timezone_anomaly")

    return min(score, 1.0), confirmed


def _timezone_anomaly(raw: dict) -> bool:
    tz = raw.get("timezone", "") or ""
    langs = raw.get("languages") or []
    # Solo UTC esplicito — timezone vuota è già coperta da no_timezone
    if tz in ("UTC", "Etc/UTC") and langs:
        first = langs[0].lower() if langs else ""
        if not first.startswith("en"):
            return True
    return False


def _parse_browser(ua: str) -> str:
    if "HeadlessChrome" in ua: return "HeadlessChrome"
    if "Firefox/" in ua:       return "Firefox"
    if "Edg/" in ua:           return "Edge"
    if "OPR/" in ua:           return "Opera"
    if "Chrome/" in ua:        return "Chrome"
    if "Safari/" in ua:        return "Safari"
    return "unknown"


def _parse_os(ua: str) -> str:
    if "Windows NT" in ua:             return "Windows"
    if "Macintosh" in ua:              return "macOS"
    if "iPhone" in ua or "iPad" in ua: return "iOS"
    if "Android" in ua:                return "Android"
    if "Linux" in ua:                  return "Linux"
    return "unknown"
