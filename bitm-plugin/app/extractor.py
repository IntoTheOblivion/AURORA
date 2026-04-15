"""
Feature Extractor v4
- Rimosso import re (inutilizzato)
- Aggiunto campo is_mobile: Safari iOS/Android legittimamente non ha plugin
- zero_plugins non viene segnalato per piattaforme mobile
- Aggiunto campo pre_risk_score: punteggio deterministico pre-LLM
- Aggiunto campo confirmed_signals: segnali certi da passare esplicitamente all'LLM
"""

import hashlib
import statistics


# Piattaforme mobile che legittimamente non hanno plugin
_MOBILE_PLATFORMS = {"iphone", "ipad", "android", "ipod"}
_MOBILE_UA_TOKENS = ("iphone", "ipad", "android", "mobile")


def extract_features(raw: dict, ip: str, store: dict) -> dict:
    ua = raw.get("userAgent", "") or ""
    ua_lower = ua.lower()
    plugins = raw.get("plugins") or []
    platform = raw.get("platform", "") or ""

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

    # Punteggio deterministico pre-LLM (usato nel prompt come base)
    pre_score, confirmed = _pre_score(raw, headless_signals, timings_pos, avg_timing)

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
        "confirmed_signals": confirmed,     # segnali certi da mostrare all'LLM
        "pre_risk_score":   round(pre_score, 3),  # score deterministico base
        # IP metadata (fornito dal client o da GeoIP esterno)
        "ip_meta":          raw.get("ip_meta") or {},
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


def _pre_score(raw: dict, headless_signals: list,
               timings_pos: list, avg_timing: float) -> tuple[float, list]:
    """
    Calcola un punteggio deterministico base e una lista di segnali confermati.
    Questi vengono passati all'LLM come punto di partenza affidabile.
    """
    score = 0.0
    confirmed = []

    signal_set = set(headless_signals)

    weights = {
        "headlesschrome_ua": 0.50,
        "phantomjs_ua":      0.55,
        "webdriver_true":    0.45,
        "swiftshader_webgl": 0.30,
        "no_webgl_renderer": 0.20,
        "zero_plugins":      0.20,
        "empty_canvas":      0.15,
        "no_languages":      0.15,
        "no_timezone":       0.10,
        "suspicious_resolution": 0.10,
    }

    for sig, w in weights.items():
        if sig in signal_set:
            score += w
            confirmed.append(sig)

    # Latenza (>300ms supera sicuramente soglia CHALLENGE su payment=0.20)
    if avg_timing > 500:
        score += 0.32
        confirmed.append(f"extreme_latency_{int(avg_timing)}ms")
    elif avg_timing > 300:
        score += 0.22
        confirmed.append(f"high_latency_{int(avg_timing)}ms")
    elif avg_timing > 150:
        score += 0.09
        confirmed.append(f"elevated_latency_{int(avg_timing)}ms")

    # VPN / Tor (se forniti)
    ip_meta = raw.get("ip_meta") or {}
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
    if tz in ("UTC", "Etc/UTC", "") and langs:
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
