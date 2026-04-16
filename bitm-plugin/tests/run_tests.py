"""
BitM Detection Plugin — Test Suite v6.2

Copertura:
  • legit      → browser reali in vari contesti
  • attack     → bot/headless/automazione
  • suspicious → segnali ambigui in pagine sensibili
  • edge       → casi limite (payload minimi, UA unicode, sequenze)
  • system     → feature v6.x (session store, GeoIP, rate-limit, admin, webhook)

Esecuzione:
  python tests/run_tests.py
  python tests/run_tests.py --filter attack
  python tests/run_tests.py --only T01,T05
  python tests/run_tests.py --parallel 4
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import uuid
from datetime import datetime

import httpx


# ── Colori ANSI ───────────────────────────────────────────────────────────────
G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"; C = "\033[36m"
B = "\033[1m";  D = "\033[2m";  X = "\033[0m"


# ─────────────────────────────────────────────────────────────────────────────
#   DATASET: singoli scenari /api/bitm/collect
# ─────────────────────────────────────────────────────────────────────────────
CASES: list[dict] = [
    # ── LEGITTIMI ─────────────────────────────────────────────────────────────
    {
        "id": "T01", "cat": "legit", "name": "Chrome / Windows / Italia",
        "expected": "allow",
        "payload": {
            "sessionId": "t01", "page": "/dashboard",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer", "Chrome PDF Viewer", "Widevine Content Decryption Module", "Native Client"],
            "webgl": "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0)",
            "canvas": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAASwAAABkCAYAAAA8AQ3AAA",
            "webdriver": False, "languages": ["it-IT", "it", "en-US", "en"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "Europe/Rome", "platform": "Win32", "timing": 14,
        },
    },
    {
        "id": "T02", "cat": "legit", "name": "Firefox / macOS / Italia",
        "expected": "allow",
        "payload": {
            "sessionId": "t02", "page": "/profile",
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0",
            "plugins": ["OpenH264 Video Codec provided by Cisco Systems, Inc."],
            "webgl": "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)",
            "canvas": "data:image/png;base64,firefoxcanvasABCDEF123456789",
            "webdriver": False, "languages": ["it-IT", "en-US"],
            "screenRes": "2560x1600", "colorDepth": 30,
            "timezone": "Europe/Rome", "platform": "MacIntel", "timing": 8,
        },
    },
    {
        "id": "T03", "cat": "legit", "name": "Safari / iPhone / Italia (zero plugin = normale)",
        "expected": "allow",
        "payload": {
            "sessionId": "t03", "page": "/news",
            "userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            "plugins": [], "webgl": "Apple GPU",
            "canvas": "data:image/png;base64,safariiosCANVAS987654",
            "webdriver": False, "languages": ["it-IT", "it"],
            "screenRes": "390x844", "colorDepth": 32,
            "timezone": "Europe/Rome", "platform": "iPhone", "timing": 22,
        },
    },
    {
        "id": "T04", "cat": "legit", "name": "Edge / Windows / Italia",
        "expected": "allow",
        "payload": {
            "sessionId": "t04", "page": "/home",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "plugins": ["PDF Viewer", "Chrome PDF Viewer"],
            "webgl": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11)",
            "canvas": "data:image/png;base64,edgeCANVAS987654XYZ",
            "webdriver": False, "languages": ["it-IT", "en-US"],
            "screenRes": "2560x1440", "colorDepth": 24,
            "timezone": "Europe/Rome", "platform": "Win32", "timing": 11,
        },
    },
    {
        "id": "T05", "cat": "legit", "name": "Chrome Android / timing naturale",
        "expected": "allow",
        "payload": {
            "sessionId": "t05", "page": "/catalog",
            "userAgent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "plugins": [], "webgl": "Adreno (TM) 740",
            "canvas": "data:image/png;base64,androidCANVAS8877",
            "webdriver": False, "languages": ["it-IT", "it", "en"],
            "screenRes": "412x915", "colorDepth": 24,
            "timezone": "Europe/Rome", "platform": "Linux armv8l", "timing": 28,
        },
    },

    # ── ATTACCHI ──────────────────────────────────────────────────────────────
    {
        "id": "T06", "cat": "attack", "name": "HeadlessChrome / Evilginx",
        "expected": "block",
        "payload": {
            "sessionId": "t06", "page": "/login",
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
            "plugins": [], "webgl": "unavailable", "canvas": "",
            "webdriver": True, "languages": [],
            "screenRes": "800x600", "colorDepth": 24,
            "timezone": "", "platform": "Linux x86_64", "timing": 487,
        },
    },
    {
        "id": "T07", "cat": "attack", "name": "Playwright / webdriver=true / SwiftShader",
        "expected": "block",
        "payload": {
            "sessionId": "t07", "page": "/login",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": [],
            "webgl": "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)))",
            "canvas": "", "webdriver": True, "languages": ["en-US"],
            "screenRes": "1280x720", "colorDepth": 24,
            "timezone": "UTC", "platform": "Win32", "timing": 312,
        },
    },
    {
        "id": "T08", "cat": "attack", "name": "Selenium / no plugin + no WebGL / desktop",
        "expected": "block",
        "payload": {
            "sessionId": "t08", "page": "/payment",
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
            "plugins": [], "webgl": "", "canvas": "",
            "webdriver": False, "languages": ["en"],
            "screenRes": "1024x768", "colorDepth": 24,
            "timezone": "UTC", "platform": "Linux x86_64", "timing": 55,
        },
    },
    {
        "id": "T09", "cat": "attack", "name": "Tor exit node / checkout",
        "expected": "block",
        "payload": {
            "sessionId": "t09", "page": "/checkout",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
            "plugins": ["OpenH264 Video Codec"],
            "webgl": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
            "canvas": "data:image/png;base64,torCANVAS123",
            "webdriver": False, "languages": ["en-US"],
            "screenRes": "1000x800", "colorDepth": 24,
            "timezone": "UTC", "platform": "Win32", "timing": 210,
            "ip_meta": {"is_vpn": False, "is_tor": True, "country": "?"},
        },
    },
    {
        "id": "T10", "cat": "attack", "name": "Puppeteer UA marker",
        "expected": "block",
        "payload": {
            "sessionId": "t10", "page": "/admin",
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64) Puppeteer/21.5.0 HeadlessChrome/118.0",
            "plugins": [], "webgl": "unavailable", "canvas": "",
            "webdriver": True, "languages": ["en-US"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "UTC", "platform": "Linux x86_64", "timing": 180,
        },
    },
    {
        "id": "T11", "cat": "attack", "name": "Latenza estrema (>600ms) = scraping",
        "expected": "block",
        "payload": {
            "sessionId": "t11", "page": "/api/data",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer"], "webgl": "ANGLE (NVIDIA)", "canvas": "data:image/png;base64,x",
            "webdriver": False, "languages": ["en-US"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "UTC", "platform": "Win32", "timing": 950,
        },
    },

    # ── SOSPETTI ──────────────────────────────────────────────────────────────
    {
        "id": "T12", "cat": "suspicious", "name": "VPN + pagina login",
        "expected": "challenge",
        "payload": {
            "sessionId": "t12", "page": "/login",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "plugins": ["OpenH264 Video Codec"],
            "webgl": "Mesa Intel(R) UHD Graphics 630",
            "canvas": "data:image/png;base64,vpnCANVAS456",
            "webdriver": False, "languages": ["en-US"],
            "screenRes": "1366x768", "colorDepth": 24,
            "timezone": "America/New_York", "platform": "Win32", "timing": 95,
            "ip_meta": {"is_vpn": True, "is_tor": False, "country": "US"},
        },
    },
    {
        "id": "T13", "cat": "suspicious", "name": "Latenza alta (380ms) / pagamento",
        "expected": "challenge",
        "payload": {
            "sessionId": "t13", "page": "/payment",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer"],
            "webgl": "ANGLE (NVIDIA, NVIDIA GeForce GTX 1060 Direct3D11)",
            "canvas": "data:image/png;base64,normalCANVAS99887",
            "webdriver": False, "languages": ["en-GB"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "Europe/London", "platform": "Win32", "timing": 380,
        },
    },
    {
        "id": "T14", "cat": "suspicious", "name": "VPN + canvas vuoto + login",
        "expected": "challenge",
        "payload": {
            "sessionId": "t14", "page": "/signin",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer"],
            "webgl": "ANGLE (Intel, Intel(R) HD Graphics 4000)",
            "canvas": "",
            "webdriver": False, "languages": ["fr-FR"],
            "screenRes": "1280x800", "colorDepth": 24,
            "timezone": "Europe/Paris", "platform": "Win32", "timing": 45,
            "ip_meta": {"is_vpn": True, "is_tor": False, "country": "FR"},
        },
    },
    {
        "id": "T15", "cat": "suspicious", "name": "Timezone UTC + lingua italiana (anomalia)",
        "expected": "challenge",
        "payload": {
            "sessionId": "t15", "page": "/account",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer", "Widevine"],
            "webgl": "ANGLE (Intel, Intel(R) UHD Graphics 620)",
            "canvas": "data:image/png;base64,normalCANVAS111",
            "webdriver": False, "languages": ["it-IT", "it"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "UTC", "platform": "Win32", "timing": 35,
        },
    },
    {
        "id": "T16", "cat": "suspicious", "name": "Risoluzione 1024x768 + no-lingua / login",
        "expected": "challenge",
        "payload": {
            "sessionId": "t16", "page": "/login",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer"],
            "webgl": "ANGLE (Intel)",
            "canvas": "data:image/png;base64,lowresCANVAS",
            "webdriver": False, "languages": [],
            "screenRes": "1024x768", "colorDepth": 24,
            "timezone": "Europe/Berlin", "platform": "Win32", "timing": 60,
        },
    },

    # ── EDGE CASES ────────────────────────────────────────────────────────────
    {
        "id": "T17", "cat": "edge", "name": "Payload minimo (solo UA)",
        "expected_in": ("challenge", "block"),
        "payload": {
            "sessionId": "t17", "page": "/login",
            "userAgent": "Mozilla/5.0",
        },
    },
    {
        "id": "T18", "cat": "edge", "name": "User-Agent con caratteri unicode",
        "expected": "allow",
        "payload": {
            "sessionId": "t18", "page": "/",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 お茶/1.0",
            "plugins": ["PDF Viewer", "Chrome PDF Viewer"],
            "webgl": "ANGLE (Intel)", "canvas": "data:image/png;base64,unicodeCANVAS",
            "webdriver": False, "languages": ["ja-JP", "ja"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "Asia/Tokyo", "platform": "Win32", "timing": 12,
        },
    },
    {
        "id": "T19", "cat": "edge", "name": "Static asset (soglie rilassate)",
        "expected": "allow",
        "payload": {
            "sessionId": "t19", "page": "/assets/logo.png",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer"], "webgl": "ANGLE", "canvas": "data:image/png;base64,staticX",
            "webdriver": False, "languages": ["en-US"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "Europe/Rome", "platform": "Win32", "timing": 5,
        },
    },
    {
        "id": "T20", "cat": "edge", "name": "Path sconosciuto = default context",
        "expected": "allow",
        "payload": {
            "sessionId": "t20", "page": "/foo/bar/baz",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer", "Chrome PDF Viewer"],
            "webgl": "ANGLE (Intel)", "canvas": "data:image/png;base64,uCANVAS",
            "webdriver": False, "languages": ["en-US"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "Europe/Rome", "platform": "Win32", "timing": 17,
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#   TEST RUNNER per scenari
# ─────────────────────────────────────────────────────────────────────────────

async def run_case(client: httpx.AsyncClient, case: dict, base: str) -> dict:
    t0 = time.time()
    try:
        r    = await client.post(f"{base}/api/bitm/collect",
                                 json=case["payload"], timeout=60)
        data = r.json()
        ms   = round((time.time() - t0) * 1000)
        got  = data.get("action", "?")

        if "expected" in case:
            passed = got == case["expected"]
            expected_desc = case["expected"]
        else:
            passed = got in case["expected_in"]
            expected_desc = "|".join(case["expected_in"])

        return {
            "id":         case["id"],
            "cat":        case["cat"],
            "name":       case["name"],
            "passed":     passed,
            "expected":   expected_desc,
            "got":        got,
            "score":      data.get("score", 0),
            "verdict":    data.get("verdict", "?"),
            "confidence": data.get("confidence", "?"),
            "indicators": data.get("indicators", []),
            "reason":     data.get("reason", ""),
            "context":    data.get("context", "?"),
            "plugin_ms":  data.get("latency_ms", 0),
            "total_ms":   ms,
        }
    except Exception as e:
        return {
            "id": case["id"], "cat": case["cat"], "name": case["name"],
            "passed": False,
            "expected": case.get("expected", "|".join(case.get("expected_in", []))),
            "got": "error", "score": 0, "error": str(e),
            "total_ms": round((time.time() - t0) * 1000),
        }


# ─────────────────────────────────────────────────────────────────────────────
#   SYSTEM CHECKS v6.0 (Redis / GeoIP / Admin / Rate limit)
# ─────────────────────────────────────────────────────────────────────────────

def _legit_payload(sid: str, page: str = "/home") -> dict:
    return {
        "sessionId": sid, "page": page,
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "plugins": ["PDF Viewer", "Chrome PDF Viewer"],
        "webgl": "ANGLE (Intel, Intel(R) UHD Graphics 620)",
        "canvas": "data:image/png;base64,sysCANVAS",
        "webdriver": False, "languages": ["it-IT", "en-US"],
        "screenRes": "1920x1080", "colorDepth": 24,
        "timezone": "Europe/Rome", "platform": "Win32", "timing": 12,
    }


def _headless_payload(sid: str, page: str = "/login") -> dict:
    return {
        "sessionId": sid, "page": page,
        "userAgent": "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0 Safari/537.36",
        "plugins": [], "webgl": "unavailable", "canvas": "",
        "webdriver": True, "languages": [],
        "screenRes": "800x600", "colorDepth": 24,
        "timezone": "", "platform": "Linux x86_64", "timing": 420,
    }


async def sys_health(client: httpx.AsyncClient, base: str) -> dict:
    """S01 — /health deve esporre versione 6.x, store, GeoIP e webhook."""
    passed, detail = True, []
    try:
        r = await client.get(f"{base}/health", timeout=5)
        j = r.json()
        if not str(j.get("version", "")).startswith("6."):
            passed = False; detail.append(f"versione non 6.x ({j.get('version')})")
        for k in ("store", "geoip", "sessions", "blocked_ips", "webhook"):
            if k not in j:
                passed = False; detail.append(f"manca campo {k}")
        return {"id": "S01", "cat": "system",
                "name": "Health esposto v6.2 (store/geoip/webhook)",
                "passed": passed, "detail": "; ".join(detail) or "ok",
                "extra": j}
    except Exception as e:
        return {"id": "S01", "cat": "system",
                "name": "Health esposto v6.2 (store/geoip/webhook)",
                "passed": False, "detail": f"errore: {e}"}


async def sys_session_persistence(client: httpx.AsyncClient, base: str) -> dict:
    """S02 — più POST sullo stesso sessionId accumulano pagine e timings."""
    sid = f"sys-{uuid.uuid4().hex[:8]}"
    pages = ["/home", "/catalog", "/product/1", "/cart"]
    for pg in pages:
        await client.post(f"{base}/api/bitm/collect",
                          json=_legit_payload(sid, pg), timeout=30)
    r = await client.get(f"{base}/api/bitm/sessions", timeout=10)
    j = r.json()
    sess = j.get("sessions", {}).get(sid)
    passed = bool(sess) and sess.get("request_count", 0) >= len(pages)
    return {
        "id": "S02", "cat": "system",
        "name": "Session store persiste richieste multi-step",
        "passed": passed,
        "detail": (f"backend={j.get('backend')} req_count="
                   f"{sess.get('request_count') if sess else 'N/A'} atteso>={len(pages)}"),
    }


async def sys_ip_block_escalation(client: httpx.AsyncClient, base: str) -> dict:
    """S03 — la stessa sessione bloccata 3 volte aggiunge l'IP al set bloccati."""
    fake_ip = f"203.0.113.{(int(time.time()) % 250) + 1}"
    headers = {"X-Forwarded-For": fake_ip}
    sid     = f"esc-{uuid.uuid4().hex[:6]}"
    # Azzera contesto precedente
    await client.delete(f"{base}/api/bitm/sessions", timeout=10)
    for _ in range(3):
        await client.post(f"{base}/api/bitm/collect",
                          json=_headless_payload(sid),
                          headers=headers, timeout=30)
    r = await client.get(f"{base}/api/bitm/sessions", timeout=10)
    blocked = set(r.json().get("blocked_ips", []))
    passed = fake_ip in blocked
    return {
        "id": "S03", "cat": "system",
        "name": "IP-block escalation dopo 3 block consecutivi",
        "passed": passed,
        "detail": f"ip={fake_ip} in blocked={passed} (n blocked={len(blocked)})",
    }


async def sys_rate_limit(client: httpx.AsyncClient, base: str) -> dict:
    """S04 — oltre RATE_LIMIT richieste nella finestra → 429 RATE_LIMITED."""
    fake_ip = f"198.51.100.{(int(time.time()) % 250) + 1}"
    headers = {"X-Forwarded-For": fake_ip}
    saw_429 = False
    responses = 0
    for i in range(40):
        try:
            r = await client.post(f"{base}/api/bitm/collect",
                                  json=_legit_payload(f"rl-{i}"),
                                  headers=headers, timeout=10)
            responses += 1
            if r.status_code == 429:
                saw_429 = True
                break
        except Exception:
            break
    return {
        "id": "S04", "cat": "system",
        "name": "Rate-limit scatta oltre la soglia",
        "passed": saw_429,
        "detail": f"richieste prima del 429: {responses} (atteso <= RATE_LIMIT+poche)",
    }


async def sys_geoip_private(client: httpx.AsyncClient, base: str) -> dict:
    """S05 — IP privato (loopback) non produce crash e /health resta coerente."""
    r = await client.post(f"{base}/api/bitm/collect",
                          json=_legit_payload("geoip-priv"), timeout=30)
    h = await client.get(f"{base}/health", timeout=5)
    passed = r.status_code == 200 and h.status_code == 200
    return {
        "id": "S05", "cat": "system",
        "name": "GeoIP enrichment gestisce IP privato senza errori",
        "passed": passed,
        "detail": f"collect={r.status_code} health={h.status_code}",
    }


async def sys_admin_clear(client: httpx.AsyncClient, base: str) -> dict:
    """S06 — DELETE /api/bitm/sessions azzera sessioni e blocked."""
    sid = f"wipe-{uuid.uuid4().hex[:6]}"
    await client.post(f"{base}/api/bitm/collect",
                      json=_legit_payload(sid), timeout=30)
    before = (await client.get(f"{base}/health", timeout=5)).json()
    await client.delete(f"{base}/api/bitm/sessions", timeout=10)
    after = (await client.get(f"{base}/health", timeout=5)).json()
    passed = after.get("sessions", 1) == 0 and after.get("blocked_ips", 1) == 0
    return {
        "id": "S06", "cat": "system",
        "name": "Admin DELETE azzera sessioni e blocked",
        "passed": passed,
        "detail": f"prima=({before.get('sessions')},{before.get('blocked_ips')}) "
                  f"dopo=({after.get('sessions')},{after.get('blocked_ips')})",
    }


async def sys_cache_speedup(client: httpx.AsyncClient, base: str) -> dict:
    """S07 — la seconda chiamata con stesso fingerprint è più veloce (cache TTL)."""
    sid = f"cache-{uuid.uuid4().hex[:6]}"
    p   = _legit_payload(sid, "/home")
    r1  = await client.post(f"{base}/api/bitm/collect", json=p, timeout=30)
    t1  = r1.json().get("latency_ms", 9999)
    r2  = await client.post(f"{base}/api/bitm/collect", json=p, timeout=30)
    t2  = r2.json().get("latency_ms", 9999)
    passed = t2 <= t1 + 50   # margine generoso
    return {
        "id": "S07", "cat": "system",
        "name": "Cache LLM velocizza richieste successive",
        "passed": passed,
        "detail": f"primo={t1}ms secondo={t2}ms",
    }


async def sys_webhook_field(client: httpx.AsyncClient, base: str) -> dict:
    """S08 — /health espone il campo 'webhook' con struttura valida (v6.2)."""
    passed, detail = True, []
    try:
        r = await client.get(f"{base}/health", timeout=5)
        j = r.json()
        wh = j.get("webhook")
        if wh is None:
            passed = False
            detail.append("campo 'webhook' assente in /health")
        elif not isinstance(wh, dict):
            passed = False
            detail.append(f"'webhook' non è un oggetto: {wh!r}")
        else:
            if "enabled" not in wh:
                passed = False
                detail.append("manca 'enabled' in webhook")
            # Se abilitato deve avere almeno type e url
            if wh.get("enabled"):
                for k in ("type", "url", "timeout", "retries"):
                    if k not in wh:
                        passed = False
                        detail.append(f"manca '{k}' nel webhook abilitato")
        return {
            "id": "S08", "cat": "system",
            "name": "Webhook push — campo esposto in /health (v6.2)",
            "passed": passed,
            "detail": "; ".join(detail) or f"ok  enabled={wh.get('enabled')}",
            "extra": wh,
        }
    except Exception as e:
        return {
            "id": "S08", "cat": "system",
            "name": "Webhook push — campo esposto in /health (v6.2)",
            "passed": False, "detail": f"errore: {e}",
        }


async def sys_webhook_nonblocking(client: httpx.AsyncClient, base: str) -> dict:
    """S09 — un evento BLOCK con webhook irraggiungibile non rallenta la risposta."""
    # Inviamo un headless BLOCK e misuriamo il round-trip dal client.
    # Se il notifier fosse bloccante, questo supererebbe di molto il WEBHOOK_TIMEOUT.
    # Con fire-and-forget il round-trip dev'essere < 4000ms anche se il webhook pende.
    sid = f"nb-{uuid.uuid4().hex[:6]}"
    t0  = time.time()
    r   = await client.post(
        f"{base}/api/bitm/collect",
        json=_headless_payload(sid),
        timeout=30,
    )
    elapsed_ms = round((time.time() - t0) * 1000)
    passed = r.status_code == 200 and elapsed_ms < 4000
    return {
        "id": "S09", "cat": "system",
        "name": "Webhook non-blocking — BLOCK risponde senza attendere il webhook",
        "passed": passed,
        "detail": (f"status={r.status_code}  round-trip={elapsed_ms}ms  "
                   f"action={r.json().get('action','?')} (atteso block, <4000ms)"),
    }


SYSTEM_CHECKS = [
    sys_health,
    sys_session_persistence,
    sys_ip_block_escalation,
    sys_rate_limit,
    sys_geoip_private,
    sys_admin_clear,
    sys_cache_speedup,
    sys_webhook_field,
    sys_webhook_nonblocking,
]


# ─────────────────────────────────────────────────────────────────────────────
#   REPORTING
# ─────────────────────────────────────────────────────────────────────────────

def print_report(cases: list, systems: list) -> dict:
    total   = len(cases) + len(systems)
    passed  = sum(1 for r in cases if r["passed"]) + sum(1 for r in systems if r["passed"])
    pct     = round(100 * passed / total) if total else 0

    by_cat: dict[str, list] = {}
    for r in cases:
        by_cat.setdefault(r["cat"], []).append(r)

    print(f"\n{B}{'='*72}{X}")
    print(f"{B}  BitM Detection Plugin v6.2 — Test Suite{X}")
    print(f"{'='*72}")

    for cat in ("legit", "attack", "suspicious", "edge"):
        rows = by_cat.get(cat, [])
        if not rows:
            continue
        cat_pass = sum(1 for r in rows if r["passed"])
        print(f"\n{B}{cat.upper()} ({cat_pass}/{len(rows)}){X}")
        for r in rows:
            ok   = r["passed"]
            icon = f"{G}✓{X}" if ok else f"{R}✗{X}"
            print(f"  {icon} [{r['id']}] {r['name']}")
            got_c = G if ok else R
            print(f"      atteso={r['expected'].upper():<15} "
                  f"ottenuto={got_c}{r['got'].upper()}{X}  "
                  f"score={r.get('score',0):.3f}  ctx={r.get('context','?'):<8} "
                  f"{r.get('plugin_ms','?')}ms")
            if r.get("indicators"):
                print(f"      {D}segnali: {', '.join(r['indicators'][:5])}{X}")
            if r.get("reason"):
                print(f"      {D}{r['reason'][:80]}{X}")
            if r.get("error"):
                print(f"      {R}errore: {r['error']}{X}")

    if systems:
        sys_pass = sum(1 for r in systems if r["passed"])
        print(f"\n{B}SYSTEM v6.2 ({sys_pass}/{len(systems)}){X}")
        for r in systems:
            icon = f"{G}✓{X}" if r["passed"] else f"{R}✗{X}"
            print(f"  {icon} [{r['id']}] {r['name']}")
            detail = r.get("detail", "")
            if detail:
                print(f"      {D}{detail[:150]}{X}")

    bar_c = G if pct >= 90 else (Y if pct >= 70 else R)
    print(f"\n{B}{'='*72}{X}")
    print(f"  {B}TOTALE: {passed}/{total}  {bar_c}{pct}%{X}")
    print(f"{'='*72}\n")

    report = {
        "timestamp": datetime.now().isoformat(),
        "version":   "6.2",
        "passed":    passed,
        "total":     total,
        "accuracy":  round(passed / total, 3) if total else 0,
        "cases":     cases,
        "system":    systems,
    }
    with open("test_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"Report: test_report.json\n")
    return report


# ─────────────────────────────────────────────────────────────────────────────
#   MAIN
# ─────────────────────────────────────────────────────────────────────────────

def _select(cases: list, flt: str | None, only: str | None) -> list:
    out = cases
    if flt:
        wanted = set(flt.split(","))
        out = [c for c in out if c["cat"] in wanted]
    if only:
        ids = set(only.split(","))
        out = [c for c in out if c["id"] in ids]
    return out


async def main():
    parser = argparse.ArgumentParser(description="BitM Test Suite v6.2")
    parser.add_argument("--filter", help="Categorie separate da virgola (legit,attack,...)")
    parser.add_argument("--only",   help="ID specifici separati da virgola (T01,T05,...)")
    parser.add_argument("--parallel", type=int, default=1,
                        help="Numero di test in parallelo (default 1)")
    parser.add_argument("--skip-system", action="store_true",
                        help="Salta i system check v6.0")
    args = parser.parse_args()

    base = os.getenv("BITM_URL", "http://localhost:8000")
    print(f"{B}Connessione a {base}...{X}")

    async with httpx.AsyncClient() as client:
        try:
            h = await client.get(f"{base}/health", timeout=5)
            info = h.json()
            print(f"Server v{info.get('version','?')}  "
                  f"modello={info.get('model','?')}  "
                  f"store={info.get('store','?')}  "
                  f"geoip=\"{info.get('geoip','?')}\"\n")
        except Exception:
            print(f"{R}✗ Server non raggiungibile su {base}{X}")
            print("  Avvia con: python run.py")
            sys.exit(1)

        # Azzera lo stato per evitare sporcature da run precedenti
        try:
            await client.delete(f"{base}/api/bitm/sessions", timeout=10)
        except Exception:
            pass

        cases = _select(CASES, args.filter, args.only)

        # Scenari /collect
        results: list = []
        if args.parallel > 1:
            sem = asyncio.Semaphore(args.parallel)
            async def _guarded(c):
                async with sem:
                    print(f"  {C}▶{X} [{c['id']}] {c['name'][:50]}")
                    return await run_case(client, c, base)
            results = await asyncio.gather(*[_guarded(c) for c in cases])
        else:
            for c in cases:
                label = f"[{c['id']}] {c['name'][:52]}"
                print(f"  {label:<58}", end=" ", flush=True)
                r = await run_case(client, c, base)
                results.append(r)
                ok = f"{G}✓{X}" if r["passed"] else f"{R}✗{X}"
                print(f"{ok}  ({r.get('plugin_ms','?')}ms)")
                await asyncio.sleep(0.3)

        # System checks v6
        systems: list = []
        if not args.skip_system and not args.only:
            print(f"\n  {C}── SYSTEM CHECKS v6.2 ──{X}")
            # Reset prima dei system check
            try:
                await client.delete(f"{base}/api/bitm/sessions", timeout=10)
            except Exception:
                pass
            for check in SYSTEM_CHECKS:
                t0 = time.time()
                try:
                    res = await check(client, base)
                except Exception as e:
                    res = {"id": check.__name__, "cat": "system",
                           "name": check.__doc__ or check.__name__,
                           "passed": False, "detail": f"eccezione: {e}"}
                ms = round((time.time() - t0) * 1000)
                icon = f"{G}✓{X}" if res["passed"] else f"{R}✗{X}"
                print(f"  {icon} [{res['id']}] {res['name']:<52} ({ms}ms)")
                systems.append(res)

        report = print_report(results, systems)

    sys.exit(0 if report["passed"] == report["total"] else 1)


if __name__ == "__main__":
    asyncio.run(main())
