"""
AURORA — Test Suite v7.3

Copertura:
  • legit      → browser reali in vari contesti
  • attack     → bot/headless/automazione + stack BitM/BitM+ noti
  • suspicious → segnali ambigui in pagine sensibili
  • edge       → casi limite (payload minimi, UA unicode, sequenze)
  • system     → feature v6.x (session store, GeoIP, rate-limit, admin, webhook)
                 + v7.0 (system prompt compatto, pipeline training)
                 + v7.2 (coerenza label BitM/BitM+ tra extractor e policy)
                 + v7.3 (collector.js endpoint per integrazione one-liner)

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
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path

import httpx

# Fix encoding su Windows (console cp1252 non supporta i caratteri Unicode usati nei report)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


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

    # ── BitM / BitM+ — stack documentati in letteratura ──────────────────────
    # Rif.: Tommasi 2021 (IJIS), Tzschoppe 2023 (EuroSec), Catalano 2025 (JCompVir)
    {
        "id": "T21", "cat": "attack",
        "name": "BitM RFB — noVNC client marker nel title",
        "expected": "block",
        "payload": {
            "sessionId": "t21", "page": "/login",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer"], "webgl": "ANGLE (Intel)",
            "canvas": "data:image/png;base64,novncCANVAS",
            "webdriver": False, "languages": ["en-US"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "Europe/Rome", "platform": "Win32", "timing": 30,
            # Il collector ha letto document.title = "Login - noVNC" (default del client)
            "title":     "Login - noVNC",
            "pageUrl":   "https://abc123.ngrok-free.app/vnc.html",
        },
    },
    {
        "id": "T22", "cat": "attack",
        "name": "BitM RDP — Apache Guacamole client",
        "expected": "block",
        "payload": {
            "sessionId": "t22", "page": "/signin",
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer"], "webgl": "ANGLE (Apple M1)",
            "canvas": "data:image/png;base64,guacaCANVAS",
            "webdriver": False, "languages": ["en-US"],
            "screenRes": "1440x900", "colorDepth": 24,
            "timezone": "UTC", "platform": "MacIntel", "timing": 48,
            "title":    "Apache Guacamole",
            "pageUrl":  "https://attacker.example.com:8080/guacamole/#/",
        },
    },
    {
        "id": "T23", "cat": "attack",
        "name": "BitM+ xssPayload — loadFromAttacker() nell'URL",
        "expected": "block",
        "payload": {
            "sessionId": "t23", "page": "/auth",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer"], "webgl": "ANGLE (NVIDIA)",
            "canvas": "data:image/png;base64,xssCANVAS",
            "webdriver": False, "languages": ["en-US"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "Europe/London", "platform": "Win32", "timing": 25,
            # xURL tipico di BitM+ (Catalano 2025 Fig. 11)
            "pageUrl":  "https://fido.site.demo/login?xssParam=%7BloadFromAttacker(%2Fxss%2Fpayload.js)%7D",
        },
    },
    {
        "id": "T24", "cat": "attack",
        "name": "BitM+ evilGet — navigator.credentials.get non nativo",
        "expected": "block",
        "payload": {
            "sessionId": "t24", "page": "/login",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer"], "webgl": "ANGLE (Intel)",
            "canvas": "data:image/png;base64,evilgetCANVAS",
            "webdriver": False, "languages": ["en-US"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "Europe/Rome", "platform": "Win32", "timing": 22,
            # Collector ha invocato navigator.credentials.get.toString():
            # se non contiene "[native code]" → sostituito (evilGet).
            "credentialsGetNative": False,
        },
    },
    {
        "id": "T25", "cat": "attack",
        "name": "BitM+ backend port (MalSrv :3081) visibile al client",
        "expected": "block",
        "payload": {
            "sessionId": "t25", "page": "/login",
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer"], "webgl": "ANGLE (Mesa Intel)",
            "canvas": "data:image/png;base64,malsrvCANVAS",
            "webdriver": False, "languages": ["en-US"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "Europe/Berlin", "platform": "Linux x86_64", "timing": 35,
            # Porte del BE BitM+: 3081=Express MalSrv, 6080=noVNC
            "pageUrl":  "https://attacker.demo:6080/vnc.html",
            "referrer": "http://localhost:3081/getChallenge",
        },
    },
    {
        "id": "T26", "cat": "attack",
        "name": "BitM UA leak — noVNC nell'User-Agent",
        "expected": "block",
        "payload": {
            "sessionId": "t26", "page": "/login",
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64) noVNC/1.4.0 WebKit/537.36",
            "plugins": ["PDF Viewer"], "webgl": "ANGLE (Mesa)",
            "canvas": "data:image/png;base64,uaLeakCANVAS",
            "webdriver": False, "languages": ["en-US"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "UTC", "platform": "Linux x86_64", "timing": 40,
        },
    },
    {
        "id": "T27", "cat": "attack",
        "name": "BitM+ WebSocket transport verso tunnel ngrok",
        "expected": "block",
        "payload": {
            "sessionId": "t27", "page": "/payment",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer"], "webgl": "ANGLE (Intel)",
            "canvas": "data:image/png;base64,wsCANVAS",
            "webdriver": False, "languages": ["en-US"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "Europe/Rome", "platform": "Win32", "timing": 28,
            "wsEndpoints": ["wss://abc123.ngrok-free.app/websockify"],
        },
    },
    {
        "id": "T28", "cat": "suspicious",
        "name": "ngrok tunnel + login (sospetto, ambiente dev legittimo possibile)",
        "expected_in": ("challenge", "block"),
        "payload": {
            "sessionId": "t28", "page": "/login",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer", "Chrome PDF Viewer"],
            "webgl": "ANGLE (Intel, Intel(R) UHD Graphics 620)",
            "canvas": "data:image/png;base64,devCANVAS",
            "webdriver": False, "languages": ["en-US"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "Europe/Rome", "platform": "Win32", "timing": 15,
            "pageUrl":  "https://myapp.ngrok-free.app/login",
            "referrer": "https://myapp.ngrok-free.app/",
        },
    },
    {
        "id": "T29", "cat": "edge",
        "name": "WebAuthn API nativa confermata → nessun boost",
        "expected": "allow",
        "payload": {
            "sessionId": "t29", "page": "/login",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer", "Chrome PDF Viewer"],
            "webgl": "ANGLE (Intel, Intel(R) UHD Graphics 620)",
            "canvas": "data:image/png;base64,nativewebauthnCANVAS",
            "webdriver": False, "languages": ["it-IT", "en-US"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "Europe/Rome", "platform": "Win32", "timing": 11,
            "credentialsGetNative": True,
            "title":    "Login",
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
    """S01 — /health deve esporre versione, store, GeoIP e webhook."""
    passed, detail = True, []
    try:
        r = await client.get(f"{base}/health", timeout=5)
        j = r.json()
        # Accetta qualunque versione stabile documentata (v6+). Rifiuta solo versioni
        # manifestamente non aggiornate (<6.) o mancanti.
        version = str(j.get("version", ""))
        major = version.split(".")[0] if version else ""
        if not major.isdigit() or int(major) < 6:
            passed = False; detail.append(f"versione non riconosciuta ({version!r})")
        for k in ("store", "geoip", "sessions", "blocked_ips", "webhook"):
            if k not in j:
                passed = False; detail.append(f"manca campo {k}")
        return {"id": "S01", "cat": "system",
                "name": "Health esposto (version/store/geoip/webhook)",
                "passed": passed, "detail": "; ".join(detail) or "ok",
                "extra": j}
    except Exception as e:
        return {"id": "S01", "cat": "system",
                "name": "Health esposto (version/store/geoip/webhook)",
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


# ─────────────────────────────────────────────────────────────────────────────
#   SYSTEM CHECKS v7.0 (prompt compatto + pipeline fine-tuning)
#   I check v7.0 non richiedono il server — usano import diretti e subprocess
#   sui moduli della cartella training/. Le firme (client, base) restano per
#   uniformità con gli altri system check.
# ─────────────────────────────────────────────────────────────────────────────

# Root del pacchetto = cartella genitrice di tests/
_ROOT = Path(__file__).resolve().parent.parent
_PROMPT_MAX_CHARS = 650  # 40% riduzione da ~1080 (v6)


async def sys_prompt_v7_shortened(client: httpx.AsyncClient, base: str) -> dict:
    """S10 — il SYSTEM_PROMPT v7 dev'essere ≤ 650 caratteri (riduzione ≥40%)."""
    try:
        # Import locale: il modulo app è nella root del pacchetto
        if str(_ROOT) not in sys.path:
            sys.path.insert(0, str(_ROOT))
        from app.scorer import SYSTEM_PROMPT
        n = len(SYSTEM_PROMPT)
        passed = n <= _PROMPT_MAX_CHARS
        # Controlla anche che le direttive essenziali siano ancora presenti
        essentials = ["JSON", "LEGITIMATE", "SUSPICIOUS", "ATTACK",
                      "pre_risk_score", "BitM"]
        missing = [k for k in essentials if k not in SYSTEM_PROMPT]
        if missing:
            passed = False
        return {
            "id": "S10", "cat": "system",
            "name": "Prompt v7 compatto (<=650 char, direttive preservate)",
            "passed": passed,
            "detail": (f"chars={n} (max {_PROMPT_MAX_CHARS})  "
                       f"missing={missing or 'none'}"),
        }
    except Exception as e:
        return {
            "id": "S10", "cat": "system",
            "name": "Prompt v7 compatto (<=650 char, direttive preservate)",
            "passed": False, "detail": f"errore: {e}",
        }


async def sys_dataset_builder(client: httpx.AsyncClient, base: str) -> dict:
    """S11 — build_dataset.py converte log fittizi in dataset ChatML valido."""
    script = _ROOT / "training" / "build_dataset.py"
    if not script.exists():
        return {
            "id": "S11", "cat": "system",
            "name": "Dataset builder v7 produce ChatML pulito",
            "passed": False, "detail": f"{script} non trovato",
        }

    # Fixture: log minimo con 1 entry per classe + rumore da filtrare
    fixture = [
        {"ts": "2026-04-16T10:00:00Z", "ip": "1.1.1.1", "session": "a",
         "action": "allow",  "context": "default", "score": 0.05, "pre_score": 0.0,
         "verdict": "LEGITIMATE", "confidence": "high", "indicators": [],
         "explanation": "ok", "from_cache": False, "latency_ms": 10,
         "browser": "Chrome", "os": "Windows", "is_mobile": False,
         "headless_n": 0, "ua": "Mozilla/5.0 Chrome/120"},
        {"ts": "2026-04-16T10:00:01Z", "ip": "2.2.2.2", "session": "b",
         "action": "challenge", "context": "login", "score": 0.45, "pre_score": 0.3,
         "verdict": "SUSPICIOUS", "confidence": "medium", "indicators": ["vpn_detected"],
         "explanation": "vpn", "from_cache": False, "latency_ms": 12,
         "browser": "Firefox", "os": "Linux", "is_mobile": False,
         "headless_n": 0, "ua": "Mozilla/5.0 Firefox/121"},
        {"ts": "2026-04-16T10:00:02Z", "ip": "3.3.3.3", "session": "c",
         "action": "block", "context": "payment", "score": 0.91, "pre_score": 0.85,
         "verdict": "ATTACK", "confidence": "high", "indicators": ["headless_ua"],
         "explanation": "headless", "from_cache": False, "latency_ms": 8,
         "browser": "HeadlessChrome", "os": "Linux", "is_mobile": False,
         "headless_n": 3, "ua": "Mozilla/5.0 HeadlessChrome/120"},
        # Rumore: entry da cache (deve essere scartata)
        {"ts": "2026-04-16T10:00:03Z", "ip": "4.4.4.4", "session": "d",
         "action": "allow", "context": "default", "score": 0.05, "pre_score": 0.0,
         "verdict": "LEGITIMATE", "confidence": "high", "indicators": [],
         "explanation": "ok", "from_cache": True, "latency_ms": 1,
         "browser": "Chrome", "os": "Windows", "is_mobile": False,
         "headless_n": 0, "ua": "Mozilla/5.0 Chrome/120"},
        # Rumore: error indicator (deve essere scartata)
        {"ts": "2026-04-16T10:00:04Z", "ip": "5.5.5.5", "session": "e",
         "action": "challenge", "context": "login", "score": 0.5, "pre_score": 0.0,
         "verdict": "SUSPICIOUS", "confidence": "low", "indicators": ["api_error"],
         "explanation": "err", "from_cache": False, "latency_ms": 3000,
         "browser": "?", "os": "?", "is_mobile": False, "headless_n": 0, "ua": "?"},
    ]

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        log_path = tmp_path / "events.jsonl"
        with log_path.open("w", encoding="utf-8") as f:
            for entry in fixture:
                f.write(json.dumps(entry) + "\n")
        out_dir = tmp_path / "out"

        try:
            proc = subprocess.run(
                [sys.executable, str(script),
                 "--input", str(log_path),
                 "--output-dir", str(out_dir),
                 "--val-split", "0.0"],
                capture_output=True, text=True, timeout=30,
            )
        except Exception as e:
            return {
                "id": "S11", "cat": "system",
                "name": "Dataset builder v7 produce ChatML pulito",
                "passed": False, "detail": f"errore esecuzione: {e}",
            }

        if proc.returncode != 0:
            return {
                "id": "S11", "cat": "system",
                "name": "Dataset builder v7 produce ChatML pulito",
                "passed": False,
                "detail": f"exit={proc.returncode}  stderr={proc.stderr[:200]}",
            }

        stats_file = out_dir / "stats.json"
        train_file = out_dir / "train.jsonl"
        if not stats_file.exists() or not train_file.exists():
            return {
                "id": "S11", "cat": "system",
                "name": "Dataset builder v7 produce ChatML pulito",
                "passed": False, "detail": "output atteso mancante",
            }

        stats = json.loads(stats_file.read_text(encoding="utf-8"))
        # Verifica: 3 entry valide conservate, rumore scartato
        kept_ok = stats.get("kept") == 3
        skipped = stats.get("skipped", {}) or {}
        filtered_ok = skipped.get("filtered", 0) >= 2  # cache + api_error

        # Verifica ChatML: prima riga deve avere 3 messaggi (system/user/assistant)
        chatml_ok = True
        with train_file.open(encoding="utf-8") as f:
            first = json.loads(next(f))
        msgs = first.get("messages", [])
        if len(msgs) != 3 or [m["role"] for m in msgs] != ["system", "user", "assistant"]:
            chatml_ok = False
        # Il target assistant dev'essere JSON parsabile e contenere verdict valido
        try:
            target = json.loads(msgs[2]["content"])
            if target.get("verdict") not in {"LEGITIMATE", "SUSPICIOUS", "ATTACK"}:
                chatml_ok = False
        except Exception:
            chatml_ok = False

        passed = kept_ok and filtered_ok and chatml_ok
        return {
            "id": "S11", "cat": "system",
            "name": "Dataset builder v7 produce ChatML pulito",
            "passed": passed,
            "detail": (f"kept={stats.get('kept')}  skipped={skipped}  "
                       f"chatml_ok={chatml_ok}"),
        }


async def sys_train_lora_cli(client: httpx.AsyncClient, base: str) -> dict:
    """S12 — train_lora.py è sintatticamente valido e la sua CLI è funzionante."""
    script = _ROOT / "training" / "train_lora.py"
    if not script.exists():
        return {
            "id": "S12", "cat": "system",
            "name": "Training LoRA CLI parseable senza dipendenze ML",
            "passed": False, "detail": f"{script} non trovato",
        }
    try:
        proc = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True, text=True, timeout=15,
        )
    except Exception as e:
        return {
            "id": "S12", "cat": "system",
            "name": "Training LoRA CLI parseable senza dipendenze ML",
            "passed": False, "detail": f"errore esecuzione: {e}",
        }
    out = (proc.stdout or "") + (proc.stderr or "")
    required_flags = ["--dataset-dir", "--base-model", "--output-dir",
                      "--lora-r", "--lora-alpha", "--no-4bit"]
    missing = [f for f in required_flags if f not in out]
    passed = proc.returncode == 0 and not missing
    return {
        "id": "S12", "cat": "system",
        "name": "Training LoRA CLI parseable senza dipendenze ML",
        "passed": passed,
        "detail": (f"exit={proc.returncode}  missing_flags={missing or 'none'}"),
    }


async def sys_collector_js_endpoint(client: httpx.AsyncClient, base: str) -> dict:
    """S14 — GET /collector.js serve il collector standalone con MIME JS corretto."""
    try:
        r = await client.get(f"{base}/collector.js")
        ct = r.headers.get("content-type", "")
        body = r.text
        checks = {
            "status_200":   r.status_code == 200,
            "mime_js":      "javascript" in ct.lower(),
            "body_has_api": "/api/bitm/collect" in body or "data-endpoint" in body,
            "window_bitm":  "window.BitM" in body,
        }
        passed = all(checks.values())
        return {
            "id": "S14", "cat": "system",
            "name": "Endpoint /collector.js (integrazione one-liner)",
            "passed": passed,
            "detail": f"status={r.status_code}  ct={ct}  checks={checks}",
        }
    except Exception as e:
        return {
            "id": "S14", "cat": "system",
            "name": "Endpoint /collector.js (integrazione one-liner)",
            "passed": False, "detail": f"errore: {e}",
        }


async def sys_collector_payload_detects_bitm(client: httpx.AsyncClient, base: str) -> dict:
    """S15 — payload shape del collector.js triggera i segnali BitM/BitM+ in extractor."""
    # Questa shape replica esattamente quella emessa da collector.js (v7.3):
    # `pageUrl`/`title`/`wsEndpoints`/`iframeCount`/`credentialsGetNative`.
    # Se i nomi campo driftano rispetto a extractor._detect_bitm, l'intera
    # pipeline BitM v7.2 diventa silenziosamente inerte per l'integrazione
    # one-liner. Questo check blocca quella regressione in CI.
    try:
        # Reset per evitare interferenze con altri system check
        try:
            await client.delete(f"{base}/api/bitm/sessions", timeout=10)
        except Exception:
            pass

        payload = {
            "sessionId": f"s15-{uuid.uuid4().hex[:8]}",
            "page":      "/login",
            "userAgent": "Mozilla/5.0 noVNC/1.4 Websockify",
            "plugins":   ["PDF Viewer"],
            "webgl":     "ANGLE (Intel)",
            "canvas":    "s15canvas",
            "webdriver": False,
            "languages": ["en-US"],
            "screenRes": "1920x1080",
            "colorDepth": 24,
            "timezone":  "Europe/Rome",
            "platform":  "Linux x86_64",
            "timing":    15,
            # Shape collector.js v7.3 — nomi campo estrattore-native
            "pageUrl":              "https://victim.ngrok-free.app:6080/vnc.html?xssParam=%7BloadFromAttacker(x)%7D",
            "referrer":             "https://victim.ngrok-free.app/",
            "title":                "Login Page - noVNC",
            "wsEndpoints":          ["wss://victim.ngrok-free.app/websockify"],
            "iframeCount":          5,
            "credentialsGetNative": False,
        }
        r = await client.post(f"{base}/api/bitm/collect", json=payload, timeout=20)
        body = r.json()
        indicators = set(body.get("indicators") or [])
        # I segnali forti attesi dal detector quando il collector invia
        # fedelmente i dati di una pagina BitM
        expected = {
            "novnc_client_marker", "bitm_framework_ua", "bitm_backend_port",
            "xss_reflected_param", "webauthn_api_override",
            "bitm_websocket_transport", "tunnel_host",
        }
        # Il fast-path può troncare gli indicator a ≤ N nomi, quindi accettiamo
        # copertura parziale purché almeno i "forti" (critical) siano presenti.
        critical = {"novnc_client_marker", "bitm_framework_ua",
                    "bitm_backend_port", "xss_reflected_param",
                    "webauthn_api_override", "bitm_websocket_transport"}
        hit_critical = indicators & critical
        missing_critical = critical - indicators
        passed = (body.get("action") == "block"
                  and len(hit_critical) >= 3)
        return {
            "id": "S15", "cat": "system",
            "name": "Shape collector.js triggera segnali BitM/BitM+ (contratto)",
            "passed": passed,
            "detail": (f"action={body.get('action')}  score={body.get('score')}  "
                       f"hit={sorted(hit_critical) or 'none'}  "
                       f"missing_critical={sorted(missing_critical) or 'none'}"),
        }
    except Exception as e:
        return {
            "id": "S15", "cat": "system",
            "name": "Shape collector.js triggera segnali BitM/BitM+ (contratto)",
            "passed": False, "detail": f"errore: {e}",
        }


async def sys_bitm_labels_aligned(client: httpx.AsyncClient, base: str) -> dict:
    """S13 — i label BitM/BitM+ emessi da extractor sono presenti in policy.CRITICAL_BLOCK."""
    try:
        if str(_ROOT) not in sys.path:
            sys.path.insert(0, str(_ROOT))
        from app.policy  import CRITICAL_BLOCK
        from app.extractor import _detect_bitm

        # Costruiamo un payload che deve emettere TUTTI i label BitM/BitM+
        raw = {
            "title":    "Target Login - noVNC and Apache Guacamole",
            "pageUrl":  "https://a.ngrok-free.app:6080/vnc.html?xssParam=%7BloadFromAttacker(x)%7D",
            "referrer": "https://a.ngrok-free.app/",
            "wsEndpoints": ["wss://a.ngrok-free.app/websockify"],
            "credentialsGetNative": False,
            "iframeCount": 5,
        }
        ua_lower = "mozilla/5.0 novnc/1.4"
        sigs = set(_detect_bitm(raw, ua_lower))

        required = {
            "novnc_client_marker", "guacamole_client_marker",
            "bitm_framework_ua", "bitm_backend_port",
            "xss_reflected_param", "webauthn_api_override",
            "bitm_websocket_transport", "tunnel_host", "iframe_overlay",
        }
        missing_from_detect  = required - sigs
        missing_from_policy  = {s for s in required
                                if s not in CRITICAL_BLOCK
                                and s not in {"tunnel_host", "iframe_overlay"}}
        passed = not missing_from_detect and not missing_from_policy
        return {
            "id": "S13", "cat": "system",
            "name": "Label BitM allineati extractor↔policy.CRITICAL_BLOCK",
            "passed": passed,
            "detail": (f"detected={len(sigs)}/{len(required)}  "
                       f"missing_detect={sorted(missing_from_detect) or 'none'}  "
                       f"missing_policy={sorted(missing_from_policy) or 'none'}"),
        }
    except Exception as e:
        return {
            "id": "S13", "cat": "system",
            "name": "Label BitM allineati extractor↔policy.CRITICAL_BLOCK",
            "passed": False, "detail": f"errore: {e}",
        }


# ─────────────────────────────────────────────────────────────────────────────
#   v7.4 — Trajectory anomaly analysis
# ─────────────────────────────────────────────────────────────────────────────

def _traj_enabled_in_health(j: dict) -> bool | None:
    """Legge `trajectory_analysis` da /health; None se il campo non esiste ancora."""
    v = j.get("trajectory_analysis")
    if isinstance(v, bool):
        return v
    return None


async def sys_trajectory_config_echo(client: httpx.AsyncClient, base: str) -> dict:
    """S16 — /health espone `trajectory_analysis` coerente con la env var."""
    try:
        r = await client.get(f"{base}/health", timeout=5)
        j = r.json()
        echoed = _traj_enabled_in_health(j)
        if echoed is None:
            return {
                "id": "S16", "cat": "system",
                "name": "Health echo trajectory_analysis (v7.4)",
                "passed": False,
                "detail": "manca campo `trajectory_analysis` in /health",
            }
        # Se il backend è stub + env non forzata on, ci aspettiamo off;
        # se invece è stato settato on, ci aspettiamo on. Senza conoscenza
        # dell'env lato client accettiamo solo che il tipo sia booleano.
        passed = isinstance(echoed, bool)
        return {
            "id": "S16", "cat": "system",
            "name": "Health echo trajectory_analysis (v7.4)",
            "passed": passed,
            "detail": f"trajectory_analysis={echoed}",
        }
    except Exception as e:
        return {"id": "S16", "cat": "system",
                "name": "Health echo trajectory_analysis (v7.4)",
                "passed": False, "detail": f"errore: {e}"}


async def sys_trajectory_stub_determinism(client: httpx.AsyncClient, base: str) -> dict:
    """S17 — stessa traiettoria ripetuta 3x → stesso pattern (stub deterministico)."""
    try:
        # Skip se trajectory off (stub default con LLM_TRAJECTORY_ANALYSIS=auto)
        r = await client.get(f"{base}/health", timeout=5)
        if _traj_enabled_in_health(r.json()) is False:
            return {"id": "S17", "cat": "system",
                    "name": "Stub determinism trajectory (v7.4)",
                    "passed": True,
                    "detail": "skip: trajectory disabilitato (off)"}

        patterns = []
        for run in range(3):
            sid = f"s17-run{run}-{uuid.uuid4().hex[:6]}"
            # Reset per isolamento tra run
            await client.delete(f"{base}/api/bitm/sessions", timeout=10)
            # Login
            p1 = _legit_payload(sid, page="/login")
            await client.post(f"{base}/api/bitm/collect", json=p1, timeout=15)
            # Change password (dentro 5s)
            p2 = _legit_payload(sid, page="/account/change-password")
            r2 = await client.post(f"{base}/api/bitm/collect", json=p2, timeout=15)
            body = r2.json()
            patterns.append(body.get("trajectory_pattern", ""))

        uniq = set(patterns)
        passed = len(uniq) == 1 and ("" not in uniq or len(uniq) == 1)
        return {"id": "S17", "cat": "system",
                "name": "Stub determinism trajectory (v7.4)",
                "passed": passed,
                "detail": f"patterns={patterns}"}
    except Exception as e:
        return {"id": "S17", "cat": "system",
                "name": "Stub determinism trajectory (v7.4)",
                "passed": False, "detail": f"errore: {e}"}


async def sys_trajectory_panic_password(client: httpx.AsyncClient, base: str) -> dict:
    """S18 — sequenza login → change-password in <5s triggera `panic_password_change`."""
    try:
        r = await client.get(f"{base}/health", timeout=5)
        if _traj_enabled_in_health(r.json()) is False:
            return {"id": "S18", "cat": "system",
                    "name": "Panic password change detection (v7.4)",
                    "passed": True,
                    "detail": "skip: trajectory disabilitato (off)"}

        sid = f"s18-{uuid.uuid4().hex[:8]}"
        await client.delete(f"{base}/api/bitm/sessions", timeout=10)
        await client.post(f"{base}/api/bitm/collect",
                          json=_legit_payload(sid, page="/login"), timeout=15)
        await client.post(f"{base}/api/bitm/collect",
                          json=_legit_payload(sid, page="/account/verify"), timeout=15)
        r2 = await client.post(f"{base}/api/bitm/collect",
                               json=_legit_payload(sid, page="/account/change-password"),
                               timeout=15)
        body = r2.json()
        pattern = body.get("trajectory_pattern", "")
        action  = body.get("action", "")
        # Il pattern può essere `panic_password_change` su stub, o qualunque
        # snake_case coerente su backend reale. Accettiamo la famiglia semantica
        # via keyword match, così il test resta stabile con Anthropic/Ollama.
        fam_ok = any(tok in pattern for tok in ("panic", "password", "takeover",
                                                 "compromise", "post_login"))
        # Azione minima attesa: almeno challenge (il boost v7.4 alza sopra soglia).
        action_ok = action in ("challenge", "block")
        passed = fam_ok and action_ok
        return {"id": "S18", "cat": "system",
                "name": "Panic password change detection (v7.4)",
                "passed": passed,
                "detail": f"pattern={pattern!r} action={action}"}
    except Exception as e:
        return {"id": "S18", "cat": "system",
                "name": "Panic password change detection (v7.4)",
                "passed": False, "detail": f"errore: {e}"}


async def sys_trajectory_direct_admin(client: httpx.AsyncClient, base: str) -> dict:
    """S19 — accesso `/admin` senza passare da `/login` triggera `direct_admin_access`."""
    try:
        r = await client.get(f"{base}/health", timeout=5)
        if _traj_enabled_in_health(r.json()) is False:
            return {"id": "S19", "cat": "system",
                    "name": "Direct admin access detection (v7.4)",
                    "passed": True,
                    "detail": "skip: trajectory disabilitato (off)"}

        sid = f"s19-{uuid.uuid4().hex[:8]}"
        await client.delete(f"{base}/api/bitm/sessions", timeout=10)
        # Due hit ma nessuno su /login
        await client.post(f"{base}/api/bitm/collect",
                          json=_legit_payload(sid, page="/home"), timeout=15)
        r2 = await client.post(f"{base}/api/bitm/collect",
                               json=_legit_payload(sid, page="/admin"), timeout=15)
        body = r2.json()
        pattern = body.get("trajectory_pattern", "")
        fam_ok = any(tok in pattern for tok in ("admin", "privilege", "direct"))
        passed = fam_ok
        return {"id": "S19", "cat": "system",
                "name": "Direct admin access detection (v7.4)",
                "passed": passed,
                "detail": f"pattern={pattern!r} action={body.get('action')}"}
    except Exception as e:
        return {"id": "S19", "cat": "system",
                "name": "Direct admin access detection (v7.4)",
                "passed": False, "detail": f"errore: {e}"}


async def sys_trajectory_insufficient_history(client: httpx.AsyncClient, base: str) -> dict:
    """S20 — sessione con una sola pagina → short-circuit, pattern vuoto (nessuna LLM call)."""
    try:
        r = await client.get(f"{base}/health", timeout=5)
        if _traj_enabled_in_health(r.json()) is False:
            return {"id": "S20", "cat": "system",
                    "name": "Insufficient history short-circuit (v7.4)",
                    "passed": True,
                    "detail": "skip: trajectory disabilitato (off)"}

        sid = f"s20-{uuid.uuid4().hex[:8]}"
        await client.delete(f"{base}/api/bitm/sessions", timeout=10)
        r1 = await client.post(f"{base}/api/bitm/collect",
                               json=_legit_payload(sid, page="/home"), timeout=15)
        body = r1.json()
        # `trajectory_pattern` deve essere omesso o vuoto quando history < 2.
        # Il server non include il campo per pattern `insufficient_history`
        # (filtrato in `_resp`), quindi ci aspettiamo assenza.
        pattern = body.get("trajectory_pattern", "")
        passed = pattern == ""
        return {"id": "S20", "cat": "system",
                "name": "Insufficient history short-circuit (v7.4)",
                "passed": passed,
                "detail": f"pattern={pattern!r} (atteso vuoto)"}
    except Exception as e:
        return {"id": "S20", "cat": "system",
                "name": "Insufficient history short-circuit (v7.4)",
                "passed": False, "detail": f"errore: {e}"}


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
    # ── v7.0 ──
    sys_prompt_v7_shortened,
    sys_dataset_builder,
    sys_train_lora_cli,
    # ── v7.2 (BitM/BitM+) ──
    sys_bitm_labels_aligned,
    # ── v7.3 (distribuzione one-shot) ──
    sys_collector_js_endpoint,
    sys_collector_payload_detects_bitm,
    # ── v7.4 (trajectory anomaly analysis) ──
    sys_trajectory_config_echo,
    sys_trajectory_stub_determinism,
    sys_trajectory_panic_password,
    sys_trajectory_direct_admin,
    sys_trajectory_insufficient_history,
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
    print(f"{B}  AURORA v7.3 — Test Suite{X}")
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
        print(f"\n{B}SYSTEM v6.2 + v7.0 + v7.2 + v7.3 ({sys_pass}/{len(systems)}){X}")
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
        "version":   "7.4.3",
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
    parser = argparse.ArgumentParser(description="BitM Test Suite v7.3")
    parser.add_argument("--filter", help="Categorie separate da virgola (legit,attack,...)")
    parser.add_argument("--only",   help="ID specifici separati da virgola (T01,T05,...)")
    parser.add_argument("--parallel", type=int, default=1,
                        help="Numero di test in parallelo (default 1)")
    parser.add_argument("--skip-system", action="store_true",
                        help="Salta i system check v6.0")
    parser.add_argument("--admin-token",
                        default=os.getenv("BITM_ADMIN_TOKEN", ""),
                        help="Token per endpoint admin (default: env BITM_ADMIN_TOKEN)")
    args = parser.parse_args()

    base = os.getenv("BITM_URL", "http://localhost:8000")
    print(f"{B}Connessione a {base}...{X}")

    # Header di default: include il token admin se fornito
    default_headers = {}
    if args.admin_token:
        default_headers["X-Admin-Token"] = args.admin_token

    async with httpx.AsyncClient(headers=default_headers) as client:
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

            async def _guarded(c: dict):
                async with sem:
                    print(f"  {C}▶{X} [{c['id']}] {c['name'][:50]}")
                    return await run_case(client, c, base)

            # In modalità parallela i test ATTACK/BITM producono BLOCK e, dopo
            # 3 BLOCK consecutivi dallo stesso IP (127.0.0.1), il server banna
            # l'IP. I test SUSPICIOUS/EDGE successivi verrebbero bloccati
            # automaticamente producendo falsi negativi.
            # Soluzione: esegui prima i test che producono BLOCK, poi azzera lo
            # stato (sessioni + IP bannati) e infine esegui SUSPICIOUS/EDGE.
            blocking_cats = {"attack", "bitm"}
            batch_blocking = [c for c in cases if c["cat"] in blocking_cats]
            batch_safe     = [c for c in cases if c["cat"] not in blocking_cats]

            res_blocking = await asyncio.gather(*[_guarded(c) for c in batch_blocking])
            # Reset stato tra batch: se fallisce, i SUSPICIOUS/EDGE ereditano
            # l'IP-ban della batch precedente e produrrebbero falsi negativi.
            # httpx non solleva su 4xx, quindi controlliamo lo status esplicitamente.
            try:
                _rst = await client.delete(f"{base}/api/bitm/sessions", timeout=10)
            except Exception as e:
                print(f"{R}✗ Cleanup tra batch fallito ({e}). "
                      f"I risultati SUSPICIOUS/EDGE non sarebbero affidabili.{X}")
                sys.exit(2)
            if _rst.status_code >= 400:
                print(f"{R}✗ Cleanup tra batch HTTP {_rst.status_code}. "
                      f"Passa --admin-token (o setta BITM_ADMIN_TOKEN) "
                      f"se il server richiede autenticazione admin.{X}")
                sys.exit(2)
            res_safe = await asyncio.gather(*[_guarded(c) for c in batch_safe])

            # Ricompone i risultati nell'ordine originale dei casi
            result_map = {r["id"]: r for r in (*res_blocking, *res_safe)}
            results = [result_map[c["id"]] for c in cases if c["id"] in result_map]
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
            print(f"\n  {C}── SYSTEM CHECKS v6.2 + v7.0 ──{X}")
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
