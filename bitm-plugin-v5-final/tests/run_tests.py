"""
Test Suite v4 — 12 scenari con analisi dei fallimenti.
Esegui con: python tests/run_tests.py
"""

import asyncio, httpx, json, os, sys, time
from datetime import datetime

# ── Colori ANSI ───────────────────────────────────────────────────────────────
G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"
B = "\033[1m";  D = "\033[2m";  X = "\033[0m"

# ── Dataset ───────────────────────────────────────────────────────────────────
CASES = [
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
        }
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
        }
    },
    {
        "id": "T03", "cat": "legit", "name": "Safari / iPhone / Italia (zero plugin = normale)",
        "expected": "allow",
        # Safari iOS NON ha plugin per design — non deve essere segnalato
        "payload": {
            "sessionId": "t03", "page": "/news",
            "userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            "plugins": [],
            "webgl": "Apple GPU",
            "canvas": "data:image/png;base64,safariiosCANVAS987654",
            "webdriver": False, "languages": ["it-IT", "it"],
            "screenRes": "390x844", "colorDepth": 32,
            "timezone": "Europe/Rome", "platform": "iPhone", "timing": 22,
        }
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
        }
    },
    # ── ATTACCHI ──────────────────────────────────────────────────────────────
    {
        "id": "T05", "cat": "attack", "name": "HeadlessChrome / Evilginx",
        "expected": "block",
        "payload": {
            "sessionId": "t05", "page": "/login",
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
            "plugins": [], "webgl": "unavailable", "canvas": "",
            "webdriver": True, "languages": [],
            "screenRes": "800x600", "colorDepth": 24,
            "timezone": "", "platform": "Linux x86_64", "timing": 487,
        }
    },
    {
        "id": "T06", "cat": "attack", "name": "Playwright / webdriver=true / SwiftShader",
        "expected": "block",
        "payload": {
            "sessionId": "t06", "page": "/login",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": [],
            "webgl": "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)))",
            "canvas": "", "webdriver": True, "languages": ["en-US"],
            "screenRes": "1280x720", "colorDepth": 24,
            "timezone": "UTC", "platform": "Win32", "timing": 312,
        }
    },
    {
        "id": "T07", "cat": "attack", "name": "Selenium / no plugin + no WebGL / desktop",
        "expected": "block",
        # webdriver=False ma combinazione no-plugin+no-webgl su desktop = attacco
        "payload": {
            "sessionId": "t07", "page": "/payment",
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
            "plugins": [], "webgl": "", "canvas": "",
            "webdriver": False, "languages": ["en"],
            "screenRes": "1024x768", "colorDepth": 24,
            "timezone": "UTC", "platform": "Linux x86_64", "timing": 55,
        }
    },
    {
        "id": "T08", "cat": "attack", "name": "Tor exit node / checkout",
        "expected": "block",
        # Tor su pagina di pagamento → blocco deterministico
        "payload": {
            "sessionId": "t08", "page": "/checkout",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
            "plugins": ["OpenH264 Video Codec"],
            "webgl": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
            "canvas": "data:image/png;base64,torCANVAS123",
            "webdriver": False, "languages": ["en-US"],
            "screenRes": "1000x800", "colorDepth": 24,
            "timezone": "UTC", "platform": "Win32", "timing": 210,
            "ip_meta": {"is_vpn": False, "is_tor": True, "country": "?"},
        }
    },
    # ── SOSPETTI ──────────────────────────────────────────────────────────────
    {
        "id": "T09", "cat": "suspicious", "name": "VPN + pagina login",
        "expected": "challenge",
        "payload": {
            "sessionId": "t09", "page": "/login",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "plugins": ["OpenH264 Video Codec"],
            "webgl": "Mesa Intel(R) UHD Graphics 630",
            "canvas": "data:image/png;base64,vpnCANVAS456",
            "webdriver": False, "languages": ["en-US"],
            "screenRes": "1366x768", "colorDepth": 24,
            "timezone": "America/New_York", "platform": "Win32", "timing": 95,
            "ip_meta": {"is_vpn": True, "is_tor": False, "country": "US"},
        }
    },
    {
        "id": "T10", "cat": "suspicious", "name": "Latenza alta (380ms) / pagamento",
        "expected": "challenge",
        # pre_score includerà high_latency_380ms → boost → supera soglia challenge 0.20
        "payload": {
            "sessionId": "t10", "page": "/payment",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer"],
            "webgl": "ANGLE (NVIDIA, NVIDIA GeForce GTX 1060 Direct3D11)",
            "canvas": "data:image/png;base64,normalCANVAS99887",
            "webdriver": False, "languages": ["en-GB"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "Europe/London", "platform": "Win32", "timing": 380,
        }
    },
    {
        "id": "T11", "cat": "suspicious", "name": "VPN + canvas vuoto + login",
        "expected": "challenge",
        "payload": {
            "sessionId": "t11", "page": "/signin",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer"],
            "webgl": "ANGLE (Intel, Intel(R) HD Graphics 4000)",
            "canvas": "",   # canvas vuoto + VPN → challenge
            "webdriver": False, "languages": ["fr-FR"],
            "screenRes": "1280x800", "colorDepth": 24,
            "timezone": "Europe/Paris", "platform": "Win32", "timing": 45,
            "ip_meta": {"is_vpn": True, "is_tor": False, "country": "FR"},
        }
    },
    {
        "id": "T12", "cat": "suspicious", "name": "Timezone UTC + lingua italiana (anomalia)",
        "expected": "challenge",
        "payload": {
            "sessionId": "t12", "page": "/account",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "plugins": ["PDF Viewer", "Widevine"],
            "webgl": "ANGLE (Intel, Intel(R) UHD Graphics 620)",
            "canvas": "data:image/png;base64,normalCANVAS111",
            "webdriver": False, "languages": ["it-IT", "it"],
            "screenRes": "1920x1080", "colorDepth": 24,
            "timezone": "UTC",   # anomalia: italiano ma UTC
            "platform": "Win32", "timing": 35,
        }
    },
]


# ── Runner ────────────────────────────────────────────────────────────────────

async def run_one(client: httpx.AsyncClient, case: dict, base: str) -> dict:
    t0 = time.time()
    try:
        r    = await client.post(f"{base}/api/bitm/collect",
                                 json=case["payload"], timeout=35)
        data = r.json()
        ms   = round((time.time() - t0) * 1000)
        got  = data.get("action", "?")
        return {
            "id":         case["id"],
            "cat":        case["cat"],
            "name":       case["name"],
            "passed":     got == case["expected"],
            "expected":   case["expected"],
            "got":        got,
            "score":      data.get("score", 0),
            "pre":        data.get("pre_score", "—"),   # non restituito ancora, sarà nei log
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
            "passed": False, "expected": case["expected"], "got": "error",
            "score": 0, "error": str(e),
            "total_ms": round((time.time() - t0) * 1000),
        }


def print_report(results: list):
    passed = sum(1 for r in results if r["passed"])
    total  = len(results)
    pct    = 100 * passed // total

    # Raggruppa per categoria
    by_cat: dict = {}
    for r in results:
        by_cat.setdefault(r["cat"], []).append(r)

    print(f"\n{B}{'='*68}{X}")
    print(f"{B}  BitM Detection Plugin v4 — Test Suite{X}")
    print(f"{'='*68}")

    for cat, rows in by_cat.items():
        cat_pass = sum(1 for r in rows if r["passed"])
        cat_c    = G if cat_pass == len(rows) else (Y if cat_pass > 0 else R)
        print(f"\n{B}{cat.upper()} ({cat_pass}/{len(rows)}){X}")
        for r in rows:
            ok   = r["passed"]
            icon = f"{G}✓{X}" if ok else f"{R}✗{X}"
            print(f"  {icon} [{r['id']}] {r['name']}")
            got_c = G if ok else R
            print(f"      atteso={r['expected'].upper():<10} "
                  f"ottenuto={got_c}{r['got'].upper()}{X:<10} "
                  f"score={r.get('score',0):.3f} "
                  f"ctx={r.get('context','?')} "
                  f"{r.get('plugin_ms','?')}ms")
            if r.get("indicators"):
                print(f"      {D}segnali: {', '.join(r['indicators'][:5])}{X}")
            if r.get("reason"):
                print(f"      {D}{r['reason'][:75]}{X}")
            if r.get("error"):
                print(f"      {R}errore: {r['error']}{X}")

    bar_c = G if pct >= 90 else (Y if pct >= 70 else R)
    print(f"\n{B}{'='*68}{X}")
    print(f"  {B}TOTALE: {passed}/{total}  {bar_c}{pct}%{X}")
    print(f"{'='*68}\n")

    report = {
        "timestamp": datetime.now().isoformat(),
        "passed": passed, "total": total,
        "accuracy": round(passed / total, 3),
        "results": results,
    }
    with open("test_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"Report: test_report.json\n")


async def main():
    base = os.getenv("BITM_URL", "http://localhost:8000")
    print(f"Connessione a {base}...")

    async with httpx.AsyncClient() as client:
        try:
            h = await client.get(f"{base}/health", timeout=5)
            info = h.json()
            print(f"Server v{info.get('version','?')} — modello: {info.get('model','?')}\n")
        except Exception:
            print(f"{R}✗ Server non raggiungibile su {base}{X}")
            print("  Avvia con: python run.py")
            sys.exit(1)

        results = []
        for case in CASES:
            label = f"[{case['id']}] {case['name'][:50]}"
            print(f"  {label:<55}", end=" ", flush=True)
            r = await run_one(client, case, base)
            results.append(r)
            ok_sym = f"{G}✓{X}" if r["passed"] else f"{R}✗{X}"
            print(f"{ok_sym}  ({r.get('plugin_ms','?')}ms)")
            await asyncio.sleep(0.5)   # evita di saturare l'API

    print_report(results)


if __name__ == "__main__":
    asyncio.run(main())
