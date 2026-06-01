"""
BitM E2E Playwright Suite v7.1 — simulazione di attacchi evasivi reali.

Per ogni scenario:
  1. lancia Chromium headless con init-script e context configurati ad hoc
  2. apre una pagina minima (about:blank con body stub) e raccoglie il
     fingerprint REALE del browser via page.evaluate()
  3. POST a /api/bitm/collect con il fingerprint + eventuali campi di scenario
  4. classifica l'esito: action ∈ {allow(bypass), challenge, block, error}

Al termine stampa un report con:
  - detection_rate = (challenge + block) / totali
  - bypass_rate    = allow / totali
  - Exit code 1 se detection_rate < --min-detection (default 0.90)

Tecniche di evasione implementate (>= 5):
  A01 Plain headless                      — baseline
  A02 UA rotation mid-session             — UA diverso a ogni iterazione
  A03 Fast input injection                — timing sub-human (3ms)
  A04 No static resources                 — route blocking di img/css/font
  A05 Stealth patches                     — webdriver=undefined + plugins fake + languages fake
  A06 Stealth + canvas noise + WebGL spoof — fingerprint perturbati
  A07 Tor exit node (ip_meta injection)   — segnale critico deterministico

Uso:
  python run_e2e.py --url http://localhost:8000 --min-detection 0.9
  python run_e2e.py --report /tmp/e2e.json

Requisiti: playwright + httpx. Installare con:
  pip install -r tests/e2e_playwright/requirements-e2e.txt
  python -m playwright install --with-deps chromium
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from playwright.async_api import async_playwright, Playwright


# ── Colori ANSI ───────────────────────────────────────────────────────────────
G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"; C = "\033[36m"
B = "\033[1m";  D = "\033[2m";  X = "\033[0m"


# ── JS: raccolta fingerprint reale del browser ────────────────────────────────
FINGERPRINT_JS = r"""
() => {
  const canvas = document.createElement('canvas');
  canvas.width = 220; canvas.height = 50;
  const ctx = canvas.getContext('2d');
  ctx.textBaseline = 'top';
  ctx.font = '14px Arial';
  ctx.fillStyle = '#f60'; ctx.fillRect(0, 0, 220, 50);
  ctx.fillStyle = '#069'; ctx.fillText('bitm-e2e-fp', 2, 2);

  let webgl = 'unavailable';
  try {
    const c  = document.createElement('canvas');
    const gl = c.getContext('webgl2') || c.getContext('webgl') || c.getContext('experimental-webgl');
    if (gl) {
      const dbg = gl.getExtension('WEBGL_debug_renderer_info');
      webgl = dbg ? String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL))
                  : String(gl.getParameter(gl.RENDERER) || 'unknown');
    }
  } catch (e) {}

  return {
    userAgent:  navigator.userAgent,
    plugins:    Array.from(navigator.plugins || []).map(p => p.name),
    webgl:      webgl,
    canvas:     canvas.toDataURL(),
    webdriver:  !!navigator.webdriver,
    languages:  Array.from(navigator.languages || []),
    screenRes:  (screen.width || 0) + 'x' + (screen.height || 0),
    colorDepth: screen.colorDepth || 24,
    timezone:   (Intl.DateTimeFormat().resolvedOptions().timeZone || ''),
    platform:   navigator.platform || ''
  };
}
"""


# ── Init scripts (evasioni applicate al context prima di ogni pagina) ─────────
WEBDRIVER_HIDE = (
    "Object.defineProperty(navigator, 'webdriver', { get: () => undefined });"
)

FAKE_PLUGINS = r"""
Object.defineProperty(navigator, 'plugins', {
  get: () => {
    const arr = [
      { name: 'PDF Viewer' }, { name: 'Chrome PDF Viewer' },
      { name: 'Chromium PDF Viewer' }, { name: 'Microsoft Edge PDF Viewer' },
      { name: 'WebKit built-in PDF' }
    ];
    arr.item = i => arr[i] || null;
    arr.namedItem = n => arr.find(p => p.name === n) || null;
    arr.refresh = () => {};
    return arr;
  }
});
"""

FAKE_LANGUAGES = (
    "Object.defineProperty(navigator, 'languages', "
    "{ get: () => ['it-IT', 'it', 'en-US', 'en'] });"
)

CANVAS_NOISE = r"""
(() => {
  const orig = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function (...args) {
    const d = orig.apply(this, args);
    return d.slice(0, -1) + (Math.random() < 0.5 ? 'A' : 'B');
  };
})();
"""

WEBGL_SPOOF = r"""
(() => {
  const getParameter = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function (p) {
    if (p === 37446) return 'NVIDIA GeForce RTX 3060';     // UNMASKED_RENDERER_WEBGL
    if (p === 37445) return 'NVIDIA Corporation';          // UNMASKED_VENDOR_WEBGL
    return getParameter.call(this, p);
  };
})();
"""


# ── Scenari ────────────────────────────────────────────────────────────────────
REAL_WIN_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
UA_POOL = [
    REAL_WIN_UA,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0",
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    ),
]

STATIC_GLOB = (
    "**/*.{png,jpg,jpeg,gif,svg,webp,ico,css,woff,woff2,ttf,otf,eot}"
)


@dataclass
class Scenario:
    id: str
    name: str
    target_page: str = "/login"          # pagina ad alte soglie = più facile detection
    init_scripts: list[str] = field(default_factory=list)
    user_agent: str | None = None        # None = UA di default Playwright (HeadlessChrome)
    rotate_ua: bool = False
    block_static: bool = False
    timing_ms: int = 50
    ip_meta: dict | None = None
    iterations: int = 2


SCENARIOS: list[Scenario] = [
    Scenario(
        id="A01", name="Plain headless (baseline)",
        init_scripts=[], user_agent=None, timing_ms=200, target_page="/login",
    ),
    Scenario(
        id="A02", name="UA rotation mid-session",
        init_scripts=[WEBDRIVER_HIDE], user_agent=REAL_WIN_UA,
        rotate_ua=True, timing_ms=40, target_page="/login",
        iterations=3,
    ),
    Scenario(
        id="A03", name="Fast input injection (sub-human 3ms)",
        init_scripts=[WEBDRIVER_HIDE, FAKE_PLUGINS], user_agent=REAL_WIN_UA,
        timing_ms=3, target_page="/login",
    ),
    Scenario(
        id="A04", name="No static resources (images/css/fonts abortiti)",
        init_scripts=[WEBDRIVER_HIDE, FAKE_PLUGINS], user_agent=REAL_WIN_UA,
        block_static=True, timing_ms=45, target_page="/payment",
    ),
    Scenario(
        id="A05", name="Stealth patches (webdriver+plugins+lang)",
        init_scripts=[WEBDRIVER_HIDE, FAKE_PLUGINS, FAKE_LANGUAGES],
        user_agent=REAL_WIN_UA, timing_ms=80, target_page="/login",
    ),
    Scenario(
        id="A06", name="Stealth + canvas noise + WebGL spoof",
        init_scripts=[WEBDRIVER_HIDE, FAKE_PLUGINS, FAKE_LANGUAGES,
                      CANVAS_NOISE, WEBGL_SPOOF],
        user_agent=REAL_WIN_UA, timing_ms=75, target_page="/admin",
    ),
    Scenario(
        id="A07", name="Tor exit node (ip_meta injection)",
        init_scripts=[WEBDRIVER_HIDE, FAKE_PLUGINS, FAKE_LANGUAGES],
        user_agent=REAL_WIN_UA, timing_ms=60, target_page="/checkout",
        ip_meta={"is_tor": True, "is_vpn": False, "country": "??"},
    ),
]


# ── Esecuzione ────────────────────────────────────────────────────────────────

async def _collect_fingerprint(pw: Playwright, scen: Scenario, iteration: int) -> dict:
    """Lancia un browser isolato, applica le evasioni, raccoglie il fingerprint."""
    browser = await pw.chromium.launch(
        headless=True,
        args=["--no-sandbox", "--disable-dev-shm-usage"],
    )
    try:
        ua = scen.user_agent
        if scen.rotate_ua:
            ua = UA_POOL[iteration % len(UA_POOL)]

        ctx_kwargs: dict[str, Any] = {}
        if ua:
            ctx_kwargs["user_agent"] = ua
        context = await browser.new_context(**ctx_kwargs)

        for script in scen.init_scripts:
            await context.add_init_script(script)
        if scen.block_static:
            await context.route(STATIC_GLOB, lambda route: asyncio.create_task(route.abort()))

        page = await context.new_page()
        # Pagina minima: serve solo l'esecuzione di JS e non richiede il server
        await page.set_content(
            "<!doctype html><html><body><h1>bitm-e2e</h1></body></html>"
        )
        fp = await page.evaluate(FINGERPRINT_JS)
        await context.close()
        return fp
    finally:
        await browser.close()


async def _post_collect(http: httpx.AsyncClient, base: str, payload: dict) -> dict:
    try:
        r = await http.post(f"{base}/api/bitm/collect", json=payload, timeout=60)
        if r.status_code == 429:
            return {"action": "challenge", "_rate_limited": True}
        if r.status_code != 200:
            return {"action": "error", "_http": r.status_code, "_body": r.text[:200]}
        return r.json()
    except Exception as e:
        return {"action": "error", "_exc": f"{type(e).__name__}: {e}"}


async def run_scenario(pw: Playwright, scen: Scenario,
                        base: str, http: httpx.AsyncClient) -> list[dict]:
    results: list[dict] = []
    for i in range(scen.iterations):
        t0 = time.time()
        fp = await _collect_fingerprint(pw, scen, i)

        payload: dict = {
            "sessionId": f"{scen.id.lower()}-{i}-{random.randint(1000, 9999)}",
            "page":      scen.target_page,
            "timing":    scen.timing_ms,
            **fp,
        }
        if scen.ip_meta:
            payload["ip_meta"] = scen.ip_meta

        resp = await _post_collect(http, base, payload)
        action = resp.get("action", "error")
        elapsed = round((time.time() - t0) * 1000)

        results.append({
            "scenario_id":   scen.id,
            "scenario_name": scen.name,
            "iteration":     i,
            "target_page":   scen.target_page,
            "ua":            (fp.get("userAgent") or "")[:80],
            "webdriver_fp":  fp.get("webdriver"),
            "action":        action,
            "score":         resp.get("score"),
            "verdict":       resp.get("verdict"),
            "confidence":    resp.get("confidence"),
            "indicators":    resp.get("indicators", []),
            "reason":        resp.get("reason", ""),
            "total_ms":      elapsed,
            "http_err":      resp.get("_http"),
            "exc":           resp.get("_exc"),
        })
    return results


# ── Reporting ─────────────────────────────────────────────────────────────────

def _summarize(results: list[dict]) -> dict:
    total = len(results)
    detected = sum(1 for r in results if r["action"] in ("challenge", "block"))
    bypassed = sum(1 for r in results if r["action"] == "allow")
    errors   = sum(1 for r in results if r["action"] == "error")
    return {
        "total":          total,
        "detected":       detected,
        "bypassed":       bypassed,
        "errors":         errors,
        "detection_rate": (detected / total) if total else 0.0,
        "bypass_rate":    (bypassed / total) if total else 0.0,
    }


def print_report(results: list[dict], min_detection: float) -> dict:
    summary = _summarize(results)

    # Raggruppa per scenario
    by_scen: dict[str, list[dict]] = {}
    for r in results:
        by_scen.setdefault(r["scenario_id"], []).append(r)

    print(f"\n{B}{'=' * 72}{X}")
    print(f"{B}  BitM E2E Playwright v7.1 — Report finale{X}")
    print(f"{'=' * 72}")
    print(f"  Tecniche di evasione:   {len(SCENARIOS)}")
    print(f"  Probe totali:           {summary['total']}")
    print(f"  Detected (chal+block):  {G}{summary['detected']}{X}"
          f"  ({summary['detection_rate'] * 100:.1f}%)")
    print(f"  Bypassed (allow):       {R}{summary['bypassed']}{X}"
          f"  ({summary['bypass_rate'] * 100:.1f}%)")
    print(f"  Errori:                 {summary['errors']}")
    print(f"  Soglia minima richiesta: {min_detection * 100:.0f}%")
    print(f"{'-' * 72}")

    for scen in SCENARIOS:
        rs = by_scen.get(scen.id, [])
        if not rs:
            continue
        d = sum(1 for r in rs if r["action"] in ("challenge", "block"))
        b = sum(1 for r in rs if r["action"] == "allow")
        if d == len(rs):
            status, color = "PASS", G
        elif d > 0:
            status, color = "WARN", Y
        else:
            status, color = "FAIL", R
        print(f"  {color}[{scen.id}] {status}{X}  "
              f"detected={d}/{len(rs)}  bypassed={b}  {D}{scen.name}{X}")
        for r in rs:
            ind = ",".join((r.get("indicators") or [])[:3]) or "-"
            print(f"       iter={r['iteration']}  action={r['action']:<9}  "
                  f"score={r.get('score')}  ind=[{ind}]")

    print(f"{'=' * 72}\n")

    report = {
        "version":                 "7.1",
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "headless":                True,
        "scenarios":               len(SCENARIOS),
        "min_detection_threshold": min_detection,
        **summary,
        "results":                 results,
    }
    return report


# ── Main ──────────────────────────────────────────────────────────────────────

async def main_async(args: argparse.Namespace) -> int:
    base = args.url.rstrip("/")

    async with httpx.AsyncClient() as http:
        # Ping API prima di iniziare (fail-fast)
        try:
            h = await http.get(f"{base}/health", timeout=5)
            h.raise_for_status()
            info = h.json()
            print(f"{B}BitM API reachable{X}  "
                  f"v{info.get('version', '?')}  "
                  f"backend={info.get('backend', '?')}  "
                  f"model={info.get('model', '?')}")
        except Exception as e:
            print(f"{R}✗ API non raggiungibile su {base}: {e}{X}", file=sys.stderr)
            print(f"  Avvia con: python run.py", file=sys.stderr)
            return 2

        # Reset stato pulito (sessioni + blocked + rate-limit)
        try:
            await http.delete(f"{base}/api/bitm/sessions", timeout=10)
        except Exception:
            pass

        print(f"\n{B}Lancio {len(SCENARIOS)} scenari evasivi (headless){X}")
        all_results: list[dict] = []
        async with async_playwright() as pw:
            for scen in SCENARIOS:
                print(f"  {C}▶{X} [{scen.id}] {scen.name}  ({scen.iterations}x)")
                try:
                    res = await run_scenario(pw, scen, base, http)
                except Exception as e:
                    print(f"    {R}errore scenario: {type(e).__name__}: {e}{X}")
                    res = [{
                        "scenario_id":   scen.id,
                        "scenario_name": scen.name,
                        "iteration":     i,
                        "action":        "error",
                        "exc":           f"{type(e).__name__}: {e}",
                        "indicators":    [],
                    } for i in range(scen.iterations)]
                for r in res:
                    mark = G + "✓" + X if r["action"] in ("challenge", "block") else \
                           (Y + "~" + X if r["action"] == "error" else R + "✗" + X)
                    print(f"    {mark} iter={r['iteration']}  action={r['action']:<9} "
                          f"score={r.get('score')!s:<6} "
                          f"ind={','.join((r.get('indicators') or [])[:3]) or '-'}")
                all_results.extend(res)

    report = print_report(all_results, args.min_detection)

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"  Report JSON: {report_path}\n")

    if report["detection_rate"] < args.min_detection:
        print(f"{R}{B}✗ Detection rate {report['detection_rate'] * 100:.1f}% "
              f"< soglia {args.min_detection * 100:.0f}%{X}\n")
        return 1

    print(f"{G}{B}✓ Detection rate {report['detection_rate'] * 100:.1f}% "
          f">= soglia {args.min_detection * 100:.0f}%{X}\n")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="BitM E2E Playwright Suite v7.1")
    ap.add_argument("--url", default="http://localhost:8000",
                    help="base URL della BitM API (default: http://localhost:8000)")
    ap.add_argument("--min-detection", type=float, default=0.90,
                    help="detection rate minima per passare (default 0.90 = 90%%)")
    ap.add_argument("--report", default="tests/e2e_playwright/e2e_report.json",
                    help="path del report JSON finale")
    args = ap.parse_args()

    exit_code = asyncio.run(main_async(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
