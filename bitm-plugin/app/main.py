"""
BitM Detection Plugin — FastAPI server v6.2

Novità v6:
- Sessioni persistenti su Redis (SessionStore), condivisibili tra processi/istanze
- Arricchimento automatico della Request con metadati GeoIP (Country/ASN/ISP)
- Rimossa la gestione manuale di ip_meta dal payload client

Novità v6.2:
- Modulo notifier: webhook push asincrono per eventi BLOCK
  (Slack Blocks API, Microsoft Teams Adaptive Cards, SIEM JSON)
"""

import time
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware

from app.config import LLM_BACKEND, summary as config_summary, validate as config_validate
from app.extractor import extract_features
from app.scorer import score_session, get_selected_model
from app.policy import decide, Action, detect_page_context
from app.logger import log_event
from app.redis_client import get_store
from app.geoip import resolve as geoip_resolve, summary as geoip_summary
from app.broadcaster import get_broadcaster
from app.notifier import notify_block, webhook_status

app = FastAPI(title="BitM Detection Plugin", version="7.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR  = Path(__file__).parent / "static"
RATE_LIMIT  = 30
RATE_WINDOW = 60
BLOCK_AFTER = 3

_store       = get_store()
_broadcaster = get_broadcaster()


# ── Middleware: GeoIP enrichment ──────────────────────────────────────────────

@app.middleware("http")
async def enrich_geoip(request: Request, call_next):
    """
    Arricchisce ogni Request con `request.state.ip` e `request.state.ip_meta`
    (country, asn, isp, is_tor, is_vpn) risolti automaticamente dal GeoIP.
    """
    ip = (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
          or (request.client.host if request.client else "unknown"))
    request.state.ip      = ip
    request.state.ip_meta = geoip_resolve(ip)
    return await call_next(request)


# ── Startup / Shutdown ────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    errors = config_validate()
    if errors:
        for e in errors:
            print(f"[config] ERRORE: {e}")
    print(f"[bitm] Backend LLM: {config_summary()}")
    await _store.connect()
    print(f"[bitm] Session store: {_store.backend}")
    print(f"[bitm] GeoIP: {geoip_summary()}")


@app.on_event("shutdown")
async def shutdown():
    await _store.close()


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    p = STATIC_DIR / "test_page.html"
    if not p.exists():
        raise HTTPException(404, detail="test_page.html non trovato")
    return p.read_text(encoding="utf-8")


@app.get("/collector.js")
async def collector():
    """
    Collector JS standalone per integrazione one-liner.
    Esposto con MIME JS e cache pubblica (1h) per permettere il caching a CDN/proxy.
    """
    p = STATIC_DIR / "collector.js"
    if not p.exists():
        raise HTTPException(404, detail="collector.js non trovato")
    return Response(
        content=p.read_text(encoding="utf-8"),
        media_type="application/javascript",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@app.get("/health")
async def health():
    return {
        "status":      "ok",
        "version":     "7.3.0",
        "backend":     LLM_BACKEND,
        "model":       get_selected_model(),
        "sessions":    await _store.session_count(),
        "blocked_ips": await _store.blocked_count(),
        "store":       _store.backend,
        "geoip":       geoip_summary(),
        "ws_clients":  _broadcaster.client_count,
        "webhook":     webhook_status(),
    }


@app.post("/api/bitm/collect")
async def collect(request: Request, body: dict):
    t0 = time.time()

    ip      = getattr(request.state, "ip", "unknown")
    ip_meta = dict(getattr(request.state, "ip_meta", {}) or {})

    # Hint dai test/dev: se il body include ip_meta, lo usiamo per
    # completare i campi che il GeoIP non copre (es. is_tor, che richiede
    # un feed dedicato). Non è la "ground truth" di prima: è solo un
    # override controllato, utile in ambienti privi di feed esterno.
    body_hint = body.get("ip_meta") or {}
    if body_hint:
        for k, v in body_hint.items():
            if v is None:
                continue
            if ip_meta.get(k) in (None, False, ""):
                ip_meta[k] = v
            elif k in ("is_tor", "is_vpn") and v:
                ip_meta[k] = True

    # Rate limiting
    if not await _store.rate_check(ip, RATE_LIMIT, RATE_WINDOW):
        return _resp("block", 1.0, "RATE_LIMITED", ["rate_limit_exceeded"],
                     "Troppe richieste", "default", 0, status=429)

    # IP già bloccato
    if await _store.is_blocked(ip):
        return _resp("block", 1.0, "ATTACK", ["ip_previously_blocked"],
                     "IP precedentemente bloccato", "default", 0)

    # Sessione (persistente su Redis)
    sid   = (body.get("sessionId") or "").strip() or ip
    store = await _store.get_session(sid)
    if store is None:
        store = {
            "pages": [], "timings": [], "first_seen": t0,
            "block_count": 0, "challenge_count": 0,
        }
    page = (body.get("page") or "/").strip()
    store["pages"].append(page)
    store["timings"].append(body.get("timing") or 0)

    # Feature extraction
    features = extract_features(body, ip, store, ip_meta=ip_meta)
    context  = detect_page_context(page)

    # Regole deterministiche (nessuna chiamata LLM)
    fast_sigs = _fast_rules(features)
    if fast_sigs:
        result = {
            "risk_score":  0.97,
            "verdict":     "ATTACK",
            "confidence":  "high",
            "indicators":  fast_sigs,
            "explanation": f"Blocco deterministico: {', '.join(fast_sigs[:3])}",
        }
    else:
        result = await score_session(features)

    # Decisione finale (policy)
    action, reason = decide(result, context, features)

    if action == Action.BLOCK:
        store["block_count"] = store.get("block_count", 0) + 1
        if store["block_count"] >= BLOCK_AFTER:
            await _store.add_blocked(ip)
    elif action == Action.CHALLENGE:
        store["challenge_count"] = store.get("challenge_count", 0) + 1

    await _store.set_session(sid, store)

    elapsed = round((time.time() - t0) * 1000, 1)
    entry   = log_event(ip, sid, features, result, action, elapsed, context)
    await _broadcaster.publish(entry)
    notify_block(entry)  # fire-and-forget; no-op se webhook non configurato

    return _resp(
        action.value,
        round(result["risk_score"], 3),
        result.get("verdict", "UNKNOWN"),
        result.get("indicators", []),
        reason,
        context,
        elapsed,
        confidence=result.get("confidence", "low"),
    )


def _fast_rules(features: dict) -> list[str]:
    """Regole deterministiche a latenza zero — nomi allineati con CRITICAL_BLOCK."""
    signals  = []
    ua_lower = (features.get("user_agent") or "").lower()

    for marker in ("headlesschrome", "headless chrome", "phantomjs",
                   "slimerjs", "jsdom", "selenium", "puppeteer"):
        if marker in ua_lower:
            signals.append("headless_ua")
            break

    if features.get("webdriver") is True:
        signals.append("webdriver_flag")

    no_plugins = features.get("plugin_count", 1) == 0
    no_webgl   = features.get("webgl") in ("unavailable", "", None)
    is_mobile  = features.get("is_mobile", False)
    if no_plugins and no_webgl and not is_mobile:
        signals.append("no_plugins_no_webgl")

    if features.get("avg_timing_ms", 0) > 600:
        signals.append("extreme_latency")

    if (features.get("ip_meta") or {}).get("is_tor"):
        signals.append("tor_exit_node")

    # BitM/BitM+ — propaghiamo i marker diagnostici già calcolati dall'extractor
    # nel fast path. Tutti i label qui sono presenti anche in CRITICAL_BLOCK.
    bitm_sigs = set(features.get("bitm_signals") or [])
    for label in ("novnc_client_marker", "guacamole_client_marker",
                  "bitm_framework_ua", "bitm_backend_port",
                  "xss_reflected_param", "webauthn_api_override",
                  "bitm_websocket_transport"):
        if label in bitm_sigs:
            signals.append(label)

    return signals


def _resp(action: str, score: float, verdict: str, indicators: list,
          reason: str, context: str, latency: float,
          confidence: str = "high", status: int = 200) -> JSONResponse:
    return JSONResponse({
        "action":     action,
        "score":      round(score, 3),
        "verdict":    verdict,
        "confidence": confidence,
        "indicators": indicators,
        "reason":     reason,
        "context":    context,
        "latency_ms": latency,
    }, status_code=status)


# ── Admin endpoints ───────────────────────────────────────────────────────────

@app.get("/api/bitm/sessions")
async def sessions_info():
    recent = await _store.recent_sessions(limit=20)
    return {
        "count":       await _store.session_count(),
        "blocked_ips": await _store.blocked_list(),
        "backend":     _store.backend,
        "sessions": {
            sid: {
                "pages":           (s.get("pages") or [])[-5:],
                "request_count":   len(s.get("timings") or []),
                "block_count":     s.get("block_count", 0),
                "challenge_count": s.get("challenge_count", 0),
            }
            for sid, s in recent.items()
        },
    }


@app.delete("/api/bitm/sessions")
async def clear():
    await _store.clear_sessions()
    await _store.clear_blocked()
    await _store.clear_rate()
    return {"cleared": True, "backend": _store.backend}


# ── Dashboard real-time (v6.1) ────────────────────────────────────────────────

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    p = STATIC_DIR / "dashboard.html"
    if not p.exists():
        raise HTTPException(404, detail="dashboard.html non trovato")
    return p.read_text(encoding="utf-8")


@app.websocket("/ws/events")
async def ws_events(ws: WebSocket):
    """Feed real-time degli eventi /api/bitm/collect."""
    await _broadcaster.connect(ws)
    try:
        while True:
            # Consumiamo eventuali messaggi dal client (ping/keepalive).
            # Non ci aspettiamo comandi: è un canale pubblicazione-only.
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await _broadcaster.disconnect(ws)
