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

import asyncio
import hashlib
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware

from app.config import (
    ADMIN_TOKEN,
    LLM_BACKEND,
    LLM_TRAJECTORY_ANALYSIS,
    check_admin_token,
    is_trusted_proxy,
    summary as config_summary,
    validate as config_validate,
)
from app.extractor import extract_features
from app.scorer import score_session, analyze_trajectory, get_selected_model
from app.policy import decide, Action, detect_page_context
from app.logger import log_event
from app.redis_client import get_store
from app.geoip import resolve as geoip_resolve, summary as geoip_summary
from app.broadcaster import get_broadcaster
from app.notifier import notify_block, webhook_status

STATIC_DIR  = Path(__file__).parent / "static"
RATE_LIMIT  = 30
RATE_WINDOW = 60
BLOCK_AFTER = 3

_store       = get_store()
_broadcaster = get_broadcaster()


@asynccontextmanager
async def lifespan(app: FastAPI):
    errors = config_validate()
    if errors:
        for e in errors:
            print(f"[config] ERRORE: {e}")
    print(f"[bitm] Backend LLM: {config_summary()}")
    await _store.connect()
    print(f"[bitm] Session store: {_store.backend}")
    print(f"[bitm] GeoIP: {geoip_summary()}")
    if not ADMIN_TOKEN:
        print("[bitm] [!] ADMIN_TOKEN non impostato: endpoint admin/dashboard "
              "/ws/events accessibili senza autenticazione")
    try:
        yield
    finally:
        await _store.close()


app = FastAPI(title="BitM Detection Plugin", version="7.4.2", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth helpers ─────────────────────────────────────────────────────────────

def require_admin(request: Request) -> None:
    """Dependency FastAPI: 401 se ADMIN_TOKEN è impostato e mancante/errato."""
    token = request.headers.get("X-Admin-Token") or request.query_params.get("token")
    if not check_admin_token(token):
        raise HTTPException(status_code=401, detail="Admin token richiesto")


# ── Middleware: GeoIP enrichment ──────────────────────────────────────────────

@app.middleware("http")
async def enrich_geoip(request: Request, call_next):
    """
    Arricchisce ogni Request con `request.state.ip` e `request.state.ip_meta`
    (country, asn, isp, is_tor, is_vpn) risolti automaticamente dal GeoIP.

    X-Forwarded-For viene letto SOLO se il peer diretto è in TRUSTED_PROXIES.
    Altrimenti si usa request.client.host, per evitare che un attaccante possa
    ruotare IP via header spoofing e aggirare rate-limit / IP-block.
    """
    peer = request.client.host if request.client else ""
    ip = peer or "unknown"
    xff = request.headers.get("X-Forwarded-For", "")
    if xff and is_trusted_proxy(peer):
        # Il proxy appende il client in coda; prendiamo l'ultimo non-trusted
        # da destra verso sinistra per evitare header manipolati dal client.
        for candidate in reversed([p.strip() for p in xff.split(",") if p.strip()]):
            if not is_trusted_proxy(candidate):
                ip = candidate
                break
    request.state.ip      = ip
    request.state.ip_meta = geoip_resolve(ip)
    return await call_next(request)


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
        "status":              "ok",
        "version":             "7.4.2",
        "backend":             LLM_BACKEND,
        "model":               get_selected_model(),
        "trajectory_analysis": LLM_TRAJECTORY_ANALYSIS,
        "sessions":            await _store.session_count(),
        "blocked_ips":         await _store.blocked_count(),
        "store":               _store.backend,
        "geoip":               geoip_summary(),
        "ws_clients":          _broadcaster.client_count,
        "webhook":             webhook_status(),
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

    # Sessione (persistente su Redis).
    # Se il client non fornisce sessionId, ricadiamo su un hash di ip +
    # fingerprint (UA + canvas + languages): due client diversi dietro lo
    # stesso NAT hanno fingerprint diversi, quindi non condividono la
    # sessione e i relativi block_count. Collector v7.x fornisce sempre
    # un sessionId, questo è solo il fallback.
    sid_raw = (body.get("sessionId") or "").strip()
    if sid_raw:
        sid = sid_raw
    else:
        fp = "|".join([
            ip,
            (body.get("userAgent") or "")[:200],
            (body.get("canvas") or "")[:200],
            ",".join(body.get("languages") or [])[:80],
        ])
        sid = "anon-" + hashlib.sha1(fp.encode("utf-8")).hexdigest()[:16]
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

    # Session snapshot passato al layer trajectory (aggiornato sopra con pages/timings)
    session_snapshot = {
        "session_id": sid,
        "pages":      list(store.get("pages") or []),
        "timings":    list(store.get("timings") or []),
        "first_seen": store.get("first_seen", t0),
    }

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
        # Fast path → nessuna analisi trajectory: già blocco critico.
        traj = {"trajectory_score": 0.0, "pattern": "bypassed_fast_rules",
                "explanation_user": "", "explanation_admin": ""}
    elif LLM_TRAJECTORY_ANALYSIS:
        # Scoring + trajectory in parallelo per evitare di sommare latenze.
        result, traj = await asyncio.gather(
            score_session(features),
            analyze_trajectory(session_snapshot, features),
        )
    else:
        result = await score_session(features)
        traj   = {"trajectory_score": 0.0, "pattern": "disabled",
                  "explanation_user": "", "explanation_admin": ""}

    # Decisione finale (policy) — trajectory_score come boost capped separato.
    t_score = float(traj.get("trajectory_score") or 0.0)
    action, reason = decide(result, context, features, trajectory_score=t_score)

    if action == Action.BLOCK:
        store["block_count"] = store.get("block_count", 0) + 1
        if store["block_count"] >= BLOCK_AFTER:
            await _store.add_blocked(ip)
    elif action == Action.CHALLENGE:
        store["challenge_count"] = store.get("challenge_count", 0) + 1

    await _store.set_session(sid, store)

    elapsed = round((time.time() - t0) * 1000, 1)
    entry   = log_event(ip, sid, features, result, action, elapsed, context,
                        trajectory=traj)
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
        trajectory=traj,
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

    no_plugins  = features.get("plugin_count", 1) == 0
    no_webgl    = features.get("webgl") in ("unavailable", "", None)
    is_mobile   = features.get("is_mobile", False)
    no_canvas   = features.get("canvas_empty", False)
    no_languages = features.get("language_count", 1) == 0
    # Richiede 3 segnali: browser moderni hanno legittimamente 0 plugin,
    # serve almeno un'altra anomalia hard (canvas vuoto o lingue assenti).
    if no_plugins and no_webgl and (no_canvas or no_languages) and not is_mobile:
        signals.append("no_plugins_no_webgl")

    # Soglia allineata con extractor._pre_score: >600ms è considerato scraping/bot.
    # Label identica a CRITICAL_BLOCK per lo short-circuit deterministico.
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
          confidence: str = "high", status: int = 200,
          trajectory: dict | None = None) -> JSONResponse:
    payload = {
        "action":     action,
        "score":      round(score, 3),
        "verdict":    verdict,
        "confidence": confidence,
        "indicators": indicators,
        "reason":     reason,
        "context":    context,
        "latency_ms": latency,
    }
    if trajectory:
        pattern = trajectory.get("pattern") or ""
        # Non-payload patterns: disabled / bypassed / insufficient_history /
        # normal_flow → omessi per restare backward-compatible con client v7.3
        # e non inviare rumore sul pattern "tutto normale".
        if pattern and pattern not in ("disabled", "bypassed_fast_rules",
                                       "insufficient_history", "normal_flow"):
            payload["trajectory_pattern"] = pattern
            payload["trajectory_score"]   = round(
                float(trajectory.get("trajectory_score") or 0.0), 3)
        eu = trajectory.get("explanation_user") or ""
        ea = trajectory.get("explanation_admin") or ""
        if eu:
            payload["explanation_user"]  = eu
        if ea and action != "allow":
            payload["explanation_admin"] = ea
    return JSONResponse(payload, status_code=status)


# ── Admin endpoints ───────────────────────────────────────────────────────────

@app.get("/api/bitm/sessions", dependencies=[Depends(require_admin)])
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


@app.delete("/api/bitm/sessions", dependencies=[Depends(require_admin)])
async def clear():
    await _store.clear_sessions()
    await _store.clear_blocked()
    await _store.clear_rate()
    return {"cleared": True, "backend": _store.backend}


# ── Dashboard real-time (v6.1) ────────────────────────────────────────────────

@app.get("/dashboard", response_class=HTMLResponse,
         dependencies=[Depends(require_admin)])
async def dashboard():
    p = STATIC_DIR / "dashboard.html"
    if not p.exists():
        raise HTTPException(404, detail="dashboard.html non trovato")
    return p.read_text(encoding="utf-8")


@app.websocket("/ws/events")
async def ws_events(ws: WebSocket):
    """Feed real-time degli eventi /api/bitm/collect."""
    # Auth: se ADMIN_TOKEN è impostato, richiede ?token= o header X-Admin-Token
    # (il browser non può settare header custom sull'handshake WS, quindi la
    # query è il fallback primario per la dashboard).
    token = ws.query_params.get("token") or ws.headers.get("x-admin-token")
    if not check_admin_token(token):
        await ws.close(code=1008)  # policy violation
        return
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
