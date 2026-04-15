"""
BitM Detection Plugin — FastAPI server v5
Supporta Anthropic Claude e Ollama (llama3.1) come backend LLM.
"""

import time
from pathlib import Path
from collections import defaultdict, deque

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from app.config import LLM_BACKEND, summary as config_summary, validate as config_validate
from app.extractor import extract_features
from app.scorer import score_session, get_selected_model
from app.policy import decide, Action, detect_page_context
from app.logger import log_event

app = FastAPI(title="BitM Detection Plugin", version="5.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Storage in-memory ─────────────────────────────────────────────────────────
_sessions: dict = {}
_ip_rate:  dict = defaultdict(deque)
_blocked:  set  = set()

STATIC_DIR  = Path(__file__).parent / "static"
RATE_LIMIT  = 30
RATE_WINDOW = 60
BLOCK_AFTER = 3


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    errors = config_validate()
    if errors:
        for e in errors:
            print(f"[config] ERRORE: {e}")
    print(f"[bitm] Backend LLM: {config_summary()}")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    p = STATIC_DIR / "test_page.html"
    if not p.exists():
        raise HTTPException(404, detail="test_page.html non trovato")
    return p.read_text(encoding="utf-8")


@app.get("/health")
async def health():
    return {
        "status":      "ok",
        "version":     "5.0.0",
        "backend":     LLM_BACKEND,
        "model":       get_selected_model(),
        "sessions":    len(_sessions),
        "blocked_ips": len(_blocked),
    }


@app.post("/api/bitm/collect")
async def collect(request: Request, body: dict):
    t0 = time.time()

    # IP reale
    ip = (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
          or (request.client.host if request.client else "unknown"))

    # Rate limiting
    now    = time.time()
    window = _ip_rate[ip]
    while window and now - window[0] > RATE_WINDOW:
        window.popleft()
    if len(window) >= RATE_LIMIT:
        return _resp("block", 1.0, "RATE_LIMITED", ["rate_limit_exceeded"],
                     "Troppe richieste", "default", 0, status=429)
    window.append(now)

    # IP già bloccato
    if ip in _blocked:
        return _resp("block", 1.0, "ATTACK", ["ip_previously_blocked"],
                     "IP precedentemente bloccato", "default", 0)

    # Sessione
    sid = (body.get("sessionId") or "").strip() or ip
    if sid not in _sessions:
        _sessions[sid] = {
            "pages": [], "timings": [], "first_seen": t0,
            "block_count": 0, "challenge_count": 0,
        }
    store = _sessions[sid]
    page  = (body.get("page") or "/").strip()
    store["pages"].append(page)
    store["timings"].append(body.get("timing") or 0)

    # Feature extraction
    features = extract_features(body, ip, store)
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
        store["block_count"] += 1
        if store["block_count"] >= BLOCK_AFTER:
            _blocked.add(ip)
    elif action == Action.CHALLENGE:
        store["challenge_count"] += 1

    elapsed = round((time.time() - t0) * 1000, 1)
    log_event(ip, sid, features, result, action, elapsed, context)

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
    return {
        "count":       len(_sessions),
        "blocked_ips": sorted(_blocked),
        "sessions": {
            sid: {
                "pages":           store["pages"][-5:],
                "request_count":   len(store["timings"]),
                "block_count":     store.get("block_count", 0),
                "challenge_count": store.get("challenge_count", 0),
            }
            for sid, store in list(_sessions.items())[-20:]
        },
    }


@app.delete("/api/bitm/sessions")
async def clear():
    _sessions.clear()
    _blocked.clear()
    _ip_rate.clear()
    return {"cleared": True}
