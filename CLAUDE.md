# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository layout

- `bitm-plugin/` — the FastAPI detection service (the only thing that runs in production). All backend commands run from here.
- `bitm-extension/` — Chrome Manifest V3 extension ("BitM Shield") that acts as the browser-side collector and shows the block/challenge banner. Loads `src/page-hook.js` in MAIN world at `document_start`, plus a chain of isolated content scripts (`settings → detection → session → banner → content-script`).
- `tesi/` — thesis material (Italian, University of Bari): `genera_tesi.py` builds `tesi_BitM_LLM.docx` from `Template_Tesi.docx` and the `tesi_figures/*.png` it produces. `tesi/doc/` holds the reference papers. Run with `python tesi/genera_tesi.py`; output is always written next to the script regardless of CWD.
- `docker-compose.yml` (root) — profiles `api`, `redis`, `ollama` for the full stack.

## Commands

All commands run from `bitm-plugin/`.

```bash
# Install
pip install -r requirements.txt

# Run the API (reads .env, uvicorn on 0.0.0.0:$PORT, default 8000, reload=True)
python run.py

# Diagnose the configured LLM backend (Anthropic or Ollama) end-to-end
python diagnose.py

# Full test suite (49 cases across legit/attack/suspicious/edge/system)
python tests/run_tests.py

# Subset runs
python tests/run_tests.py --filter attack              # one or more categories
python tests/run_tests.py --filter legit,suspicious
python tests/run_tests.py --only T06,T11               # specific case IDs
python tests/run_tests.py --parallel 4                 # concurrent workers
python tests/run_tests.py --skip-system                # skip system checks (S01–S20)
```

The test runner assumes the API is already running on `http://localhost:8000` and writes `test_report.json` at the end. It exits non-zero if any case fails. System checks (S01–S20) exercise `/health`, session persistence, IP-block escalation (3 consecutive blocks → IP banned), rate limiting, GeoIP, admin endpoints, LLM cache, webhook delivery, and several v7-era invariants.

## Environment

Configuration lives in `bitm-plugin/.env` (see `.env.example`). The most load-bearing variables:

- `LLM_BACKEND` — `anthropic` or `ollama`. Switches the scorer backend end-to-end.
- `ANTHROPIC_API_KEY` — required when `LLM_BACKEND=anthropic`; must start with `sk-`.
- `OLLAMA_HOST` / `OLLAMA_MODEL` / `OLLAMA_TIMEOUT` — used when `LLM_BACKEND=ollama`.
- `REDIS_URL` / `REDIS_SESSION_TTL` / `REDIS_KEY_PREFIX` — optional; absence triggers in-memory fallback.
- `MAXMIND_CITY_DB` / `MAXMIND_ASN_DB` — optional `.mmdb` paths; absence returns empty GeoIP metadata without error.
- `CACHE_TTL` — seconds for the in-process LLM response cache (default 300).

## Architecture

Single FastAPI service (`app/main.py`) that classifies each `/api/bitm/collect` request as `allow` / `challenge` / `block`. The request path through the code is fixed and important to preserve when making changes:

```
HTTP request
  → GeoIP middleware (app/main.py)           sets request.state.ip + ip_meta
  → rate_check (app/redis_client.py)         sliding window; 429 if exceeded
  → is_blocked (app/redis_client.py)         banned-IP set
  → session load/merge (app/redis_client.py) pages/timings appended
  → extract_features (app/extractor.py)      computes pre_risk_score + confirmed_signals
  → _fast_rules (app/main.py)                deterministic short-circuit, skips LLM
  → score_session (app/scorer.py)            LLM call (if not short-circuited), with TTL cache
  → decide (app/policy.py)                   final Action + reason
  → session persist + log_event              JSONL log to bitm_events.jsonl
  → broadcaster.publish (app/broadcaster.py) fan-out to /ws/events clients
```

Key architectural invariants:

- **Two-stage scoring.** `extractor.py` computes `pre_risk_score` (deterministic) and `confirmed_signals`. `policy.py` uses `pre_risk_score` as a **floor** on the LLM score so the LLM cannot argue away certainties, and it **unions** the LLM `indicators` with `confirmed_signals` before applying context boosts. When adding a signal, add the label to `_detect_headless` / `_pre_score` in `extractor.py` and, if it should drive an immediate block, to `CRITICAL_BLOCK` in `policy.py`.
- **Critical signals bypass scoring.** Names in `CRITICAL_BLOCK` (e.g. `headlesschrome_ua`, `webdriver_true`, `tor_exit_node`) force `BLOCK` regardless of score. The `_fast_rules` set in `main.py` uses related but differently-named labels (`headless_ua`, `webdriver_flag`, `no_plugins_no_webgl`, `extreme_latency`, `tor_exit_node`) — both label sets must stay aligned.
- **Contextual thresholds.** `policy.THRESHOLDS` has `(challenge, block)` pairs per page context (`login`, `payment`, `admin`, `static`, `default`). `detect_page_context` maps URL path prefixes. Weak signals are amplified only in login/payment/admin, with boost capped at `MAX_BOOST = 0.25` so no stack of weak signals alone can cross the block threshold.
- **Score parsing gotcha.** `policy.decide` reads `risk_score` with an explicit `None` check, not `or`, because `0.0 or 0.5 == 0.5` would silently turn legit traffic into 0.5. Preserve that pattern anywhere scores are handled.

### Scorer (`app/scorer.py`)

Both backends share `SYSTEM_PROMPT`, `_build_prompt`, `_parse_llm_response`, `_validate_result`, and the TTL cache keyed on `(canvas_hash, user_agent[:60])`. Transient errors (HTTP 5xx, connection, timeout, parse) use a 3-attempt retry with backoff and are **not cached**. Model selection for Anthropic probes `ANTHROPIC_MODELS` in order at first use and caches the first one that accepts a ping. Ollama relies on `format: "json"` to keep llama3.1 from prepending prose; the parser is still defensive (strips markdown fences, locates the outermost `{...}`).

`_validate_result` enforces verdict↔score coherence: a LEGITIMATE verdict with score ≥ 0.65 is upgraded to ATTACK, and ATTACK with score ≤ 0.30 is downgraded to SUSPICIOUS. Don't loosen this without updating the threshold table in `policy.py`.

### Session store (`app/redis_client.py`)

`SessionStore` is a single class that transparently switches between Redis and in-memory state. Every Redis method has an `except → self._connected = False → fall through to memory` branch, so a Redis outage mid-run degrades instead of raising. The `backend` property (`"redis"` / `"memory"`) is what `/health` and `/api/bitm/sessions` report. Rate-limit uses a Redis sorted-set sliding window (`zremrangebyscore` + `zcard` + `zadd` + `expire` in one pipeline); the in-memory fallback uses a `deque` per IP.

### GeoIP (`app/geoip.py`)

Resolver is a lazy singleton holding open MaxMind readers. `is_vpn` is inferred from a hardcoded `_VPN_ASNS` set (cloud/VPN ASNs). `is_tor` cannot be derived from MaxMind — the endpoint accepts a `body["ip_meta"]` hint that can set `is_tor`/`is_vpn` to `True` (never downgrades) and fill fields the resolver left empty. This is intentional: it lets tests inject Tor/VPN signals without an external feed.

### Versioning

Version string lives in three places that must stay in sync: `FastAPI(version=...)` and the `/health` payload in `app/main.py`, plus the README. Current version is `7.4.2`. The test suite's S01 asserts `/health` exposes a `version` field — update the assertion's expected prefix in `tests/run_tests.py` if you bump the major.

### Logging

Every request ends with `log_event(...)` appending a JSON line to `bitm-plugin/bitm_events.jsonl`. The file is gitignored (it grows on every request and creates merge noise), but it is the source of truth for offline analysis and feeds the dashboard's backlog. `log_event` also returns the entry dict so `main.py` can hand the same payload to the WebSocket broadcaster.

### Real-time dashboard

`app/broadcaster.py` is an in-process pub/sub: the `EventBroadcaster` singleton holds a set of connected `/ws/events` clients plus a 500-slot ring buffer. New WebSocket clients receive the ring as a `{"type":"backlog"}` frame so the dashboard doesn't start empty; every subsequent `/api/bitm/collect` produces one `{"type":"event"}` frame. It is **single-worker only** — running uvicorn with `--workers > 1` would give each worker its own broadcaster; promote the transport to Redis pub/sub if that's needed. The dashboard itself is plain HTML/JS at `app/static/dashboard.html`, served at `/dashboard`, using Chart.js from CDN and generating CSV client-side from its in-memory event buffer.