"""
LLM Scorer v5 — supporta Anthropic Claude e Ollama (llama3.1).

Backend selezionato tramite LLM_BACKEND nel .env:
  LLM_BACKEND=anthropic   → usa Anthropic API (default)
  LLM_BACKEND=ollama      → usa Ollama locale (llama3.1 o altro)

Architettura:
  score_session(features) → chiama il backend corretto → dict con risk_score, verdict, ecc.
  Cache TTL condivisa tra entrambi i backend.
"""

import os
import json
import time
import asyncio
import httpx
import anthropic

from app.config import (
    LLM_BACKEND,
    ANTHROPIC_API_KEY, ANTHROPIC_MODELS,
    OLLAMA_HOST, OLLAMA_MODEL, OLLAMA_TIMEOUT,
    CACHE_TTL_S,
)

# ── Cache ─────────────────────────────────────────────────────────────────────
_score_cache: dict       = {}
_selected_model: str | None = None   # usato solo dal backend Anthropic

# ── System prompt comune ─────────────────────────────────────────────────────
# v7.0 — versione compatta (~40% più corta della v6) per ridurre la latenza
# d'inferenza ed i token in input della cache prompt. Rimosse ridondanze
# ("NON scrivere", "ISTRUZIONE CRITICA", esempio completo) mantenendo le
# direttive essenziali:
#   1) output JSON puro (niente markdown / testo fuori dal JSON)
#   2) schema con enum espliciti per verdict/confidence
#   3) mappatura soglie → verdict (coerenza enforce-ata da _validate_result)
#   4) vincolo di "floor" sul pre_risk_score (coerente con policy.decide)
# La lunghezza ridotta è validata dal test S01 (health) + test_report LLM.
SYSTEM_PROMPT = """\
Rilevi attacchi Browser-in-the-Middle (BitM/BitM+) analizzando le feature di \
una sessione web.

Rispondi SOLO con un oggetto JSON su una singola riga. Nessun testo, commento \
o markdown fuori dal JSON.

Schema ESATTO:
{"risk_score":<float 0-1>,"verdict":"LEGITIMATE"|"SUSPICIOUS"|"ATTACK","confidence":"low"|"medium"|"high","indicators":[<str>],"explanation":"<=120 char"}

Soglie risk_score → verdict:
 0.00-0.30 → LEGITIMATE (browser reale)
 0.31-0.64 → SUSPICIOUS (segnali ambigui)
 0.65-1.00 → ATTACK (headless/proxy/noVNC/Guacamole/ngrok/xssPayload)

Vincolo: se pre_risk_score>=0.65 con segnali confermati, non scendere sotto 0.65."""


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_selected_model() -> str:
    if LLM_BACKEND == "ollama":
        return f"ollama/{OLLAMA_MODEL}"
    if LLM_BACKEND == "stub":
        return "stub/deterministic"
    return _selected_model or "anthropic/?"


def _cache_get(key: str) -> dict | None:
    entry = _score_cache.get(key)
    if entry:
        result, ts = entry
        if time.time() - ts < CACHE_TTL_S:
            return result
        del _score_cache[key]
    return None


def _cache_set(key: str, result: dict) -> None:
    _score_cache[key] = (result, time.time())
    if len(_score_cache) > 2000:
        oldest = min(_score_cache, key=lambda k: _score_cache[k][1])
        del _score_cache[oldest]


def _parse_llm_response(text: str) -> dict:
    """
    Estrae il blocco JSON dalla risposta in modo robusto.
    Llama3.1 spesso scrive testo introduttivo prima del JSON — gestiamo questo.
    """
    text = text.strip()

    # 1. Rimuovi blocchi markdown ```json ... ```
    if "```" in text:
        for chunk in text.split("```"):
            chunk = chunk.strip()
            if chunk.lower().startswith("json"):
                chunk = chunk[4:].strip()
            if chunk.startswith("{"):
                text = chunk
                break

    # 2. Trova il primo { e l'ultimo } corrispondente
    #    (gestisce testo prima/dopo il JSON)
    if not text.startswith("{"):
        start = text.find("{")
        if start == -1:
            raise json.JSONDecodeError("Nessun blocco JSON trovato", text, 0)
        # Trova la chiusura bilanciata
        depth = 0
        end   = -1
        for i, ch in enumerate(text[start:], start):
            if ch == "{": depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end == -1:
            raise json.JSONDecodeError("JSON non chiuso correttamente", text, start)
        text = text[start:end]

    return json.loads(text)


def _validate_result(result: dict) -> dict:
    """Normalizza e valida tutti i campi della risposta LLM."""
    defaults = {
        "risk_score":  0.5,
        "verdict":     "SUSPICIOUS",
        "confidence":  "low",
        "indicators":  [],
        "explanation": "nessuna spiegazione fornita",
    }
    for field, default in defaults.items():
        if field not in result or result[field] is None:
            result[field] = default

    try:
        result["risk_score"] = max(0.0, min(1.0, float(result["risk_score"])))
    except (TypeError, ValueError):
        result["risk_score"] = 0.5

    if not isinstance(result["indicators"], list):
        result["indicators"] = []
    result["indicators"] = [str(i) for i in result["indicators"]]

    valid_verdicts    = {"LEGITIMATE", "SUSPICIOUS", "ATTACK"}
    valid_confidences = {"low", "medium", "high"}
    if result["verdict"] not in valid_verdicts:
        result["verdict"] = "SUSPICIOUS"
    if result["confidence"] not in valid_confidences:
        result["confidence"] = "low"

    # Coerenza verdict ↔ score
    score = result["risk_score"]
    if score >= 0.65 and result["verdict"] == "LEGITIMATE":
        result["verdict"] = "ATTACK"
    elif score <= 0.30 and result["verdict"] == "ATTACK":
        result["verdict"] = "SUSPICIOUS"

    return result


def _error(msg: str, indicator: str) -> dict:
    return {
        "risk_score":  0.5,
        "verdict":     "SUSPICIOUS",
        "confidence":  "low",
        "indicators":  [indicator],
        "explanation": msg[:120],
    }


def _build_prompt(f: dict) -> str:
    """Prompt identico per entrambi i backend."""
    pre_score     = f.get("pre_risk_score", 0.0)
    confirmed     = f.get("confirmed_signals") or []
    confirmed_str = ", ".join(confirmed) if confirmed else "nessuno"

    plugins    = f.get("plugins") or []
    plugin_str = ", ".join(plugins[:5]) if plugins else "nessuno"

    ip_meta = f.get("ip_meta") or {}
    ip_str  = (
        f"VPN={ip_meta.get('is_vpn','?')}, "
        f"Tor={ip_meta.get('is_tor','?')}, "
        f"paese={ip_meta.get('country','?')}"
    )

    pages     = f.get("page_sequence") or []
    pages_str = " > ".join(pages[-5:]) if pages else "/"

    headless     = f.get("headless_signals") or []
    headless_str = ", ".join(headless) if headless else "nessuno"

    bitm_sigs = f.get("bitm_signals") or []
    bitm_str  = ", ".join(bitm_sigs) if bitm_sigs else "nessuno"

    return (
        f"=== PUNTEGGIO DETERMINISTICO PRE-CALCOLATO ===\n"
        f"pre_risk_score: {pre_score:.3f}\n"
        f"Segnali confermati: {confirmed_str}\n"
        f"Marker BitM/BitM+: {bitm_str}\n\n"
        f"=== DETTAGLI BROWSER ===\n"
        f"User-Agent: {(f.get('user_agent') or '?')[:100]}\n"
        f"Browser: {f.get('ua_browser','?')} | OS: {f.get('ua_os','?')} | "
        f"Mobile: {f.get('is_mobile', False)}\n"
        f"Plugin ({f.get('plugin_count',0)}): {plugin_str}\n"
        f"WebGL: {(f.get('webgl') or 'unavailable')[:70]}\n"
        f"SwiftShader: {f.get('webgl_swiftshader', False)}\n"
        f"Canvas: hash={f.get('canvas_hash','?')}, vuoto={f.get('canvas_empty', True)}\n"
        f"webdriver: {f.get('webdriver', False)}\n"
        f"Lingue ({f.get('language_count',0)}): "
        f"{', '.join((f.get('languages') or [])[:3]) or 'nessuna'}\n"
        f"Schermo: {f.get('screen','?')} | colorDepth: {f.get('color_depth',0)}\n"
        f"Timezone: {f.get('timezone','?') or '(vuoto)'} | "
        f"Anomalia: {f.get('timezone_anomaly', False)}\n"
        f"Platform: {f.get('platform','?')}\n\n"
        f"=== RETE E TIMING ===\n"
        f"IP info: {ip_str}\n"
        f"Latenza media: {f.get('avg_timing_ms',0)}ms | "
        f"max: {f.get('max_timing_ms',0)}ms | "
        f"stdev: {f.get('stdev_timing_ms',0)}ms\n"
        f"Richieste totali: {f.get('request_count',1)}\n\n"
        f"=== COMPORTAMENTO ===\n"
        f"Pagine visitate: {pages_str}\n"
        f"Segnali headless: {headless_str}\n\n"
        f"Rispondi SOLO con il JSON."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Backend Anthropic
# ─────────────────────────────────────────────────────────────────────────────

async def _anthropic_pick_model(client: anthropic.AsyncAnthropic) -> str:
    global _selected_model
    if _selected_model:
        return _selected_model

    print("[scorer/anthropic] Ricerca modello disponibile...")
    for model in ANTHROPIC_MODELS:
        try:
            await client.messages.create(
                model=model, max_tokens=5,
                messages=[{"role": "user", "content": "ping"}]
            )
            _selected_model = model
            print(f"[scorer/anthropic] Modello attivo: {model}")
            return model
        except anthropic.APIStatusError as e:
            if e.status_code == 401:
                raise ValueError(
                    "API key Anthropic non valida o scaduta.\n"
                    "Verifica ANTHROPIC_API_KEY in .env"
                )
            print(f"[scorer/anthropic]   {model} → HTTP {e.status_code}")
            continue
        except Exception as e:
            print(f"[scorer/anthropic]   {model} → {type(e).__name__}: {e}")
            continue

    raise RuntimeError(
        "Nessun modello Claude disponibile.\n"
        "Esegui: python diagnose.py"
    )


async def _score_anthropic(features: dict) -> dict:
    if not ANTHROPIC_API_KEY or not ANTHROPIC_API_KEY.startswith("sk-"):
        raise ValueError(
            "ANTHROPIC_API_KEY mancante in .env\n"
            "Oppure imposta LLM_BACKEND=ollama per usare Ollama."
        )

    client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
    model  = await _anthropic_pick_model(client)
    prompt = _build_prompt(features)
    raw    = ""

    for attempt in range(3):
        try:
            msg = await client.messages.create(
                model=model,
                max_tokens=256,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )
            raw    = msg.content[0].text
            result = _parse_llm_response(raw)
            return _validate_result(result)

        except json.JSONDecodeError:
            print(f"[scorer/anthropic] JSONDecodeError (attempt {attempt+1}/3) raw: {raw[:150]!r}")
            if attempt < 2:
                await asyncio.sleep(1)
                continue
            return _error("Risposta non JSON", "llm_parse_error")

        except anthropic.APIStatusError as e:
            global _selected_model
            code = e.status_code
            print(f"[scorer/anthropic] HTTP {code} (attempt {attempt+1}/3)")
            if code == 529 and attempt < 2:
                await asyncio.sleep(2 ** attempt)
                continue
            if code in (400, 404):
                _selected_model = None
            return _error(f"API error {code}", "api_error")

        except Exception as e:
            print(f"[scorer/anthropic] {type(e).__name__}: {e}")
            if attempt < 2:
                await asyncio.sleep(1)
                continue
            return _error(str(e)[:80], "unknown_error")

    return _error("Troppi tentativi falliti", "max_retries")


# ─────────────────────────────────────────────────────────────────────────────
# Backend Ollama
# ─────────────────────────────────────────────────────────────────────────────

async def _score_ollama(features: dict) -> dict:
    """
    Chiama Ollama tramite l'API REST /api/chat (formato nativo Ollama).
    Compatibile con llama3.1 e qualsiasi modello installato localmente.

    Ollama tende a "chiacchierare" → forziamo JSON puro con:
    - format: "json"  (supportato da llama3.1, forza output JSON)
    - system prompt con esempio concreto
    - istruzione finale esplicita nel prompt utente
    """
    prompt = _build_prompt(features)
    url    = f"{OLLAMA_HOST}/api/chat"

    payload = {
        "model":  OLLAMA_MODEL,
        "stream": False,
        "format": "json",        # forza Ollama a produrre JSON puro
        "options": {
            "temperature": 0.1,  # bassa temperatura = risposte più deterministiche
            "num_predict": 300,  # max token risposta
        },
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
    }

    raw = ""
    for attempt in range(3):
        try:
            async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
                resp = await client.post(url, json=payload)

            if resp.status_code != 200:
                body = resp.text[:200]
                print(f"[scorer/ollama] HTTP {resp.status_code} (attempt {attempt+1}/3): {body}")

                if resp.status_code == 404:
                    raise RuntimeError(
                        f"Modello '{OLLAMA_MODEL}' non trovato in Ollama.\n"
                        f"Esegui: ollama pull {OLLAMA_MODEL}"
                    )
                if resp.status_code in (500, 503) and attempt < 2:
                    await asyncio.sleep(2)
                    continue
                return _error(f"Ollama HTTP {resp.status_code}", "ollama_http_error")

            data = resp.json()

            # Ollama /api/chat → { "message": { "content": "..." } }
            raw = data.get("message", {}).get("content", "")
            if not raw:
                raise json.JSONDecodeError("Risposta Ollama vuota", "", 0)

            result = _parse_llm_response(raw)
            return _validate_result(result)

        except json.JSONDecodeError:
            print(f"[scorer/ollama] JSONDecodeError (attempt {attempt+1}/3) raw: {raw[:200]!r}")
            if attempt < 2:
                await asyncio.sleep(1)
                continue
            return _error("Risposta Ollama non è JSON", "ollama_parse_error")

        except httpx.ConnectError:
            msg = (
                f"Ollama non raggiungibile su {OLLAMA_HOST}.\n"
                f"  1. Verifica che Ollama sia avviato: ollama serve\n"
                f"  2. Verifica OLLAMA_HOST in .env (default: http://localhost:11434)"
            )
            print(f"[scorer/ollama] {msg}")
            if attempt < 2:
                await asyncio.sleep(2)
                continue
            return _error("Ollama non raggiungibile", "ollama_connection_error")

        except httpx.TimeoutException:
            print(f"[scorer/ollama] Timeout dopo {OLLAMA_TIMEOUT}s (attempt {attempt+1}/3)")
            if attempt < 2:
                await asyncio.sleep(1)
                continue
            return _error(f"Timeout Ollama {OLLAMA_TIMEOUT}s", "ollama_timeout")

        except RuntimeError as e:
            # Errori definitivi (modello non trovato ecc.)
            print(f"[scorer/ollama] Errore definitivo: {e}")
            return _error(str(e)[:100], "ollama_error")

        except Exception as e:
            print(f"[scorer/ollama] {type(e).__name__}: {e}")
            if attempt < 2:
                await asyncio.sleep(1)
                continue
            return _error(str(e)[:80], "unknown_error")

    return _error("Troppi tentativi Ollama falliti", "max_retries")


# ─────────────────────────────────────────────────────────────────────────────
# Backend stub (deterministico) — usato in CI / E2E / dev senza LLM reale.
# Non fa rete, deriva score e verdict dai segnali già calcolati da extractor.
# ─────────────────────────────────────────────────────────────────────────────

async def _score_stub(features: dict) -> dict:
    pre = float(features.get("pre_risk_score", 0.0))
    confirmed = list(features.get("confirmed_signals") or [])
    headless_sig = list(features.get("headless_signals") or [])

    # Usa direttamente pre_risk_score: è già la somma pesata deterministica
    # dei segnali. Alzare artificialmente a 0.5/0.65 sommava al boost contestuale
    # in policy.decide e spingeva casi suspicious (T12/T14/T15/T16) sopra la
    # soglia block. Il floor vero vive già in policy (pre_risk_score >= score).
    score = pre

    if score >= 0.65:
        verdict = "ATTACK"
    elif score >= 0.31:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LEGITIMATE"

    return {
        "risk_score":  round(min(1.0, max(0.0, score)), 3),
        "verdict":     verdict,
        "confidence":  "high" if confirmed or headless_sig else "low",
        "indicators":  (confirmed + headless_sig)[:6],
        "explanation": "stub scorer deterministico (pre_risk_score + segnali)",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Entry point pubblico
# ─────────────────────────────────────────────────────────────────────────────

async def score_session(features: dict) -> dict:
    """
    Punto di ingresso unico per lo scoring LLM.
    Seleziona automaticamente Anthropic / Ollama / stub in base a LLM_BACKEND.
    """
    cache_key = f"{features.get('canvas_hash','x')}:{features.get('user_agent','')[:60]}"
    cached = _cache_get(cache_key)
    if cached:
        return {**cached, "_from_cache": True}

    if LLM_BACKEND == "stub":
        result = await _score_stub(features)
    elif LLM_BACKEND == "ollama":
        result = await _score_ollama(features)
    else:
        result = await _score_anthropic(features)

    # Caching solo se la risposta non è un errore tecnico
    if result.get("indicators") and result["indicators"][0] in (
        "api_error", "ollama_connection_error", "ollama_timeout",
        "ollama_http_error", "max_retries", "unknown_error"
    ):
        return result  # non caching degli errori

    _cache_set(cache_key, result)
    return result
