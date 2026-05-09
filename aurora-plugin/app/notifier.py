"""
Webhook Notifier v6.2 — notifiche push per eventi BLOCK.

Ogni volta che il sistema emette un'azione BLOCK, questo modulo
spedisce un HTTP POST asincrono (fire-and-forget) verso uno o più
webhook configurati. Non blocca mai la risposta all'utente.

Configurazione (env vars, tutte opzionali tranne WEBHOOK_URL):

  WEBHOOK_URL          URL destinazione (richiesto per attivare le notifiche)
  WEBHOOK_TYPE         slack | teams | siem   (default: siem)
  WEBHOOK_TIMEOUT      secondi per richiesta HTTP (default: 5)
  WEBHOOK_RETRIES      tentativi in caso di errore (default: 3)
  WEBHOOK_CONFIG_FILE  percorso a un file JSON con la config completa
                       (sovrascrive le singole variabili sopra)

Formato file JSON (WEBHOOK_CONFIG_FILE):

  {
    "url":     "https://hooks.slack.com/services/...",
    "type":    "slack",
    "timeout": 5,
    "retries": 3,
    "headers": { "Authorization": "Bearer token" }
  }

  Il campo "headers" è opzionale e viene aggiunto ad ogni richiesta.

Tipi di integrazione:
  - slack  → Blocks API  (blocchi Section + Header + Context)
  - teams  → Adaptive Cards (schema v1.4, compatibile con connettori O365)
  - siem   → JSON strutturato standard (campo "event_type", ISO-8601 timestamp)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("aurora.notifier")


# ── Configurazione ─────────────────────────────────────────────────────────────

class WebhookConfig:
    """Configurazione di un singolo webhook endpoint."""

    def __init__(
        self,
        url: str,
        kind: str = "siem",
        timeout: float = 5.0,
        retries: int = 3,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.url     = url
        self.kind    = kind.lower().strip()
        self.timeout = max(1.0, float(timeout))
        self.retries = max(1, int(retries))
        self.headers = headers or {}

    def __repr__(self) -> str:
        return f"WebhookConfig(type={self.kind!r}, url={self.url[:40]!r}...)"


def _load_config() -> WebhookConfig | None:
    """
    Carica la configurazione webhook nell'ordine:
    1. WEBHOOK_CONFIG_FILE (file JSON, se presente)
    2. Variabili d'ambiente singole (WEBHOOK_URL, WEBHOOK_TYPE, …)

    Restituisce None se nessun URL è configurato.
    """
    cfg_file = os.getenv("WEBHOOK_CONFIG_FILE", "").strip()
    if cfg_file:
        p = Path(cfg_file)
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                url = data.get("url", "").strip()
                if url:
                    return WebhookConfig(
                        url=url,
                        kind=data.get("type", "siem"),
                        timeout=data.get("timeout", 5),
                        retries=data.get("retries", 3),
                        headers=data.get("headers") or {},
                    )
            except Exception as exc:
                logger.warning("[notifier] Impossibile leggere WEBHOOK_CONFIG_FILE: %s", exc)
        else:
            logger.warning("[notifier] WEBHOOK_CONFIG_FILE non trovato: %s", cfg_file)

    url = os.getenv("WEBHOOK_URL", "").strip()
    if not url:
        return None

    return WebhookConfig(
        url=url,
        kind=os.getenv("WEBHOOK_TYPE", "siem"),
        timeout=float(os.getenv("WEBHOOK_TIMEOUT", "5")),
        retries=int(os.getenv("WEBHOOK_RETRIES", "3")),
    )


# ── Formatters ─────────────────────────────────────────────────────────────────

def _fmt_siem(event: dict[str, Any]) -> dict[str, Any]:
    """
    Payload JSON standard SIEM.
    Tutti i campi sono top-level, nessuna struttura proprietaria.
    """
    return {
        "event_type":   "BLOCK",
        "product":      "AURORA",
        "version":      "6.2",
        "timestamp":    event.get("ts"),
        "severity":     "HIGH",
        "source_ip":    event.get("ip"),
        "session_id":   event.get("session"),
        "risk_score":   event.get("score"),
        "pre_score":    event.get("pre_score"),
        "verdict":      event.get("verdict"),
        "confidence":   event.get("confidence"),
        "indicators":   event.get("indicators", []),
        "explanation":  event.get("explanation"),
        "context":      event.get("context"),
        "latency_ms":   event.get("latency_ms"),
        "browser":      event.get("browser"),
        "os":           event.get("os"),
        "is_mobile":    event.get("is_mobile"),
        "from_cache":   event.get("from_cache"),
        "ua":           event.get("ua"),
    }


def _fmt_slack(event: dict[str, Any]) -> dict[str, Any]:
    """
    Payload Slack Blocks API.
    https://api.slack.com/block-kit
    """
    indicators = event.get("indicators") or []
    ind_text   = ", ".join(f"`{i}`" for i in indicators[:8]) or "—"
    score      = event.get("score", 0)
    verdict    = event.get("verdict", "?")
    ip         = event.get("ip", "?")
    context    = event.get("context", "?")
    session    = event.get("session", "?")
    ts         = event.get("ts", "?")
    explanation = (event.get("explanation") or "")[:120]

    color = "#E53935"  # rosso per BLOCK

    return {
        "text": f":rotating_light: BitM BLOCK — IP {ip}  score={score:.3f}",
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": ":rotating_light: BitM Detection — BLOCK Alert",
                            "emoji": True,
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*IP*\n`{ip}`"},
                            {"type": "mrkdwn", "text": f"*Score*\n`{score:.3f}`"},
                            {"type": "mrkdwn", "text": f"*Verdict*\n`{verdict}`"},
                            {"type": "mrkdwn", "text": f"*Contesto*\n`{context}`"},
                            {"type": "mrkdwn", "text": f"*Sessione*\n`{session}`"},
                            {"type": "mrkdwn", "text": f"*Timestamp*\n{ts}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Segnali rilevati*\n{ind_text}",
                        },
                    },
                    *(
                        [
                            {
                                "type": "context",
                                "elements": [
                                    {
                                        "type": "mrkdwn",
                                        "text": f":speech_balloon: _{explanation}_",
                                    }
                                ],
                            }
                        ]
                        if explanation
                        else []
                    ),
                ],
            }
        ],
    }


def _fmt_teams(event: dict[str, Any]) -> dict[str, Any]:
    """
    Payload Microsoft Teams via Incoming Webhook (Adaptive Cards schema v1.4).
    Compatibile con connettori O365 e Power Automate.
    """
    indicators = event.get("indicators") or []
    ind_text   = ", ".join(indicators[:8]) or "—"
    score      = event.get("score", 0)
    verdict    = event.get("verdict", "?")
    ip         = event.get("ip", "?")
    context    = event.get("context", "?")
    session    = event.get("session", "?")
    ts         = event.get("ts", "?")
    explanation = (event.get("explanation") or "")[:120]

    facts = [
        {"title": "IP",        "value": ip},
        {"title": "Score",     "value": f"{score:.3f}"},
        {"title": "Verdict",   "value": verdict},
        {"title": "Contesto",  "value": context},
        {"title": "Sessione",  "value": session},
        {"title": "Timestamp", "value": ts},
        {"title": "Segnali",   "value": ind_text},
    ]

    body: list[dict] = [
        {
            "type":   "TextBlock",
            "size":   "Large",
            "weight": "Bolder",
            "color":  "Attention",
            "text":   "🚨 BitM Detection — BLOCK Alert",
        },
        {
            "type":  "FactSet",
            "facts": facts,
        },
    ]
    if explanation:
        body.append({
            "type":    "TextBlock",
            "wrap":    True,
            "isSubtle": True,
            "text":    explanation,
        })

    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl":  None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type":    "AdaptiveCard",
                    "version": "1.4",
                    "body":    body,
                },
            }
        ],
    }


_FORMATTERS = {
    "slack": _fmt_slack,
    "teams": _fmt_teams,
    "siem":  _fmt_siem,
}


def build_payload(event: dict[str, Any], kind: str) -> dict[str, Any]:
    """Costruisce il payload per il tipo di integrazione specificato."""
    formatter = _FORMATTERS.get(kind, _fmt_siem)
    return formatter(event)


# ── Dispatcher asincrono ───────────────────────────────────────────────────────

async def _post_with_retry(
    cfg: WebhookConfig,
    payload: dict[str, Any],
    event_ts: str,
) -> None:
    """
    Invia il payload al webhook con retry esponenziale.
    Completamente fire-and-forget: le eccezioni vengono loggiate, mai propagate.
    """
    headers = {"Content-Type": "application/json", **cfg.headers}
    body    = json.dumps(payload, ensure_ascii=False, default=str)

    attempt = 0
    delay   = 1.0  # backoff iniziale

    async with httpx.AsyncClient(timeout=cfg.timeout) as client:
        while attempt < cfg.retries:
            attempt += 1
            try:
                resp = await client.post(cfg.url, content=body, headers=headers)
                if resp.status_code < 400:
                    logger.debug(
                        "[notifier] Webhook OK (tentativo %d) ts=%s status=%d",
                        attempt, event_ts, resp.status_code,
                    )
                    return
                # 4xx non è un errore di rete: non ha senso ritentare
                if resp.status_code < 500:
                    logger.warning(
                        "[notifier] Webhook risposta %d (client error), no retry. ts=%s",
                        resp.status_code, event_ts,
                    )
                    return
                logger.warning(
                    "[notifier] Webhook risposta %d (tentativo %d/%d) ts=%s",
                    resp.status_code, attempt, cfg.retries, event_ts,
                )
            except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError) as exc:
                logger.warning(
                    "[notifier] Errore di rete (tentativo %d/%d): %s ts=%s",
                    attempt, cfg.retries, exc, event_ts,
                )
            except Exception as exc:
                logger.error(
                    "[notifier] Errore imprevisto (tentativo %d/%d): %s ts=%s",
                    attempt, cfg.retries, exc, event_ts,
                )
                return  # errori non-transitori: non ritentare

            if attempt < cfg.retries:
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30.0)  # max 30 s

    logger.error(
        "[notifier] Webhook fallito dopo %d tentativi. ts=%s url=%s",
        cfg.retries, event_ts, cfg.url[:60],
    )


# ── API pubblica ───────────────────────────────────────────────────────────────

# Config caricata lazy al primo uso: leggendola a import-time non si
# recepivano cambi di env var fatti dopo l'import (tipico nei test).
_cfg: WebhookConfig | None = None
_cfg_loaded: bool = False

# Strong ref set: Python può GC'are i task creati con create_task se non c'è
# un riferimento vivo (docs: "save a reference [...] to avoid a task
# disappearing mid-execution"). Li teniamo qui e li rimuoviamo a done.
_pending_tasks: set[asyncio.Task] = set()


def _get_cfg() -> WebhookConfig | None:
    global _cfg, _cfg_loaded
    if not _cfg_loaded:
        _cfg = _load_config()
        _cfg_loaded = True
    return _cfg


def reload_config() -> None:
    """Forza la rilettura della config (utile nei test)."""
    global _cfg, _cfg_loaded
    _cfg = None
    _cfg_loaded = False


def notify_block(event: dict[str, Any]) -> None:
    """
    Punto di ingresso principale.

    Invia in background (fire-and-forget) una notifica al webhook configurato
    se e solo se l'azione dell'evento è 'block'.

    Chiamare da qualsiasi contesto async senza await:
        notify_block(entry)
    """
    cfg = _get_cfg()
    if cfg is None:
        return

    action = event.get("action", "")
    if action != "block":
        return

    payload  = build_payload(event, cfg.kind)
    event_ts = event.get("ts", "?")

    task = asyncio.create_task(
        _post_with_retry(cfg, payload, event_ts),
        name=f"webhook-block-{event_ts}",
    )
    _pending_tasks.add(task)
    task.add_done_callback(_pending_tasks.discard)


def webhook_status() -> dict[str, Any]:
    """
    Restituisce lo stato corrente del webhook (usato da /health).
    """
    cfg = _get_cfg()
    if cfg is None:
        return {"enabled": False}
    return {
        "enabled": True,
        "type":    cfg.kind,
        "url":     cfg.url[:40] + "..." if len(cfg.url) > 40 else cfg.url,
        "timeout": cfg.timeout,
        "retries": cfg.retries,
    }
