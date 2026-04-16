"""
Config v6 — legge .env e decide quale backend LLM usare.

Variabili supportate:

  LLM_BACKEND=anthropic   (default) usa Anthropic API
  LLM_BACKEND=ollama      usa Ollama locale

  # Anthropic
  ANTHROPIC_API_KEY=sk-ant-...

  # Ollama
  OLLAMA_HOST=http://localhost:11434   (default)
  OLLAMA_MODEL=llama3.1                (default)
  OLLAMA_TIMEOUT=60                    (secondi, default 60)

  # Redis (sessioni persistenti condivise multi-processo)
  REDIS_URL=redis://localhost:6379/0
  REDIS_SESSION_TTL=3600               (secondi, default 1h)

  # GeoIP (MaxMind GeoLite2)
  MAXMIND_CITY_DB=/path/to/GeoLite2-City.mmdb
  MAXMIND_ASN_DB=/path/to/GeoLite2-ASN.mmdb

  # Webhook push notifications (v6.2)
  WEBHOOK_URL=https://hooks.slack.com/services/...
  WEBHOOK_TYPE=slack           slack | teams | siem  (default: siem)
  WEBHOOK_TIMEOUT=5            secondi per richiesta HTTP (default: 5)
  WEBHOOK_RETRIES=3            tentativi in caso di errore (default: 3)
  WEBHOOK_CONFIG_FILE=/path/to/webhook.json   config completa via JSON
"""

import os

# ── Backend selector ──────────────────────────────────────────────────────────
LLM_BACKEND: str = os.getenv("LLM_BACKEND", "anthropic").strip().lower()

# ── Anthropic ─────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "").strip()

ANTHROPIC_MODELS = [
    "claude-haiku-4-5-20251001",
    "claude-3-5-haiku-20241022",
    "claude-sonnet-4-6",
    "claude-3-5-sonnet-20241022",
    "claude-3-haiku-20240307",
]

# ── Ollama ────────────────────────────────────────────────────────────────────
OLLAMA_HOST: str    = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL: str   = os.getenv("OLLAMA_MODEL", "llama3.1")
OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "60"))

# ── Redis ─────────────────────────────────────────────────────────────────────
REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_SESSION_TTL: int = int(os.getenv("REDIS_SESSION_TTL", "3600"))
REDIS_KEY_PREFIX: str = os.getenv("REDIS_KEY_PREFIX", "bitm:")

# ── Webhook push notifications (v6.2) ─────────────────────────────────────────
WEBHOOK_URL: str         = os.getenv("WEBHOOK_URL", "").strip()
WEBHOOK_TYPE: str        = os.getenv("WEBHOOK_TYPE", "siem").strip().lower()
WEBHOOK_TIMEOUT: float   = float(os.getenv("WEBHOOK_TIMEOUT", "5"))
WEBHOOK_RETRIES: int     = int(os.getenv("WEBHOOK_RETRIES", "3"))
WEBHOOK_CONFIG_FILE: str = os.getenv("WEBHOOK_CONFIG_FILE", "").strip()

# ── GeoIP (MaxMind GeoLite2) ──────────────────────────────────────────────────
MAXMIND_CITY_DB: str = os.getenv("MAXMIND_CITY_DB", "").strip()
MAXMIND_ASN_DB:  str = os.getenv("MAXMIND_ASN_DB",  "").strip()

# ── Cache ─────────────────────────────────────────────────────────────────────
CACHE_TTL_S: int = int(os.getenv("CACHE_TTL", "300"))   # 5 minuti default


def validate() -> list[str]:
    """Restituisce lista di errori di configurazione (vuota = OK)."""
    errors = []
    if LLM_BACKEND == "anthropic":
        if not ANTHROPIC_API_KEY or not ANTHROPIC_API_KEY.startswith("sk-"):
            errors.append(
                "LLM_BACKEND=anthropic ma ANTHROPIC_API_KEY mancante o non valida.\n"
                "  Formato: ANTHROPIC_API_KEY=sk-ant-api03-..."
            )
    elif LLM_BACKEND == "ollama":
        pass   # validato al primo uso (Ollama potrebbe non essere ancora avviato)
    else:
        errors.append(
            f"LLM_BACKEND='{LLM_BACKEND}' non riconosciuto. "
            "Valori validi: 'anthropic', 'ollama'"
        )
    return errors


def summary() -> str:
    if LLM_BACKEND == "ollama":
        return f"ollama @ {OLLAMA_HOST}  model={OLLAMA_MODEL}"
    return f"anthropic  key={ANTHROPIC_API_KEY[:12]}..." if ANTHROPIC_API_KEY else "anthropic  (no key)"
