"""
Config v6 — legge .env e decide quale backend LLM usare.

Variabili supportate:

  LLM_BACKEND=stub        (default) scorer deterministico, zero-config
  LLM_BACKEND=anthropic   usa Anthropic API (richiede ANTHROPIC_API_KEY)
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

import ipaddress
import os

# ── Backend selector ──────────────────────────────────────────────────────────
LLM_BACKEND: str = os.getenv("LLM_BACKEND", "stub").strip().lower()


# ── Trusted proxies (per X-Forwarded-For) ─────────────────────────────────────
# CSV di IP o CIDR. Vuoto (default) = non fidarsi mai dell'header XFF.
# Esempio produzione dietro nginx/ingress:
#   TRUSTED_PROXIES=10.0.0.0/8,127.0.0.1
def _parse_trusted_proxies(raw: str) -> list:
    out = []
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            out.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            print(f"[config] TRUSTED_PROXIES: valore ignorato '{item}'")
    return out


TRUSTED_PROXIES = _parse_trusted_proxies(os.getenv("TRUSTED_PROXIES", ""))


# ── Admin token ───────────────────────────────────────────────────────────────
# Se impostato, protegge /api/bitm/sessions (GET/DELETE), /dashboard e
# /ws/events. Richiesto via header X-Admin-Token (JSON) o query ?token=
# (dashboard/WS dove non si può impostare l'header). Vuoto = endpoint aperti
# (retrocompatibile, ma il server stampa un warning al startup).
ADMIN_TOKEN: str = os.getenv("ADMIN_TOKEN", "").strip()


def is_trusted_proxy(ip: str) -> bool:
    if not TRUSTED_PROXIES or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in TRUSTED_PROXIES)


def check_admin_token(provided: str | None) -> bool:
    """Confronta in tempo costante per evitare timing attack."""
    import hmac
    if not ADMIN_TOKEN:
        return True   # auth disattivata
    if not provided:
        return False
    return hmac.compare_digest(ADMIN_TOKEN, provided)

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

# ── Trajectory analysis (v7.4) ────────────────────────────────────────────────
# Secondo layer LLM che legge la sequenza di pagine/timings per riconoscere
# pattern post-compromissione (panic password change, direct admin access...).
# "auto" = on se il backend è un LLM reale, off con stub (no-op a costo zero).
# "on"/"off" forzano il comportamento. Vedi scorer.analyze_trajectory.
_TRAJECTORY_RAW: str = os.getenv("LLM_TRAJECTORY_ANALYSIS", "auto").strip().lower()
if _TRAJECTORY_RAW in ("on", "true", "1", "yes"):
    LLM_TRAJECTORY_ANALYSIS = True
elif _TRAJECTORY_RAW in ("off", "false", "0", "no"):
    LLM_TRAJECTORY_ANALYSIS = False
else:
    LLM_TRAJECTORY_ANALYSIS = LLM_BACKEND in ("anthropic", "ollama")

TRAJECTORY_CACHE_TTL_S: int = int(os.getenv("TRAJECTORY_CACHE_TTL", "60"))


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
    elif LLM_BACKEND == "stub":
        pass   # nessuna dipendenza esterna
    else:
        errors.append(
            f"LLM_BACKEND='{LLM_BACKEND}' non riconosciuto. "
            "Valori validi: 'anthropic', 'ollama', 'stub'"
        )
    return errors


def summary() -> str:
    if LLM_BACKEND == "ollama":
        core = f"ollama @ {OLLAMA_HOST}  model={OLLAMA_MODEL}"
    elif LLM_BACKEND == "stub":
        core = "stub (deterministico, no-LLM)"
    else:
        core = f"anthropic  key={ANTHROPIC_API_KEY[:12]}..." if ANTHROPIC_API_KEY else "anthropic  (no key)"
    traj = "on" if LLM_TRAJECTORY_ANALYSIS else "off"
    return f"{core}  trajectory={traj}"
