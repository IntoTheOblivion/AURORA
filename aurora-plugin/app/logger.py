"""Logger v4 — stdout colorato + file JSONL."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

# Path del log: risolto relativo alla radice del progetto (parent del pacchetto
# `app/`), così il file finisce sempre in `bitm-plugin/bitm_events.jsonl`
# indipendentemente dalla CWD dal quale uvicorn / i test vengono invocati.
# Override esplicito via env BITM_LOG_FILE (path assoluto consigliato).
_DEFAULT_LOG = Path(__file__).resolve().parent.parent / "bitm_events.jsonl"
LOG_FILE = os.getenv("BITM_LOG_FILE", str(_DEFAULT_LOG))

_C = {
    "allow":     "\033[32m",
    "challenge": "\033[33m",
    "block":     "\033[31m",
}
_R  = "\033[0m"
_D  = "\033[2m"
_B  = "\033[1m"


def log_event(ip: str, sid: str, features: dict,
              result: dict, action, elapsed_ms: float,
              context: str = "default",
              trajectory: dict | None = None) -> dict:

    av     = action.value
    color  = _C.get(av, "")
    score  = result.get("risk_score", 0)
    inds   = result.get("indicators") or []
    cached = result.get("_from_cache", False)
    pre    = features.get("pre_risk_score", 0.0)

    tag = f"{_D}[cache]{_R}" if cached else ""
    print(
        f"{color}{_B}[{av.upper():9s}]{_R} "
        f"score={score:.3f} pre={pre:.3f} "
        f"ctx={context:<8s} {elapsed_ms:6.1f}ms {tag} "
        f"{_D}{(features.get('user_agent') or '')[:45]}{_R}"
    )
    if inds:
        print(f"           {_D}signals: {', '.join(inds[:6])}{_R}")
    if result.get("explanation"):
        print(f"           {(result['explanation'] or '')[:90]}")

    entry = {
        "ts":          datetime.now(timezone.utc).isoformat(),
        "ip":          ip,
        "session":     sid,
        "action":      av,
        "context":     context,
        "score":       round(score, 4),
        "pre_score":   round(pre, 4),
        "verdict":     result.get("verdict", "?"),
        "confidence":  result.get("confidence", "low"),
        "indicators":  inds,
        "explanation": (result.get("explanation") or "")[:120],
        "from_cache":  cached,
        "latency_ms":  elapsed_ms,
        "browser":     features.get("ua_browser", "?"),
        "os":          features.get("ua_os", "?"),
        "is_mobile":   features.get("is_mobile", False),
        "headless_n":  features.get("headless_score", 0),
        "ua":          (features.get("user_agent") or "")[:80],
    }

    if trajectory:
        t_score   = trajectory.get("trajectory_score", 0.0)
        t_pattern = trajectory.get("pattern", "")
        if t_pattern and t_pattern not in ("disabled",):
            entry["trajectory_score"]   = round(float(t_score or 0.0), 4)
            entry["trajectory_pattern"] = t_pattern
            eu = trajectory.get("explanation_user") or ""
            ea = trajectory.get("explanation_admin") or ""
            if eu:
                entry["explanation_user"]  = eu[:200]
            if ea:
                entry["explanation_admin"] = ea[:240]

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass

    return entry
