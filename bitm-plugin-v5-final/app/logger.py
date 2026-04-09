"""Logger v4 — stdout colorato + file JSONL."""

import json
from datetime import datetime, timezone

LOG_FILE = "bitm_events.jsonl"

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
              context: str = "default") -> None:

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

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass
