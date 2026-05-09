"""
build_dataset.py — converte aurora_events.jsonl in un dataset SFT per LLaMA 3.1.

Prende i log prodotti da app/logger.py e genera un dataset in formato
"messages" (ChatML) compatibile con trl.SFTTrainer / HuggingFace Datasets.

Pulizia applicata:
  - scarta entry da cache (duplicati inferenziali)
  - scarta entry con indicators tecnici (api_error, ollama_*_error, parse_error…)
  - deduplica per (ua[:60], verdict, pre_score) per evitare ripetizione di
    session replay nei log
  - garantisce coerenza verdict↔score (stesso check di scorer._validate_result)

Output:
  <output-dir>/train.jsonl
  <output-dir>/val.jsonl
  <output-dir>/stats.json

Uso:
  python build_dataset.py \\
      --input ../aurora_events.jsonl \\
      --output-dir ./dataset \\
      --val-split 0.1
"""

from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from pathlib import Path

# Etichette di indicator che rappresentano errori tecnici del backend
# (non vanno in addestramento: non riflettono il segnale di sicurezza).
TECH_ERROR_INDICATORS = {
    "api_error",
    "llm_parse_error",
    "max_retries",
    "unknown_error",
    "ollama_http_error",
    "ollama_parse_error",
    "ollama_connection_error",
    "ollama_timeout",
    "ollama_error",
}

# System prompt v7 — tenuto sincronizzato con app/scorer.py::SYSTEM_PROMPT.
# Duplicato qui per rendere lo script di preprocessing riproducibile anche
# senza importare l'applicazione (utile in ambiente di training isolato).
SYSTEM_PROMPT = (
    "Rilevi attacchi Browser-in-the-Middle (BitM) analizzando le feature di una "
    "sessione web.\n\n"
    "Rispondi SOLO con un oggetto JSON su una singola riga. Nessun testo, "
    "commento o markdown fuori dal JSON.\n\n"
    "Schema ESATTO:\n"
    '{"risk_score":<float 0-1>,"verdict":"LEGITIMATE"|"SUSPICIOUS"|"ATTACK",'
    '"confidence":"low"|"medium"|"high","indicators":[<str>],'
    '"explanation":"<=120 char"}\n\n'
    "Soglie risk_score → verdict:\n"
    " 0.00-0.30 → LEGITIMATE (browser reale)\n"
    " 0.31-0.64 → SUSPICIOUS (segnali ambigui)\n"
    " 0.65-1.00 → ATTACK (automazione/proxy/headless)\n\n"
    "Vincolo: se pre_risk_score>=0.65 con segnali confermati, "
    "non scendere sotto 0.65."
)


def _is_trainable(entry: dict) -> bool:
    """Scarta entry non adatte al training."""
    if entry.get("from_cache"):
        return False
    verdict = entry.get("verdict")
    if verdict not in {"LEGITIMATE", "SUSPICIOUS", "ATTACK"}:
        return False
    inds = entry.get("indicators") or []
    if any(ind in TECH_ERROR_INDICATORS for ind in inds):
        return False
    # verdict↔score coherence (stesso criterio di scorer._validate_result)
    score = float(entry.get("score", 0.5))
    if score >= 0.65 and verdict == "LEGITIMATE":
        return False
    if score <= 0.30 and verdict == "ATTACK":
        return False
    return True


def _build_user_prompt(entry: dict) -> str:
    """Ricostruisce un prompt compatto dai campi presenti nel log."""
    inds = entry.get("indicators") or []
    signals = ", ".join(inds) if inds else "nessuno"
    return (
        "=== PUNTEGGIO DETERMINISTICO PRE-CALCOLATO ===\n"
        f"pre_risk_score: {float(entry.get('pre_score', 0.0)):.3f}\n"
        f"Segnali confermati: {signals}\n\n"
        "=== DETTAGLI BROWSER ===\n"
        f"User-Agent: {(entry.get('ua') or '?')[:100]}\n"
        f"Browser: {entry.get('browser','?')} | "
        f"OS: {entry.get('os','?')} | "
        f"Mobile: {entry.get('is_mobile', False)}\n"
        f"Segnali headless: {entry.get('headless_n', 0)}\n\n"
        "=== CONTESTO ===\n"
        f"Pagina: {entry.get('context','default')}\n\n"
        "Rispondi SOLO con il JSON."
    )


def _build_assistant_json(entry: dict) -> str:
    """Il target è il JSON canonico identico a quello che l'LLM deve produrre."""
    return json.dumps(
        {
            "risk_score":  round(float(entry.get("score", 0.5)), 3),
            "verdict":     entry["verdict"],
            "confidence":  entry.get("confidence", "low"),
            "indicators":  entry.get("indicators") or [],
            "explanation": (entry.get("explanation") or "")[:120],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _sample(entry: dict) -> dict:
    return {
        "messages": [
            {"role": "system",    "content": SYSTEM_PROMPT},
            {"role": "user",      "content": _build_user_prompt(entry)},
            {"role": "assistant", "content": _build_assistant_json(entry)},
        ]
    }


def _dedupe_key(entry: dict) -> tuple:
    return (
        (entry.get("ua") or "")[:60],
        entry.get("verdict"),
        round(float(entry.get("pre_score", 0.0)), 2),
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="percorso di aurora_events.jsonl")
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--val-split", type=float, default=0.1)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--max-per-class", type=int, default=0,
                    help="se >0, bilancia ciascuna classe a N esempi")
    args = ap.parse_args()

    src = Path(args.input)
    if not src.exists():
        raise SystemExit(f"Input non trovato: {src}")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(args.seed)

    total = 0
    kept_raw: list[dict] = []
    skipped = Counter()
    with src.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                skipped["bad_json"] += 1
                continue
            if not _is_trainable(entry):
                skipped["filtered"] += 1
                continue
            kept_raw.append(entry)

    # Dedup
    seen: set[tuple] = set()
    kept: list[dict] = []
    for entry in kept_raw:
        key = _dedupe_key(entry)
        if key in seen:
            skipped["duplicate"] += 1
            continue
        seen.add(key)
        kept.append(entry)

    # Bilanciamento opzionale
    if args.max_per_class > 0:
        by_class: dict[str, list[dict]] = {"LEGITIMATE": [], "SUSPICIOUS": [], "ATTACK": []}
        for e in kept:
            by_class[e["verdict"]].append(e)
        balanced: list[dict] = []
        for cls, items in by_class.items():
            rng.shuffle(items)
            balanced.extend(items[: args.max_per_class])
        kept = balanced

    rng.shuffle(kept)
    split_at = max(1, int(len(kept) * (1.0 - args.val_split)))
    train, val = kept[:split_at], kept[split_at:]

    def _dump(path: Path, items: list[dict]) -> None:
        with path.open("w", encoding="utf-8") as f:
            for entry in items:
                f.write(json.dumps(_sample(entry), ensure_ascii=False) + "\n")

    _dump(out_dir / "train.jsonl", train)
    _dump(out_dir / "val.jsonl",   val)

    stats = {
        "input":        str(src),
        "lines_read":   total,
        "skipped":      dict(skipped),
        "kept":         len(kept),
        "train":        len(train),
        "val":          len(val),
        "verdict_dist": dict(Counter(e["verdict"] for e in kept)),
        "system_prompt_chars": len(SYSTEM_PROMPT),
    }
    (out_dir / "stats.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
