"""
Diagnostica v5 — testa Anthropic e/o Ollama in base al .env.
Esegui con: python diagnose.py
"""

import os, json, asyncio
from dotenv import load_dotenv
load_dotenv()

G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"; B = "\033[1m"; X = "\033[0m"

ANTHROPIC_MODELS = [
    "claude-haiku-4-5-20251001",
    "claude-3-5-haiku-20241022",
    "claude-sonnet-4-6",
    "claude-3-5-sonnet-20241022",
    "claude-3-haiku-20240307",
]

TEST_PROMPT = """\
=== PUNTEGGIO DETERMINISTICO PRE-CALCOLATO ===
pre_risk_score: 0.050
Segnali confermati: nessuno

=== DETTAGLI BROWSER ===
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0
Browser: Chrome | OS: Windows | Mobile: False
Plugin (4): PDF Viewer, Chrome PDF Viewer, Widevine, Native Client
WebGL: ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11)
SwiftShader: False
Canvas: hash=abc123def456, vuoto=False
webdriver: False
Lingue (4): it-IT, it, en-US
Schermo: 1920x1080 | colorDepth: 24
Timezone: Europe/Rome | Anomalia: False
Platform: Win32

=== RETE E TIMING ===
IP info: VPN=False, Tor=False, paese=IT
Latenza media: 14ms | max: 18ms | stdev: 2ms
Richieste totali: 1

=== COMPORTAMENTO ===
Pagine visitate: /dashboard
Segnali headless: nessuno

Rispondi SOLO con il JSON."""

SYSTEM = """\
Sei un sistema di sicurezza per rilevamento attacchi BitM.
Rispondi SOLO con JSON valido, zero testo fuori dal JSON.
Esempio: {"risk_score":0.05,"verdict":"LEGITIMATE","confidence":"high","indicators":[],"explanation":"browser reale"}"""


async def test_anthropic():
    print(f"\n{B}── TEST ANTHROPIC ──────────────────────────────────{X}")
    key = os.getenv("ANTHROPIC_API_KEY", "")
    if not key or not key.startswith("sk-"):
        print(f"  {Y}Skippato: ANTHROPIC_API_KEY non configurata{X}")
        return

    try:
        import anthropic
    except ImportError:
        print(f"  {R}anthropic non installato: pip install anthropic{X}")
        return

    print(f"  Key: {key[:14]}...{key[-4:]}")
    client = anthropic.AsyncAnthropic(api_key=key)
    working = None

    for model in ANTHROPIC_MODELS:
        try:
            await client.messages.create(
                model=model, max_tokens=5,
                messages=[{"role": "user", "content": "ping"}]
            )
            print(f"  {G}✓{X} {model}")
            if not working: working = model
        except anthropic.APIStatusError as e:
            print(f"  {R}✗{X} {model}  HTTP {e.status_code}")
        except Exception as e:
            print(f"  {R}✗{X} {model}  {e}")

    if not working:
        print(f"\n  {R}Nessun modello disponibile.{X}")
        print(f"  Verifica credito: https://console.anthropic.com/settings/billing")
        return

    print(f"\n  Test risposta con {working}...")
    try:
        msg = await client.messages.create(
            model=working, max_tokens=200,
            system=SYSTEM,
            messages=[{"role": "user", "content": TEST_PROMPT}]
        )
        raw    = msg.content[0].text.strip()
        parsed = json.loads(raw)
        print(f"  {G}✓ JSON valido{X}  score={parsed.get('risk_score')} "
              f"verdict={parsed.get('verdict')}")
        print(f"  Usa: LLM_BACKEND=anthropic")
    except json.JSONDecodeError:
        print(f"  {Y}⚠ Risposta non JSON:{X} {raw[:150]!r}")
    except Exception as e:
        print(f"  {R}✗ {e}{X}")


async def test_ollama():
    print(f"\n{B}── TEST OLLAMA ─────────────────────────────────────{X}")
    host  = os.getenv("OLLAMA_HOST",  "http://localhost:11434").rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "llama3.1")
    timeout = int(os.getenv("OLLAMA_TIMEOUT", "60"))

    print(f"  Host:    {host}")
    print(f"  Modello: {model}")
    print(f"  Timeout: {timeout}s")

    try:
        import httpx
    except ImportError:
        print(f"  {R}httpx non installato: pip install httpx{X}")
        return

    # 1. Check connessione
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{host}/api/tags")
        if r.status_code != 200:
            print(f"  {R}✗ Ollama risponde HTTP {r.status_code}{X}")
            print(f"  Avvia Ollama con: ollama serve")
            return
        data     = r.json()
        models   = [m["name"] for m in data.get("models", [])]
        print(f"  {G}✓ Ollama raggiungibile{X}")
        print(f"  Modelli installati: {', '.join(models) if models else '(nessuno)'}")
    except httpx.ConnectError:
        print(f"  {R}✗ Ollama non raggiungibile su {host}{X}")
        print(f"  Avvia con: ollama serve")
        return
    except Exception as e:
        print(f"  {R}✗ {e}{X}")
        return

    # 2. Check modello
    model_base = model.split(":")[0]
    available  = [m.split(":")[0] for m in models]
    if model_base not in available:
        print(f"\n  {R}✗ Modello '{model}' non installato.{X}")
        print(f"  Installalo con: ollama pull {model}")
        print(f"  Modelli disponibili: {', '.join(models) if models else 'nessuno'}")
        return
    print(f"  {G}✓ Modello '{model}' disponibile{X}")

    # 3. Test risposta JSON
    print(f"\n  Test risposta JSON (può richiedere fino a {timeout}s)...")
    payload = {
        "model":  model,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1, "num_predict": 200},
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user",   "content": TEST_PROMPT},
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            resp = await c.post(f"{host}/api/chat", json=payload)

        if resp.status_code != 200:
            print(f"  {R}✗ HTTP {resp.status_code}: {resp.text[:150]}{X}")
            return

        raw    = resp.json().get("message", {}).get("content", "")
        parsed = json.loads(raw)
        print(f"  {G}✓ JSON valido{X}  score={parsed.get('risk_score')} "
              f"verdict={parsed.get('verdict')}")
        print(f"  explanation: {parsed.get('explanation','')[:80]}")
        print(f"\n  {G}✓ Ollama funziona correttamente!{X}")
        print(f"  Usa: LLM_BACKEND=ollama  OLLAMA_MODEL={model}")

    except json.JSONDecodeError:
        print(f"  {Y}⚠ Risposta non è JSON puro:{X}")
        print(f"  raw: {raw[:250]!r}")
        print(f"  Prova: ollama pull {model}  (aggiorna il modello)")
    except httpx.TimeoutException:
        print(f"  {Y}⚠ Timeout dopo {timeout}s. Il modello è lento.{X}")
        print(f"  Prova ad aumentare: OLLAMA_TIMEOUT=120")
    except Exception as e:
        print(f"  {R}✗ {type(e).__name__}: {e}{X}")


async def main():
    backend = os.getenv("LLM_BACKEND", "anthropic").lower()
    print(f"\n{B}{'='*52}{X}")
    print(f"{B}  BitM Plugin v5 — Diagnostica{X}")
    print(f"{B}{'='*52}{X}")
    print(f"  LLM_BACKEND configurato: {B}{backend}{X}")

    if backend == "ollama":
        await test_ollama()
    elif backend == "anthropic":
        await test_anthropic()
    else:
        print(f"  {R}Backend '{backend}' non riconosciuto.{X}")
        print(f"  Valori validi: 'anthropic', 'ollama'")
        await test_ollama()
        await test_anthropic()

    print(f"\n{B}{'='*52}{X}\n")

asyncio.run(main())
