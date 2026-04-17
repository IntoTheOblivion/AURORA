# BitM Detection Plugin

Sistema di rilevamento in tempo reale di attacchi **Browser-in-the-Middle (BitM)**, automazione malevola e bot non autorizzati. Combina fingerprinting comportamentale del browser, regole deterministiche a latenza zero e un motore LLM (Anthropic Claude o Ollama) per classificare ogni richiesta come `allow`, `challenge` o `block`.

> **Versione corrente: 7.3.0** (runtime)
> Distribuzione one-shot via Docker/GHCR: `docker compose up` per un'istanza zero-config, oppure `<script src="…/collector.js">` per integrazione one-liner su qualsiasi sito. Default `LLM_BACKEND=stub` → nessuna API key richiesta per il primo avvio.
>
> Storico rilasci stabili:
> - **v7.3** — Dockerfile + docker-compose + workflow GHCR + collector.js standalone + default `LLM_BACKEND=stub` + S14
> - **v7.2** — Rilevamento stack BitM / BitM+ (noVNC/Websockify/Guacamole + ngrok/MalSrv/evilGet), T21–T29, S13
> - **v7.1** — Suite E2E Playwright + workflow GitHub Actions + backend `stub` deterministico
> - **v7.0** — Infrastruttura fine-tuning LoRA per LLaMA 3.1 + system prompt compatto (~40% più corto)
> - **v6.2** — Webhook push notifications (Slack / Teams / SIEM) per eventi BLOCK, retry esponenziale

---

## Indice

- [⚡ Quickstart](#-quickstart-v73)
- [Caratteristiche](#-caratteristiche)
- [Come funziona](#-come-funziona)
- [Struttura del progetto](#-struttura-del-progetto)
- [Requisiti](#-requisiti)
- [Installazione & Setup](#-installazione--setup)
- [Avvio](#-avvio)
- [Payload e risposta API](#-payload-e-risposta-api)
- [Endpoints](#-endpoints)
- [Segnali rilevati](#-segnali-rilevati)
- [Soglie e politica decisionale](#-soglie-e-politica-decisionale)
- [GeoIP](#-geoip)
- [Sessioni e Redis](#-sessioni-e-redis)
- [Dashboard real-time](#-dashboard-real-time)
- [Webhook push notifications](#-webhook-push-notifications-v62)
- [Log eventi](#-log-eventi)
- [Fine-tuning LoRA (v7.0)](#-fine-tuning-lora-v70)
- [E2E Playwright + CI (v7.1)](#-e2e-playwright--ci-v71)
- [Test](#-test)
- [Rilevamento BitM / BitM+ (v7.2)](#-rilevamento-bitm--bitm-v72)
- [Distribuzione Docker + collector.js (v7.3)](#-distribuzione-docker--collectorjs-v73)
- [Changelog](#-changelog)

---

## ⚡ Quickstart (v7.3)

Tre percorsi per provare il progetto. Nessuno richiede una API key al primo avvio grazie al backend `stub` deterministico.

### A. Provalo subito con Docker (~30 secondi)

```bash
git clone <repo-url> && cd Bitm_LLM
docker compose up --build
```

Apri `http://localhost:8000/` per la pagina di test e `http://localhost:8000/dashboard` per la dashboard real-time.
Nessuna configurazione necessaria: il servizio parte con `LLM_BACKEND=stub` (scorer deterministico basato su `pre_risk_score` + segnali BitM/BitM+).

Per usare un LLM reale:

```bash
# Anthropic cloud (richiede API key)
LLM_BACKEND=anthropic ANTHROPIC_API_KEY=sk-ant-... docker compose up

# Ollama locale (nessun costo ricorrente)
docker compose --profile ollama up
docker exec -it bitm-ollama ollama pull llama3.1
LLM_BACKEND=ollama docker compose --profile ollama up
```

### B. Integrazione one-liner su un sito esistente

Una volta avviato il backend (locale o remoto), aggiungi questo tag al sito da proteggere:

```html
<script src="https://<host>:8000/collector.js"
        data-endpoint="https://<host>:8000/api/bitm/collect"
        data-auto="true"></script>
```

Il collector raccoglie il fingerprint (UA, plugins, WebGL/canvas, timezone, marker BitM/BitM+) e invia a `/api/bitm/collect` al caricamento della pagina. L'oggetto `window.BitM` espone `BitM.classify()`, `BitM.fingerprint()` e `BitM.onResult(fn)` per integrazioni programmatiche.

### C. Ricercatori e studenti

```bash
docker run --rm -p 8000:8000 ghcr.io/<owner>/bitm-llm:latest
```

Poi apri `http://localhost:8000/` e clicca "Simula attacco BitM" per vedere la pipeline in azione. I paper di riferimento sono in `doc/` (Tommasi 2021, Tzschoppe 2023, Catalano 2025).

---

---

## 🚀 Caratteristiche

| Feature | Descrizione |
|---------|-------------|
| **Fast-track deterministico** | Blocca bot noti (HeadlessChrome, Puppeteer, Selenium, Tor) in < 1 ms senza toccare l'LLM |
| **Scoring LLM** | Anthropic Claude o Ollama analizzano il fingerprint completo e restituiscono `risk_score`, `verdict`, `indicators` |
| **Due stadi di score** | `pre_risk_score` deterministico funge da floor: l'LLM non può "scagionare" segnali certi |
| **Soglie contestuali** | Thresholds diversi per `login`, `payment`, `admin`, `static`, `default` |
| **GeoIP automatico** | Country / ASN / ISP via MaxMind GeoLite2; rilevamento VPN su ASN cloud noti |
| **Sessioni persistenti** | Redis con fallback in-memory; multi-step tracking per escalation |
| **IP-block escalation** | Dopo 3 BLOCK consecutivi l'IP entra nel set bloccati permanenti |
| **Rate-limiting** | Sliding window Redis (zset); risponde HTTP 429 oltre soglia |
| **Cache LLM** | Risultati TTL-cached per `(canvas_hash, user_agent[:60])` |
| **Dashboard WebSocket** | Feed live eventi + ring buffer 500 slot + chart + export CSV |
| **Webhook push** | Notifica HTTP POST asincrona verso Slack / Teams / SIEM ad ogni BLOCK |
| **Fine-tuning LoRA** | Pipeline di conversione `bitm_events.jsonl → dataset ChatML` + training LoRA di LLaMA 3.1 |
| **Rilevamento BitM/BitM+** | Firme specifiche per noVNC/WebSockify/TigerVNC (RFB), Apache Guacamole/FreeRDP (RDP), ngrok/Puppeteer/MalSrv/evilGet (BitM+) |

---

## 🔍 Come funziona

Ogni richiesta a `/api/bitm/collect` attraversa questa pipeline nell'ordine:

```
HTTP POST /api/bitm/collect
  │
  ├─ GeoIP middleware          → arricchisce la Request con country/ASN/ISP/is_tor/is_vpn
  ├─ rate_check                → sliding window; 429 se superato
  ├─ is_blocked                → controlla il set IP bloccati permanenti
  ├─ session load/merge        → carica la sessione da Redis (o memory), appende page + timing
  ├─ extract_features          → calcola pre_risk_score + confirmed_signals + headless_signals
  ├─ _fast_rules               → regole deterministiche (0ms); se scattano → skip LLM
  ├─ score_session (LLM)       → chiamata Anthropic / Ollama con cache TTL
  ├─ decide (policy)           → applica floor pre_score, boost contestuale, soglie
  ├─ session persist + log     → aggiorna Redis, scrive JSONL
  ├─ broadcaster.publish       → fan-out WebSocket ai client /ws/events
  └─ notify_block              → webhook HTTP fire-and-forget (solo se action=BLOCK)
        │
        └─ risposta JSON: { action, score, verdict, confidence, indicators, reason, context, latency_ms }
```

### Scoring a due stadi

1. **`extractor.py`** calcola `pre_risk_score` con pesi deterministici (es. `webdriver_true → +0.45`, `tor_exit_node → +0.30`) e una lista `confirmed_signals` inviata all'LLM come base affidabile.
2. **`scorer.py`** interroga l'LLM che restituisce il suo `risk_score`.
3. **`policy.py`** prende il valore massimo tra i due: il pre-score agisce da **floor** — l'LLM non può ridurre la certezza di segnali già confermati.

### Boost contestuale

In contesti `login`, `payment`, `admin`, segnali deboli amplificano lo score con pesi individuali (cappati a `MAX_BOOST = 0.25`):

| Segnale debole | Boost |
|----------------|-------|
| `vpn_detected` | +0.16 |
| `timezone_anomaly` | +0.12 |
| `swiftshader_webgl` | +0.10 |
| `zero_plugins` | +0.09 |
| `no_languages` / `no_webgl_renderer` | +0.08 |
| `empty_canvas` / `suspicious_resolution` | +0.06–0.07 |
| `no_timezone` | +0.06 |

---

## 📁 Struttura del progetto

```
bitm-plugin/
├── app/
│   ├── main.py          # FastAPI entry point, middleware GeoIP, endpoint /api/bitm/collect
│   ├── config.py        # Variabili d'ambiente: LLM, Redis, GeoIP, Webhook
│   ├── extractor.py     # Feature extraction: pre_risk_score, confirmed_signals, headless_signals
│   ├── scorer.py        # LLM scorer: Anthropic / Ollama, cache TTL, retry, model probe
│   ├── policy.py        # Soglie contestuali, boost, fast-track, decide()
│   ├── geoip.py         # Resolver MaxMind GeoLite2, VPN ASN detection        [v6]
│   ├── redis_client.py  # SessionStore: Redis + fallback in-memory             [v6]
│   ├── broadcaster.py   # Pub/sub in-process, ring buffer WebSocket            [v6.1]
│   ├── notifier.py      # Webhook push asincrono per eventi BLOCK              [v6.2]
│   ├── logger.py        # log_event() → stdout colorato + bitm_events.jsonl
│   └── static/
│       ├── dashboard.html   # Dashboard real-time
│       └── test_page.html   # Pagina di test manuale
├── tests/
│   ├── run_tests.py     # Test suite (32 casi: legit/attack/suspicious/edge/system)
│   └── e2e_playwright/                                                          [v7.1]
│       ├── run_e2e.py          # Orchestratore scenari evasivi + report
│       └── requirements-e2e.txt
├── training/                                                                    [v7.0]
│   ├── build_dataset.py # Converte bitm_events.jsonl → dataset ChatML SFT
│   └── train_lora.py    # Fine-tuning LoRA di LLaMA 3.1 (transformers + peft + trl)
├── diagnose.py          # Diagnostica end-to-end del backend LLM
├── run.py               # Entry point uvicorn
├── requirements.txt
├── .env.example
└── bitm_events.jsonl    # Log eventi JSONL (append-only)
```

---

## 📋 Requisiti

| Componente | Versione | Note |
|------------|----------|------|
| Python | >= 3.10 | Richiesto `asyncio` con `TaskGroup` |
| Ollama | qualsiasi | Solo se `LLM_BACKEND=ollama` |
| Redis | >= 5 | Opzionale — fallback in-memory automatico |
| MaxMind GeoLite2 | City + ASN | Opzionale — senza i `.mmdb` GeoIP ritorna vuoto |

### Dipendenze Python

```
fastapi>=0.109.0
uvicorn[standard]>=0.27.0
anthropic>=0.20.0
httpx>=0.26.0          # scorer + notifier
python-dotenv>=1.0.0
redis>=5.0.0
websockets>=12.0
geoip2>=4.7.0
```

---

## 🛠 Installazione & Setup

### 1. Ambiente virtuale

```bash
cd bitm-plugin
python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Redis (consigliato)

```bash
# Docker — opzione più rapida
docker run -d --name bitm-redis -p 6379:6379 redis:7-alpine
```

Senza Redis il sistema parte comunque con fallback in-memory (singolo processo, nessuna persistenza tra riavvii).

### 3. File `.env`

```bash
cp .env.example .env
```

Apri `.env` e configura le sezioni rilevanti:

#### Backend LLM

```env
# Scegli uno dei due
LLM_BACKEND=ollama          # backend locale gratuito
LLM_BACKEND=anthropic       # API cloud Anthropic
```

**Ollama** — assicurati che il server sia avviato (`ollama serve`) e il modello scaricato (`ollama pull llama3.1`):

```env
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.1
OLLAMA_TIMEOUT=60
```

**Anthropic** — inserisci la tua API key:

```env
ANTHROPIC_API_KEY=sk-ant-api03-...
```

Il sistema prova automaticamente i modelli in ordine di preferenza:
`claude-haiku-4-5-20251001` → `claude-3-5-haiku-20241022` → `claude-sonnet-4-6` → `claude-3-5-sonnet-20241022` → `claude-3-haiku-20240307`

#### Redis

```env
REDIS_URL=redis://localhost:6379/0
REDIS_SESSION_TTL=3600      # TTL sessione in secondi (default 1h)
REDIS_KEY_PREFIX=bitm:      # prefisso chiavi Redis
```

#### GeoIP

Scarica i database gratuiti da [maxmind.com](https://www.maxmind.com/en/geolite2/signup) e configura i percorsi:

```env
MAXMIND_CITY_DB=/path/to/GeoLite2-City.mmdb
MAXMIND_ASN_DB=/path/to/GeoLite2-ASN.mmdb
```

Se omessi, il sistema funziona normalmente senza arricchimento GeoIP.

#### Cache LLM

```env
CACHE_TTL=300    # secondi (default 5 minuti)
```

#### Webhook (v6.2)

```env
# Slack (Blocks API)
WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
WEBHOOK_TYPE=slack

# Microsoft Teams (Adaptive Cards v1.4)
WEBHOOK_URL=https://outlook.office.com/webhook/...
WEBHOOK_TYPE=teams

# SIEM / endpoint generico JSON
WEBHOOK_URL=https://siem.azienda.local/events
WEBHOOK_TYPE=siem

# Parametri comuni (opzionali)
WEBHOOK_TIMEOUT=5      # timeout HTTP per richiesta (default 5s)
WEBHOOK_RETRIES=3      # tentativi in caso di errore rete/5xx (default 3)
```

Per header personalizzati (es. token di autenticazione) usa un file JSON:

```env
WEBHOOK_CONFIG_FILE=/path/to/webhook.json
```

```json
{
  "url":     "https://siem.azienda.local/events",
  "type":    "siem",
  "timeout": 5,
  "retries": 3,
  "headers": { "Authorization": "Bearer my-token" }
}
```

---

## 🚀 Avvio

```bash
# Dalla cartella bitm-plugin/
python run.py
```

Output atteso all'avvio:

```
[bitm] Backend LLM: ollama @ http://localhost:11434  model=llama3.1
[redis] connesso a redis://localhost:6379/0
[bitm] Session store: redis
[bitm] GeoIP: MaxMind attivo (city+asn)
```

L'API è disponibile su `http://0.0.0.0:8000` (porta configurabile con la variabile `PORT` nel `.env`).

Per la diagnostica del backend LLM:

```bash
python diagnose.py
```

---

## 📨 Payload e risposta API

### Request — `POST /api/bitm/collect`

```json
{
  "sessionId":  "abc-123",
  "page":       "/login",
  "userAgent":  "Mozilla/5.0 ...",
  "plugins":    ["PDF Viewer", "Widevine"],
  "webgl":      "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11)",
  "canvas":     "data:image/png;base64,...",
  "webdriver":  false,
  "languages":  ["it-IT", "it", "en-US"],
  "screenRes":  "1920x1080",
  "colorDepth": 24,
  "timezone":   "Europe/Rome",
  "platform":   "Win32",
  "timing":     14
}
```

Il campo `ip_meta` può essere aggiunto per ambienti di test/sviluppo senza feed GeoIP reale (non sovrascrive valori già risolti dal resolver, eccetto `is_tor`/`is_vpn` che sono always-true):

```json
{
  "ip_meta": { "is_tor": true, "is_vpn": false, "country": "US" }
}
```

**Campi opzionali per il rilevamento BitM/BitM+ (v7.2)** — se il collector lato sito li fornisce, entrano nelle firme; se mancano vengono semplicemente ignorati (vedi §[Rilevamento BitM/BitM+](#-rilevamento-bitm--bitm-v72)):

```json
{
  "pageUrl":   "https://example.com/login",
  "referrer":  "https://example.com/",
  "title":     "Login",
  "wsEndpoints": ["wss://example.com/notify"],
  "iframeCount": 0,
  "credentialsGetNative": true
}
```

### Response

```json
{
  "action":     "block",
  "score":      0.973,
  "verdict":    "ATTACK",
  "confidence": "high",
  "indicators": ["headless_ua", "webdriver_flag", "no_plugins_no_webgl"],
  "reason":     "Segnale critico: headless_ua",
  "context":    "login",
  "latency_ms": 12.4
}
```

| Campo | Valori | Significato |
|-------|--------|-------------|
| `action` | `allow` / `challenge` / `block` | Decisione finale |
| `score` | 0.0 – 1.0 | Risk score finale (post boost) |
| `verdict` | `LEGITIMATE` / `SUSPICIOUS` / `ATTACK` | Etichetta LLM |
| `confidence` | `low` / `medium` / `high` | Confidenza LLM |
| `indicators` | lista stringhe | Segnali rilevati (LLM + deterministici) |
| `context` | `login` / `payment` / `admin` / `static` / `default` | Contesto URL |
| `latency_ms` | float | Latenza interna del plugin (ms) |

---

## 🌐 Endpoints

| Metodo | Path | Descrizione |
|--------|------|-------------|
| `POST` | `/api/bitm/collect` | Classifica una sessione browser |
| `GET` | `/health` | Stato di tutti i sottosistemi |
| `GET` | `/api/bitm/sessions` | Vista admin: sessioni + IP bloccati |
| `DELETE` | `/api/bitm/sessions` | Azzera sessioni, blocked, rate-limit |
| `GET` | `/dashboard` | Dashboard HTML real-time |
| `WS` | `/ws/events` | WebSocket feed eventi raw |
| `GET` | `/` | Pagina di test manuale |

### `GET /health` — esempio risposta

```json
{
  "status":      "ok",
  "version":     "7.3.0",
  "backend":     "ollama",
  "model":       "ollama/llama3.1",
  "sessions":    4,
  "blocked_ips": 1,
  "store":       "redis",
  "geoip":       "MaxMind attivo (city+asn)",
  "ws_clients":  2,
  "webhook": {
    "enabled": true,
    "type":    "slack",
    "url":     "https://hooks.slack.com/ser...",
    "timeout": 5.0,
    "retries": 3
  }
}
```

---

## 🔎 Segnali rilevati

### Segnali critici (BLOCK immediato, bypass LLM)

| Segnale | Origine | Causa |
|---------|---------|-------|
| `headless_ua` / `headlesschrome_ua` | UA string | Marker `HeadlessChrome` nell'User-Agent |
| `phantomjs_ua` | UA string | Marker `PhantomJS` |
| `webdriver_flag` / `webdriver_true` | `navigator.webdriver` | Flag `true` iniettato da Selenium/Playwright |
| `no_plugins_no_webgl` | plugin + WebGL | Zero plugin + WebGL assente su desktop |
| `extreme_latency` | timing | Timing medio > 600ms (scraping) |
| `tor_exit_node` | GeoIP / ip_meta | IP appartiene alla rete Tor |

### Segnali deboli (amplificano lo score in contesti sensibili)

| Segnale | Trigger |
|---------|---------|
| `vpn_detected` | ASN appartiene a cloud/VPN noti |
| `swiftshader_webgl` | WebGL renderer = SwiftShader (Chrome headless) |
| `zero_plugins` | Nessun plugin su desktop |
| `no_webgl_renderer` | WebGL assente o `unavailable` |
| `empty_canvas` | Canvas fingerprint vuoto |
| `no_languages` | Lista `navigator.languages` vuota |
| `no_timezone` | `timezone` assente nel payload |
| `suspicious_resolution` | Risoluzione `800x600`, `1024x768` o `0x0` |
| `timezone_anomaly` | Timezone UTC con lingua non inglese |
| `high_latency_Xms` | Timing medio 300–500ms |
| `elevated_latency_Xms` | Timing medio 150–300ms |

---

## ⚖️ Soglie e politica decisionale

### Thresholds per contesto

| Contesto | CHALLENGE | BLOCK | URL prefissi |
|----------|-----------|-------|--------------|
| `login` | ≥ 0.28 | ≥ 0.62 | `/login`, `/signin`, `/auth`, `/accedi` |
| `payment` | ≥ 0.20 | ≥ 0.55 | `/payment`, `/checkout`, `/pay`, `/pagamento` |
| `admin` | ≥ 0.22 | ≥ 0.60 | `/admin`, `/settings`, `/account`, `/profile` |
| `default` | ≥ 0.40 | ≥ 0.75 | tutto il resto |
| `static` | ≥ 0.70 | ≥ 0.92 | `.js`, `.css`, `.png`, `.ico`, ecc. |

### Priorità decisionale

1. **Segnali critici** → BLOCK immediato (indipendente dallo score)
2. **Floor pre-score** → lo score LLM non scende sotto il `pre_risk_score` deterministico
3. **Boost contestuale** → segnali deboli amplificano lo score in `login`/`payment`/`admin`, cap `MAX_BOOST = 0.25`
4. **Soglie** → confronto `score_amplified` con la coppia `(challenge, block)` del contesto

---

## 🌍 GeoIP

Il middleware GeoIP arricchisce ogni request automaticamente prima di qualunque logica applicativa:

- **Country** e **City** via `GeoLite2-City.mmdb`
- **ASN** e **ISP** via `GeoLite2-ASN.mmdb`
- **VPN detection** — confronto ASN con una lista di ~50 cloud/VPN provider noti (AWS, Azure, GCP, Cloudflare, NordVPN, ExpressVPN, ecc.)
- **Tor detection** — non ricavabile da MaxMind; il campo `is_tor` è impostabile tramite il campo `ip_meta` nel body (utile per feed esterni o test)

IP privati e loopback (`127.x`, `10.x`, `192.168.x`, `::1`) non producono errori — il resolver restituisce metadati vuoti.

---

## 🗄️ Sessioni e Redis

`SessionStore` è una classe che gestisce in modo trasparente due backend:

| Operazione | Redis | In-memory fallback |
|------------|-------|--------------------|
| Sessioni | Hash con TTL | `dict` in RAM |
| IP bloccati | Set Redis | `set` in RAM |
| Rate-limit | Sorted set (zset) sliding window | `deque` per IP |

Se Redis non è raggiungibile all'avvio o durante il run, il sistema degrada automaticamente in-memory senza sollevare eccezioni. Il campo `store` in `/health` indica il backend attivo (`"redis"` o `"memory"`).

**Escalation automatica:** se la stessa sessione totalizza ≥ 3 BLOCK consecutivi, l'IP sorgente viene aggiunto al set dei bloccati permanenti e ogni richiesta successiva da quell'IP riceve BLOCK istantaneo.

---

## 📊 Dashboard real-time

Disponibile a `http://localhost:8000/dashboard`.

- Feed WebSocket da `/ws/events` aggiornato ad ogni richiesta
- Ring buffer degli ultimi 500 eventi (i client appena connessi ricevono il backlog)
- Grafico a linee score nel tempo (Chart.js)
- Tabella eventi con filtri per `action`
- Export CSV degli eventi in memoria

> **Nota:** il broadcaster è in-process (single-worker). Con `--workers > 1` ogni worker avrebbe il proprio broadcaster; in quel caso promuovere il trasporto a Redis pub/sub.

---

## 📡 Webhook push notifications (v6.2)

`app/notifier.py` intercetta ogni azione `BLOCK` e invia una notifica HTTP POST non bloccante.

### Flusso

```
BLOCK action
  └─ notify_block(entry)          sincrono, istantaneo (< 1µs)
       └─ asyncio.create_task()   fire-and-forget
            └─ httpx.AsyncClient.post  HTTP POST con timeout
                 └─ retry backoff      1s → 2s → 4s → … (max 30s)
```

### Formati payload

**`siem`** — JSON flat, tutti i campi diagnostici:

```json
{
  "event_type": "BLOCK",
  "product": "BitM Detection Plugin",
  "version": "6.2",
  "timestamp": "2026-04-16T10:00:00Z",
  "severity": "HIGH",
  "source_ip": "1.2.3.4",
  "session_id": "sess-001",
  "risk_score": 0.97,
  "verdict": "ATTACK",
  "indicators": ["headless_ua", "webdriver_flag"],
  "explanation": "Headless browser rilevato",
  "context": "login"
}
```

**`slack`** — Blocks API con attachment colorato (rosso), campi IP / score / verdict / segnali / spiegazione.

**`teams`** — Adaptive Card v1.4 con `FactSet` e `TextBlock`, compatibile con connettori O365 e Power Automate.

### Comportamento errori

| Situazione | Comportamento |
|-----------|---------------|
| Rete / timeout / 5xx | Retry fino a `WEBHOOK_RETRIES` con backoff esponenziale |
| Risposta 4xx | Nessun retry, log warning |
| Eccezione non di rete | Nessun retry, log error |
| Webhook non configurato | No-op, nessun overhead |

Il fallimento del webhook **non influisce mai** sulla risposta all'utente né genera eccezioni nell'applicazione.

---

## 📝 Log eventi

Ogni richiesta produce una riga JSON in `bitm_events.jsonl`:

```json
{
  "ts": "2026-04-16T10:00:00.123456+00:00",
  "ip": "1.2.3.4",
  "session": "sess-001",
  "action": "block",
  "context": "login",
  "score": 0.9730,
  "pre_score": 0.8500,
  "verdict": "ATTACK",
  "confidence": "high",
  "indicators": ["headless_ua", "webdriver_flag"],
  "explanation": "Headless browser rilevato con webdriver attivo",
  "from_cache": false,
  "latency_ms": 12.4,
  "browser": "HeadlessChrome",
  "os": "Linux",
  "is_mobile": false,
  "ua": "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120..."
}
```

---

## 🎓 Fine-tuning LoRA (v7.0)

La cartella `bitm-plugin/training/` contiene l'infrastruttura per specializzare LLaMA 3.1 sulle decisioni dello scorer, riducendo progressivamente la dipendenza da backend cloud.

### Prompt compatto

Il `SYSTEM_PROMPT` in `app/scorer.py` è stato riscritto in versione v7 — **609 caratteri contro i 1080 della v6 (~43% in meno)** — preservando le 4 direttive essenziali: output JSON puro, schema con enum, mappatura soglie→verdict, floor su `pre_risk_score`. Meno token in input = minor latenza per inferenza e (su Anthropic) minor costo per chiamata. La motivazione della riduzione è documentata in `app/scorer.py` sopra la costante.

### 1. Conversione log → dataset (`build_dataset.py`)

Converte `bitm_events.jsonl` in un dataset SFT in formato **ChatML** (`{"messages":[system,user,assistant]}`) compatibile con `trl.SFTTrainer` e HuggingFace Datasets.

Pulizia applicata:

- scarta entry `from_cache=true` (duplicati inferenziali)
- scarta entry con indicator tecnici (`api_error`, `ollama_*_error`, `llm_parse_error`, …)
- deduplica per `(ua[:60], verdict, pre_score)` → rimuove session replay ripetitivi
- enforcea la stessa coerenza `verdict↔score` di `scorer._validate_result`

Output: `train.jsonl`, `val.jsonl`, `stats.json`.

```bash
cd bitm-plugin
python training/build_dataset.py \
    --input bitm_events.jsonl \
    --output-dir training/dataset \
    --val-split 0.1 \
    --max-per-class 500      # opzionale, bilancia le 3 classi
```

### 2. Fine-tuning LoRA (`train_lora.py`)

Training LoRA efficiente con `transformers` + `peft` + `trl.SFTTrainer`, 4-bit NF4 via `bitsandbytes` (opzionale), gradient checkpointing, target modules dell'architettura LLaMA.

```bash
# Dipendenze (solo sulla macchina di training, non nel runtime)
pip install "transformers>=4.44" "peft>=0.12" "trl>=0.10" \
            "datasets>=2.20" "accelerate>=0.33" "bitsandbytes>=0.43"

# Training su GPU (8B in 4bit)
python training/train_lora.py \
    --dataset-dir training/dataset \
    --base-model meta-llama/Meta-Llama-3.1-8B-Instruct \
    --output-dir training/lora-bitm-v7 \
    --epochs 3 --batch-size 2 --grad-accum 8

# Smoke test CPU (modello minuscolo, nessuna quantizzazione)
python training/train_lora.py \
    --dataset-dir training/dataset \
    --base-model sshleifer/tiny-gpt2 \
    --output-dir training/smoke \
    --no-4bit --epochs 1 --batch-size 1 --grad-accum 1
```

| Parametro | Default | Note |
|-----------|---------|------|
| `--lora-r` | 16 | Rank adapter LoRA |
| `--lora-alpha` | 32 | Scaling LoRA |
| `--lora-dropout` | 0.05 | |
| `--max-seq-len` | 2048 | Più lungo = più memoria |
| `--no-4bit` | off | Disabilita `bitsandbytes` (CPU/debug) |

L'adapter salvato è caricabile a runtime con `peft.PeftModel.from_pretrained(base_model, "training/lora-bitm-v7")` per l'inferenza locale via Ollama/vLLM.

---

## 🎭 E2E Playwright + CI (v7.1)

La suite `bitm-plugin/tests/e2e_playwright/run_e2e.py` guida browser Chromium **headless** reali con Playwright e li fa attaccare l'API. Ogni scenario applica evasioni concrete (init-script JS, route blocking, rotazione UA, canvas/WebGL spoof) e POSTa il fingerprint reale a `/api/bitm/collect`.

### Tecniche di evasione (7, ≥ 5 richieste)

| ID | Tecnica | Meccanismo |
|----|---------|-----------|
| A01 | Plain headless (baseline) | UA HeadlessChrome di default |
| A02 | UA rotation mid-session | UA diverso a ogni iterazione (`UA_POOL`) |
| A03 | Fast input injection | `timing: 3ms` (sub-human) |
| A04 | No static resources | `context.route('**/*.{png,css,woff,…}', abort)` |
| A05 | Stealth patches | `navigator.webdriver=undefined` + plugins fake + `languages` fake |
| A06 | Canvas noise + WebGL spoof | `toDataURL` perturbato + `getParameter` → NVIDIA finto |
| A07 | Tor exit node | Iniezione `ip_meta.is_tor=true` |

### Metrica e criterio di accettazione

```
detection_rate = (challenge + block) / totale_probe
bypass_rate    = allow / totale_probe
```

Exit code ≠ 0 se `detection_rate < --min-detection` (default **0.90**).

### Esecuzione locale

```bash
cd bitm-plugin

# 1. Deps e browser
pip install -r tests/e2e_playwright/requirements-e2e.txt
python -m playwright install --with-deps chromium

# 2. Server (stub = no LLM reale necessario)
LLM_BACKEND=stub python run.py &

# 3. Suite E2E
python tests/e2e_playwright/run_e2e.py \
    --url http://localhost:8000 \
    --min-detection 0.90 \
    --report tests/e2e_playwright/e2e_report.json
```

Output:

```
BitM E2E Playwright v7.1 — Report finale
  Tecniche di evasione:   7
  Probe totali:           15
  Detected (chal+block):  15  (100.0%)
  Bypassed (allow):       0   (0.0%)
  Soglia minima richiesta: 90%
  [A01] PASS  detected=2/2  bypassed=0  Plain headless (baseline)
  [A02] PASS  detected=3/3  bypassed=0  UA rotation mid-session
  …
✓ Detection rate 100.0% >= soglia 90%
```

### GitHub Actions

Il workflow `.github/workflows/e2e-playwright.yml` parte su push/PR toccando `bitm-plugin/**` (o via `workflow_dispatch` con override della soglia):

1. Setup Python 3.11 + cache pip
2. Installa `requirements.txt` + `requirements-e2e.txt`
3. `playwright install --with-deps chromium`
4. Avvia `python run.py` in background con `LLM_BACKEND=stub`, attende `/health`
5. Esegue `run_e2e.py` con `--min-detection 0.90`
6. Upload di `e2e_report.json` + `api.log` come artefatto (sempre)
7. Kill del processo API

Per usare un LLM reale in CI: aggiungere il secret `ANTHROPIC_API_KEY`, impostare `LLM_BACKEND: anthropic` ed esportare la env dal secret.

### Backend `stub` dello scorer

Per evitare dipendenze esterne in CI e sblocccare detection_rate significativi, `app/scorer.py` espone un terzo backend **`stub`** (oltre ad `anthropic` e `ollama`) che calcola verdict e score in modo deterministico a partire da `pre_risk_score` + `confirmed_signals` + `headless_signals` dell'extractor. Nessuna rete, nessuna chiave. Attivabile con `LLM_BACKEND=stub`.

---

## 🧪 Test

La test suite copre **41 scenari** suddivisi in 5 categorie:

| Categoria | N° | Scenari |
|-----------|----|---------|
| `legit` | 5 | Chrome/Windows, Firefox/macOS, Safari/iPhone, Edge/Windows, Chrome Android |
| `attack` | 13 | HeadlessChrome, Playwright+SwiftShader, Selenium, Tor, Puppeteer, latenza estrema + **T21–T27** BitM/BitM+ (noVNC title, Guacamole title, xssPayload URL, evilGet override, MalSrv port, noVNC UA leak, ngrok WS) |
| `suspicious` | 6 | VPN+login, latenza alta+payment, VPN+canvas vuoto, timezone anomala, risoluzione sospetta, **T28 ngrok-dev+login** |
| `edge` | 5 | Payload minimo, UA unicode, static asset, path sconosciuto, **T29 WebAuthn API nativa** |
| `system` | 13 | Health, session persistence, IP-block escalation, rate-limit, GeoIP, admin clear, cache, webhook field, webhook non-blocking, prompt v7 compatto, dataset builder, train LoRA CLI, **S13 allineamento label BitM** |

### Esecuzione

```bash
# Avvia prima il server
python run.py

# Full suite (da un secondo terminale)
python tests/run_tests.py

# Filtri
python tests/run_tests.py --filter attack
python tests/run_tests.py --filter legit,suspicious
python tests/run_tests.py --only T06,T11
python tests/run_tests.py --parallel 4
python tests/run_tests.py --skip-system
```

Il runner azzera automaticamente lo stato all'inizio, scrive `test_report.json` al termine ed esce con codice `0` solo se tutti i test passano.

### System check v6.2 + v7.0

| ID | Verifica |
|----|----------|
| S01 | `/health` espone `version 6.x`, `store`, `geoip`, `sessions`, `blocked_ips`, `webhook` |
| S02 | Sessione multi-step: `request_count` cresce a ogni POST sullo stesso `sessionId` |
| S03 | IP-block escalation: 3 BLOCK consecutivi → IP nel set bloccati permanenti |
| S04 | Rate-limit: 40 richieste in rapida successione → almeno una `429` |
| S05 | GeoIP: IP loopback/privato non produce errori, `/health` rimane `200` |
| S06 | `DELETE /api/bitm/sessions` azzera sessioni e IP bloccati |
| S07 | Cache LLM: seconda chiamata con stesso fingerprint non è più lenta della prima |
| S08 | `/health` campo `webhook` ha struttura valida (`enabled`; se attivo: `type`, `url`, `timeout`, `retries`) |
| S09 | BLOCK con webhook irraggiungibile: round-trip < 4000ms (notifier non-blocking) |
| **S10** | **Prompt v7 ≤ 650 caratteri e direttive essenziali preservate (JSON/LEGITIMATE/SUSPICIOUS/ATTACK/pre_risk_score/BitM)** |
| **S11** | **`build_dataset.py` su fixture: scarta `from_cache` e `api_error`, conserva le 3 classi, emette ChatML (system/user/assistant) con target JSON valido** |
| **S12** | **`train_lora.py --help` termina con exit 0 ed espone tutti i flag principali (`--dataset-dir`, `--base-model`, `--output-dir`, `--lora-r`, `--lora-alpha`, `--no-4bit`)** |
| **S13** | **Label BitM/BitM+ allineati fra `extractor._detect_bitm` e `policy.CRITICAL_BLOCK` (regressione su v7.2)** |

---

## 🕵️ Rilevamento BitM / BitM+ (v7.2)

Questa versione aggiunge un livello di rilevamento **specifico per gli stack di attacco BitM / BitM+ documentati in letteratura**, al di sopra del fingerprinting generico di headless / automation.

### Minaccia — riepilogo tecnico

| Variante | Tooling attaccante | Riferimento |
|---------|--------------------|-------------|
| **BitM — RFB variant** | noVNC (client JS) + WebSockify (WS↔RFB proxy) + TigerVNC (server Linux con Firefox fullscreen) | Tommasi 2021, Tzschoppe 2023 §4.1 |
| **BitM — RDP variant** | Apache Guacamole (web client su Tomcat) + estensione NoAuth + FreeRDP + Windows RDP server | Tzschoppe 2023 §4.2 |
| **BitM+** | Docker BE: Node.js + Express.js (**MalSrv** su `:3081`) + Puppeteer-controlled Chromium + noVNC (`:6080`) esposto via **ngrok HTTPS tunnel** (HTTPS richiesto da WebAuthn); **xssPayload** riflesso nell'URL (`xURL`) che sovrascrive `navigator.credentials.get()` con `evilGet()` per inoltrare la challenge FIDO2/WebAuthn a V | Catalano 2025 |

### Firme rilevate

Il plugin estrae 9 nuovi segnali diagnostici da campi opzionali del payload (il collector lato client può fornirli o no — i campi mancanti semplicemente non contribuiscono):

| Segnale | Trigger | Peso pre-score | Severità |
|---------|---------|----------------|----------|
| `novnc_client_marker` | `document.title` contiene `noVNC` / `Websockify` | +0.80 | **CRITICAL → BLOCK** |
| `guacamole_client_marker` | `document.title` contiene `Guacamole` | +0.80 | **CRITICAL → BLOCK** |
| `bitm_framework_ua` | User-Agent contiene `noVNC` / `websockify` / `guacamole` / `tigervnc` (PoC non-stealth) | +0.80 | **CRITICAL → BLOCK** |
| `bitm_backend_port` | URL pagina/referrer su porte BE BitM+ (`:3081` Express MalSrv, `:6080` noVNC, `:4822` Guacamole Tomcat, `:5900` VNC) | +0.78 | **CRITICAL → BLOCK** |
| `xss_reflected_param` | URL contiene payload XSS: `<script`, `onerror=`, `javascript:`, `document.createElement`, `appendChild`, `loadFromAttacker`, `eval(`, `fromCharCode` | +0.70 | **CRITICAL → BLOCK** |
| `webauthn_api_override` | `navigator.credentials.get.toString()` non è `[native code]` → probabile `evilGet()` (BitM+) | +0.70 | **CRITICAL → BLOCK** |
| `bitm_websocket_transport` | WS endpoint su host tunneling, porta BE, o path `/websockify`, `/vnc`, `/guacamole` | +0.55 | **CRITICAL → BLOCK** |
| `tunnel_host` | `pageUrl` o `referrer` su tunnel HTTPS (`*.ngrok.io`, `*.ngrok-free.app`, `*.ngrok.app`, `*.ngrok.dev`, `*.trycloudflare.com`, `*.loca.lt`, `*.localtunnel.me`, `*.serveo.net`) | +0.25 | weak — amplifica su login/payment/admin |
| `iframe_overlay` | ≥ 3 iframe nella pagina (tipico di BitM+ per sovrapporre la GUI al RP) | +0.15 | weak — amplifica su login/payment/admin |

### Come arrivare alle firme dal client

Il plugin è agnostico rispetto al collector. Un collector JavaScript lato sito può facilmente aggiungere questi campi al POST `/api/bitm/collect`:

```js
// client-side snippet
fetch('/api/bitm/collect', { method: 'POST', body: JSON.stringify({
  // ... i campi esistenti (userAgent, plugins, webgl, canvas, …)
  pageUrl:  window.location.href,
  referrer: document.referrer,
  title:    document.title,
  iframeCount: document.getElementsByTagName('iframe').length,
  credentialsGetNative: (navigator.credentials?.get
      ? /\[native code\]/.test(Function.prototype.toString.call(navigator.credentials.get))
      : null),
  // wsEndpoints: lista degli URL WS aperti (se il collector li traccia)
})});
```

### Campi `CRITICAL_BLOCK` e fast-path

I label BitM/BitM+ sono replicati su tre livelli per coerenza architetturale:

1. `app/extractor.py::_detect_bitm` — produce i label
2. `app/policy.py::CRITICAL_BLOCK` — forza BLOCK quando uno di questi compare negli `indicators` (unione di LLM + extractor)
3. `app/main.py::_fast_rules` — propaga i label già calcolati dall'extractor nel fast-path, evitando la chiamata LLM

Il system check **S13** verifica che i 3 insiemi restino allineati in CI.

### Casi di test dedicati (T21–T29)

| ID | Scenario | Atteso |
|----|----------|--------|
| T21 | BitM RFB — `title="Login - noVNC"` + `pageUrl` ngrok | `block` |
| T22 | BitM RDP — `title="Apache Guacamole"` + porta `:8080` | `block` |
| T23 | BitM+ — xURL con `?xssParam={loadFromAttacker(...)}` | `block` |
| T24 | BitM+ — `credentialsGetNative=false` → `evilGet()` | `block` |
| T25 | BitM+ — `pageUrl` su `:6080`, `referrer` su `:3081/getChallenge` | `block` |
| T26 | BitM — UA contiene `noVNC/1.4.0` (PoC non-stealth) | `block` |
| T27 | BitM+ — `wsEndpoints=["wss://...ngrok.../websockify"]` | `block` |
| T28 | Dev ngrok legittimo su `/login` | `challenge` o `block` |
| T29 | `credentialsGetNative=true` → WebAuthn API nativa | `allow` |

### Limiti noti

- L'attaccante può **mascherare il `document.title`** (Tzschoppe 2023 segnala che basta rimuovere il suffisso `-noVNC` dalla build di noVNC, e Guacamole permette l'override del thumbnail). I marker di titolo sono quindi firme "a bassa difesa": utili su PoC e operatori distratti, non su APT. I segnali **forti indipendenti dalla collaborazione dell'attaccante** sono `tunnel_host`, `xss_reflected_param`, `webauthn_api_override` e `bitm_backend_port`.
- `tunnel_host` da solo **non** blocca (ngrok è legittimo in sviluppo): richiede coincidenza con un contesto sensibile (`login`/`payment`/`admin`) o con un altro segnale BitM.
- L'override di `navigator.credentials.get` richiede che il collector sia eseguito **dopo** il payload XSS — su una pagina BitM+ pulita, prima dell'injection, il segnale può non scattare. La difesa raccomandata rimane l'attestation/subject-verification lato Relying Party (cfr. Catalano 2025 §6).

---

## 📦 Distribuzione Docker + collector.js (v7.3)

Obiettivo della v7.3: eliminare la barriera d'ingresso per i tre pubblici principali — sviluppatori che integrano su un sito esistente, utenti non-tecnici che vogliono provarlo subito, ricercatori che studiano BitM. Prima di v7.3 l'onboarding richiedeva ≥ 6 passaggi (pip install, API key, run.py, snippet JS da copiare a mano); ora è un singolo `docker compose up` oppure un singolo `<script>` tag.

### File aggiunti

- `bitm-plugin/Dockerfile` — `python:3.13-slim`, utente non-root `bitm`, healthcheck integrato su `/health`, `CMD` diretto a `uvicorn` (no `--reload`)
- `bitm-plugin/.dockerignore` — esclude `__pycache__/`, `.env`, `tests/`, `doc/`, `bitm_events.jsonl`, artefatti IDE
- `docker-compose.yml` (root) — servizio `api` di default + profili opzionali `redis` e `ollama`
- `bitm-plugin/app/static/collector.js` — collector vanilla JS (~140 righe, nessuna dipendenza), legge `data-endpoint`/`data-page`/`data-auto` dal tag `<script>`, espone `window.BitM`
- `.github/workflows/docker-publish.yml` — build multi-arch (`amd64`/`arm64`) + push su `ghcr.io/<owner>/bitm-llm:{latest,sha-...,vX.Y.Z}` a ogni push su `master`/tag `v*`

### File modificati

- `bitm-plugin/app/config.py` — `LLM_BACKEND` default `anthropic` → `stub`. Chi vuole LLM reale passa esplicitamente `LLM_BACKEND=anthropic|ollama`
- `bitm-plugin/app/main.py` — nuovo endpoint `GET /collector.js` (MIME `application/javascript`, cache 1h)
- `bitm-plugin/.env.example` — riordinato per promuovere `stub` come prima opzione
- `bitm-plugin/tests/run_tests.py` — nuovo **S14 `sys_collector_js_endpoint`**: verifica 200, MIME JS, stringhe `/api/bitm/collect` e `window.BitM` nel body. Totale test 41 → 42

### API del collector JS

```js
// Dopo che lo <script> è stato caricato:
BitM.classify()       // → Promise<{action, score, verdict, indicators, reason, ...}>
BitM.fingerprint()    // → Promise<Fingerprint> (senza invio al server)
BitM.onResult(fn)     // listener chiamato a ogni classify()
BitM.endpoint         // → URL configurato via data-endpoint
```

Il collector popola i campi opzionali letti da `extractor.py::_detect_bitm` usando gli stessi nomi (nessun layer di remap): `pageUrl = location.href`, `referrer = document.referrer`, `title = document.title`, `wsEndpoints = [...]` (tracciato via hook su `new WebSocket`), `iframeCount = document.getElementsByTagName('iframe').length`, `credentialsGetNative = navigator.credentials.get.toString().includes('[native code]')`. La coerenza del contratto è verificata da **S15** (`sys_collector_payload_detects_bitm`).

---

## 📦 Changelog

### v7.3.0 — Distribuzione one-shot (Docker + GHCR + collector.js)
- **Docker** (`bitm-plugin/Dockerfile`, `.dockerignore`, `docker-compose.yml` in root): onboarding via `docker compose up` senza dipendenze Python locali. Profili opzionali `redis` e `ollama` per stack avanzato
- **Collector standalone** (`bitm-plugin/app/static/collector.js` + `GET /collector.js` in `app/main.py`): integrazione one-liner via `<script src=".../collector.js" data-endpoint="..." data-auto="true">`. Espone `window.BitM` con `classify()`, `fingerprint()`, `onResult(fn)`
- **Default `LLM_BACKEND=stub`** (`app/config.py`): eliminata la necessità di una API key per il primo avvio. Lo scorer deterministico `_score_stub` (già presente in v7.1) produce verdetti basati su `pre_risk_score` + segnali BitM/BitM+, sufficiente per demo e ricerca
- **Workflow GHCR** (`.github/workflows/docker-publish.yml`): build multi-arch (amd64/arm64) + push a `ghcr.io/<owner>/bitm-llm` su push/tag. Permette `docker run ghcr.io/<owner>/bitm-llm:latest` da terminale pulito
- **Test suite**: 41 → 43 casi. Aggiunti **S14 `sys_collector_js_endpoint`** (endpoint `/collector.js`: 200 + MIME JS + stringhe chiave nel body) e **S15 `sys_collector_payload_detects_bitm`** (POST di un payload collector-shaped su una pagina BitM noVNC simulata → verifica che i segnali forti BitM/BitM+ scattino, blocca il drift silenzioso del contratto collector↔extractor)



### v7.2.0 — Rilevamento BitM / BitM+ specifico
- **Firme dedicate agli stack BitM documentati** (`app/extractor.py::_detect_bitm`): 9 nuovi segnali (`novnc_client_marker`, `guacamole_client_marker`, `bitm_framework_ua`, `bitm_backend_port`, `xss_reflected_param`, `webauthn_api_override`, `bitm_websocket_transport`, `tunnel_host`, `iframe_overlay`) estratti da campi opzionali del payload (`pageUrl`, `referrer`, `title`, `wsEndpoints`, `credentialsGetNative`, `iframeCount`)
- **Allineamento tri-file** di `CRITICAL_BLOCK` (policy) / fast-path (main) / detector (extractor) con nuovo system check **S13** a garanzia
- **SYSTEM_PROMPT** aggiornato per segnalare gli stack BitM+ all'LLM senza sforare il limite v7.0 (≤ 650 char; attuale 636)
- **Test suite**: 32 → 41 casi. Aggiunti T21–T29 (noVNC/Guacamole/xssPayload/evilGet/MalSrv port/UA leak/WS tunnel/ngrok-dev/WebAuthn nativa) + S13 (label alignment)
- **Riferimenti**: Tommasi 2021 (IJIS), Tzschoppe & Löhr 2023 (EuroSec), Catalano 2025 (J. Computer Virology)

### v7.1.0 — E2E Playwright + CI
- **E2E Playwright** (`bitm-plugin/tests/e2e_playwright/run_e2e.py`): 7 tecniche di evasione reali (UA rotation, timing sub-human, no-static, stealth patches, canvas noise, WebGL spoof, Tor) eseguite su Chromium headless con init-script e route-blocking
- **Metrica di accettazione**: `detection_rate = (challenge+block)/totale`, exit ≠ 0 se < `--min-detection` (default 0.90). Report JSON persistito su disco
- **CI GitHub Actions** (`.github/workflows/e2e-playwright.yml`): pipeline completa (setup Python → `playwright install chromium` → `run.py` in background → `run_e2e.py` → upload artefatto) su push/PR per `bitm-plugin/**` + `workflow_dispatch` con soglia override
- **Backend `stub` scorer** (`app/scorer.py` + `app/config.py`): aggiunto terzo backend deterministico (oltre `anthropic`/`ollama`) per CI e dev senza credenziali. Derivato esclusivamente da `pre_risk_score` + segnali dell'extractor

### v7.0.0 — Infrastruttura fine-tuning LoRA
- **System prompt compatto** (`app/scorer.py`): riscrittura del `SYSTEM_PROMPT` in versione v7 — 609 caratteri vs 1080 della v6 (~43% in meno), direttive essenziali preservate, rationale documentato inline
- **Pipeline dataset** (`training/build_dataset.py`): conversione `bitm_events.jsonl → ChatML` con filtri su cache/errori tecnici, dedup per `(ua, verdict, pre_score)`, split train/val, bilanciamento opzionale per classe
- **Training LoRA** (`training/train_lora.py`): fine-tuning di LLaMA 3.1 con `transformers + peft + trl.SFTTrainer`, quantizzazione 4-bit NF4 opzionale, target modules LLaMA, gradient checkpointing, import lazy (`--help` funziona senza dipendenze ML installate)
- **Test suite**: 29 → 32 casi. Aggiunti `S10` (lunghezza prompt + direttive preservate), `S11` (build_dataset su fixture: dedup, filtri, ChatML target JSON parsabile), `S12` (train_lora CLI parseable senza dipendenze ML). Aggiornati header e report a `v7.0`

### v6.2.0
- **Webhook push notifications** (`app/notifier.py`): notifica HTTP POST asincrona fire-and-forget per ogni evento BLOCK
- Formati supportati: Slack Blocks API, Microsoft Teams Adaptive Cards v1.4, SIEM JSON
- Retry con backoff esponenziale (1s → 2s → 4s, max 30s), no-retry su 4xx
- Configurazione via variabili d'ambiente o file JSON (`WEBHOOK_CONFIG_FILE`) con supporto header custom
- `/health` espone campo `webhook` con stato e configurazione attiva
- Test suite: aggiunti S08 e S09; totale 29 casi

### v6.1.0
- **Dashboard real-time** (`app/broadcaster.py`): pub/sub in-process con ring buffer 500 slot
- WebSocket feed `/ws/events`: frame `backlog` al connect + frame `event` per ogni richiesta
- Dashboard HTML/JS (`/dashboard`) con Chart.js e export CSV

### v6.0.0
- **Sessioni persistenti su Redis** (`app/redis_client.py`): `SessionStore` con fallback in-memory
- **GeoIP automatico** (`app/geoip.py`): middleware arricchisce ogni request con country/ASN/ISP
- Rimozione gestione manuale di `ip_meta` dal payload client
- Rate-limit con sliding window Redis (zset)
- IP-block escalation dopo 3 BLOCK consecutivi
- Test suite: 27 scenari (S01–S07)
