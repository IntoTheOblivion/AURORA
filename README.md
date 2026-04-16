# BitM Detection Plugin

Sistema di rilevamento in tempo reale di attacchi **Browser-in-the-Middle (BitM)**, automazione malevola e bot non autorizzati. Combina fingerprinting comportamentale del browser, regole deterministiche a latenza zero e un motore LLM (Anthropic Claude o Ollama) per classificare ogni richiesta come `allow`, `challenge` o `block`.

> **Versione corrente: 6.2.0** (runtime)
> Webhook push notifications (Slack / Teams / SIEM) per eventi BLOCK — notifiche HTTP asincrone fire-and-forget con retry esponenziale.
>
> **In preparazione: 7.0** — infrastruttura di fine-tuning LoRA per LLaMA 3.1 (`bitm-plugin/training/`) e system prompt compatto (~40% più corto) per ridurre la latenza di inferenza.

---

## Indice

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
- [Test](#-test)
- [Changelog](#-changelog)

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
│   └── run_tests.py     # Test suite (29 casi: legit/attack/suspicious/edge/system)
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
  "version":     "6.2.0",
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

## 🧪 Test

La test suite copre **32 scenari** suddivisi in 5 categorie:

| Categoria | N° | Scenari |
|-----------|----|---------|
| `legit` | 5 | Chrome/Windows, Firefox/macOS, Safari/iPhone, Edge/Windows, Chrome Android |
| `attack` | 6 | HeadlessChrome, Playwright+SwiftShader, Selenium, Tor, Puppeteer, latenza estrema |
| `suspicious` | 5 | VPN+login, latenza alta+payment, VPN+canvas vuoto, timezone anomala, risoluzione sospetta |
| `edge` | 4 | Payload minimo, UA unicode, static asset, path sconosciuto |
| `system` | 12 | Health, session persistence, IP-block escalation, rate-limit, GeoIP, admin clear, cache, webhook field, webhook non-blocking, **prompt v7 compatto, dataset builder, train LoRA CLI** |

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

---

## 📦 Changelog

### v7.0 — work in progress (infrastruttura training)
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
