# BitM Detection Plugin

Questo repository contiene il codice sorgente per il progetto **BitM Detection Plugin**, progettato per rilevare l'utilizzo di automazione, bot non autorizzati e profili fittizi tramite un mix di impronte digitali comportamentali del client e analisi gestita tramite LLM.

Il plugin utilizza **FastAPI** come server e offre la possibilità di scegliere come motore di intelligenza artificiale per l'analisi sia le API in cloud di **Anthropic (Claude)**, sia backend locali tramite **Ollama** (es. LLaMA 3.1).

> **Versione corrente: 6.2.0** — Webhook push notifications (Slack / Teams / SIEM) per eventi BLOCK, notifiche HTTP asincrone fire-and-forget con retry.

## 🚀 Caratteristiche Principali

- **Analisi comportamentale**: Raccolta della telemetria del browser (User-Agent, WebGL, num. plugin, IP, timings e molto altro).
- **Regole Fast-Track Deterministiche**: Blocca minacce palesi in zero millisecondi saltando la verifica con l'LLM (es. Headless Chrome, Tor, Puppeteer).
- **Intelligenza tramite LLM**: Analizza il "Browser Fingerprint" passandolo all'LLM (Anthropic o Ollama) chiedendo un responso basato sul rischio di automazione e botting.
- **GeoIP automatico (v6)**: Ogni Request viene arricchita in automatico con `Country`, `ASN`, `ISP` tramite i database MaxMind GeoLite2. Rilevamento VPN su ASN noti e hook per feed Tor esterno.
- **Sessioni persistenti su Redis (v6)**: Le sessioni utente, gli IP bloccati e le finestre di rate-limit sono mantenute su Redis → condivisibili in ambienti multi-processo / multi-istanza. Fallback in-memory automatico se Redis non è disponibile.
- **Rate-Limiting sliding window**: Mitigazione del traffico malevolo con finestra scorrevole (Redis zset) contro richieste ripetute e attacchi brute force.
- **Dashboard real-time WebSocket (v6.1)**: Feed live degli eventi su `/ws/events` con ring buffer degli ultimi 500 eventi. Dashboard HTML/JS a `/dashboard` con Chart.js e export CSV.
- **Webhook push notifications (v6.2)**: Notifica HTTP asincrona fire-and-forget verso Slack, Microsoft Teams o un endpoint SIEM aziendale ad ogni evento BLOCK. Retry automatico con backoff esponenziale. Nessun impatto sulla latenza di risposta.
- **Architettura Modulare**: Organizzato in moduli (`config`, `extractor`, `policy`, `scorer`, `geoip`, `redis_client`, `broadcaster`, `notifier`).
- **Supporto Multipiattaforma backend**: Modalità Cloud (`anthropic`) o Locale gratuita (`ollama`).

## 📁 Struttura del Progetto

Tutto il codice principale della versione finale risiede nella cartella `bitm-plugin`:

- `app/` - Moduli della logica centrale di FastAPI:
  - `main.py` - Entry FastAPI + middleware GeoIP + endpoint `/api/bitm/collect`
  - `config.py` - Configurazione (LLM, Redis, GeoIP, Webhook) caricata da `.env`
  - `extractor.py` - Feature extraction dal payload client
  - `scorer.py` - Interfaccia LLM (Anthropic / Ollama) con cache TTL
  - `policy.py` - Soglie contestuali e decisione finale (ALLOW/CHALLENGE/BLOCK)
  - `geoip.py` - **(v6)** Resolver MaxMind GeoLite2 per Country/ASN/ISP
  - `redis_client.py` - **(v6)** `SessionStore` async su Redis con fallback in-memory
  - `broadcaster.py` - **(v6.1)** Pub/sub in-process per la dashboard WebSocket real-time
  - `notifier.py` - **(v6.2)** Webhook push asincrono per eventi BLOCK (Slack / Teams / SIEM)
  - `logger.py` - Log eventi in `bitm_events.jsonl`
- `diagnose.py` - Script per la diagnostica della piattaforma.
- `run.py` - Entry point incaricato di caricare configurazioni e lanciare un worker di uvicorn.
- `requirements.txt` - Le dipendenze per l'ambiente virtuale python.
- `tests/run_tests.py` - Test suite con 29 scenari (20 legit/attack/suspicious/edge + 9 system).
- `test_report.json` e `bitm_events.jsonl` - Files di log o report generati.

## 📋 Requisiti di base

- `Python >= 3.10`
- `Ollama` installato in locale se il backend selezionato è locale. In alternativa, occorre specificare una API KEY valida targata Anthropic Claude.
- **Redis >= 5** (opzionale ma consigliato): se non raggiungibile il sistema usa il fallback in-memory senza interruzioni.
- **MaxMind GeoLite2** (opzionale): i DB `.mmdb` per City e ASN abilitano l'arricchimento GeoIP automatico. Scaricabili gratuitamente da [maxmind.com](https://www.maxmind.com/en/geolite2/signup).

## 🛠 Installazione & Setup

1. **Clona/spostati nella cartella root:**
   ```bash
   # (Se ancora non sei nella directory) e poi vai nel plugin core
   cd bitm-plugin
   ```

2. **Setup dell'ambiente virtuale (Consigliato):**
   ```bash
   python -m venv .venv
   # Per attivarlo in ambiente Windows:
   .venv\Scripts\activate
   # Per Linux/macOS:
   source .venv/bin/activate
   ```

3. **Installazione dipendenze:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Avvio di Redis (consigliato):**
   ```bash
   # Docker (opzione più rapida)
   docker run -d --name bitm-redis -p 6379:6379 redis:7-alpine
   # Oppure installazione nativa: https://redis.io/download
   ```

5. **Configurazione variabili d'ambiente (`.env`):**
   Copia prima il file d'esempio predisposto per il plugin.
   ```bash
   cp .env.example .env
   ```
   **Modifica il file `.env`** aprendolo con un editor:
   - **Backend LLM:**
     - **(Modalità Anthropic)** Inserisci: `LLM_BACKEND=anthropic` e configura `ANTHROPIC_API_KEY=sk-ant-api03-...`
     - **(Modalità Locale)** Inserisci: `LLM_BACKEND=ollama` ed evt. verifica che l'`OLLAMA_MODEL` coincida con uno installato (es. `llama3.1`). Assicurati ovviamente che l'Ollama server sia già su (`ollama serve`).
   - **Redis (v6):** `REDIS_URL=redis://localhost:6379/0` (default). Opzionali: `REDIS_SESSION_TTL=3600`, `REDIS_KEY_PREFIX=bitm:`.
   - **GeoIP (v6):** indicizza i database MaxMind:
     ```env
     MAXMIND_CITY_DB=/path/to/GeoLite2-City.mmdb
     MAXMIND_ASN_DB=/path/to/GeoLite2-ASN.mmdb
     ```
     Se omessi, l'arricchimento GeoIP ritorna metadati vuoti senza errori.
   - **Webhook (v6.2):** abilita le notifiche push per eventi BLOCK:
     ```env
     # Slack
     WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
     WEBHOOK_TYPE=slack

     # Microsoft Teams
     WEBHOOK_URL=https://outlook.office.com/webhook/...
     WEBHOOK_TYPE=teams

     # SIEM / endpoint generico
     WEBHOOK_URL=https://siem.azienda.local/events
     WEBHOOK_TYPE=siem

     # Parametri opzionali
     WEBHOOK_TIMEOUT=5     # timeout HTTP in secondi (default 5)
     WEBHOOK_RETRIES=3     # tentativi in caso di errore di rete o 5xx (default 3)
     ```
     In alternativa, usa `WEBHOOK_CONFIG_FILE=/path/to/webhook.json` per una configurazione completa che include anche header custom (es. token di autenticazione):
     ```json
     {
       "url":     "https://siem.azienda.local/events",
       "type":    "siem",
       "timeout": 5,
       "retries": 3,
       "headers": { "Authorization": "Bearer my-token" }
     }
     ```

## 🚀 Utilizzo (Avvio API)

Dalla cartella in cui si risiede (`bitm-plugin`), per far partire l'istanza back-end esegui il file di lancio:

```bash
python run.py
```

L'API si metterà in ascolto all'indirizzo locale `http://0.0.0.0:8000` (oppure con la porta definita nelle variabili del `.env`).
Puoi simulare un invio di pacchetti a `http://localhost:8000/api/bitm/collect`.

All'avvio la console segnala lo stato di tutti i sottosistemi, ad esempio:

```
[bitm] Backend LLM: ollama @ http://localhost:11434  model=llama3.1
[redis] connesso a redis://localhost:6379/0
[bitm] Session store: redis
[bitm] GeoIP: MaxMind attivo (city+asn)
```

## 🌐 Endpoints Principali (FastAPI)

- `GET /health` - Stato del sistema: versione, backend LLM, modello attivo, n. sessioni, n. IP bloccati, backend sessioni (`redis`/`memory`), stato GeoIP, stato webhook.
- `POST /api/bitm/collect` - Endpoint Core per inviare profili telemetrici client; ritorna JSON con `action`, `verdict`, `score`, `indicators`, `reason`, `context`. I metadati IP (country/ASN/ISP) sono risolti automaticamente dal resolver GeoIP. Gli eventi BLOCK scatenano la notifica webhook in modo asincrono.
- `GET /api/bitm/sessions` - View admin delle sessioni persistenti e degli IP bloccati (con indicazione del backend in uso).
- `DELETE /api/bitm/sessions` - Pulisce sessioni, IP bloccati e finestre di rate-limit.
- `GET /dashboard` - Dashboard HTML real-time con feed WebSocket degli ultimi 500 eventi.
- `GET /ws/events` - WebSocket feed degli eventi raw (un frame JSON per ogni `/api/bitm/collect`).

## 📡 Webhook push notifications (v6.2)

Il modulo `app/notifier.py` intercetta ogni azione `BLOCK` generata dal sistema e invia una notifica HTTP POST non bloccante verso il webhook configurato.

### Flusso

```
BLOCK action
  → notify_block(entry)          chiamata sincrona, istantanea
  → asyncio.create_task(...)     fire-and-forget, non blocca la risposta
      → httpx.AsyncClient.post   HTTP POST con timeout configurabile
      → retry con backoff        1s → 2s → 4s → … (max 30s)
```

### Formati payload

| Tipo | Struttura |
|------|-----------|
| `slack` | Attachments con Header block + Section fields (IP, score, verdict, segnali) + Context (spiegazione) — Blocks API |
| `teams` | Adaptive Card v1.4 con `FactSet` + `TextBlock` — compatibile con connettori O365 e Power Automate |
| `siem`  | JSON flat con `event_type`, `source_ip`, `risk_score`, `indicators`, `timestamp` ISO-8601 e tutti i campi diagnostici |

### Comportamento in caso di errore

- Errori di rete o risposte 5xx: il sistema ritenta fino a `WEBHOOK_RETRIES` volte con backoff esponenziale.
- Risposte 4xx (client error): nessun retry, l'errore viene loggato.
- Errori imprevisti (eccezioni non di rete): nessun retry, l'errore viene loggato.
- In tutti i casi il fallimento del webhook **non influisce** sulla risposta all'utente né genera eccezioni nell'applicazione.

## 🧪 Test

La test suite v6.2 copre **29 test** suddivisi in 5 categorie:

| Categoria      | N° | Descrizione                                                                |
|----------------|----|----------------------------------------------------------------------------|
| `legit`        | 5  | Browser reali (Chrome/Firefox/Safari/Edge desktop, Chrome Android).        |
| `attack`       | 6  | HeadlessChrome, Playwright, Selenium, Tor, Puppeteer, latenza estrema.     |
| `suspicious`   | 5  | VPN, canvas vuoto, timezone anomala, risoluzione sospetta in login/payment.|
| `edge`         | 4  | Payload minimo, UA unicode, static asset, path sconosciuto.                |
| `system` (v6.2)| 9  | Health, sessioni multi-step, IP-block escalation, rate-limit, GeoIP, admin, cache, webhook field, webhook non-blocking. |

### Esecuzione

```bash
# Full suite
python tests/run_tests.py

# Solo una categoria
python tests/run_tests.py --filter attack
python tests/run_tests.py --filter legit,suspicious

# Singoli casi per ID
python tests/run_tests.py --only T06,T11

# Esecuzione in parallelo (4 worker)
python tests/run_tests.py --parallel 4

# Salta i system check
python tests/run_tests.py --skip-system
```

### System check v6.2

| ID   | Verifica                                                                           |
|------|------------------------------------------------------------------------------------|
| S01  | `/health` espone versione 6.x e campi `store`, `geoip`, `sessions`, `blocked_ips`, `webhook`. |
| S02  | Una sessione persiste richieste multi-step (page sequence + counter).              |
| S03  | Dopo 3 block consecutivi sulla stessa sessione l'IP finisce nel set bloccati.      |
| S04  | Rate-limit sliding window risponde con HTTP 429 oltre la soglia.                   |
| S05  | GeoIP enrichment gestisce IP privati / loopback senza errori.                      |
| S06  | `DELETE /api/bitm/sessions` azzera sessioni e blocked.                             |
| S07  | La cache LLM evita chiamate duplicate con lo stesso fingerprint.                   |
| S08  | `/health` espone il campo `webhook` con struttura valida (`enabled`, e se abilitato: `type`, `url`, `timeout`, `retries`). |
| S09  | Un evento BLOCK con webhook irraggiungibile non rallenta la risposta (round-trip < 4000ms). |

Al termine viene generato `test_report.json` con dettaglio per singolo caso. Il runner esce con codice 0 solo se tutti i test passano. Con LLM attivo + regole deterministiche la v6.2 raggiunge **29/29 (100%)** sui casi di riferimento.
