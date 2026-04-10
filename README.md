# BitM Detection Plugin

Questo repository contiene il codice sorgente per il progetto **BitM Detection Plugin**, progettato per rilevare l'utilizzo di automazione, bot non autorizzati e profili fittizi tramite un mix di impronte digitali comportamentali del client e analisi gestita tramite LLM.

Il plugin utilizza **FastAPI** come server e offre la possibilità di scegliere come motore di intelligenza artificiale per l'analisi sia le API in cloud di **Anthropic (Claude)**, sia backend locali tramite **Ollama** (es. LLaMA 3.1).

## 🚀 Caratteristiche Principali

- **Analisi comportamentale**: Raccolta della telemetria del browser (User-Agent, WebGL, num. plugin, IP, timings e molto altro).
- **Regole Fast-Track Deterministiche**: Blocca minacce palesi in zero millisecondi saltando la verifica con l'LLM (es. Headless Chrome, Tor, Puppeteer).
- **Intelligenza tramite LLM**: Analizza il "Browser Fingerprint" passandolo all'LLM (Anthropic o Ollama) chiedendo un responso basato sul rischio di automazione e botting.
- **Rate-Limiting in-memory**: Mitigazione del traffico malevolo bloccando richieste ripetute e attacchi brute force.
- **Architettura Modulare**: Organizzato in moduli (`config`, `extractor`, `policy`, `scorer`).
- **Supporto Multipiattaforma backend**: Modalità Cloud (`anthropic`) o Locale gratuita (`ollama`).

## 📁 Struttura del Progetto

Tutto il codice principale della versione finale risiede nella cartella `bitm-plugin-v5-final`:

- `app/` - Contiene i moduli della logica centrale di FastAPI (`main.py`, `config.py`, `scorer.py` etc.).
- `diagnose.py` - Script per la diagnostica della piattaforma (utile per eseguire test manuali).
- `run.py` - Entry point v5 incaricato di caricare configurazioni e lanciare un worker di uvicorn.
- `requirements.txt` - Le dipendenze per l'ambiente virtuale python.
- `test_report.json` e `bitm_events.jsonl` - Files di log o report generati.

## 📋 Requisiti di base

- `Python >= 3.10`
- `Ollama` installato in locale se il backend selezionato è locale. In alternativa, occorre specificare una API KEY valida targata Anthropic Claude.

## 🛠 Installazione & Setup

1. **Clona/spostati nella cartella root:**
   ```bash
   # (Se ancora non sei nella directory) e poi vai nel plugin core
   cd bitm-plugin-v5-final
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

4. **Configurazione variabili d'ambiente (`.env`):**
   Copia prima il file d'esempio predisposto per il plugin.
   ```bash
   cp .env.example .env
   ```
   **Modifica il file `.env`** aprendolo con un editor per scegliere il backend desiderato:
   - **(Modalità Anthropic)** Inserisci: `LLM_BACKEND=anthropic` e configura `ANTHROPIC_API_KEY=sk-ant-api03-...`
   - **(Modalità Locale)** Inserisci: `LLM_BACKEND=ollama` ed evt. verifica che l'`OLLAMA_MODEL` coincida con uno installato (es. `llama3.1`). Assicurati ovviamente che l'Ollama server sia già su (`ollama serve`).

## 🚀 Utilizzo (Avvio API)

Dalla cartella in cui si risiede (`bitm-plugin-v5-final`), per far partire l'istanza back-end esegui il file di lancio:

```bash
python run.py
```

L'API si metterà in ascolto all'inidirizzo locale `http://0.0.0.0:8000` (oppure con la porta definita nelle variabili del `.env`). 
Puoi simulare un invio di pacchetti a `http://localhost:8000/api/bitm/collect`.

## 🌐 Endpoints Principali (FastAPI)

- `GET /health` - Per ricavare stat e controllare se l'LLM è attivo e i backend correttamente configurati.
- `POST /api/bitm/collect` - Endpoint Core per inviare profili telemetrici client per le valutazioni e capire in JSON quale è il `verdict`.
- `GET /api/bitm/sessions` - Permette una view admin delle sessioni in-memory o bloccate.
