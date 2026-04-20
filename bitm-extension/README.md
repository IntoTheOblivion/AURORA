# BitM Shield — browser extension

Estensione MV3 (Chrome/Edge/Brave) che rileva attacchi Browser-in-the-Middle
direttamente nel browser. **v0.2.0** introduce integrazione opzionale con il
backend `bitm-plugin/` per ottenere spiegazioni in italiano generate da LLM,
trajectory patterns e blocklist di rete a livello `declarativeNetRequest`.

## Installazione (dev)

1. Apri `chrome://extensions/`.
2. Attiva **Modalità sviluppatore**.
3. Clicca **Carica estensione non pacchettizzata** e seleziona questa cartella.
4. Il badge icona si aggiorna: grigio (allow), arancione `!` (challenge), rosso `X` (block).

## Modalità operative

Il popup → tab **Impostazioni** espone tre modalità:

| Modalità | Cosa fa                                                                       | Rete esterna |
|----------|-------------------------------------------------------------------------------|--------------|
| `off`    | Estensione disattivata, nessun detection                                      | ❌           |
| `local`  | **Default**. Rileva localmente i segnali BitM (stessi di v0.1)                | ❌           |
| `hybrid` | POSTa fingerprint + trajectory al backend e riceve `explanation_user` LLM     | ✅ (solo `backendUrl`) |

In `hybrid` il backend v7.4+ aggiunge:

- `trajectory_pattern` → es. `panic_password_change`, `direct_admin_access`;
- `explanation_user` in italiano, mostrato nel banner;
- merge "worst wins": il verdict più grave tra locale e remoto vince.

Se il backend è irraggiungibile, l'estensione fa fallback silenzioso al verdict
locale — nessuna eccezione, nessun loop di retry, nessun utente bloccato da un
server spento.

## Tab popup

- **Stato** — verdict corrente della tab attiva, segnali rilevati, pattern
  trajectory (se presente), spiegazione utente, origine. Badge header:
  `online` / `offline` / `solo locale`.
- **Storico** — ultimi 50 verdict non-`allow` registrati (solo incidenti).
  `Svuota storico` resetta. Persistenza in `chrome.storage.local`.
- **Impostazioni** — modalità, URL backend, test connessione (→ `GET /health`),
  toggle blocklist di rete.

## Hardening MV3 (declarativeNetRequest)

Quando l'utente attiva **Blocca tunnel noti a livello rete**, l'estensione
installa regole dinamiche che bloccano — prima che la pagina parta — tutte le
richieste verso host noti di tunneling BitM+:

```
ngrok.io · ngrok-free.app · ngrok-free.dev · trycloudflare.com
loca.lt · localtunnel.me · serveo.net
```

Inoltre il ruleset statico (`src/net-rules.json`, sempre disponibile) blocca
qualsiasi richiesta il cui path contenga `/websockify` o `/guacamole/` — tipico
del client-side di una BitM stack basata su noVNC/Guacamole.

## Struttura file

```
bitm-extension/
├── manifest.json           — MV3 manifest (v0.2.0)
├── _locales/
│   ├── it/messages.json    — stringhe UI italiane (default)
│   └── en/messages.json
├── src/
│   ├── page-hook.js        — MAIN world: WebSocket patch, canvas, WebGL, ...
│   ├── detection.js        — Porting JS di extractor._detect_bitm
│   ├── session.js          — Tracker pages[]+timings[] in sessionStorage
│   ├── banner.js           — Shadow DOM banner condiviso (IT + EN)
│   ├── content-script.js   — Pipeline detect → hybrid probe → banner
│   ├── background.js       — SW: merge verdict, history, alarms, net-rules
│   ├── net-rules.js        — Regole declarativeNetRequest dinamiche
│   ├── net-rules.json      — Regole statiche (/websockify, /guacamole)
│   ├── settings.js         — Wrapper chrome.storage.local
│   ├── popup.html/.js/.css — Popup 3-tab
└── tests/
    └── manual_playwright.js — 4 scenari manuali
```

## Privacy

- In `mode=local` **nessun byte lascia il browser**. Nessuna analytics,
  nessun beacon, zero dipendenze esterne.
- In `mode=hybrid` il service worker inoltra al solo `backendUrl` configurato:
  `sessionId` (UUID locale), `userAgent`, `page` (path), fingerprint browser
  (plugin list, WebGL renderer, canvas prefix, lingue, timezone, risoluzione).
  Nessun cookie, nessuna credenziale, nessun body di form. Vedi
  `bitm-plugin/.env.example` per i TTL lato server.

## Verifica

```bash
cd bitm-extension
node tests/manual_playwright.js           # tutti i 4 scenari
node tests/manual_playwright.js 1         # solo scenario N
```

Gli scenari 2 e 4 richiedono interazione manuale nel popup (configurare mode +
toggle). Playwright apre il browser in non-headless e attende 15-30s per
permettere la configurazione.

### Test E2E automatico (hybrid mode)

`tests/e2e_hybrid.js` valida end-to-end l'integrazione con il backend v7.4
**senza interazione manuale**: seed della traiettoria via POST diretti, pre-seed
di `chrome.storage.local` via `serviceWorker.evaluate`, verifica finale su 3
canali indipendenti (backend sessions, SW state, banner nel DOM).

```bash
# shell 1: backend in stub mode (deterministico)
cd bitm-plugin
LLM_BACKEND=stub LLM_TRAJECTORY_ANALYSIS=on python run.py

# shell 2: test
cd bitm-extension
node tests/e2e_hybrid.js
# atteso: 3× "✓ assert N" e "EXIT 0 — hybrid e2e OK"
```

Con `LLM_BACKEND=ollama|anthropic` il test degrada a "accetto qualsiasi pattern
non vuoto" invece del match esatto `panic_password_change`.
