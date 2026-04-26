/*
 * BitM Shield — background.js (service worker, MV3)
 *
 * Tiene lo stato per-tab in memoria, gestisce il badge, il ring buffer
 * history (chrome.storage.local), e — in mode=hybrid — inoltra il verdict
 * locale al backend per ottenere trajectory_pattern + explanation_user.
 *
 * Invariante: con mode=off|local nessun fetch esce. Hybrid + backend
 * irraggiungibile = degrado silenzioso al verdetto locale, mai eccezioni.
 */
try {
  // classic SW (non module): carica deps sincronamente all'avvio.
  importScripts("./settings.js", "./net-rules.js");
} catch (e) {
  console.error("[BitM] importScripts failed", e);
}

// ── Stato per-tab ───────────────────────────────────────────────────────────
// In MV3 il service worker viene terminato dopo ~30s di idle: una Map pura
// perderebbe lo stato ad ogni respawn (badge/popup vuoti alla prima query
// successiva). Tenevamo solo `state = new Map()` e questo era il bug.
// Ora la Map resta come cache in-memory, con shadow-write su
// chrome.storage.session (persiste finché il browser è aperto) e lazy-load
// su cache-miss.
const state = new Map(); // tabId → verdict payload (cache)
// Esposto su self per permettere test E2E (tests/e2e_hybrid.js) di leggere
// lo stato via serviceWorker.evaluate. Non usato dal runtime dell'estensione.
self.__bitmState = state;
const SESSION_STATE_KEY = "bitm-tab-state";
const HISTORY_KEY = "bitm-history";
const HISTORY_MAX = 50;
const RANK = { allow: 0, challenge: 1, block: 2 };

async function loadStateFromSession() {
  try {
    const items = await chrome.storage.session.get([SESSION_STATE_KEY]);
    const raw = items && items[SESSION_STATE_KEY];
    if (raw && typeof raw === "object") {
      for (const [tabId, payload] of Object.entries(raw)) {
        // Le chiavi JSON sono sempre stringhe: riconverto a number.
        const id = Number(tabId);
        if (Number.isFinite(id)) state.set(id, payload);
      }
    }
  } catch (_) { /* quota / disabled */ }
}

let persistChain = Promise.resolve();
function persistStateToSession() {
  // Serializziamo le scritture: multiple applyAndPersist() concorrenti non
  // devono fare read-modify-write corrotti.
  persistChain = persistChain.then(async () => {
    try {
      const obj = {};
      for (const [tabId, payload] of state.entries()) obj[tabId] = payload;
      await chrome.storage.session.set({ [SESSION_STATE_KEY]: obj });
    } catch (_) { /* noop */ }
  });
  return persistChain;
}

async function getTabState(tabId) {
  if (state.has(tabId)) return state.get(tabId);
  // Cache miss dopo respawn SW: tenta di rileggere da storage.session.
  await loadStateFromSession();
  return state.get(tabId) || null;
}

const BADGE = {
  allow:     { text: "",  color: "#1e7f3c" },
  challenge: { text: "!", color: "#e67e22" },
  block:     { text: "X", color: "#c0392b" },
};

function applyBadge(tabId, verdict) {
  const b = BADGE[verdict] || BADGE.allow;
  try {
    chrome.action.setBadgeText({ tabId, text: b.text });
    chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
    const title = verdict === "allow"
      ? chrome.i18n.getMessage("badge_title_allow")     || "BitM Shield — pagina pulita"
      : verdict === "challenge"
      ? chrome.i18n.getMessage("badge_title_challenge") || "BitM Shield — segnali sospetti"
      : chrome.i18n.getMessage("badge_title_block")     || "BitM Shield — BLOCCO: rilevato BitM";
    chrome.action.setTitle({ tabId, title });
  } catch (_) { /* tab chiusa */ }
}

// ── URL safety ──────────────────────────────────────────────────────────────
// Accettiamo solo http/https: file:, chrome-extension:, javascript:, data:
// non sono backend legittimi e data:/javascript: potrebbero essere usati per
// smuggling se l'UI non filtrasse l'input.
//
// Normalizziamo all'ORIGIN: altrimenti un utente che incolla
// "http://host/api" produrrebbe "http://host/api" + "/api/bitm/collect" =
// "/api/api/bitm/collect" (doppio prefisso). Il path del backend è fisso.
function safeBackendUrl(raw) {
  const s = String(raw || "").trim();
  if (!s) return "";
  try {
    const u = new URL(s);
    if (u.protocol !== "http:" && u.protocol !== "https:") return "";
    return u.origin;
  } catch (_) { return ""; }
}

// ── History ring buffer (chrome.storage.local) ──────────────────────────────
// Serializziamo le scritture per evitare race read-modify-write quando più
// tab concludono un verdict in rapida successione.
let historyWriteChain = Promise.resolve();
function _entryKey(e) {
  // Stessa origin + stesso verdict + stessi segnali = stesso "incidente".
  // Signals viene già da Array.from(new Set(...)) ma non è ordinato; lo
  // ordiniamo qui per evitare miss di dedup dovuti all'ordine di arrivo.
  const sigs = Array.isArray(e.signals) ? [...e.signals].sort().join(",") : "";
  return (e.origin || "") + "|" + (e.verdict || "") + "|" + sigs;
}
function pushHistory(entry) {
  historyWriteChain = historyWriteChain.then(async () => {
    try {
      const items = await chrome.storage.local.get([HISTORY_KEY]);
      const list  = Array.isArray(items[HISTORY_KEY]) ? items[HISTORY_KEY] : [];
      const head = list[0];
      if (head && _entryKey(head) === _entryKey(entry)) {
        // Stessa entry consecutiva (es. refresh ripetuti): bump count + at.
        head.count = (head.count || 1) + 1;
        head.at = entry.at || Date.now();
        // Esplicitazione campi che possono essere arrivati arricchiti dal
        // backend al secondo giro (es. explanation/pattern arrivati con il
        // probe successivo): teniamo i valori non-vuoti più recenti.
        if (entry.explanationUser) head.explanationUser = entry.explanationUser;
        if (entry.pattern)         head.pattern         = entry.pattern;
        if (entry.source)          head.source          = entry.source;
      } else {
        entry.count = 1;
        list.unshift(entry);
        if (list.length > HISTORY_MAX) list.length = HISTORY_MAX;
      }
      await chrome.storage.local.set({ [HISTORY_KEY]: list });
    } catch (_) { /* quota / disabled */ }
  });
  return historyWriteChain;
}

// ── Merge locale + remoto ───────────────────────────────────────────────────
function mergeVerdicts(local, remote) {
  // verdict peggiore vince; union signals; explanation/pattern dal remoto.
  const mapRemoteAction = { allow: "allow", challenge: "challenge", block: "block" };
  const rv = remote && mapRemoteAction[remote.action];
  const worst = rv && RANK[rv] > RANK[local.verdict] ? rv : local.verdict;
  const signalsLocal  = local.signals || [];
  const signalsRemote = (remote && Array.isArray(remote.indicators)) ? remote.indicators : [];
  return {
    verdict: worst,
    score: Math.max(local.score || 0, (remote && Number(remote.score)) || 0),
    signals: Array.from(new Set([...signalsLocal, ...signalsRemote])),
    // `critical` arriva solo dal lato locale (segnali in CRITICAL_BLOCK). Il
    // backend non lo ritorna esplicitamente: se era già critico, resta critico.
    critical: !!local.critical,
    explanationUser: (remote && remote.explanation_user) || local.explanationUser || "",
    pattern: (remote && remote.trajectory_pattern) || "",
    source: "hybrid",
    remoteOnline: true,
  };
}

async function reportToBackend(local, fingerprint, trajectory, settings) {
  // Skip remoto: mode non-hybrid, URL non settato/invalido, o block locale certo.
  if (settings.mode !== "hybrid") return local;
  const base = safeBackendUrl(settings.backendUrl);
  if (!base) return local;
  if (local.verdict === "block" && local.critical) return local;

  const url = base + "/api/bitm/collect";
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const res = await fetch(url, {
      method: "POST",
      mode: "cors",
      credentials: "omit",   // niente cookie cross-origin
      cache: "no-store",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: settings.sessionId,
        page: trajectory.latestPage || "/",
        userAgent: fingerprint.userAgent,
        webdriver: false,
        plugins: fingerprint.plugins || [],
        platform: fingerprint.platform || "",
        languages: fingerprint.languages || [],
        timezone: fingerprint.timezone || "",
        screenRes: fingerprint.screenRes || "",
        // `??`: preserva colorDepth=0 (anomalia) invece di mascherarla a 24.
        colorDepth: fingerprint.colorDepth ?? 24,
        canvas: fingerprint.canvas || "",
        webgl: fingerprint.webgl || "",
        pageUrl: fingerprint.pageUrl || "",
        referrer: fingerprint.referrer || "",
        title: fingerprint.title || "",
        wsEndpoints: fingerprint.wsEndpoints || [],
        credentialsGetNative: fingerprint.credentialsGetNative !== false,
        iframeCount: fingerprint.iframeCount ?? 0,
        timing: fingerprint.timing ?? 0,
      }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return { ...local, remoteOnline: false };
    const remote = await res.json();
    return mergeVerdicts(local, remote);
  } catch (e) {
    // Offline-first: se il backend non risponde, il verdict locale vale da solo.
    return { ...local, remoteOnline: false };
  }
}

// ── Message handler principale ──────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg) return false;

  // v0.1 path: verdict locale "secco" dal content-script
  if (msg.type === "bitm-verdict") {
    handleVerdict(msg, sender).catch(() => { /* noop */ });
    return false;
  }

  // v0.2 hybrid path: content-script invia fingerprint+trajectory, ci aspettiamo
  // di ritornare il verdict mergiato (asyncronamente).
  if (msg.type === "bitm-hybrid-probe") {
    (async () => {
      try {
        const settings = await BitMSettings.get();
        const local = {
          verdict: msg.verdict,
          score: msg.score || 0,
          signals: msg.signals || [],
          critical: !!msg.critical,
          explanationUser: "",
          pattern: "",
          source: "local",
          remoteOnline: false,
        };
        const merged = await reportToBackend(local, msg.fingerprint || {}, msg.trajectory || {}, settings);
        await applyAndPersist(sender.tab && sender.tab.id, sender.tab && sender.tab.url, merged);
        sendResponse(merged);
      } catch (e) {
        sendResponse({ verdict: msg.verdict, error: String(e) });
      }
    })();
    return true; // manteniamo il channel aperto per sendResponse async
  }

  if (msg.type === "bitm-popup-query") {
    // Async: potremmo dover leggere da storage.session se il SW è appena
    // stato respawnato e la Map è fredda.
    (async () => {
      try {
        sendResponse(await getTabState(msg.tabId));
      } catch (_) {
        sendResponse(null);
      }
    })();
    return true;
  }

  if (msg.type === "bitm-popup-test-connection") {
    (async () => {
      const base = safeBackendUrl(msg.backendUrl);
      if (!base) { sendResponse({ ok: false, error: "invalid_scheme" }); return; }
      const url = base + "/health";
      // 1) tentativo CORS standard: se risponde leggiamo /health e finiamo.
      try {
        const c1 = new AbortController();
        const t1 = setTimeout(() => c1.abort(), 2500);
        const r = await fetch(url, {
          signal: c1.signal,
          credentials: "omit",
          cache: "no-store",
        });
        clearTimeout(t1);
        if (!r.ok) { sendResponse({ ok: false, error: "http_status", status: r.status }); return; }
        const body = await r.json();
        sendResponse({
          ok: true,
          version: body.version,
          trajectory: !!body.trajectory_analysis,
          backend: body.backend,
        });
        return;
      } catch (corsErr) {
        // 2) Riprova in no-cors: una response opaca conferma che TCP+TLS+HTTP
        //    funzionano e il backend rifiuta solo perché manca
        //    `Access-Control-Allow-Origin: chrome-extension://...`. Distinguere
        //    questo caso dall'irraggiungibilità è il bugfix: prima entrambi
        //    cadevano nello stesso "Non raggiungibile" generico.
        try {
          const c2 = new AbortController();
          const t2 = setTimeout(() => c2.abort(), 2000);
          await fetch(url, {
            signal: c2.signal,
            mode: "no-cors",
            credentials: "omit",
            cache: "no-store",
          });
          clearTimeout(t2);
          sendResponse({ ok: false, error: "cors_blocked", reachable: true });
        } catch (_) {
          // Se anche no-cors fallisce, il problema è davvero a livello rete:
          // host inesistente, porta chiusa, TLS error, timeout.
          sendResponse({ ok: false, error: "unreachable", detail: String(corsErr && corsErr.message || corsErr) });
        }
      }
    })();
    return true;
  }

  if (msg.type === "bitm-popup-toggle-netrules") {
    (async () => {
      try {
        if (msg.enabled) await BitMNetRules.enable();
        else             await BitMNetRules.disable();
        await BitMSettings.set({ blockNetRulesEnabled: !!msg.enabled });
        sendResponse({ ok: true, active: await BitMNetRules.isActive() });
      } catch (e) { sendResponse({ ok: false, error: String(e) }); }
    })();
    return true;
  }

  return false;
});

async function handleVerdict(msg, sender) {
  const tabId = sender.tab && sender.tab.id;
  if (typeof tabId !== "number") return;

  const prev = state.get(tabId);
  const worst = prev && RANK[prev.verdict] > RANK[msg.verdict] ? prev.verdict : msg.verdict;
  const payload = {
    url: msg.url,
    origin: msg.origin,
    verdict: worst,
    score: Math.max(prev ? prev.score : 0, msg.score || 0),
    signals: Array.from(new Set([...(prev ? prev.signals : []), ...(msg.signals || [])])),
    critical: !!(msg.critical || (prev && prev.critical)),
    explanationUser: msg.explanationUser || (prev && prev.explanationUser) || "",
    pattern: msg.pattern || (prev && prev.pattern) || "",
    source: msg.source || "local",
    remoteOnline: !!msg.remoteOnline,
    at: Date.now(),
  };
  await applyAndPersist(tabId, msg.url, payload);
}

async function applyAndPersist(tabId, url, payload) {
  if (typeof tabId === "number") {
    state.set(tabId, payload);
    applyBadge(tabId, payload.verdict);
    // Mirror su chrome.storage.session per sopravvivere al respawn del SW.
    persistStateToSession();
  }
  // Scrivi in history solo verdict non-allow: evita di saturare lo storage
  // con navigazioni normali. La sezione history del popup è per incidenti.
  if (payload.verdict !== "allow") {
    await pushHistory({
      at: Date.now(),
      url: url || payload.url || "",
      origin: payload.origin || "",
      verdict: payload.verdict,
      score: payload.score,
      signals: payload.signals,
      explanationUser: payload.explanationUser,
      pattern: payload.pattern,
      source: payload.source,
    });
  }
}

chrome.tabs.onRemoved.addListener((tabId) => {
  state.delete(tabId);
  persistStateToSession();
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading" && changeInfo.url) {
    state.delete(tabId);
    applyBadge(tabId, "allow");
    persistStateToSession();
  }
});

// ── Init: crea sessionId se assente, ripristina net-rules e lo stato per-tab
//    dopo un respawn del service worker.
(async () => {
  try {
    await loadStateFromSession();
    const s = await BitMSettings.ensureSessionId();
    if (s.blockNetRulesEnabled) await BitMNetRules.enable();
    else                         await BitMNetRules.disable();
  } catch (e) { console.warn("[BitM] init failed", e); }
})();
