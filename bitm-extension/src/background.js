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

// ── Stato in memoria ────────────────────────────────────────────────────────
const state = new Map(); // tabId → verdict payload
const HISTORY_KEY = "bitm-history";
const HISTORY_MAX = 50;
const RANK = { allow: 0, challenge: 1, block: 2 };

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

// ── History ring buffer (chrome.storage.local) ──────────────────────────────
async function pushHistory(entry) {
  try {
    const items = await chrome.storage.local.get([HISTORY_KEY]);
    const list  = Array.isArray(items[HISTORY_KEY]) ? items[HISTORY_KEY] : [];
    list.unshift(entry);
    if (list.length > HISTORY_MAX) list.length = HISTORY_MAX;
    await chrome.storage.local.set({ [HISTORY_KEY]: list });
  } catch (_) { /* quota / disabled */ }
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
    explanationUser: (remote && remote.explanation_user) || local.explanationUser || "",
    pattern: (remote && remote.trajectory_pattern) || "",
    source: "hybrid",
    remoteOnline: true,
  };
}

async function reportToBackend(local, fingerprint, trajectory, settings) {
  // Skip remoto: mode non-hybrid, URL non settato, o block locale già certo.
  if (settings.mode !== "hybrid") return local;
  if (!settings.backendUrl)       return local;
  if (local.verdict === "block" && local.critical) return local;

  const url = settings.backendUrl.replace(/\/$/, "") + "/api/bitm/collect";
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const res = await fetch(url, {
      method: "POST",
      mode: "cors",
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
        colorDepth: fingerprint.colorDepth || 24,
        canvas: fingerprint.canvas || "",
        webgl: fingerprint.webgl || "",
        pageUrl: fingerprint.pageUrl || "",
        referrer: fingerprint.referrer || "",
        title: fingerprint.title || "",
        wsEndpoints: fingerprint.wsEndpoints || [],
        credentialsGetNative: fingerprint.credentialsGetNative !== false,
        iframeCount: fingerprint.iframeCount || 0,
        timing: fingerprint.timing || 0,
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
    sendResponse(state.get(msg.tabId) || null);
    return false;
  }

  if (msg.type === "bitm-popup-test-connection") {
    (async () => {
      try {
        const url = String(msg.backendUrl || "").replace(/\/$/, "") + "/health";
        const controller = new AbortController();
        const t = setTimeout(() => controller.abort(), 2500);
        const r = await fetch(url, { signal: controller.signal });
        clearTimeout(t);
        if (!r.ok) { sendResponse({ ok: false, status: r.status }); return; }
        const body = await r.json();
        sendResponse({ ok: true, version: body.version, trajectory: !!body.trajectory_analysis, backend: body.backend });
      } catch (e) { sendResponse({ ok: false, error: String(e) }); }
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

chrome.tabs.onRemoved.addListener((tabId) => state.delete(tabId));

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading" && changeInfo.url) {
    state.delete(tabId);
    applyBadge(tabId, "allow");
  }
});

// ── Init: crea sessionId se assente e ripristina net-rules dopo restart SW ─
(async () => {
  try {
    const s = await BitMSettings.ensureSessionId();
    if (s.blockNetRulesEnabled) await BitMNetRules.enable();
    else                         await BitMNetRules.disable();
  } catch (e) { console.warn("[BitM] init failed", e); }
})();
