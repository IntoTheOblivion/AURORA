/*
 * BitM Shield — background.js (service worker)
 *
 * Tiene lo stato per tab in memoria (tabId → { verdict, score, signals, url }).
 * Aggiorna il badge dell'icona in base al verdetto peggiore visto sulla tab
 * corrente. Risponde al popup per mostrare il dettaglio.
 *
 * Nessun dato lascia il browser: niente fetch, niente storage remoto.
 */
const state = new Map(); // tabId → verdict payload

const BADGE = {
  allow:     { text: "",    color: "#1e7f3c" },
  challenge: { text: "!",   color: "#e67e22" },
  block:     { text: "X",   color: "#c0392b" },
};

function applyBadge(tabId, verdict) {
  const b = BADGE[verdict] || BADGE.allow;
  chrome.action.setBadgeText({ tabId, text: b.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
  const title = verdict === "allow"
    ? "BitM Shield — pagina pulita"
    : verdict === "challenge"
    ? "BitM Shield — segnali sospetti"
    : "BitM Shield — BLOCCO: rilevato BitM";
  chrome.action.setTitle({ tabId, title });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== "bitm-verdict") return false;
  const tabId = sender.tab && sender.tab.id;
  if (typeof tabId !== "number") return false;

  const prev = state.get(tabId);
  // Se nella stessa tab avevamo già visto un verdict peggiore, non declassare
  const rank = { allow: 0, challenge: 1, block: 2 };
  const worst = prev && rank[prev.verdict] > rank[msg.verdict] ? prev.verdict : msg.verdict;

  const payload = {
    url: msg.url,
    origin: msg.origin,
    verdict: worst,
    score: Math.max(prev ? prev.score : 0, msg.score),
    signals: Array.from(new Set([...(prev ? prev.signals : []), ...(msg.signals || [])])),
    at: Date.now(),
  };
  state.set(tabId, payload);
  applyBadge(tabId, payload.verdict);
  return false;
});

chrome.tabs.onRemoved.addListener((tabId) => state.delete(tabId));

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  // Reset quando la tab inizia a caricare una nuova URL
  if (changeInfo.status === "loading" && changeInfo.url) {
    state.delete(tabId);
    applyBadge(tabId, "allow");
  }
});

// Il popup chiede lo stato della tab attiva
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "bitm-popup-query") {
    const tabId = msg.tabId;
    sendResponse(state.get(tabId) || null);
    return true;
  }
  return false;
});
