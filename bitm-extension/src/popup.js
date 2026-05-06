/*
 * BitM-LLM Shield — popup.js (v0.2.0)
 *
 * Tab Status: verdict + spiegazione (da hybrid se disponibile) della tab attiva.
 * Tab History: ring buffer `bitm-history` in chrome.storage.local.
 * Tab Settings: mode {off, local, hybrid}, backend URL, test-connection, toggle
 * net-rules; salvataggio via chrome.storage.local.
 */
(async function () {
  "use strict";

  function t(key, fallback) {
    try { var v = chrome.i18n.getMessage(key); if (v) return v; }
    catch (_) { /* noop */ }
    return fallback;
  }

  // ── Applica i18n ai nodi statici ────────────────────────────────────────────
  document.querySelectorAll("[data-i18n]").forEach(function (el) {
    var key = el.getAttribute("data-i18n");
    var msg = t(key, el.textContent);
    if (msg) el.textContent = msg;
  });
  var backendInput = document.getElementById("backend-url");
  if (backendInput) backendInput.placeholder = t("settings_backend_placeholder", "http://localhost:8000");

  // ── Tab switcher ────────────────────────────────────────────────────────────
  var tabs   = document.querySelectorAll("nav.tabs .tab");
  var panels = document.querySelectorAll(".panel");
  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      tabs.forEach(function (x) { x.classList.remove("active"); });
      panels.forEach(function (p) { p.classList.remove("active"); });
      tab.classList.add("active");
      var target = document.getElementById("panel-" + tab.dataset.tab);
      if (target) target.classList.add("active");
      if (tab.dataset.tab === "history") renderHistory();
    });
  });

  // ── Status tab ──────────────────────────────────────────────────────────────
  var boxEl     = document.getElementById("verdict-box");
  var verdictEl = document.getElementById("verdict");
  var scoreEl   = document.getElementById("score");
  var sigsEl    = document.getElementById("signals");
  var originEl  = document.getElementById("origin");
  var patternBox = document.getElementById("pattern-box");
  var patternEl  = document.getElementById("pattern");
  var explBox    = document.getElementById("explanation-box");
  var explEl     = document.getElementById("explanation");
  var backendStatus = document.getElementById("backend-status");
  var footerNote = document.getElementById("footer-note");

  function renderSignals(signals) {
    sigsEl.innerHTML = "";
    if (!signals || signals.length === 0) {
      var li = document.createElement("li");
      li.className = "muted";
      li.textContent = t("popup_signals_none", "Nessuno");
      sigsEl.appendChild(li);
      return;
    }
    signals.forEach(function (s) {
      var li = document.createElement("li");
      li.textContent = s;
      sigsEl.appendChild(li);
    });
  }

  function renderStatus(payload, origin) {
    var verdict = (payload && payload.verdict) || "allow";
    boxEl.className = verdict;
    verdictEl.textContent =
      verdict === "allow"     ? t("popup_verdict_ok", "OK") :
      verdict === "challenge" ? t("popup_verdict_challenge", "Sospetto") :
      verdict === "block"     ? t("popup_verdict_block", "Bloccato") : verdict;
    scoreEl.textContent = "score " + ((payload && payload.score) || 0).toFixed(3);
    renderSignals(payload && payload.signals);
    originEl.textContent = origin || "—";

    var pattern = payload && payload.pattern;
    if (pattern) {
      patternBox.hidden = false;
      patternEl.textContent = pattern;
    } else {
      patternBox.hidden = true;
    }

    var expl = payload && payload.explanationUser;
    if (expl) {
      explBox.hidden = false;
      explEl.textContent = expl;
    } else {
      explBox.hidden = true;
    }
  }

  function renderBackendStatus(settings, payload) {
    if (!backendStatus) return;
    var cls, text;
    if (settings.mode !== "hybrid") {
      cls = "local"; text = t("popup_backend_status_local", "solo locale");
    } else if (payload && payload.source === "hybrid" && payload.remoteOnline) {
      cls = "online"; text = t("popup_backend_status_online", "online");
    } else {
      cls = "offline"; text = t("popup_backend_status_offline", "offline");
    }
    backendStatus.className = "badge " + cls;
    backendStatus.textContent = text;
  }

  async function loadStatus() {
    try {
      var settings = await BitMSettings.get();
      var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      var tab = tabs && tabs[0];
      if (!tab) { renderStatus(null, "—"); renderBackendStatus(settings, null); return; }
      var originGuess = "—";
      try { originGuess = new URL(tab.url).origin; } catch (_) { /* noop */ }
      var payload = await new Promise(function (res) {
        chrome.runtime.sendMessage({ type: "bitm-popup-query", tabId: tab.id }, function (r) {
          res(r);
        });
      });
      renderStatus(payload, payload ? payload.origin : originGuess);
      renderBackendStatus(settings, payload);
      if (footerNote) {
        footerNote.textContent = settings.mode === "hybrid"
          ? t("footer_hybrid", "Modalità ibrida: le richieste vengono inoltrate al backend configurato.")
          : t("footer_local", "Rilevamento locale. Nessun dato lascia il browser.");
      }
    } catch (e) {
      renderStatus(null, "—");
    }
  }
  loadStatus();

  // ── History tab ─────────────────────────────────────────────────────────────
  var historyList = document.getElementById("history-list");
  var historyClear = document.getElementById("history-clear");

  async function renderHistory() {
    var items = await chrome.storage.local.get(["bitm-history"]);
    var list = Array.isArray(items["bitm-history"]) ? items["bitm-history"] : [];
    historyList.innerHTML = "";
    if (list.length === 0) {
      var li = document.createElement("li");
      li.className = "muted";
      li.textContent = t("popup_history_empty", "Nessun evento registrato.");
      historyList.appendChild(li);
      return;
    }
    var ALLOWED_VERDICT = { block: 1, challenge: 1, allow: 1 };
    list.forEach(function (ev) {
      var li = document.createElement("li");
      var when = new Date(ev.at).toLocaleString();
      var origin = ev.origin || (function () { try { return new URL(ev.url).origin; } catch (_) { return "—"; } })();
      var verdictClass = ALLOWED_VERDICT[ev.verdict] ? ev.verdict : "challenge";

      var verdictSpan = document.createElement("span");
      verdictSpan.className = "row-verdict " + verdictClass;
      var verdictLabel = ev.verdict === "block"
        ? t("popup_verdict_block", "Bloccato")
        : t("popup_verdict_challenge", "Sospetto");
      if (ev.count && ev.count > 1) verdictLabel += " ×" + ev.count;
      verdictSpan.textContent = verdictLabel;
      li.appendChild(verdictSpan);

      var originEl = document.createElement("strong");
      originEl.textContent = origin;
      li.appendChild(originEl);

      if (ev.pattern) {
        li.appendChild(document.createTextNode(" "));
        var patternSpan = document.createElement("span");
        patternSpan.className = "mono";
        patternSpan.textContent = "[" + ev.pattern + "]";
        li.appendChild(patternSpan);
      }

      var metaDiv = document.createElement("div");
      metaDiv.className = "row-meta mono";
      metaDiv.textContent = when + "  ·  " + (ev.signals || []).join(", ");
      li.appendChild(metaDiv);

      if (ev.explanationUser) {
        var explDiv = document.createElement("div");
        explDiv.textContent = ev.explanationUser;
        li.appendChild(explDiv);
      }

      historyList.appendChild(li);
    });
  }

  if (historyClear) {
    historyClear.addEventListener("click", async function () {
      await chrome.storage.local.set({ "bitm-history": [] });
      renderHistory();
    });
  }

  // ── Settings tab ────────────────────────────────────────────────────────────
  var modeInputs   = document.querySelectorAll("input[name='mode']");
  var backendUrlEl = document.getElementById("backend-url");
  var testBtn      = document.getElementById("test-btn");
  var testResult   = document.getElementById("test-result");
  var netrulesEl   = document.getElementById("netrules-toggle");
  var saveBtn      = document.getElementById("save-btn");
  var saveStatus   = document.getElementById("save-status");

  async function loadSettings() {
    var s = await BitMSettings.get();
    modeInputs.forEach(function (r) { r.checked = (r.value === s.mode); });
    backendUrlEl.value = s.backendUrl || "";
    netrulesEl.checked = !!s.blockNetRulesEnabled;
  }
  await loadSettings();

  testBtn.addEventListener("click", function () {
    testResult.textContent = "…";
    testResult.className = "test-result";
    chrome.runtime.sendMessage(
      { type: "bitm-popup-test-connection", backendUrl: backendUrlEl.value },
      function (r) {
        if (r && r.ok) {
          testResult.className = "test-result ok";
          testResult.textContent = t("settings_test_ok", "Connesso") +
            " — v" + (r.version || "?") + " · backend=" + (r.backend || "?") +
            (r.trajectory ? " · trajectory:on" : "");
          return;
        }
        testResult.className = "test-result fail";
        if (!r) {
          testResult.textContent = t("settings_test_fail", "Non raggiungibile");
          return;
        }
        if (r.error === "cors_blocked") {
          // Caso più frequente in dev: backend up, manca header CORS per
          // l'origin chrome-extension://. Diciamo all'utente cosa fare.
          testResult.textContent = t(
            "settings_test_cors",
            "Backend raggiungibile ma blocca CORS — abilita Access-Control-Allow-Origin per chrome-extension://"
          );
          return;
        }
        if (r.error === "invalid_scheme") {
          testResult.textContent = t(
            "settings_test_invalid_scheme",
            "URL non valido — usa http:// o https://"
          );
          return;
        }
        if (r.error === "http_status") {
          testResult.textContent = t("settings_test_fail", "Non raggiungibile") + " (HTTP " + r.status + ")";
          return;
        }
        // unreachable o errore generico
        testResult.textContent = t("settings_test_fail", "Non raggiungibile");
      }
    );
  });

  saveBtn.addEventListener("click", async function () {
    var mode = "local";
    modeInputs.forEach(function (r) { if (r.checked) mode = r.value; });
    var url = String(backendUrlEl.value || "").trim().replace(/\/+$/, "");
    // Rifiuta schemi diversi da http/https (file:, javascript:, data:, ...)
    if (url) {
      try {
        var parsed = new URL(url);
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
          testResult.className = "test-result fail";
          testResult.textContent = t("settings_test_fail", "Non raggiungibile") + " — schema non valido";
          return;
        }
      } catch (_) {
        testResult.className = "test-result fail";
        testResult.textContent = t("settings_test_fail", "Non raggiungibile") + " — URL non valido";
        return;
      }
    }
    var netrules = !!netrulesEl.checked;

    await BitMSettings.set({ mode: mode, backendUrl: url, blockNetRulesEnabled: netrules });
    // Attiva/disattiva declarativeNetRequest via SW (SW ha chrome.declarativeNetRequest)
    chrome.runtime.sendMessage(
      { type: "bitm-popup-toggle-netrules", enabled: netrules },
      function () { /* risposta ignorata: UI conferma comunque */ }
    );
    saveStatus.textContent = t("settings_saved", "Salvato");
    setTimeout(function () { saveStatus.textContent = ""; }, 1500);
    // Se siamo in hybrid e non abbiamo URL, avviso utente
    if (mode === "hybrid" && !url) {
      testResult.className = "test-result fail";
      testResult.textContent = t("settings_test_fail", "Non raggiungibile") + " — URL mancante";
    }
  });
})();
