/*
 * BitM Shield — popup.js
 *
 * Chiede al background il verdetto della tab attiva e lo mostra.
 * Se il background non ha dati (tab nuova, chrome://...), fallback
 * a "allow" con score 0.
 */
(async function () {
  "use strict";

  var boxEl     = document.getElementById("verdict-box");
  var verdictEl = document.getElementById("verdict");
  var scoreEl   = document.getElementById("score");
  var sigsEl    = document.getElementById("signals");
  var originEl  = document.getElementById("origin");

  function renderSignals(signals) {
    sigsEl.innerHTML = "";
    if (!signals || signals.length === 0) {
      var li = document.createElement("li");
      li.className = "muted";
      li.textContent = "Nessuno";
      sigsEl.appendChild(li);
      return;
    }
    for (var i = 0; i < signals.length; i++) {
      var li2 = document.createElement("li");
      li2.textContent = signals[i];
      sigsEl.appendChild(li2);
    }
  }

  function render(payload, origin) {
    var verdict = (payload && payload.verdict) || "allow";
    boxEl.className = verdict;
    verdictEl.textContent =
      verdict === "allow" ? "OK" :
      verdict === "challenge" ? "Sospetto" :
      verdict === "block" ? "Bloccato" : verdict;
    scoreEl.textContent = "score " + ((payload && payload.score) || 0).toFixed(3);
    renderSignals(payload && payload.signals);
    originEl.textContent = origin || "—";
  }

  try {
    var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    var tab = tabs && tabs[0];
    if (!tab) { render(null, "—"); return; }

    var originGuess = "—";
    try { originGuess = new URL(tab.url).origin; } catch (_) { /* noop */ }

    var payload = await new Promise(function (res) {
      chrome.runtime.sendMessage({ type: "bitm-popup-query", tabId: tab.id }, function (r) {
        res(r);
      });
    });

    render(payload, payload ? payload.origin : originGuess);
  } catch (e) {
    render(null, "—");
  }
})();
