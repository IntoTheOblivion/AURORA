/*
 * AURORA — e2e_hybrid.js
 *
 * Test E2E automatico del flusso hybrid extension ↔ backend v7.4.
 * Verifica su 3 canali indipendenti che una traiettoria login → change-password
 * produca verdict=panic_password_change mergiato correttamente dal service
 * worker dell'estensione:
 *   1. Backend: /api/bitm/sessions contiene la sessione e ha ≥4 richieste
 *   2. SW state: __bitmState[tabId].pattern === "panic_password_change",
 *      source === "hybrid", remoteOnline === true
 *   3. DOM: banner Shadow DOM host presente nella pagina caricata
 *
 * Strategia: seed traiettoria via 3 POST diretti (login/verify/change-password)
 * PRIMA di aprire il browser, così quando l'extension fa il suo 4° probe la
 * sessione backend ha già le pagine giuste e lo stub restituisce il pattern.
 * Questo testa le 4 cose che possono regredire nella v0.2.0:
 *   (a) SW legge settings dopo seed → mode=hybrid
 *   (b) SW POSTa con lo sessionId corretto
 *   (c) SW parsa la response (trajectory_pattern field name)
 *   (d) mergeVerdicts preserva pattern + source hybrid + remoteOnline
 *
 * Prerequisiti:
 *   - aurora-plugin up su AURORA_BACKEND (default http://localhost:8000) con
 *     LLM_BACKEND=stub e LLM_TRAJECTORY_ANALYSIS=on (altrimenti il test degrada
 *     ad "accetto qualsiasi pattern non vuoto").
 *   - npm i -D playwright && npx playwright install chromium
 *
 * Uso: node tests/e2e_hybrid.js
 */
const { chromium } = require("playwright");
const path = require("path");

const EXT_DIR = path.resolve(__dirname, "..");
const BACKEND = (process.env.AURORA_BACKEND || "http://localhost:8000").replace(/\/+$/, "");
const SESSION_ID = "e2e-hybrid-" + Date.now();
const STUB_PAGES = ["/login", "/account/verify", "/account/change-password"];

function delay(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function httpJson(url, init) {
  const res = await fetch(url, init);
  let body = null;
  try { body = await res.json(); } catch (_) { /* non-JSON */ }
  return { ok: res.ok, status: res.status, body: body };
}

async function seedBackendTrajectory(sessionId) {
  for (const page of STUB_PAGES) {
    await httpJson(BACKEND + "/api/bitm/collect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sessionId: sessionId,
        page: page,
        userAgent: "Mozilla/5.0 (e2e seed)",
        webdriver: false,
      }),
    });
    await delay(150);
  }
}

async function waitForServiceWorker(context, timeoutMs) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    const arr = context.serviceWorkers();
    if (arr.length) return arr[0];
    await delay(200);
  }
  throw new Error("service worker non disponibile entro " + timeoutMs + "ms");
}

async function seedSettings(sw, settings) {
  await sw.evaluate(async (s) => {
    await chrome.storage.local.set({ "aurora-settings": s });
  }, settings);
}

async function readSwVerdict(sw) {
  return await sw.evaluate(async () => {
    const m = self.__auroraState;
    if (!m) return { error: "state_not_exposed" };
    const tabs = await chrome.tabs.query({});
    for (const t of tabs) {
      const v = m.get(t.id);
      if (v) return {
        tabId: t.id,
        url: t.url || "",
        pattern: v.pattern || "",
        source: v.source || "",
        verdict: v.verdict || "",
        remoteOnline: !!v.remoteOnline,
        score: v.score || 0,
      };
    }
    return { error: "no_state_for_any_tab", knownTabs: tabs.map((t) => t.id) };
  });
}

async function assertBannerPresent(page) {
  return await page.evaluate(() => {
    const h = document.getElementById("__aurora_banner__");
    if (!h) return false;
    const r = h.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  });
}

function pass(n, msg) { console.log("  ✓ assert " + n + ": " + msg); }
function fail(n, msg) { console.error("  ✗ assert " + n + ": " + msg); }

(async () => {
  console.log("→ Hybrid E2E test");
  console.log("  backend=" + BACKEND);
  console.log("  session=" + SESSION_ID);

  const health = await httpJson(BACKEND + "/health").catch(() => ({ ok: false }));
  if (!health.ok) {
    console.error("✗ backend non raggiungibile. Avvia aurora-plugin prima.");
    process.exit(2);
  }
  const stubMode = health.body && health.body.backend === "stub";
  if (!health.body || !health.body.trajectory_analysis) {
    console.warn("⚠ trajectory_analysis=off — rilancia con LLM_TRAJECTORY_ANALYSIS=on");
  }
  if (!stubMode) {
    console.warn("⚠ LLM_BACKEND=" + (health.body && health.body.backend) +
      " (non stub). Il pattern non è deterministico: accetto qualsiasi pattern != ''.");
  }

  await httpJson(BACKEND + "/api/bitm/sessions", { method: "DELETE" });
  await seedBackendTrajectory(SESSION_ID);
  console.log("→ trajectory seeded: " + STUB_PAGES.join(" → "));

  const context = await chromium.launchPersistentContext("", {
    headless: false,
    args: [
      "--disable-extensions-except=" + EXT_DIR,
      "--load-extension=" + EXT_DIR,
    ],
  });

  let allOk = true;
  try {
    const sw = await waitForServiceWorker(context, 10000);
    console.log("→ service worker online");

    await seedSettings(sw, {
      mode: "hybrid",
      backendUrl: BACKEND,
      sessionId: SESSION_ID,
      locale: "it",
      blockNetRulesEnabled: false,
    });
    console.log("→ settings seeded (mode=hybrid, sessionId=" + SESSION_ID + ")");
    await delay(800); // propagazione chrome.storage.onChanged

    const page = await context.newPage();
    // Il backend serve un test_page.html su "/" con collector.js embedded:
    // blocchiamo collector.js per evitare che le sue POST sporchino il nostro
    // conteggio (usa un sessionId diverso, ma il count totale sessioni aumenta).
    await page.route("**/collector.js", (route) => route.fulfill({
      status: 200, contentType: "application/javascript", body: "/* blocked by e2e */",
    }));
    await page.goto(BACKEND + "/", { waitUntil: "domcontentloaded" });
    // Il content-script dell'estensione si inietta → hybrid-probe → SW POST →
    // merge → state.set(tabId). page-hook ri-emette "probe" a +2s.
    await delay(4000);

    const sessResp = await httpJson(BACKEND + "/api/bitm/sessions");
    const mySess = sessResp.ok && sessResp.body && sessResp.body.sessions &&
                   sessResp.body.sessions[SESSION_ID];
    if (!mySess) {
      fail(1, "sessione " + SESSION_ID + " assente da /api/bitm/sessions"); allOk = false;
    } else if ((mySess.request_count || 0) < 4) {
      fail(1, "request_count=" + mySess.request_count + " (atteso ≥4)"); allOk = false;
    } else {
      pass(1, "backend ha registrato " + mySess.request_count + " richieste per la sessione");
    }

    const swState = await readSwVerdict(sw);
    if (!swState) {
      fail(2, "readSwVerdict ha restituito null"); allOk = false;
    } else if (swState.error) {
      fail(2, "errore lettura SW state: " + swState.error +
        (swState.knownTabs ? " (tabs=" + JSON.stringify(swState.knownTabs) + ")" : ""));
      allOk = false;
    } else if (stubMode && swState.pattern !== "panic_password_change") {
      fail(2, "pattern='" + swState.pattern + "' atteso panic_password_change (stub mode)");
      allOk = false;
    } else if (!stubMode && !swState.pattern) {
      fail(2, "pattern vuoto (atteso qualsiasi pattern non vuoto)"); allOk = false;
    } else if (swState.source !== "hybrid") {
      fail(2, "source='" + swState.source + "' atteso 'hybrid' — merge non è avvenuto");
      allOk = false;
    } else if (!swState.remoteOnline) {
      fail(2, "remoteOnline=false — SW non ha ricevuto la response dal backend");
      allOk = false;
    } else {
      pass(2, "SW state: pattern=" + swState.pattern +
        " verdict=" + swState.verdict +
        " source=hybrid remoteOnline=true");
    }

    const bannerOk = await assertBannerPresent(page);
    if (!bannerOk) {
      fail(3, "banner host non presente nel DOM (verdict nel SW: " +
        (swState && swState.verdict) + ", pattern: " + (swState && swState.pattern) + ")");
      allOk = false;
    } else {
      pass(3, "banner host presente nel DOM");
    }
  } catch (e) {
    console.error("✗ eccezione durante il test:", e.message || e);
    allOk = false;
  } finally {
    await context.close().catch(() => {});
    await httpJson(BACKEND + "/api/bitm/sessions", { method: "DELETE" }).catch(() => {});
  }

  console.log(allOk ? "\nEXIT 0 — hybrid e2e OK" : "\nEXIT 1 — hybrid e2e FAILED");
  process.exit(allOk ? 0 : 1);
})();
