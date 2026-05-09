/*
 * AURORA — manual_playwright.js
 *
 * Test manuale (non CI) che copre i 4 scenari v0.2.0:
 *   1. Locale offline (mode=local): pagina "noVNC" → block + banner IT
 *   2. Hybrid con backend: traiettoria panic_password_change → pattern + explanation
 *   3. Hybrid con backend offline: fallback locale, nessuna eccezione
 *   4. declarativeNetRequest attivo: richiesta verso ngrok/websockify bloccata
 *
 * Uso:
 *   1. Assicurati che il backend sia acceso per scenari 2 e 4:
 *        cd aurora-plugin && LLM_BACKEND=ollama LLM_TRAJECTORY_ANALYSIS=on python run.py
 *   2. Installa Playwright Chromium: `npm i -D playwright`
 *   3. Esegui: `node tests/manual_playwright.js`
 *
 * Note:
 *   - Shadow DOM mode:"closed" → non possiamo ispezionare il contenuto del
 *     banner; verifichiamo solo la presenza dell'host + getBoundingClientRect.
 *   - MV3 service worker è caricato con flag `--disable-extensions-except`.
 *   - Non-goal: automatizzare chrome.storage.local da Node. I settings vanno
 *     cliccati nel popup manualmente (script tiene il browser aperto 20s
 *     alla fine di ogni scenario per ispezione visiva).
 */
const { chromium } = require("playwright");
const path = require("path");

const EXT_DIR  = path.resolve(__dirname, "..");
const BACKEND  = process.env.AURORA_BACKEND || "http://localhost:8000";

async function launch(args = []) {
  return chromium.launchPersistentContext("", {
    headless: false,
    args: [
      `--disable-extensions-except=${EXT_DIR}`,
      `--load-extension=${EXT_DIR}`,
      ...args,
    ],
  });
}

async function assertBannerPresent(page, expected = true) {
  const present = await page.evaluate(() => {
    const h = document.getElementById("__aurora_banner__");
    if (!h) return false;
    const r = h.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  });
  if (present !== expected) {
    throw new Error(`banner expected=${expected} but present=${present}`);
  }
  console.log(`  ✓ banner present=${present}`);
}

async function scenario1_localOffline() {
  console.log("\n── Scenario 1: Locale offline (mode=local) ──");
  const ctx = await launch();
  const page = await ctx.newPage();
  await page.setContent(`<!doctype html><html><head><title>noVNC</title></head>
    <body><h1>honeypot</h1></body></html>`);
  await page.waitForTimeout(3000);
  await assertBannerPresent(page, true);
  await page.waitForTimeout(2000);
  await ctx.close();
}

async function scenario2_hybridPanic() {
  console.log("\n── Scenario 2: Hybrid panic_password_change ──");
  console.log("  ⚠ Richiede: popup → Settings → mode=hybrid, backendUrl=" + BACKEND + ", Salva");
  const ctx = await launch();
  const page = await ctx.newPage();
  await page.goto("chrome://extensions/", { waitUntil: "domcontentloaded" });
  console.log("  Configura manualmente il popup (hai 30s)…");
  await page.waitForTimeout(30000);

  // Resetta sessioni backend
  const reset = await page.evaluate(async (backend) => {
    try {
      const r = await fetch(backend + "/api/bitm/sessions", { method: "DELETE" });
      return r.ok;
    } catch { return false; }
  }, BACKEND);
  console.log("  backend session reset=" + reset);

  // Apri 3 pagine in sequenza rapida
  for (const p of ["/login", "/account/verify", "/account/change-password"]) {
    await page.goto(`data:text/html,<html><head><title>BitM test</title></head>
      <body><form><input type=password></form>test page ${p}</body></html>`.replace("${p}", p));
    await page.waitForTimeout(400);
  }
  await page.waitForTimeout(3000);
  console.log("  (verifica manualmente: popup deve mostrare pattern=panic_password_change)");
  await page.waitForTimeout(15000);
  await ctx.close();
}

async function scenario3_hybridBackendDown() {
  console.log("\n── Scenario 3: Hybrid con backend OFFLINE ──");
  console.log("  ⚠ Spegni il server aurora-plugin prima di eseguire questo scenario.");
  console.log("  Verifica che il banner appaia comunque (fallback locale) su pagina noVNC.");
  const ctx = await launch();
  const page = await ctx.newPage();
  await page.setContent(`<!doctype html><html><head><title>noVNC</title></head>
    <body><h1>offline test</h1></body></html>`);
  await page.waitForTimeout(3500);
  await assertBannerPresent(page, true);
  console.log("  ✓ fallback locale funzionante");
  await page.waitForTimeout(3000);
  await ctx.close();
}

async function scenario4_netRules() {
  console.log("\n── Scenario 4: declarativeNetRequest attivo ──");
  console.log("  ⚠ Attiva il toggle 'Blocca tunnel noti' nel popup prima di eseguire.");
  const ctx = await launch();
  const page = await ctx.newPage();
  // Usiamo un host ngrok noto come target. La richiesta non deve raggiungerlo.
  const errors = [];
  page.on("requestfailed", (r) => errors.push(r.url() + " → " + r.failure().errorText));
  await page.goto("data:text/html,<iframe src='https://foo.ngrok-free.app/websockify'></iframe>");
  await page.waitForTimeout(3000);
  console.log("  richieste bloccate:", errors.slice(0, 5));
  if (errors.some((e) => e.includes("ngrok-free.app"))) {
    console.log("  ✓ net-rules ha bloccato la richiesta");
  } else {
    console.log("  ✗ richiesta non bloccata — verifica toggle popup");
  }
  await page.waitForTimeout(3000);
  await ctx.close();
}

(async () => {
  const only = process.argv[2]; // "1" | "2" | "3" | "4" oppure vuoto = tutti
  try {
    if (!only || only === "1") await scenario1_localOffline();
    if (!only || only === "2") await scenario2_hybridPanic();
    if (!only || only === "3") await scenario3_hybridBackendDown();
    if (!only || only === "4") await scenario4_netRules();
    console.log("\nFine test manuali.");
  } catch (e) {
    console.error("✗", e);
    process.exit(1);
  }
})();
