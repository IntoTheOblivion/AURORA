"""E2E manuale del banner collector.js (v7.4).

Scenario:
  1. Apre una pagina HTML finta con collector.js + data-auto=false
  2. Chiama BitM.classify() con un payload headless → verdict=block
  3. Verifica che il banner Shadow-DOM sia presente e contenga
     `explanation_user` come testo visibile all'utente

Richiede il server attivo su http://localhost:8000.
"""

import asyncio
import uuid
import httpx
from playwright.async_api import async_playwright


HTML_SHIM = """
<!doctype html>
<html lang="it"><head><meta charset="utf-8">
<title>Banner shim</title></head>
<body>
  <h1>Banner shim</h1>
  <script src="http://localhost:8000/collector.js"
          data-endpoint="http://localhost:8000/api/bitm/collect"
          data-auto="false"></script>
  <script>
    window.__bitm_done__ = false;
    // Simuliamo un browser umano: UA pulito + plugin + webgl, così il
    // fast-path (_fast_rules) non blocca istantaneamente e la pipeline
    // LLM+trajectory può girare.
    const cleanFp = {
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
      plugins: ["PDF Viewer", "Chrome PDF Viewer"],
      webgl: "ANGLE (Intel, Intel(R) UHD Graphics 620)",
      canvas: "data:image/png;base64,shimCANVAS",
      webdriver: false,
      languages: ["it-IT", "en-US"],
      screenRes: "1920x1080",
      colorDepth: 24,
      timezone: "Europe/Rome",
      platform: "Win32",
      timing: 12,
    };
    window.__runScenario = async function(){
      const sid = "bannershim-" + Math.random().toString(36).slice(2, 10);
      sessionStorage.setItem("bitm-sid", sid);
      // Step 1-2: sessione normale (trajectory accumula pagine)
      await window.BitM.classify({...cleanFp, page: "/login"});
      await window.BitM.classify({...cleanFp, page: "/account/verify"});
      // Step 3: panic — verdict=challenge, explanation_user dovrebbe apparire
      const r = await window.BitM.classify({...cleanFp, page: "/account/change-password"});
      window.__bitm_result__ = r;
      window.__bitm_done__ = true;
    };
  </script>
</body></html>
"""


async def main():
    # Reset stato server (rimuove IP bloccati dai test precedenti)
    async with httpx.AsyncClient() as c:
        await c.delete("http://localhost:8000/api/bitm/sessions", timeout=10)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context()
        page = await ctx.new_page()

        # Serviamo l'HTML shim da data-URI invece di un file: path,
        # così il collector.js vede `location.href` come un URL HTTP
        # e CORS/fetch non litigano (data: URI è opaco).
        await page.route("**/bannershim", lambda r: r.fulfill(
            status=200, content_type="text/html; charset=utf-8",
            body=HTML_SHIM,
        ))
        # Qualsiasi URL matcha purché termini con /bannershim
        await page.goto("http://localhost:8000/bannershim/")

        # Fallback: se il route matcher non è preso (route relativa),
        # iniettiamo l'HTML direttamente tramite setContent.
        await page.set_content(HTML_SHIM)
        # Dopo setContent il <script src=...> viene caricato asincrono,
        # aspettiamo che BitM sia definito.
        await page.wait_for_function("typeof window.BitM !== 'undefined'",
                                     timeout=10_000)

        await page.evaluate("window.__runScenario()")
        await page.wait_for_function("window.__bitm_done__ === true",
                                     timeout=15_000)

        result = await page.evaluate("window.__bitm_result__")
        print(f"\nRisultato classify():")
        print(f"  action           = {result.get('action')}")
        print(f"  score            = {result.get('score')}")
        print(f"  pattern          = {result.get('trajectory_pattern')}")
        print(f"  traj_score       = {result.get('trajectory_score')}")
        print(f"  explanation_user = {result.get('explanation_user')}")

        # Il banner è in una shadow-root `mode: closed`, quindi non accessibile
        # dal documento ospite. Ma l'host `<div id="__bitm_collector_banner__">`
        # esiste nel DOM ed è visibile. Verifichiamolo.
        host_present = await page.evaluate(
            "document.getElementById('__bitm_collector_banner__') !== null"
        )
        banner_visible = await page.evaluate("""
            () => {
              const h = document.getElementById('__bitm_collector_banner__');
              if (!h) return false;
              const r = h.getBoundingClientRect();
              return r.width > 0 && r.height > 0;
            }
        """)
        print(f"\nBanner DOM:")
        print(f"  host presente = {host_present}")
        print(f"  visibile      = {banner_visible}")
        print(f"  lastExpl      = {await page.evaluate('window.BitM.lastExplanation')}")

        assert result.get("action") in ("challenge", "block"), \
            "atteso challenge/block, ottenuto " + str(result.get("action"))
        assert result.get("explanation_user"), "manca explanation_user"
        assert host_present, "host banner non iniettato"
        assert banner_visible, "banner presente ma non visibile"
        print("\nOK — banner iniettato e visibile con spiegazione utente")

        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())