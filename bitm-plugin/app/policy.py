"""
Policy Engine v5
Fix T11: boost calcolato su set deduplicato (indicators ∪ confirmed_signals),
cap a MAX_BOOST=0.25 per evitare che segnali deboli superino la soglia BLOCK.
"""

from enum import Enum


class Action(Enum):
    ALLOW     = "allow"
    CHALLENGE = "challenge"
    BLOCK     = "block"


# ── Path prefixes per il rilevamento del contesto ─────────────────────────────
_LOGIN_PREFIXES   = ("/login", "/signin", "/auth", "/accedi", "/logon", "/entrar")
_PAYMENT_PREFIXES = ("/payment", "/checkout", "/pay", "/pagamento", "/ordine", "/order")
_ADMIN_PREFIXES   = ("/admin", "/settings", "/account", "/profilo", "/profile", "/manage")
_STATIC_EXTS      = (".js", ".css", ".png", ".jpg", ".jpeg", ".svg",
                     ".ico", ".woff", ".woff2", ".ttf", ".map")


# ── Soglie per contesto (CHALLENGE, BLOCK) ────────────────────────────────────
THRESHOLDS = {
    "default": (0.40, 0.75),
    "login":   (0.28, 0.62),
    "payment": (0.20, 0.55),
    "admin":   (0.22, 0.60),   # abbassato challenge: timezone anomaly su account deve triggerare
    "static":  (0.70, 0.92),
}


# ── Segnali → BLOCK immediato ─────────────────────────────────────────────────
# I label BitM/BitM+ sono allineati con extractor._detect_bitm e con i fast_rules
# in main.py (label-set identici su entrambi i lati per il "short-circuit").
CRITICAL_BLOCK = frozenset({
    # Automation / headless
    "headlesschrome_ua", "phantomjs_ua", "slimerjs_ua", "jsdom_ua",
    "webdriver_true",
    "headless_ua", "webdriver_flag",
    "no_plugins_no_webgl",
    "extreme_latency",
    "tor_exit_node",
    # BitM / BitM+ — stack documentati in Tommasi 2021, Tzschoppe 2023,
    # Catalano 2025 (vedi README §Segnali BitM/BitM+).
    "novnc_client_marker",      # document.title "noVNC"
    "guacamole_client_marker",  # document.title "Guacamole"
    "bitm_framework_ua",        # UA rivela noVNC/Websockify/Guacamole/TigerVNC
    "bitm_backend_port",        # :3081/:6080/:4822/:5900 visibili al client
    "xss_reflected_param",      # xURL con loadFromAttacker/onerror/<script>
    "webauthn_api_override",    # navigator.credentials.get non nativo → evilGet
    "bitm_websocket_transport", # WebSocket su dominio tunneling o websockify
})

# ── Segnali deboli che amplificano lo score in contesti sensibili ─────────────
# Pesi individuali: segnali più forti valgono di più
_AMPLIFIER_WEIGHTS: dict[str, float] = {
    "vpn_detected":          0.16,   # VPN su pagina sensibile → challenge quasi certo
    "swiftshader_webgl":     0.10,
    "zero_plugins":          0.03,  # Chrome moderno ha sempre 0 plugin
    "no_webgl_renderer":     0.05,  # GPU disabilitata può essere legittima
    "empty_canvas":          0.07,
    "no_languages":          0.08,
    "no_timezone":           0.06,
    "suspicious_resolution": 0.06,
    "timezone_anomaly":      0.12,   # UTC + lingua non-EN su admin è genuinamente sospetto
    # Latenza: amplificata solo su contesti sensibili. La soglia extreme
    # è già in CRITICAL_BLOCK, quindi qui pesiamo solo high/elevated.
    "high_latency":          0.12,   # 300-600ms → su /payment porta sopra challenge
    "elevated_latency":      0.05,
    # BitM+ infrastruttura "debole" (ngrok può essere legittimo in dev):
    # alzare soglia su login/payment/admin, non sufficiente da solo in default.
    "tunnel_host":           0.18,
    "iframe_overlay":        0.10,
}
# Cap: il boost totale non può superare questo valore
# → impedisce che combinazioni di segnali deboli superino la soglia BLOCK
MAX_BOOST = 0.25

# Boost separato del layer trajectory (v7.4). Cappato indipendentemente
# da MAX_BOOST così un `trajectory_score` alto può spingere challenge→block
# senza però permettere alla sola traiettoria di arrivare al block su uno
# score fingerprint pulito: admin-block=0.60 > CAP=0.25, quindi la soglia
# richiede ancora che il fingerprint o i segnali abbiano contribuito.
TRAJ_BOOST_CAP = 0.25


def detect_page_context(path: str) -> str:
    """Deduce il contesto di sicurezza dalla URL."""
    p = path.lower().split("?")[0].split("#")[0]
    for prefix in _LOGIN_PREFIXES:
        if p == prefix or p.startswith(prefix + "/"):
            return "login"
    for prefix in _PAYMENT_PREFIXES:
        if p == prefix or p.startswith(prefix + "/"):
            return "payment"
    for prefix in _ADMIN_PREFIXES:
        if p == prefix or p.startswith(prefix + "/"):
            return "admin"
    if any(p.endswith(ext) for ext in _STATIC_EXTS):
        return "static"
    return "default"


def decide(score_result: dict, context: str = "default",
           features: dict | None = None,
           trajectory_score: float = 0.0) -> tuple[Action, str]:
    """
    Determina l'azione finale.

    Priorità:
    1. Segnali critici (BLOCK immediato, indipendente dallo score)
    2. pre_risk_score come floor dello score LLM
    3. Boost contestuale (cappato a MAX_BOOST) su set deduplicato
    4. Trajectory boost (cappato a TRAJ_BOOST_CAP) — non è un floor
    5. Soglie contestuali

    Effetto collaterale: aggiorna `score_result["risk_score"]` con lo score
    amplificato effettivamente usato, così il chiamante può riportarlo al
    client (altrimenti UI e action risulterebbero incoerenti: es.
    score=0.40 + action=block).
    """
    # ATTENZIONE: usare `or` con score è sbagliato perché 0.0 è falsy in Python
    # → `0.0 or 0.5` restituisce 0.5. Usare sempre controllo esplicito su None.
    _raw_score  = score_result.get("risk_score")
    score       = float(_raw_score) if _raw_score is not None else 0.5
    explanation = str(score_result.get("explanation") or "")
    # Set di tutti gli indicators: dall'LLM + dall'extractor (deduplicati)
    indicators  = set(score_result.get("indicators") or [])

    if features:
        confirmed = set(features.get("confirmed_signals") or [])
        indicators |= confirmed

        # pre_risk_score come floor: il LLM non può abbassare ciò che è già certo
        _raw_pre = features.get("pre_risk_score")
        pre      = float(_raw_pre) if _raw_pre is not None else 0.0
        if pre > score:
            score = pre
            explanation = f"[pre_score={pre:.2f}] {explanation}"

    # 1. Segnali critici → BLOCK immediato
    critical_found = indicators & CRITICAL_BLOCK
    if critical_found:
        label = ", ".join(sorted(critical_found)[:3])
        score_result["risk_score"] = max(score, 0.97)
        return Action.BLOCK, f"Segnale critico: {label}"

    # 2. Boost contestuale su set deduplicato, con pesi individuali e cap
    amplified = score
    if context in ("login", "payment", "admin"):
        # Un segnale contribuisce al boost una sola volta (set già deduplicato)
        raw_boost = sum(
            _AMPLIFIER_WEIGHTS[s]
            for s in indicators
            if s in _AMPLIFIER_WEIGHTS
        )
        boost     = min(raw_boost, MAX_BOOST)
        amplified = min(1.0, score + boost)
        if boost > 0:
            explanation = f"[ctx={context} boost={boost:.2f}] {explanation}"

    # 3. Trajectory boost — applicato dopo il boost contestuale, cap separato.
    # Serve a spingere sopra soglia quando la sequenza di pagine rivela un
    # pattern post-compromissione; non può mai declassare. Trajectory_score è
    # già un rischio 0-1, quindi contribuisce direttamente ma capato a 0.25
    # per non potere, da solo, flippare un fingerprint pulito in block.
    t_raw = max(0.0, min(1.0, float(trajectory_score or 0.0)))
    if t_raw > 0:
        traj_boost = min(TRAJ_BOOST_CAP, t_raw)
        amplified  = min(1.0, amplified + traj_boost)
        explanation = f"[traj={t_raw:.2f} +{traj_boost:.2f}] {explanation}"

    # 4. Soglie contestuali
    thresh_challenge, thresh_block = THRESHOLDS.get(context, THRESHOLDS["default"])

    # Sovrascrivi lo score esposto con quello amplificato (riflette la decisione).
    score_result["risk_score"] = round(amplified, 3)

    if amplified >= thresh_block:
        return Action.BLOCK, explanation
    if amplified >= thresh_challenge:
        return Action.CHALLENGE, explanation
    return Action.ALLOW, explanation
