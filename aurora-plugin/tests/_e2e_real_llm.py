"""E2E check on a real LLM backend — fires a panic trajectory and prints the full
response so we can read the LLM-generated `explanation_user` / `explanation_admin`.

Usage:  python tests/_e2e_real_llm.py  (server must be running)
"""

import asyncio
import json
import uuid
import httpx


BASE = "http://localhost:8000"


def legit_payload(sid, page):
    return {
        "sessionId": sid, "page": page,
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "plugins": ["PDF Viewer", "Chrome PDF Viewer"],
        "webgl": "ANGLE (Intel, Intel(R) UHD Graphics 620)",
        "canvas": "data:image/png;base64,realsess",
        "webdriver": False, "languages": ["it-IT", "en-US"],
        "screenRes": "1920x1080", "colorDepth": 24,
        "timezone": "Europe/Rome", "platform": "Win32", "timing": 12,
    }


async def scenario(client, label, pages, sid_prefix):
    sid = f"{sid_prefix}-{uuid.uuid4().hex[:8]}"
    print(f"\n── {label} ({sid}) ──")
    last = None
    for p in pages:
        r = await client.post(f"{BASE}/api/bitm/collect",
                              json=legit_payload(sid, p), timeout=90)
        last = r.json()
        print(f"  POST {p:35s} → action={last.get('action'):9s} "
              f"score={last.get('score')}  "
              f"traj={last.get('trajectory_score', '-')}  "
              f"pattern={last.get('trajectory_pattern', '-')}")
    if last.get("explanation_user"):
        print(f"  explanation_user : {last['explanation_user']}")
    if last.get("explanation_admin"):
        print(f"  explanation_admin: {last['explanation_admin']}")


async def main():
    async with httpx.AsyncClient() as client:
        health = (await client.get(f"{BASE}/health", timeout=5)).json()
        print(f"backend={health['backend']}  model={health['model']}  "
              f"trajectory={health['trajectory_analysis']}")
        await client.delete(f"{BASE}/api/bitm/sessions", timeout=10)

        await scenario(client, "Panic password change",
                       ["/login", "/account/verify", "/account/change-password"],
                       "panic")

        await client.delete(f"{BASE}/api/bitm/sessions", timeout=10)
        await scenario(client, "Direct admin access",
                       ["/home", "/admin"],
                       "admin")

        await client.delete(f"{BASE}/api/bitm/sessions", timeout=10)
        await scenario(client, "Insufficient history (short-circuit)",
                       ["/home"],
                       "shortcircuit")

        await client.delete(f"{BASE}/api/bitm/sessions", timeout=10)
        await scenario(client, "Normal flow baseline",
                       ["/home", "/products", "/cart"],
                       "normal")


if __name__ == "__main__":
    asyncio.run(main())
