"""
Redis Session Store v6.

Persiste sessioni utente, IP bloccati e finestre di rate-limit su Redis,
così da condividerle in ambienti multi-processo / multi-istanza.

Fallback in-memory automatico se Redis non è raggiungibile: il sistema
continua a funzionare (in modalità single-process) senza interruzioni.

Chiavi usate (prefisso configurabile via REDIS_KEY_PREFIX):
  {prefix}session:{sid}   hash JSON (TTL = REDIS_SESSION_TTL)
  {prefix}blocked         set di IP bloccati
  {prefix}rate:{ip}       sorted-set (timestamp → timestamp) con TTL

L'API è interamente async per integrarsi con FastAPI senza bloccare
l'event loop.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from typing import Any

try:
    import redis.asyncio as redis_async  # type: ignore
    _REDIS_AVAILABLE = True
except Exception:
    _REDIS_AVAILABLE = False

from app.config import REDIS_URL, REDIS_SESSION_TTL, REDIS_KEY_PREFIX


class SessionStore:
    """
    Store unificato per sessioni, blocked-IP e rate-limit.
    Tenta Redis; in caso di fallimento fallback a dict/deque in-memory.
    """

    def __init__(
        self,
        url: str = REDIS_URL,
        ttl: int = REDIS_SESSION_TTL,
        prefix: str = REDIS_KEY_PREFIX,
    ) -> None:
        self._url    = url
        self._ttl    = ttl
        self._prefix = prefix
        self._client: Any | None = None
        self._connected = False

        # Fallback in-memory
        self._mem_sessions: dict[str, dict] = {}
        self._mem_blocked:  set[str]        = set()
        self._mem_rate:     dict[str, deque] = defaultdict(deque)

    # ── Connection lifecycle ─────────────────────────────────────────────

    async def connect(self) -> bool:
        if not _REDIS_AVAILABLE:
            print("[redis] client non installato, uso fallback in-memory")
            return False
        try:
            self._client = redis_async.from_url(
                self._url, encoding="utf-8", decode_responses=True,
                socket_connect_timeout=2, socket_timeout=2,
            )
            await self._client.ping()
            self._connected = True
            print(f"[redis] connesso a {self._url}")
            return True
        except Exception as e:
            print(f"[redis] connessione fallita ({e}), fallback in-memory")
            self._client = None
            self._connected = False
            return False

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.close()
            except Exception:
                pass
        self._client = None
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def backend(self) -> str:
        return "redis" if self._connected else "memory"

    # ── Key helpers ──────────────────────────────────────────────────────

    def _k_session(self, sid: str) -> str: return f"{self._prefix}session:{sid}"
    def _k_blocked(self)           -> str: return f"{self._prefix}blocked"
    def _k_rate(self, ip: str)     -> str: return f"{self._prefix}rate:{ip}"

    # ── Sessions ─────────────────────────────────────────────────────────

    async def get_session(self, sid: str) -> dict | None:
        if self._connected:
            try:
                raw = await self._client.get(self._k_session(sid))
                return json.loads(raw) if raw else None
            except Exception as e:
                print(f"[redis] get_session degraded: {e}")
                self._connected = False
        return self._mem_sessions.get(sid)

    async def set_session(self, sid: str, data: dict) -> None:
        if self._connected:
            try:
                await self._client.set(
                    self._k_session(sid),
                    json.dumps(data, default=str),
                    ex=self._ttl,
                )
                return
            except Exception as e:
                print(f"[redis] set_session degraded: {e}")
                self._connected = False
        self._mem_sessions[sid] = data

    async def clear_sessions(self) -> int:
        count = 0
        if self._connected:
            try:
                pattern = f"{self._prefix}session:*"
                async for key in self._client.scan_iter(match=pattern, count=200):
                    await self._client.delete(key)
                    count += 1
            except Exception as e:
                print(f"[redis] clear_sessions degraded: {e}")
                self._connected = False
        count += len(self._mem_sessions)
        self._mem_sessions.clear()
        return count

    async def session_count(self) -> int:
        n = 0
        if self._connected:
            try:
                pattern = f"{self._prefix}session:*"
                async for _ in self._client.scan_iter(match=pattern, count=200):
                    n += 1
                return n
            except Exception as e:
                print(f"[redis] session_count degraded: {e}")
                self._connected = False
        return len(self._mem_sessions)

    async def recent_sessions(self, limit: int = 20) -> dict[str, dict]:
        out: dict[str, dict] = {}
        if self._connected:
            try:
                pattern = f"{self._prefix}session:*"
                keys: list[str] = []
                async for key in self._client.scan_iter(match=pattern, count=200):
                    keys.append(key)
                    if len(keys) >= limit:
                        break
                if keys:
                    values = await self._client.mget(keys)
                    for key, raw in zip(keys, values):
                        if not raw:
                            continue
                        sid = key.split(":", 2)[-1]
                        try:
                            out[sid] = json.loads(raw)
                        except Exception:
                            continue
                return out
            except Exception as e:
                print(f"[redis] recent_sessions degraded: {e}")
                self._connected = False
        for sid, store in list(self._mem_sessions.items())[-limit:]:
            out[sid] = store
        return out

    # ── Blocked IPs ──────────────────────────────────────────────────────

    async def is_blocked(self, ip: str) -> bool:
        if self._connected:
            try:
                return bool(await self._client.sismember(self._k_blocked(), ip))
            except Exception as e:
                print(f"[redis] is_blocked degraded: {e}")
                self._connected = False
        return ip in self._mem_blocked

    async def add_blocked(self, ip: str) -> None:
        if self._connected:
            try:
                await self._client.sadd(self._k_blocked(), ip)
                return
            except Exception as e:
                print(f"[redis] add_blocked degraded: {e}")
                self._connected = False
        self._mem_blocked.add(ip)

    async def blocked_list(self) -> list[str]:
        if self._connected:
            try:
                return sorted(await self._client.smembers(self._k_blocked()))
            except Exception as e:
                print(f"[redis] blocked_list degraded: {e}")
                self._connected = False
        return sorted(self._mem_blocked)

    async def blocked_count(self) -> int:
        if self._connected:
            try:
                return int(await self._client.scard(self._k_blocked()))
            except Exception as e:
                print(f"[redis] blocked_count degraded: {e}")
                self._connected = False
        return len(self._mem_blocked)

    async def clear_blocked(self) -> None:
        if self._connected:
            try:
                await self._client.delete(self._k_blocked())
            except Exception as e:
                print(f"[redis] clear_blocked degraded: {e}")
                self._connected = False
        self._mem_blocked.clear()

    # ── Rate limit (sliding window) ──────────────────────────────────────

    async def rate_check(self, ip: str, limit: int, window_s: int) -> bool:
        """
        True se l'IP è entro la soglia (richiesta accettata), False se va bloccato.
        Implementato come sliding window: elimina timestamp scaduti e contrae.

        Nota: il timestamp viene inserito SOLO se la richiesta è accettata,
        per evitare che richieste rifiutate gonfino la finestra e causino
        rigetti futuri. Comportamento allineato al ramo in-memory.
        """
        now = time.time()
        cutoff = now - window_s

        if self._connected:
            try:
                key = self._k_rate(ip)
                # Fase 1: pulisci e conta (senza inserire)
                pipe = self._client.pipeline()
                pipe.zremrangebyscore(key, 0, cutoff)
                pipe.zcard(key)
                _, count = await pipe.execute()
                if int(count) >= limit:
                    return False
                # Fase 2: inseriamo solo se accettato
                pipe = self._client.pipeline()
                # Membro unico: timestamp + ip — evita collisioni tra richieste
                # dello stesso micro-secondo (molto rare ma possibili).
                member = f"{now}:{ip}"
                pipe.zadd(key, {member: now})
                pipe.expire(key, window_s + 1)
                await pipe.execute()
                return True
            except Exception as e:
                print(f"[redis] rate_check degraded: {e}")
                self._connected = False

        window = self._mem_rate[ip]
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= limit:
            return False
        window.append(now)
        return True

    async def clear_rate(self) -> None:
        if self._connected:
            try:
                pattern = f"{self._prefix}rate:*"
                async for key in self._client.scan_iter(match=pattern, count=200):
                    await self._client.delete(key)
            except Exception as e:
                print(f"[redis] clear_rate degraded: {e}")
                self._connected = False
        self._mem_rate.clear()


# Singleton applicativo
_store: SessionStore | None = None


def get_store() -> SessionStore:
    global _store
    if _store is None:
        _store = SessionStore()
    return _store
