"""
Event Broadcaster v6.1 — pub/sub in-process per la dashboard real-time.

Ogni richiesta a /api/bitm/collect produce un evento che viene pubblicato
a tutti i client WebSocket connessi a /ws/events. Il broadcaster mantiene
anche un ring buffer degli ultimi N eventi, inviato come backlog ai client
appena connessi in modo che la dashboard non parta vuota.

Il modulo è volutamente in-process (single-worker). Con più worker uvicorn
gli eventi sarebbero visti solo dal worker che ha servito la richiesta:
in quel caso bisogna promuovere il trasporto a Redis pub/sub.
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from typing import Any

from fastapi import WebSocket


class EventBroadcaster:
    def __init__(self, ring_size: int = 500) -> None:
        self._clients: set[WebSocket] = set()
        self._recent: deque[dict] = deque(maxlen=ring_size)
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)
        if self._recent:
            try:
                await ws.send_text(json.dumps({
                    "type":   "backlog",
                    "events": list(self._recent),
                }))
            except Exception:
                await self.disconnect(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)
        try:
            await ws.close()
        except Exception:
            pass

    async def publish(self, event: dict[str, Any]) -> None:
        self._recent.append(event)
        if not self._clients:
            return
        msg = json.dumps({"type": "event", "event": event}, default=str)
        async with self._lock:
            targets = list(self._clients)
        dead: list[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._clients.discard(ws)

    @property
    def client_count(self) -> int:
        return len(self._clients)

    def recent(self) -> list[dict]:
        return list(self._recent)


_broadcaster: EventBroadcaster | None = None


def get_broadcaster() -> EventBroadcaster:
    global _broadcaster
    if _broadcaster is None:
        _broadcaster = EventBroadcaster()
    return _broadcaster
