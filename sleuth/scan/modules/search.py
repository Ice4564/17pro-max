"""Search-engine module: where on the web does a username / e-mail show up?"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from ... import websearch
from ...sites import load_sites
from ..core import Context, Event, Module


class WebSearch(Module):
    name = "websearch"
    title = "ค้นใน search engine"
    description = ("ค้น \"username\" และ \"อีเมล\" พร้อม site:instagram.com, site:tiktok.com ฯลฯ ใน DuckDuckGo "
                   "(สำรองด้วย Bing) แล้วเก็บหน้าที่กล่าวถึงและโปรไฟล์ที่เจอ")
    category = "identity"
    group = "search"
    watches = ("USERNAME", "EMAIL")

    def __init__(self) -> None:
        self._lock = asyncio.Lock()  # one search at a time per scan: engines block bursts
        self._engines = websearch.default_engines()  # shared, so a block is remembered for the whole scan

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        value = event.data.strip().lstrip("@")
        if not ctx.take("search", value.lower()):
            return
        async with self._lock:
            out = await websearch.search(ctx.session, [value], max_queries=4 if event.type == "USERNAME" else 1,
                                         timeout=ctx.cfg.timeout, engines=self._engines, sites=load_sites())
        for h in out["hits"]:
            if h.get("platform") and h.get("handle") and (h["same_handle"] or h["mentions"]):
                yield event.child("SOCIAL_PROFILE", h["url"], self.name, platform=h["platform"], handle=h["handle"],
                                  engine=h["engine"], query=h["query"])
            elif h["mentions"]:
                yield event.child("WEB_MENTION", h["url"], self.name, title=h["title"], snippet=h["snippet"],
                                  engine=h["engine"], query=h["query"])
