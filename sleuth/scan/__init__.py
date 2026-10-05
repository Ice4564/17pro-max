"""SpiderFoot-style multi-target scanning (domains, IPs, emails, usernames)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from .core import EVENT_TYPES, Event, ScanConfig, Scanner, detect_target
from .modules import ALL_MODULES, get_modules
from .store import Store

__all__ = ["EVENT_TYPES", "Event", "ScanConfig", "Scanner", "Store", "detect_target",
           "ALL_MODULES", "get_modules", "run_scan"]


async def run_scan(target: str, modules: list | None = None, cfg: ScanConfig | None = None,
                   store: Store | None = None) -> AsyncIterator[dict[str, Any]]:
    """Run a scan, persist it (if ``store`` is given) and stream messages."""
    scanner = Scanner(target, modules or get_modules(), cfg)
    scan_id = store.new_scan(scanner.root.data, scanner.root.type, [m.name for m in scanner.modules]) if store else None
    status = "finished"
    gen = scanner.run()
    n = 0
    try:
        async for msg in gen:
            if msg["type"] == "start":
                msg["scan_id"] = scan_id
            elif store and msg["type"] == "event":
                store.add_event(scan_id, msg["event"])
                n += 1
                if n % 50 == 0:
                    store.commit()
            elif store and msg["type"] == "finding":
                store.add_finding(scan_id, msg)
            yield msg
    except (asyncio.CancelledError, GeneratorExit):
        status = "aborted"
        raise
    finally:
        await gen.aclose()
        if store:
            store.finish(scan_id, status, scanner.counts())
