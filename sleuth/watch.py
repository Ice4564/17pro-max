"""Watchlist: re-check targets on a schedule and report only what changed.

    WATCHLIST
    ice4564
    ├─ New account detected      (an account that did not exist last time)
    ├─ Bio changed
    ├─ Username changed          (a profile links to the same platform under a new handle)
    └─ New external link

The web server runs due targets in the background while it is open; the
CLI's ``--watch-run`` does the same once, for Windows Task Scheduler / cron.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .engine import SearchConfig, Searcher
from .history import History
from .sites import Site

DEFAULT_INTERVAL_HOURS = 24


def config_for(options: dict[str, Any]) -> SearchConfig:
    return SearchConfig(depth=int(options.get("depth", 1)), variants=bool(options.get("variants", False)),
                        web_search=bool(options.get("websearch", False)), archive=False,
                        avatars=bool(options.get("avatars", True)), cache=False, host_interval=0.3,
                        timeout=float(options.get("timeout", 12)))


async def check_target(history: History, target: str, options: dict[str, Any], sites: list[Site],
                       all_sites: list[Site]) -> dict[str, Any]:
    """Search one watched target and store an alert if anything changed."""
    searcher = Searcher(sites, config_for(options), all_sites=all_sites, history=history)
    try:
        done: dict[str, Any] = {}
        async for ev in searcher.run([target]):
            if ev["type"] == "done":
                done = ev
    except Exception as e:  # one broken target must not stop the others
        history.watch_done(target, None, [], error=f"{type(e).__name__}: {e}"[:200])
        return {"target": target, "error": str(e), "changes": []}
    changes = done.get("changes", [])
    history.watch_done(target, done.get("run_id"), changes)
    return {"target": target, "run_id": done.get("run_id"), "changes": changes,
            "found": done.get("summary", {}).get("accounts_found", 0)}


async def run_due(history: History, sites: list[Site], all_sites: list[Site], targets: list[str] | None = None,
                  on_result: Callable[[dict[str, Any]], None] | None = None) -> list[dict[str, Any]]:
    """Check every due target (or the named ones, due or not)."""
    items = history.watch_list() if targets else history.watch_due()
    if targets:
        wanted = {t.lower().lstrip("@") for t in targets}
        items = [w for w in items if w["target"].lower() in wanted]
    out = []
    for w in items:
        res = await check_target(history, w["target"], w["options"], sites, all_sites)
        out.append(res)
        if on_result:
            on_result(res)
    return out
