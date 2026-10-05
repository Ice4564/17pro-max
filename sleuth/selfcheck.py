"""Verify each site's detection rule against the live site.

For every site we look up the known-claimed username (must be FOUND) and a
random username (must be NOT_FOUND). Sites that fail can be disabled.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from .engine import SearchConfig, Status, check_site, make_session, random_username
from .sites import Site


@dataclass
class CheckOutcome:
    site: Site
    claimed: Status
    unclaimed: Status
    note: str = ""

    @property
    def ok(self) -> bool:
        return self.claimed is Status.FOUND and self.unclaimed is Status.NOT_FOUND


async def self_check(sites: list[Site], cfg: SearchConfig, on_result=None) -> list[CheckOutcome]:
    cfg = SearchConfig(**{**cfg.__dict__, "extract": False})
    sites = [s for s in sites if s.check != "manual"]  # nothing to verify automatically
    sem = asyncio.Semaphore(cfg.concurrency)

    async with make_session(cfg) as session:

        async def one(site: Site) -> CheckOutcome:
            async with sem:
                fake = random_username()
                if not site.valid(fake):
                    fake = "zz" + fake[-8:]
                good, bad = await asyncio.gather(
                    check_site(session, site, site.claimed, cfg),
                    check_site(session, site, fake, cfg),
                )
            notes = []
            if good.status is not Status.FOUND:
                notes.append(f"claimed '{site.claimed}' -> {good.status.value}"
                             f" (HTTP {good.http_status}{', ' + good.error if good.error else ''})")
            if bad.status is not Status.NOT_FOUND:
                notes.append(f"random '{fake}' -> {bad.status.value}"
                             f" (HTTP {bad.http_status}{', ' + bad.error if bad.error else ''})")
            outcome = CheckOutcome(site, good.status, bad.status, "; ".join(notes))
            if on_result:
                on_result(outcome)
            return outcome

        return list(await asyncio.gather(*(one(s) for s in sites)))
