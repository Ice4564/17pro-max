"""Archive intelligence: Wayback Machine, archive.today, Google Cache.

Check archived versions of profiles, find deleted content, and track
how a profile looked at different points in time.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import quote

import aiohttp

# ---- constants ----------------------------------------------------------

WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
WAYBACK_AVAIL = "https://archive.org/wayback/available"
ARCHIVE_TODAY = "https://archive.ph"
GOOGLE_CACHE = "https://webcache.googleusercontent.com/search?q=cache:"

# ---- data classes -------------------------------------------------------


@dataclass
class Snapshot:
    """A single archived snapshot of a URL."""

    url: str
    timestamp: str  # YYYYMMDDHHMMSS
    status_code: int
    snapshot_url: str
    mime_type: str = ""
    digest: str = ""

    @property
    def dt(self) -> datetime | None:
        try:
            return datetime.strptime(self.timestamp, "%Y%m%d%H%M%S")
        except (ValueError, TypeError):
            return None

    @property
    def display_date(self) -> str:
        dt = self.dt
        return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else self.timestamp


@dataclass
class ArchiveResult:
    """Archive lookup result for a single URL."""

    url: str
    snapshots: list[Snapshot] = field(default_factory=list)
    earliest: Snapshot | None = None
    latest: Snapshot | None = None
    total_snapshots: int = 0
    archive_today_url: str | None = None
    google_cache_url: str | None = None
    error: str | None = None


# ---- Wayback Machine ----------------------------------------------------


async def wayback_snapshots(
    session: aiohttp.ClientSession,
    url: str,
    *,
    limit: int = 50,
    from_ts: str | None = None,
    to_ts: str | None = None,
) -> list[Snapshot]:
    """Query the Wayback CDX API for all snapshots of *url*.

    Returns a list of :class:`Snapshot` sorted oldest-first.
    """
    params: dict[str, str] = {
        "url": url,
        "output": "json",
        "fl": "timestamp,statuscode,mimetype,digest",
        "limit": str(limit),
        "filter": "statuscode:200",
    }
    if from_ts:
        params["from"] = from_ts
    if to_ts:
        params["to"] = to_ts

    try:
        async with session.get(WAYBACK_CDX, params=params, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return []

    if not data or len(data) < 2:
        return []

    # data[0] is the header row; subsequent rows are snapshots
    snapshots: list[Snapshot] = []
    for row in data[1:]:
        if len(row) < 4:
            continue
        ts, status, mime, digest = row[0], row[1], row[2], row[3]
        try:
            sc = int(status)
        except (ValueError, TypeError):
            sc = 0
        snap_url = f"https://web.archive.org/web/{ts}/{url}"
        snapshots.append(Snapshot(
            url=url, timestamp=ts, status_code=sc,
            snapshot_url=snap_url, mime_type=mime, digest=digest,
        ))

    snapshots.sort(key=lambda s: s.timestamp)
    return snapshots


async def wayback_available(
    session: aiohttp.ClientSession, url: str
) -> Snapshot | None:
    """Check if Wayback has at least one snapshot of *url* (quick check)."""
    params = {"url": url}
    try:
        async with session.get(WAYBACK_AVAIL, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return None

    snap_data = data.get("archived_snapshots", {}).get("closest", {})
    if not snap_data or not snap_data.get("available"):
        return None

    ts = snap_data.get("timestamp", "")
    snap_url = snap_data.get("url", "")
    try:
        sc = int(snap_data.get("status", "200"))
    except (ValueError, TypeError):
        sc = 200

    return Snapshot(url=url, timestamp=ts, status_code=sc, snapshot_url=snap_url)


async def wayback_diff(
    session: aiohttp.ClientSession, url: str
) -> dict[str, Any]:
    """Find the earliest and latest snapshots to show how a profile changed.

    Returns ``{"earliest": Snapshot, "latest": Snapshot, "count": int}``.
    """
    snaps = await wayback_snapshots(session, url, limit=200)
    if not snaps:
        return {"earliest": None, "latest": None, "count": 0, "snapshots": []}
    return {
        "earliest": snaps[0],
        "latest": snaps[-1],
        "count": len(snaps),
        "snapshots": snaps,
    }


# ---- archive.today ------------------------------------------------------


async def archive_today_lookup(
    session: aiohttp.ClientSession, url: str
) -> str | None:
    """Check archive.today for saved snapshots of *url*.

    Returns the archive.today snapshot URL if found, else None.
    """
    search_url = f"{ARCHIVE_TODAY}/newest/{url}"
    try:
        async with session.get(
            search_url,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            if resp.status == 200 and "archive.today" in str(resp.url):
                return str(resp.url)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass
    return None


# ---- Google Cache -------------------------------------------------------


def google_cache_url(url: str) -> str:
    """Build a Google Cache URL for *url*."""
    return f"{GOOGLE_CACHE}{quote(url, safe='')}"


# ---- combined lookup ----------------------------------------------------


async def check_archives(
    session: aiohttp.ClientSession, url: str
) -> ArchiveResult:
    """Check all archive sources for *url* in parallel.

    Returns an :class:`ArchiveResult` with Wayback snapshots,
    archive.today link, and Google Cache link.
    """
    wb_task = wayback_snapshots(session, url)
    at_task = archive_today_lookup(session, url)

    snaps, at_url = await asyncio.gather(wb_task, at_task, return_exceptions=True)

    if isinstance(snaps, Exception):
        snaps = []
    if isinstance(at_url, Exception):
        at_url = None

    result = ArchiveResult(
        url=url,
        snapshots=snaps,
        earliest=snaps[0] if snaps else None,
        latest=snaps[-1] if snaps else None,
        total_snapshots=len(snaps),
        archive_today_url=at_url,
        google_cache_url=google_cache_url(url),
    )
    return result


async def check_archives_batch(
    session: aiohttp.ClientSession,
    urls: list[str],
    *,
    max_concurrent: int = 5,
) -> list[ArchiveResult]:
    """Check archives for multiple URLs with concurrency limit."""
    sem = asyncio.Semaphore(max_concurrent)

    async def _one(u: str) -> ArchiveResult:
        async with sem:
            return await check_archives(session, u)

    return await asyncio.gather(*[_one(u) for u in urls])


# ---- profile change detection via archives ------------------------------


def detect_deleted_content(
    snapshots: list[Snapshot],
    current_status: str = "found",
) -> dict[str, Any]:
    """Compare archived snapshots with current status to detect deletions.

    If the URL was archived as 200 OK but the current search says not found,
    the profile may have been deleted.
    """
    if not snapshots:
        return {"deleted": False, "reason": "no archives"}

    had_content = any(s.status_code == 200 for s in snapshots)
    is_gone = current_status in ("not_found", "unknown")

    if had_content and is_gone:
        latest_snap = max(snapshots, key=lambda s: s.timestamp)
        return {
            "deleted": True,
            "reason": f"archived as 200 on {latest_snap.display_date}, now {current_status}",
            "last_seen": latest_snap.display_date,
            "snapshot_url": latest_snap.snapshot_url,
        }
    return {"deleted": False, "reason": "profile still active or never archived"}


# ---- URL builders -------------------------------------------------------


def wayback_url(url: str, timestamp: str | None = None) -> str:
    """Build a Wayback Machine URL for *url*, optionally at *timestamp*."""
    if timestamp:
        return f"https://web.archive.org/web/{timestamp}/{url}"
    return f"https://web.archive.org/web/*/{url}"
