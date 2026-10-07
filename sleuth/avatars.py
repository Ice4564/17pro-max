"""Profile-picture matching across found accounts.

Each avatar is reduced to a 64-bit difference hash (dHash). Two avatars
whose hashes differ in only a few bits are visually the same picture, which
is good evidence that two accounts belong to the same person. Needs Pillow;
without it this step is skipped.
"""

from __future__ import annotations

import asyncio
import io
import re
from typing import Any

import aiohttp

try:
    from PIL import Image, ImageStat
except ImportError:  # pragma: no cover - optional dependency
    Image = None  # type: ignore[assignment]

MAX_BYTES = 2_000_000
MAX_DISTANCE = 6      # bits out of 64
MAX_GROUP = 8         # bigger groups are a shared default/placeholder image
# Default "no photo" images that many accounts share (e.g. Mastodon's missing.png)
PLACEHOLDER_URL = re.compile(
    r"missing\.png|default[_-]?(avatar|profile|user)|avatar[_-]?default|no[_-]?avatar|placeholder|"
    r"blank[_-]?(avatar|profile)|anonymous|/identicon|gravatar\.com/avatar/0+|d=mp|d=mm|"
    # site-wide share images picked up from og:image, not the user's picture
    r"opengraph|og[_-]?image|social[_-]?(card|preview)|share[_-]?(image|card)|subscribe-card|/logo[^/]*\.\w+$|"
    r"banner|favicon|apple-touch-icon", re.I)


def available() -> bool:
    return Image is not None


def dhash(data: bytes) -> int | None:
    """64-bit difference hash, or None for blank/flat placeholder images."""
    img = Image.open(io.BytesIO(data))
    img.seek(0)
    gray = img.convert("L")
    if ImageStat.Stat(gray).stddev[0] < 12:  # near-uniform: default "no photo" icon
        return None
    small = gray.resize((9, 8), Image.Resampling.LANCZOS)
    px = list(small.tobytes())  # one byte per pixel in "L" mode
    bits = 0
    for row in range(8):
        for col in range(8):
            bits = (bits << 1) | (px[row * 9 + col] > px[row * 9 + col + 1])
    return bits


async def _fetch_hash(session: aiohttp.ClientSession, url: str, sem: asyncio.Semaphore) -> int | None:
    from .engine import read_body  # local import: engine imports this module

    async with sem:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status != 200 or not r.headers.get("Content-Type", "").startswith("image/"):
                    return None
                data = await read_body(r, MAX_BYTES)
        except Exception:
            return None
    try:
        return await asyncio.to_thread(dhash, data)
    except Exception:  # unsupported/broken image
        return None


async def hash_avatars(session: aiohttp.ClientSession, results: list[dict[str, Any]],
                       limit: int = 60) -> dict[tuple[str, str], int]:
    """``{(site, username): dhash}`` for every found account with a usable avatar."""
    if not available():
        return {}
    found = [r for r in results if r["status"] == "found"
             and str(r.get("info", {}).get("avatar", "")).startswith("http")
             and not PLACEHOLDER_URL.search(r["info"]["avatar"])]
    found = found[:limit]
    sem = asyncio.Semaphore(8)
    hashes = await asyncio.gather(*(_fetch_hash(session, r["info"]["avatar"], sem) for r in found))
    return {(r["site"].lower(), r["username"].lower()): h for r, h in zip(found, hashes) if h is not None}


def distance(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def match_hashes(results: list[dict[str, Any]],
                 hashes: dict[tuple[str, str], int]) -> dict[tuple[str, str], list[str]]:
    """Return ``{(site, username): ["Other Site (@user)", ...]}`` for look-alike avatars."""
    items = [(r, hashes[k]) for r in results
             if (k := (r["site"].lower(), r["username"].lower())) in hashes]
    matches: dict[tuple[str, str], list[str]] = {}
    for i, (a, ha) in enumerate(items):
        group = [b for j, (b, hb) in enumerate(items)
                 if j != i and b["site"] != a["site"] and distance(ha, hb) <= MAX_DISTANCE]
        if group and len(group) < MAX_GROUP:
            matches[(a["site"].lower(), a["username"].lower())] = [f"{b['site']} (@{b['username']})" for b in group]
    return matches


async def match_avatars(session: aiohttp.ClientSession, results: list[dict[str, Any]],
                        limit: int = 60) -> dict[tuple[str, str], list[str]]:
    return match_hashes(results, await hash_avatars(session, results, limit))
