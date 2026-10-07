"""Search-engine OSINT: ask DuckDuckGo / Bing where a username shows up.

For every username we build "dork" queries such as::

    "ice4564"
    "ice4564" site:instagram.com
    "ice4564" site:tiktok.com

and turn the results into evidence: which page, which engine, which query,
and whether the page is a profile on a known platform.

Engines are asked politely (one query at a time, a pause between queries).
When an engine answers with a CAPTCHA / "unusual traffic" page we stop using
it for the rest of the run and fall back to the next one; we never try to
get around the block. Google does not allow automated queries, so Google
queries are only offered as links for a person to open.
"""

from __future__ import annotations

import asyncio
import base64
import re
from dataclasses import asdict, dataclass, field
from html import unescape
from typing import Any
from urllib.parse import parse_qs, quote_plus, unquote, urlparse

import aiohttp

from .linker import match_social

# (label, query template). {u} is the username.
DORKS: list[tuple[str, str]] = [
    ("ทั่วเว็บ", '"{u}"'),
    ("Instagram", '"{u}" site:instagram.com'),
    ("TikTok", '"{u}" site:tiktok.com'),
    ("Facebook", '"{u}" site:facebook.com'),
    ("X / Twitter", '"{u}" (site:x.com OR site:twitter.com)'),
    ("GitHub", '"{u}" site:github.com'),
    ("YouTube", '"{u}" site:youtube.com'),
    ("Reddit", '"{u}" site:reddit.com'),
    ("Pantip", '"{u}" site:pantip.com'),
    ("LinkedIn", '"{u}" site:linkedin.com'),
    ("อีเมล", '"{u}@gmail.com" OR "{u}@hotmail.com"'),
]

BLOCK_MARKERS = (
    "anomaly-modal", "Unfortunately, bots use DuckDuckGo too", "captcha", "unusual traffic",
    "/challenge", "Our systems have detected",
)

TAG = re.compile(r"<[^>]+>")


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", unescape(TAG.sub(" ", html))).strip()


def queries(username: str, limit: int = 6) -> list[dict[str, str]]:
    """The dork queries for one username, most useful first."""
    u = username.strip().lstrip("@")
    return [{"label": label, "query": t.format(u=u)} for label, t in DORKS[:max(0, limit)]]


def manual_links(username: str) -> list[dict[str, str]]:
    """Every dork as Google / Bing / DuckDuckGo links for a person to open."""
    out = []
    for q in queries(username, len(DORKS)):
        out.append({**q,
                    "google": "https://www.google.com/search?q=" + quote_plus(q["query"]),
                    "bing": "https://www.bing.com/search?q=" + quote_plus(q["query"]),
                    "duckduckgo": "https://duckduckgo.com/?q=" + quote_plus(q["query"])})
    return out


@dataclass
class Hit:
    engine: str
    query: str
    username: str  # the username the query was built from
    url: str
    title: str
    snippet: str
    rank: int
    mentions: bool = False  # username appears in the URL, title or snippet
    platform: str | None = None  # known platform when the URL is a profile page
    handle: str | None = None
    same_handle: bool = False  # profile handle == searched username
    checked_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---- result-page parsers ----------------------------------------------------
def _ddg_url(href: str) -> str:
    href = unescape(href)
    if href.startswith("//"):
        href = "https:" + href
    p = urlparse(href)
    if p.netloc.endswith("duckduckgo.com") and p.path.startswith("/l/"):
        target = parse_qs(p.query).get("uddg", [""])[0]
        return unquote(target) if target else ""
    return href


def parse_duckduckgo(html: str) -> list[tuple[str, str, str]]:
    """(url, title, snippet) from html.duckduckgo.com result pages."""
    out = []
    for block in re.split(r'<div[^>]+class="[^"]*\bresult\b[^"]*"', html)[1:]:
        if "result--ad" in block[:300]:
            continue
        a = re.search(r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', block, re.S) \
            or re.search(r'<a[^>]+href="([^"]+)"[^>]+class="[^"]*result__a[^"]*"[^>]*>(.*?)</a>', block, re.S)
        if not a:
            continue
        s = re.search(r'class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</(?:a|div|td)>', block, re.S)
        url = _ddg_url(a.group(1))
        if url.startswith("http"):
            out.append((url, _text(a.group(2)), _text(s.group(1)) if s else ""))
    return out


def _bing_url(href: str) -> str:
    href = unescape(href)
    p = urlparse(href)
    if p.netloc.endswith("bing.com") and p.path.startswith("/ck/"):
        u = parse_qs(p.query).get("u", [""])[0]
        if u.startswith("a1"):
            raw = u[2:]
            try:
                return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace")
            except (ValueError, UnicodeDecodeError):
                return ""
    return href


def parse_bing(html: str) -> list[tuple[str, str, str]]:
    out = []
    for block in re.split(r'<li[^>]+class="[^"]*\bb_algo\b[^"]*"', html)[1:]:
        a = re.search(r"<h2[^>]*>.*?<a[^>]+href=\"([^\"]+)\"[^>]*>(.*?)</a>", block, re.S)
        if not a:
            continue
        s = re.search(r'<p[^>]*>(.*?)</p>', block, re.S)
        url = _bing_url(a.group(1))
        if url.startswith("http"):
            out.append((url, _text(a.group(2)), _text(s.group(1)) if s else ""))
    return out


@dataclass
class Engine:
    name: str
    url: str  # with {q}
    parse: Any
    blocked: bool = False
    errors: list[str] = field(default_factory=list)


def default_engines() -> list[Engine]:
    return [
        Engine("DuckDuckGo", "https://html.duckduckgo.com/html/?q={q}", parse_duckduckgo),
        Engine("Bing", "https://www.bing.com/search?q={q}&setlang=en&count=20", parse_bing),
    ]


def classify(hit: Hit, sites: list[Any] | None = None) -> Hit:
    """Mark whether the hit mentions the username and is a profile page."""
    u = hit.username.lower()
    core = re.sub(r"[^a-z0-9]", "", u)
    hay = f"{hit.url} {hit.title} {hit.snippet}".lower()
    hit.mentions = u in hay or (len(core) >= 4 and core in re.sub(r"[^a-z0-9]", "", hay))
    social = match_social(hit.url)
    if social:
        hit.platform, hit.handle = social
    else:
        for s in sites or []:
            name = s.match_link(hit.url)
            if name:
                hit.platform, hit.handle = s.name, name
                break
    hit.same_handle = bool(hit.handle) and hit.handle.lower() == u
    return hit


async def search(session: aiohttp.ClientSession, usernames: list[str], *, max_queries: int = 6,
                 max_results: int = 8, delay: float = 1.5, timeout: float = 15.0,
                 engines: list[Engine] | None = None, sites: list[Any] | None = None,
                 proxy: str | None = None, now: Any = None) -> dict[str, Any]:
    """Run the dork queries and return ``{"hits": [...], "engines": [...], "queries": [...]}``."""
    engines = engines if engines is not None else default_engines()
    hits: list[Hit] = []
    ran: list[dict[str, Any]] = []
    seen: set[str] = set()
    stamp = now() if now else ""
    for username in usernames:
        for q in queries(username, max_queries):
            engine = next((e for e in engines if not e.blocked), None)
            if engine is None:
                ran.append({**q, "username": username, "engine": None, "status": "skipped", "count": 0})
                continue
            status, results = await _ask(session, engine, q["query"], timeout, proxy)
            ran.append({**q, "username": username, "engine": engine.name, "status": status, "count": len(results)})
            for rank, (url, title, snippet) in enumerate(results[:max_results], 1):
                key = url.rstrip("/").lower()
                if key in seen:
                    continue
                seen.add(key)
                hits.append(classify(Hit(engine.name, q["query"], username, url, title[:200], snippet[:400], rank,
                                         checked_at=stamp), sites))
            if delay:
                await asyncio.sleep(delay)
    return {"hits": [h.to_dict() for h in hits],
            "engines": [{"name": e.name, "blocked": e.blocked, "errors": e.errors[:3]} for e in engines],
            "queries": ran}


async def _ask(session: aiohttp.ClientSession, engine: Engine, query: str, timeout: float,
               proxy: str | None) -> tuple[str, list[tuple[str, str, str]]]:
    url = engine.url.format(q=quote_plus(query))
    try:
        async with session.get(url, proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            text = await resp.text(errors="replace")
            status = resp.status
    except asyncio.TimeoutError:
        engine.errors.append("timeout")
        return "error", []
    except Exception as e:
        engine.errors.append(f"{type(e).__name__}: {e}"[:120])
        return "error", []
    results = engine.parse(text) if status == 200 else []
    if status in (202, 403, 429) or (not results and any(m.lower() in text.lower() for m in BLOCK_MARKERS)):
        engine.blocked = True
        engine.errors.append(f"blocked (HTTP {status})")
        return "blocked", []
    return "ok", results
