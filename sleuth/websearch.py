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
    # every (engine, query, rank) that returned this URL: one record per URL, however often it shows up
    found_by: list[dict[str, Any]] = field(default_factory=list)

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


def url_key(url: str) -> str:
    """Same page, different spelling: drop scheme, www., trailing slash and tracking parameters."""
    p = urlparse(url.strip())
    host = p.netloc.lower().removeprefix("www.").removeprefix("m.")
    query = "&".join(sorted(x for x in p.query.split("&") if x and not x.lower().startswith(("utm_", "fbclid", "ref="))))
    return f"{host}{p.path.rstrip('/').lower()}" + (f"?{query}" if query else "")


def build_query(username: str = "", platform: str = "", keywords: str = "", after: str = "",
                before: str = "", exact: bool = True) -> str:
    """Custom query builder: [username] + [platform] + [keyword] + [date range]."""
    parts = []
    if username.strip():
        u = username.strip().lstrip("@")
        parts.append(f'"{u}"' if exact else u)
    if keywords.strip():
        parts.append(keywords.strip())
    site = PLATFORM_SITES.get(platform.strip().lower(), platform.strip())
    if site:
        parts.append(site if site.startswith(("site:", "(")) else f"site:{site}")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", after or ""):
        parts.append(f"after:{after}")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", before or ""):
        parts.append(f"before:{before}")
    return " ".join(parts)


PLATFORM_SITES = {
    "instagram": "instagram.com", "tiktok": "tiktok.com", "facebook": "facebook.com",
    "x": "(site:x.com OR site:twitter.com)", "twitter": "(site:x.com OR site:twitter.com)",
    "github": "github.com", "youtube": "youtube.com", "reddit": "reddit.com", "pantip": "pantip.com",
    "linkedin": "linkedin.com", "threads": "threads.net", "twitch": "twitch.tv", "medium": "medium.com",
}


async def search(session: aiohttp.ClientSession, usernames: list[str], *, max_queries: int = 6,
                 max_results: int = 8, delay: float = 1.5, timeout: float = 15.0,
                 engines: list[Engine] | None = None, sites: list[Any] | None = None,
                 proxy: str | None = None, now: Any = None,
                 custom: list[dict[str, str]] | None = None) -> dict[str, Any]:
    """Run the dork queries and return ``{"hits": [...], "engines": [...], "queries": [...]}``.

    ``custom`` replaces the generated dorks with ``[{"query", "username", "label"}]``
    (the query builder). A URL returned by several queries or engines is kept
    once, with every source listed in ``found_by``.
    """
    engines = engines if engines is not None else default_engines()
    hits: dict[str, Hit] = {}
    ran: list[dict[str, Any]] = []
    stamp = now() if now else ""
    plan = custom if custom is not None else [{**q, "username": u} for u in usernames for q in queries(u, max_queries)]
    for n, q in enumerate(plan, 1):
        username = q.get("username", "")
        engine = next((e for e in engines if not e.blocked), None)
        if engine is None:
            ran.append({**q, "n": n, "engine": None, "status": "skipped", "count": 0})
            continue
        status, results = await _ask(session, engine, q["query"], timeout, proxy)
        ran.append({**q, "n": n, "engine": engine.name, "status": status, "count": len(results)})
        for rank, (url, title, snippet) in enumerate(results[:max_results], 1):
            source = {"engine": engine.name, "query": q["query"], "query_n": n, "rank": rank}
            key = url_key(url)
            if key in hits:
                hits[key].found_by.append(source)
                continue
            hits[key] = classify(Hit(engine.name, q["query"], username, url, title[:200], snippet[:400], rank,
                                     checked_at=stamp, found_by=[source]), sites)
        if delay and n < len(plan):
            await asyncio.sleep(delay)
    hits_list = list(hits.values())
    return {"hits": [h.to_dict() for h in hits_list],
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
