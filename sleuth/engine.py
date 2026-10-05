"""Async search engine: checks usernames across sites, extracts profile
data and follows newly discovered usernames (recursive search)."""

from __future__ import annotations

import asyncio
import re
import secrets
import time
from collections.abc import AsyncIterator
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

import aiohttp

from .extractor import clean_info, extract
from . import avatars
from .linker import find_social, identity_summary, match_social, variants
from .sites import Site

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)
MAX_BODY = 2_000_000

# Strings that mean we got an anti-bot page instead of the real answer.
WAF_MARKERS = (
    "<title>Just a moment...</title>",
    "Attention Required! | Cloudflare",
    "captcha-delivery.com",
    "_Incapsula_Resource",
    "<title>DDoS-Guard</title>",
    "/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page",
    "cf_challenge_text",
    "<title>Client Challenge</title>",
    "Please respect our robot policy",
)


class Status(str, Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"
    ILLEGAL = "illegal"
    MANUAL = "manual"  # platform blocks automated checks: open the link to verify


@dataclass
class Result:
    site: str
    username: str
    url: str
    status: Status
    tags: list[str] = field(default_factory=list)
    http_status: int | None = None
    elapsed: float = 0.0
    error: str | None = None
    info: dict[str, str] = field(default_factory=dict)
    links: list[str] = field(default_factory=list)
    discovered: list[str] = field(default_factory=list)
    depth: int = 0
    linked: bool = False  # the owner linked to this account from another profile
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class SearchConfig:
    timeout: float = 12.0
    concurrency: int = 40
    retries: int = 1
    proxy: str | None = None
    extract: bool = True
    depth: int = 1  # 0 = no recursion
    max_usernames: int = 10  # cap on extra usernames found by recursion
    variants: bool = False  # also try john.doe -> johndoe / john_doe
    avatars: bool = True  # compare profile pictures across found accounts (needs Pillow)
    archive: bool = True  # look up blocked platforms (IG/FB/TikTok/X) in the Wayback Machine
    user_agent: str = USER_AGENT


@dataclass
class _Response:
    status: int
    text: str
    url: str
    content_type: str
    location: str


async def read_body(resp: aiohttp.ClientResponse, limit: int) -> bytes:
    """Read up to ``limit`` bytes of the body.

    ``resp.content.read(n)`` returns only what has arrived so far, which cut
    large pages short; this keeps reading until EOF or the limit.
    """
    chunks: list[bytes] = []
    total = 0
    async for chunk in resp.content.iter_chunked(65536):
        chunks.append(chunk)
        total += len(chunk)
        if total >= limit:
            break
    return b"".join(chunks)[:limit]


def make_session(cfg: SearchConfig) -> aiohttp.ClientSession:
    connector: aiohttp.BaseConnector | None = None
    if cfg.proxy and cfg.proxy.startswith("socks"):
        try:
            from aiohttp_socks import ProxyConnector  # type: ignore
        except ImportError as e:  # pragma: no cover - optional dependency
            raise SystemExit("SOCKS/Tor proxy needs: pip install aiohttp-socks") from e
        connector = ProxyConnector.from_url(cfg.proxy, limit=cfg.concurrency, ttl_dns_cache=300)
    else:
        # ThreadedResolver uses the OS resolver; aiodns fails on some Windows setups.
        connector = aiohttp.TCPConnector(limit=cfg.concurrency, limit_per_host=6, ttl_dns_cache=300,
                                         resolver=aiohttp.ThreadedResolver())
    return aiohttp.ClientSession(
        connector=connector,
        headers={
            "User-Agent": cfg.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
        cookie_jar=aiohttp.DummyCookieJar(),
    )


async def _fetch(session: aiohttp.ClientSession, site: Site, username: str, cfg: SearchConfig) -> _Response:
    http_proxy = cfg.proxy if cfg.proxy and not cfg.proxy.startswith("socks") else None
    async with session.request(
        site.method,
        site.probe_url(username),
        json=site.body(username),
        headers=site.headers or None,
        allow_redirects=site.check != "response_url",
        proxy=http_proxy,
        timeout=aiohttp.ClientTimeout(total=cfg.timeout),
    ) as resp:
        raw = b"" if site.method == "HEAD" else await read_body(resp, MAX_BODY)
        try:
            encoding = resp.get_encoding()
        except Exception:
            encoding = "utf-8"
        return _Response(
            status=resp.status,
            text=raw.decode(encoding or "utf-8", errors="replace"),
            url=str(resp.url),
            content_type=resp.headers.get("Content-Type", "").lower(),
            location=resp.headers.get("Location", ""),
        )


def decide(site: Site, resp: _Response) -> tuple[Status, str | None]:
    """Turn an HTTP response into FOUND / NOT_FOUND / UNKNOWN."""
    if resp.status == 429:
        return Status.UNKNOWN, "rate limited (429)"
    if any(m in resp.text for m in WAF_MARKERS):
        return Status.UNKNOWN, "blocked by anti-bot protection"
    if resp.status in (401, 403) and resp.status not in site.ok_codes:
        return Status.UNKNOWN, f"access denied ({resp.status})"

    if site.check == "status_code":
        if resp.status in site.ok_codes:
            status = Status.FOUND
        elif resp.status >= 500:
            return Status.UNKNOWN, f"server error ({resp.status})"
        else:
            status = Status.NOT_FOUND
    elif site.check == "message":
        if any(msg in resp.text for msg in site.error_msg):
            status = Status.NOT_FOUND
        elif resp.status >= 500:
            return Status.UNKNOWN, f"server error ({resp.status})"
        elif site.presence_msg and not any(m in resp.text for m in site.presence_msg):
            # neither the "missing" text nor the "profile" text: some other page
            return Status.UNKNOWN, "unexpected page (maybe rate limited)"
        else:
            status = Status.FOUND
    else:  # response_url
        if 300 <= resp.status < 400:
            if site.error_url and site.error_url not in resp.location:
                status = Status.FOUND  # redirected somewhere that isn't the error page
            else:
                status = Status.NOT_FOUND
        elif resp.status in site.ok_codes:
            status = Status.FOUND
        elif resp.status >= 500:
            return Status.UNKNOWN, f"server error ({resp.status})"
        else:
            status = Status.NOT_FOUND

    if status is Status.FOUND and site.presence_msg and not any(m in resp.text for m in site.presence_msg):
        status = Status.NOT_FOUND
    return status, None


async def check_site(
    session: aiohttp.ClientSession, site: Site, username: str, cfg: SearchConfig, depth: int = 0
) -> Result:
    result = Result(site=site.name, username=username, url=site.profile_url(username),
                    status=Status.ILLEGAL, tags=site.tags, depth=depth)
    if not site.valid(username):
        result.error = "username format not allowed on this site"
        return result
    if site.check == "manual":
        result.status = Status.MANUAL
        result.error = "เว็บนี้บล็อกการตรวจอัตโนมัติ กดลิงก์เพื่อตรวจเอง"
        return result

    start = time.perf_counter()
    resp: _Response | None = None
    for attempt in range(cfg.retries + 1):
        try:
            resp = await _fetch(session, site, username, cfg)
            if resp.status in (502, 503, 504) and attempt < cfg.retries:
                await asyncio.sleep(1.0)
                continue
            break
        except asyncio.TimeoutError:
            result.error = "timeout"
        except aiohttp.ClientError as e:
            result.error = f"{type(e).__name__}: {e}"[:200]
        except Exception as e:  # unexpected (bad SSL, decode errors, ...)
            result.error = f"{type(e).__name__}: {e}"[:200]
        if attempt < cfg.retries:
            await asyncio.sleep(0.5 * (attempt + 1))
    result.elapsed = round(time.perf_counter() - start, 2)

    if resp is None:
        result.status = Status.UNKNOWN
        return result

    result.http_status = resp.status
    result.error = None
    result.status, result.error = decide(site, resp)

    if result.status is Status.FOUND and cfg.extract and site.extract:
        try:
            info, strong, all_links = extract(resp.text, resp.content_type, resp.url)
            result.info = clean_info(info, site.name, site.main, username)
            result.links = all_links
            result._strong_links = all_links if site.owner_links else strong  # type: ignore[attr-defined]
        except Exception:
            pass
    return result


@dataclass
class Discovery:
    """Another account of the same person, seen inside a found profile."""
    username: str
    platform: str | None  # site name when recognised (e.g. "Instagram")
    url: str | None
    how: str  # "link" | "bio" | "field"


def discover_usernames(result: Result, sites: list[Site]) -> list[Discovery]:
    """Find other accounts of the same person in a found profile.

    Only owner-published evidence is used: rel="me"/JSON-LD/API links,
    link-in-bio lists, explicit twitter/github fields and bio mentions
    such as "IG: @name".
    """
    found: dict[tuple[str, str], Discovery] = {}
    brand = re.sub(r"[^a-z0-9]", "", result.site.lower())

    def add(d: Discovery) -> None:
        # skip the site's own accounts (e.g. a footer link to twitter.com/github)
        if re.sub(r"[._-]", "", d.username.lower()).startswith(brand):
            return
        found.setdefault(((d.platform or "").lower(), d.username.lower()), d)

    links = list(getattr(result, "_strong_links", []))
    if result.info.get("website", "").startswith("http"):
        links.append(result.info["website"])
    for s in find_social(links, result.info.get("bio", "")):
        add(Discovery(s.handle, s.platform, s.url, s.how))
    for link in links:
        if match_social(link):
            continue
        for site in sites:
            name = site.match_link(link)
            if name:
                add(Discovery(name, site.name, link, "link"))
                break
    # explicit cross-site handles only; a generic "username" field is often a display name
    for field_name, platform in (("twitter", "X (Twitter)"), ("github", "GitHub")):
        value = result.info.get(field_name, "").lstrip("@")
        if value and " " not in value and len(value) <= 40:
            add(Discovery(value, platform, None, "field"))

    out = list(found.values())
    result.discovered = [f"{d.platform}: {d.username}" if d.platform else d.username for d in out]
    return out


class Searcher:
    """Run a search and stream events as they happen.

    Event types: ``start``, ``result``, ``discovered``, ``done``.
    """

    def __init__(self, sites: list[Site], cfg: SearchConfig | None = None,
                 all_sites: list[Site] | None = None) -> None:
        self.sites = sites
        self.all_sites = all_sites or sites  # used to recognise profile links
        self.cfg = cfg or SearchConfig()
        self.results: list[Result] = []
        self.identity: list[dict[str, Any]] = []
        self._by_name = {s.name: s for s in self.all_sites}

    def _key(self, site: str, username: str) -> tuple[str, str]:
        return site.lower(), username.lower()

    async def run(self, usernames: list[str]) -> AsyncIterator[dict[str, Any]]:
        cfg = self.cfg
        seen = {u.lower() for u in usernames}
        origin = {u.lower(): "username ตรงกับที่ค้น" for u in usernames}
        level: list[tuple[str, str | None]] = [(u, None) for u in usernames]
        if cfg.variants:
            for u in usernames:
                for v in variants(u):
                    if v.lower() not in seen:
                        seen.add(v.lower())
                        origin[v.lower()] = f"รูปแบบใกล้เคียงของ \"{u}\""
                        level.append((v, f"รูปแบบใกล้เคียงของ {u}"))
        extra_budget = cfg.max_usernames
        linked: dict[tuple[str, str], Result] = {}
        started = time.perf_counter()
        sem = asyncio.Semaphore(cfg.concurrency)

        async with make_session(cfg) as session:

            async def guarded(site: Site, username: str, depth: int) -> Result:
                async with sem:
                    return await check_site(session, site, username, cfg, depth)

            for depth in range(cfg.depth + 1):
                if not level:
                    break
                for username, source in level:
                    yield {"type": "start", "username": username, "depth": depth,
                           "source": source, "total": len(self.sites)}

                tasks = [asyncio.create_task(guarded(site, u, depth))
                         for u, _ in level for site in self.sites]
                next_level: list[tuple[str, str | None]] = []
                try:
                    for fut in asyncio.as_completed(tasks):
                        result = await fut
                        key = self._key(result.site, result.username)
                        if result.status is Status.MANUAL and key in linked:
                            continue  # already confirmed through a profile link
                        if result.status is Status.FOUND:
                            result.evidence.append(origin.get(result.username.lower(), "username ตรงกับที่ค้น"))
                        self.results.append(result)
                        yield {"type": "result", **result.to_dict()}
                        if result.status is not Status.FOUND:
                            continue

                        for d in discover_usernames(result, self.all_sites):
                            how = {"link": "ลิงก์จากโปรไฟล์", "bio": "ระบุใน bio ของ", "field": "ระบุในโปรไฟล์"}[d.how]
                            why = f"{how} {result.site} (@{result.username})"
                            site = self._by_name.get(d.platform or "")
                            # platforms we can't check automatically: the owner's own link is the evidence
                            if d.platform and (site is None or site.check == "manual"):
                                lkey = self._key(d.platform, d.username)
                                if lkey in linked:
                                    if why not in linked[lkey].evidence:
                                        linked[lkey].evidence.append(why)
                                        yield {"type": "result", **linked[lkey].to_dict()}
                                else:
                                    lr = Result(site=d.platform, username=d.username,
                                                url=d.url or (site.profile_url(d.username) if site else d.username),
                                                status=Status.FOUND, tags=site.tags if site else ["social"],
                                                depth=depth, linked=True, evidence=[why])
                                    linked[lkey] = lr
                                    self.results = [r for r in self.results
                                                    if self._key(r.site, r.username) != lkey]
                                    self.results.append(lr)
                                    yield {"type": "result", **lr.to_dict()}
                            # follow the new username on every site
                            if depth < cfg.depth and d.username.lower() not in seen and extra_budget > 0:
                                seen.add(d.username.lower())
                                extra_budget -= 1
                                origin[d.username.lower()] = f"username ที่เจอจาก {why}"
                                source = f"{result.username} @ {result.site} ({d.platform or 'link'})"
                                next_level.append((d.username, source))
                                yield {"type": "discovered", "username": d.username,
                                       "source": source, "depth": depth + 1}
                finally:
                    for t in tasks:
                        t.cancel()
                level = next_level

            if cfg.archive:
                manual = [r for r in self.results if r.status is Status.MANUAL and r.depth == 0][:20]
                if manual:
                    yield {"type": "progress", "message": "กำลังค้น IG/FB/TikTok/X ใน Wayback Machine..."}
                    for r in await archive_lookup(session, manual):
                        yield {"type": "result", **r.to_dict()}
            avatar_matches: dict = {}
            if cfg.avatars and avatars.available():
                yield {"type": "progress", "message": "กำลังเทียบรูปโปรไฟล์..."}
                avatar_matches = await avatars.match_avatars(session, [r.to_dict() for r in self.results])

        self.identity = identity_summary([r.to_dict() for r in self.results], usernames, avatar_matches)
        yield {"type": "done", "stats": self.stats(), "identity": self.identity,
               "elapsed": round(time.perf_counter() - started, 1)}

    def stats(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Status}
        for r in self.results:
            counts[r.status.value] += 1
        counts["linked"] = sum(1 for r in self.results if r.linked)
        counts["usernames"] = len({r.username.lower() for r in self.results})
        return counts


ARCHIVE_URL = {
    "Instagram": "instagram.com/{}/",
    "Facebook": "facebook.com/{}",
    "TikTok": "tiktok.com/@{}",
    "X (Twitter)": "twitter.com/{}",
    "Threads": "threads.net/@{}",
}


async def archive_lookup(session: aiohttp.ClientSession, results: list[Result]) -> list[Result]:
    """Ask the Wayback Machine whether a blocked platform's profile page was archived.

    An archived snapshot is a strong hint the account exists (or existed), and the
    user can open it to see the profile without logging in.
    """
    sem = asyncio.Semaphore(3)  # archive.org rate-limits aggressive clients

    async def one(r: Result) -> Result | None:
        pattern = ARCHIVE_URL.get(r.site)
        if not pattern:
            return None
        target = pattern.replace("{}", r.username)
        url = ("https://web.archive.org/cdx/search/cdx?output=json&fl=timestamp,original"
               f"&filter=statuscode:200&limit=-1&url={target}")
        async with sem:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    rows = await resp.json(content_type=None) if resp.status == 200 else None
            except Exception:
                return None
        if not rows or len(rows) < 2:
            return None
        ts, original = rows[-1][0], rows[-1][1]
        r.info["archived"] = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
        r.info["archive_url"] = f"https://web.archive.org/web/{ts}/{original}"
        r.error = f"archive.org เคยเก็บหน้าโปรไฟล์นี้ไว้ (ล่าสุด {r.info['archived']}) น่าจะมีบัญชีจริง กดตรวจเพื่อยืนยัน"
        return r

    done = await asyncio.gather(*(one(r) for r in results))
    return [r for r in done if r is not None]


def random_username() -> str:
    return "zz" + secrets.token_hex(6)
