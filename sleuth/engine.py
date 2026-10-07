"""Async search engine: checks usernames across sites, extracts profile
data and follows newly discovered usernames (recursive search)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import sqlite3
import time
from collections.abc import AsyncIterator
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import aiohttp

from .extractor import clean_info, extract
from . import __version__, avatars, websearch
from .evidence import account_id, build_findings, build_graph, build_timeline, domain_id, summary
from . import contradictions as contra
from .identity import clusters as identity_clusters, entities as find_entities, handle_core
from .linker import apply_contradictions, find_social, identity_summary, match_social
from .planner import plan as make_plan
from .mutations import mutations, numbered
from .similarity import JUNK_HOSTS, connections as find_connections, emails_in_text
from .sites import Site
from .verify import verify

if TYPE_CHECKING:  # pragma: no cover
    from .history import History

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
    query: str = "input"  # input = typed by the user, candidate = generated spelling, discovered = found in a profile
    candidate_of: str | None = None  # for candidates: the username the user typed
    checks: list[dict[str, Any]] = field(default_factory=list)  # page-level verification (see verify.py)
    checked_at: str = ""
    via: list[str] = field(default_factory=list)  # evidence-graph nodes that link to this account
    cached: bool = False  # answered from the history cache instead of asking the site again

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Result":
        names = {f.name for f in fields(cls)}
        kw = {k: v for k, v in d.items() if k in names}
        kw["status"] = Status(kw["status"])
        return cls(**kw)


@dataclass
class SearchConfig:
    timeout: float = 12.0
    concurrency: int = 40
    retries: int = 1
    proxy: str | None = None
    extract: bool = True
    depth: int = 1  # 0 = no recursion
    max_usernames: int = 10  # cap on extra usernames found by recursion
    variants: bool = False  # also try mutations: ice4564 -> ice_4564, ice.4564, ice4564x, ice4564th ...
    max_candidates: int = 12  # mutations per typed username
    numbers: tuple[int, int] | None = None  # also try the name + a number: (1, 10) -> ice1 ... ice10
    domains: bool = True  # follow personal websites found in profiles (needs depth >= 1)
    max_domains: int = 5
    avatars: bool = True  # compare profile pictures across found accounts (needs Pillow)
    archive: bool = True  # look up blocked platforms (IG/FB/TikTok/X) in the Wayback Machine
    web_search: bool = False  # ask DuckDuckGo/Bing for "username" site:... dorks
    max_search_queries: int = 6  # dork queries per typed username
    search_delay: float = 1.5  # seconds between search-engine queries
    cache: bool = False  # reuse found/not-found answers from the history database
    cache_ttl: float = 6 * 3600
    host_interval: float = 0.0  # min seconds between two requests to the same host (0 = no limit)
    user_agent: str = USER_AGENT


@dataclass
class _Response:
    status: int
    text: str
    url: str
    content_type: str
    location: str
    retry_after: str = ""


class HostLimiter:
    """Per-host politeness: one request every ``interval`` seconds per host,
    and a pause for every request to a host after it answers 429."""

    def __init__(self, interval: float = 0.0) -> None:
        self.interval = interval
        self._next: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def wait(self, host: str) -> None:
        if self.interval <= 0 and host not in self._next:
            return
        async with self._locks.setdefault(host, asyncio.Lock()):
            delay = self._next.get(host, 0.0) - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self._next[host] = time.monotonic() + self.interval

    def penalize(self, host: str, seconds: float) -> None:
        self._next[host] = max(self._next.get(host, 0.0), time.monotonic() + seconds)


def retry_after(value: str | None, default: float) -> float:
    try:
        return max(0.5, min(10.0, float(value))) if value else default
    except ValueError:
        return default  # HTTP-date form: not worth parsing for a 10 s cap


def site_signature(site: Site, cfg: "SearchConfig") -> str:
    """Cache key part: changes whenever the site's rule or the checker changes."""
    raw = json.dumps(site.to_dict(), sort_keys=True, ensure_ascii=False) + f"|{__version__}|{cfg.extract}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


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
            retry_after=resp.headers.get("Retry-After", ""),
        )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
    session: aiohttp.ClientSession, site: Site, username: str, cfg: SearchConfig, depth: int = 0,
    limiter: HostLimiter | None = None,
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
            if limiter and attempt:
                await limiter.wait(_host(site.probe_url(username), keep_port=True))
            resp = await _fetch(session, site, username, cfg)
            if resp.status == 429 and attempt < cfg.retries:
                # back off on this host for everyone, then ask once more
                wait = retry_after(resp.retry_after, 2.0 * (attempt + 1))
                if limiter:
                    limiter.penalize(_host(site.probe_url(username), keep_port=True), wait)
                else:
                    await asyncio.sleep(wait)
                continue
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
        result.checked_at = now_iso()
        result.status = Status.UNKNOWN
        return result

    result.http_status = resp.status
    result.error = None
    result.checked_at = now_iso()
    result.status, result.error = decide(site, resp)
    # HTTP 200 alone is not proof: look at the page itself
    result.status, why, result.checks = verify(site, username, resp, result.status)
    result.error = why or result.error

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


def discover_usernames(result: Result, sites: list[Site], skip_brand: bool = True) -> list[Discovery]:
    """Find other accounts of the same person in a found profile.

    Only owner-published evidence is used: rel="me"/JSON-LD/API links,
    link-in-bio lists, explicit twitter/github fields and bio mentions
    such as "IG: @name".
    """
    found: dict[tuple[str, str], Discovery] = {}
    brand = re.sub(r"[^a-z0-9]", "", result.site.lower())

    def add(d: Discovery) -> None:
        # skip the site's own accounts (e.g. a footer link to twitter.com/github)
        if skip_brand and re.sub(r"[._-]", "", d.username.lower()).startswith(brand):
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


TZ_IN_PAGE = re.compile(r"\b(?:Asia|Europe|America|Australia|Africa)/[A-Z][A-Za-z_]+(?:/[A-Z][A-Za-z_]+)?\b")

# Hosts that are platforms, not someone's own website.
PLATFORM_HOSTS = re.compile(
    r"(^|\.)(instagram\.com|facebook\.com|fb\.com|tiktok\.com|twitter\.com|x\.com|threads\.net|threads\.com|"
    r"linkedin\.com|youtube\.com|youtu\.be|discord\.gg|discord\.com|t\.me|wa\.me|line\.me|spotify\.com|"
    r"amazon\.[a-z.]+|paypal\.me|paypal\.com|linktr\.ee|beacons\.ai|lnk\.bio|bio\.link|google\.[a-z.]+|"
    r"github\.io|githubusercontent\.com|notion\.site|wikipedia\.org|lnk\.to|ffm\.to|smarturl\.it|found\.ee|"
    r"hyperurl\.co|orcd\.co|amazonaws\.com|cloudfront\.net|shopify\.com|akamaized\.net|fastly\.net)$", re.I)
# Asset hosts: cdn.example.com, static.example.com, s2.example.net ...
ASSET_HOST = re.compile(r"^(?:cdn\d*|static\d*|img\d*|images?|assets?|media|s\d+|i\d+)\.|(?:^|[.-])cdn(?:[.-]|$)", re.I)
HOW_TEXT = {"link": "ลิงก์จากโปรไฟล์", "bio": "ระบุใน bio ของ", "field": "ระบุในโปรไฟล์"}


def _host(url: str, keep_port: bool = False) -> str:
    h = urlparse(url).netloc.lower()
    h = h if keep_port else h.split(":")[0]
    return h[4:] if h.startswith("www.") else h


class Searcher:
    """Run a search and stream events as they happen.

    Pipeline: mutations -> verification -> recursion (profiles, domains)
    -> search engines -> correlation -> evidence / history. Event types:
    ``start``, ``result``, ``discovered``, ``domain``, ``progress``,
    ``search``, ``done``.

    With a :class:`~sleuth.history.History`, finished runs are saved
    (snapshots, first seen / last checked, profile changes) and, when
    ``cfg.cache`` is on, definitive answers are reused for ``cfg.cache_ttl``.
    """

    def __init__(self, sites: list[Site], cfg: SearchConfig | None = None,
                 all_sites: list[Site] | None = None, history: "History | None" = None) -> None:
        self.sites = sites
        self.all_sites = all_sites or sites  # used to recognise profile links
        self.cfg = cfg or SearchConfig()
        self.history = history
        self.results: list[Result] = []
        self.identity: list[dict[str, Any]] = []
        self.connections: list[dict[str, Any]] = []
        self.clusters: list[dict[str, Any]] = []
        self.domains: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self.timeline: list[dict[str, Any]] = []
        self.changes: list[dict[str, Any]] = []
        self.search: dict[str, Any] = {"hits": [], "engines": [], "queries": [], "manual": []}
        self.summary: dict[str, Any] = {}
        self.run_id: int | None = None
        self.queries: dict[str, dict[str, Any]] = {}  # every username searched, and why
        self.graph: dict[str, list] = {"nodes": [], "edges": []}
        self.limiter = HostLimiter(self.cfg.host_interval)
        self.cache_hits = 0
        self._uncommitted = 0
        self.contradictions: list[dict[str, Any]] = []
        self.entities: list[dict[str, Any]] = []
        self.plan: list[dict[str, Any]] = []
        self.replay: list[dict[str, Any]] = []  # what the engine did, in order (investigation replay)
        self._replay_sent = 0
        self._t0 = time.perf_counter()
        self.skipped: list[dict[str, Any]] = []  # usernames the owner published that depth/budget left unsearched
        self._by_name = {s.name: s for s in self.all_sites}
        self._site_hosts = {_host(s.main, keep_port=True) for s in self.all_sites}
        self._budget = self.cfg.max_usernames
        self._linked: dict[tuple[str, str], Result] = {}
        self._via: dict[tuple[str, str], list[str]] = {}  # (site, user) -> nodes that linked to it
        self._domain_queue: list[tuple[str, str, str, bool]] = []  # (url, source node, label, names the person)

    # ---- investigation replay ---------------------------------------------
    def _log(self, action: str, detail: str = "", ref: str | None = None) -> None:
        self.replay.append({"n": len(self.replay) + 1, "t": now_iso(), "s": round(time.perf_counter() - self._t0, 1),
                            "action": action, "detail": detail, "ref": ref})

    def _drain(self) -> list[dict[str, Any]]:
        new, self._replay_sent = self.replay[self._replay_sent:], len(self.replay)
        return [{"type": "log", **x} for x in new]

    def _key(self, site: str, username: str) -> tuple[str, str]:
        return site.lower(), username.lower()

    # ---- bookkeeping ---------------------------------------------------
    def _add_query(self, username: str, query: str, depth: int, source: str | None = None,
                   candidate_of: str | None = None, rule: str | None = None,
                   from_node: str | None = None, why: str | None = None) -> bool:
        """Register a username to search; False if it was already registered."""
        k = username.lower()
        if k in self.queries:
            q = self.queries[k]
            if from_node and from_node not in q["from"]:
                q["from"].append(from_node)
                if why:
                    q.setdefault("from_why", {})[from_node] = why
            return False
        self.queries[k] = {"username": username, "query": query, "depth": depth, "source": source,
                           "candidate_of": candidate_of, "rule": rule, "from": [from_node] if from_node else [],
                           "why": why}
        return True

    def _origin(self, username: str) -> str:
        q = self.queries.get(username.lower())
        if not q or q["query"] == "input":
            return "username ตรงกับที่ค้น"
        if q["query"] == "candidate":
            return f"username ที่ระบบเดา ({q['rule']}) จาก \"{q['candidate_of']}\" ไม่ใช่ที่คุณพิมพ์"
        return f"username ที่เจอจาก {q['why']}"

    def _is_personal_site(self, url: str) -> bool:
        if not url.startswith(("http://", "https://")):
            return False
        h = _host(url)
        if not h or "." not in h or JUNK_HOSTS.search(h) or PLATFORM_HOSTS.search(h) or ASSET_HOST.search(h):
            return False
        hp = _host(url, keep_port=True)
        if any(hp == k or hp.endswith("." + k) for k in self._site_hosts):
            return False
        return match_social(url) is None

    def _handle_discoveries(self, found: list[Discovery], src_node: str, src_label: str, src_short: str,
                            depth: int, next_level: list[str]) -> list[dict[str, Any]]:
        """Record accounts the owner pointed at and queue new usernames."""
        cfg = self.cfg
        events: list[dict[str, Any]] = []
        for d in found:
            why = f"{HOW_TEXT[d.how]} {src_label}"
            site = self._by_name.get(d.platform or "")
            if d.platform:
                via = self._via.setdefault(self._key(d.platform, d.username), [])
                if src_node not in via:
                    via.append(src_node)
            # platforms we can't check automatically: the owner's own link is the evidence
            if d.platform and (site is None or site.check == "manual"):
                lkey = self._key(d.platform, d.username)
                if lkey in self._linked:
                    lr = self._linked[lkey]
                    if why not in lr.evidence:
                        lr.evidence.append(why)
                        lr.via = list(self._via[lkey])
                        events.append({"type": "result", **lr.to_dict()})
                else:
                    lr = Result(site=d.platform, username=d.username,
                                url=d.url or (site.profile_url(d.username) if site else d.username),
                                status=Status.FOUND, tags=site.tags if site else ["social"],
                                depth=depth, linked=True, evidence=[why], query="discovered",
                                checked_at=now_iso(), via=list(self._via[lkey]))
                    self._linked[lkey] = lr
                    self.results = [r for r in self.results if self._key(r.site, r.username) != lkey]
                    self.results.append(lr)
                    events.append({"type": "result", **lr.to_dict()})
            # follow the new username on every site
            if d.username.lower() in self.queries:
                self._add_query(d.username, "discovered", depth + 1, from_node=src_node, why=why)
            elif depth < cfg.depth and self._budget > 0:
                self._budget -= 1
                source = f"{src_short} ({d.platform or 'link'})"
                self._add_query(d.username, "discovered", depth + 1, source=source, from_node=src_node, why=why)
                next_level.append(d.username)
                self._log("เจอ username ใหม่", f"@{d.username} {why} → จะค้นต่อในชั้น {depth + 1}", src_node)
                events.append({"type": "discovered", "username": d.username, "source": source, "depth": depth + 1})
            elif not any(x["username"].lower() == d.username.lower() for x in self.skipped):
                self.skipped.append({"username": d.username, "why": why, "source": src_node, "platform": d.platform})
                self._log("ข้าม username", f"@{d.username} {why} (เกินจำนวนชั้นหรือโควตา)", src_node)
        return events

    def _queue_domains(self, result: Result) -> None:
        # Only the website the owner filled in (or a link-in-bio page's links):
        # other links on a profile are mostly the platform's own CDN/API hosts.
        site = self._by_name.get(result.site)
        urls: list[str] = []
        if result.info.get("website"):
            urls.append(result.info["website"])
        # A link-in-bio page also links to press articles, shops and friends:
        # only follow domains whose name points back at this person.
        if site and site.owner_links:
            urls += [u for u in getattr(result, "_strong_links", []) if self._names_person(u, result)]
        src = account_id(result.site, result.username)
        label = f"{result.site} (@{result.username})"
        for u in urls:
            if self._is_personal_site(u):
                self._domain_queue.append((u, src, label, self._names_person(u, result)))

    def _names_person(self, url: str, result: Result) -> bool:
        host = re.sub(r"[^a-z0-9]", "", _host(url).rsplit(".", 1)[0])
        names = {result.username} | {q["username"] for q in self.queries.values() if q["query"] != "candidate"}
        if len(result.info.get("name", "").split()) >= 2:
            names.add(result.info["name"])
        cores = {re.sub(r"[^a-z0-9]", "", n.lower()) for n in names}
        return any(len(c) >= 4 and c in host for c in cores)

    async def _fetch_domain(self, session: aiohttp.ClientSession, url: str) -> dict[str, Any]:
        rec: dict[str, Any] = {"domain": _host(url), "url": url, "status": "error", "http_status": None,
                               "title": "", "checked_at": now_iso(), "error": None, "links": [], "strong": [],
                               "emails": []}
        http_proxy = self.cfg.proxy if self.cfg.proxy and not self.cfg.proxy.startswith("socks") else None
        try:
            async with session.get(url, proxy=http_proxy,
                                   timeout=aiohttp.ClientTimeout(total=self.cfg.timeout)) as resp:
                rec["http_status"] = resp.status
                raw = await read_body(resp, MAX_BODY)
                try:
                    encoding = resp.get_encoding()
                except Exception:
                    encoding = "utf-8"
                text = raw.decode(encoding or "utf-8", errors="replace")
                ctype = resp.headers.get("Content-Type", "").lower()
                final = str(resp.url)
        except asyncio.TimeoutError:
            rec["error"] = "timeout"
            return rec
        except Exception as e:
            rec["error"] = f"{type(e).__name__}: {e}"[:200]
            return rec
        if any(m in text for m in WAF_MARKERS):
            rec["status"], rec["error"] = "blocked", "blocked by anti-bot protection"
            return rec
        if rec["http_status"] >= 400:
            rec["error"] = f"HTTP {rec['http_status']}"
            return rec
        info, strong, all_links = extract(text, ctype, final)
        # addresses the site publishes (mailto: links, contact text); a personal site's are the owner's
        mailto = re.findall(r'href=["\']mailto:([^"\'?]+)', text, re.I)
        emails = sorted(emails_in_text(" ".join(mailto)) | emails_in_text(re.sub(r"<[^>]+>", " ", text)))
        tz = TZ_IN_PAGE.search(text)  # e.g. a calendar widget or "timezone": "Asia/Bangkok"
        rec.update(status="ok", title=info.get("name", ""), strong=strong, links=all_links, emails=emails[:5],
                   timezone=tz.group(0) if tz else "")
        return rec

    async def _expand_domains(self, session: aiohttp.ClientSession, depth: int,
                              next_level: list[str]) -> AsyncIterator[dict[str, Any]]:
        """Fetch personal websites listed in found profiles and follow their profile links."""
        queue, self._domain_queue = self._domain_queue, []
        known = {d["domain"]: d for d in self.domains}
        todo: dict[str, tuple[str, list[str], str, list[bool]]] = {}
        for url, src, label, personal in queue:
            h = _host(url)
            if h in known:
                if src not in known[h]["via"]:
                    known[h]["via"].append(src)
                continue
            if h not in todo:
                if len(self.domains) + len(todo) >= self.cfg.max_domains:
                    continue
                todo[h] = (url, [], label, [False])
            if src not in todo[h][1]:
                todo[h][1].append(src)
            todo[h][3][0] |= personal
        if not todo:
            return
        yield {"type": "progress", "message": f"กำลังตรวจเว็บไซต์ส่วนตัว {len(todo)} เว็บ..."}
        recs = await asyncio.gather(*(self._fetch_domain(session, t[0]) for t in todo.values()))
        for (url, via, label, (personal,)), rec in zip(todo.values(), recs):
            rec.update(via=via, source=label, depth=depth, personal=personal)
            strong, links = rec.pop("strong"), rec.pop("links")
            disc: list[Discovery] = []
            rec["found_links"] = []
            if rec["status"] == "ok":
                # A personal homepage with a handful of profile links: those are the owner's.
                # A page full of them (a blog roll, a news site) only counts rel="me"/sameAs.
                profile_links = [u for u in links
                                 if match_social(u) or any(s.match_link(u) for s in self.all_sites)]
                chosen = strong + (profile_links if len(profile_links) <= 8 else [])
                pseudo = Result(site=rec["domain"], username="", url=url, status=Status.FOUND)
                pseudo._strong_links = chosen  # type: ignore[attr-defined]
                disc = discover_usernames(pseudo, self.all_sites, skip_brand=False)
                rec["found_links"] = pseudo.discovered
            # The site links back to the profile that listed it: same owner (IndieWeb rel=me idea).
            if any(account_id(d.platform, d.username) in via for d in disc if d.platform):
                personal = rec["personal"] = True
                rec["note"] = "เว็บนี้ลิงก์กลับไปยังโปรไฟล์ที่พามา (ยืนยันเจ้าของเดียวกัน)"
            if disc and not personal:
                # e.g. an employer's site in the "website" field: its social links are the
                # company's, not the person's. Show them, but don't treat them as evidence.
                rec["note"] = "ชื่อเว็บไม่ตรงกับ username/ชื่อเจ้าของ ลิงก์ที่เจออาจเป็นของเว็บเอง จึงไม่ใช้เป็นหลักฐาน"
                disc = []
            if not personal:
                rec["emails"] = []  # a company's contact address is not the person's
            self.domains.append(rec)
            self._log("ตรวจเว็บไซต์", f"{rec['domain']}: {rec['status']}"
                      + (f", ลิงก์ {', '.join(rec['found_links'][:4])}" if rec.get("found_links") else "")
                      + (f", อีเมล {', '.join(rec['emails'])}" if rec.get("emails") else ""), domain_id(rec["domain"]))
            yield {"type": "domain", **rec}
            for ev in self._handle_discoveries(disc, domain_id(rec["domain"]), f"เว็บไซต์ {rec['domain']}",
                                               rec["domain"], depth, next_level):
                yield ev

    # ---- cache -----------------------------------------------------------
    def _from_cache(self, site: Site, username: str, depth: int) -> Result | None:
        if not (self.history and self.cfg.cache) or site.check == "manual":
            return None
        try:
            d = self.history.cached(site.name, username, site_signature(site, self.cfg), self.cfg.cache_ttl)
        except sqlite3.Error:
            return None
        if not d:
            return None
        r = Result.from_dict({**d, "depth": depth, "evidence": [], "via": [], "linked": False, "cached": True})
        r._strong_links = d.get("_strong_links", [])  # type: ignore[attr-defined]
        self.cache_hits += 1
        return r

    def _to_cache(self, site: Site, r: Result) -> None:
        if not (self.history and self.cfg.cache) or r.cached or r.status not in (Status.FOUND, Status.NOT_FOUND):
            return
        d = r.to_dict()
        for k in ("evidence", "via", "linked", "query", "candidate_of", "depth", "cached", "discovered"):
            d.pop(k, None)
        d["_strong_links"] = list(getattr(r, "_strong_links", []))
        try:
            self.history.put_cache(site.name, r.username, site_signature(site, self.cfg), d)
            self._uncommitted += 1
            if self._uncommitted >= 20:  # never hold the database's write lock for a whole search
                self.history.commit()
                self._uncommitted = 0
        except sqlite3.Error:
            pass

    def _apply_search(self) -> list[dict[str, Any]]:
        """Mark blocked-platform placeholders whose profile page a search engine has indexed."""
        events = []
        manual = {self._key(r.site, r.username): r for r in self.results if r.status is Status.MANUAL}
        for h in self.search["hits"]:
            if not (h.get("platform") and h.get("same_handle")):
                continue
            r = manual.get(self._key(h["platform"], h["handle"]))
            if r and "indexed" not in r.info:
                r.info["indexed"] = h["engine"]
                r.info["indexed_url"] = h["url"]
                events.append({"type": "result", **r.to_dict()})
        return events

    # ---- main loop -------------------------------------------------------
    async def run(self, usernames: list[str]) -> AsyncIterator[dict[str, Any]]:
        cfg = self.cfg
        level: list[str] = []
        for u in usernames:
            if self._add_query(u, "input", 0):
                level.append(u)
        if cfg.variants:
            for u in usernames:
                for c in mutations(u, cfg.max_candidates):
                    if self._add_query(c.username, "candidate", 0, source=f"candidate ของ {u}: {c.rule}",
                                       candidate_of=u, rule=c.rule):
                        level.append(c.username)
        if cfg.numbers:
            for u in usernames:
                for c in numbered(u, *cfg.numbers):
                    if self._add_query(c.username, "candidate", 0, source=f"candidate ของ {u}: {c.rule}",
                                       candidate_of=u, rule=c.rule):
                        level.append(c.username)
        started = time.perf_counter()
        run_started = now_iso()
        sem = asyncio.Semaphore(cfg.concurrency)
        http_proxy = cfg.proxy if cfg.proxy and not cfg.proxy.startswith("socks") else None

        async with make_session(cfg) as session:

            async def guarded(site: Site, username: str, depth: int) -> Result:
                cached = self._from_cache(site, username, depth)
                if cached:
                    return cached
                if site.check != "manual" and site.valid(username):
                    await self.limiter.wait(_host(site.probe_url(username), keep_port=True))
                async with sem:
                    result = await check_site(session, site, username, cfg, depth, self.limiter)
                self._to_cache(site, result)
                return result

            # search engines run alongside the site checks (one polite query at a time)
            search_task = None
            if cfg.web_search:
                typed = [u for u in usernames if self.queries.get(u.lower(), {}).get("query") == "input"]
                self.search["manual"] = [{"username": u, **q} for u in typed for q in websearch.manual_links(u)]
                search_task = asyncio.create_task(websearch.search(
                    session, typed, max_queries=cfg.max_search_queries, delay=cfg.search_delay,
                    timeout=cfg.timeout, sites=self.all_sites, proxy=http_proxy, now=now_iso))
            try:
                for depth in range(cfg.depth + 1):
                    if not level:
                        break
                    for username in level:
                        q = self.queries[username.lower()]
                        yield {"type": "start", "username": username, "depth": depth, "query": q["query"],
                               "candidate_of": q["candidate_of"], "source": q["source"], "total": len(self.sites)}
                    typed_n = sum(1 for u in level if self.queries[u.lower()]["query"] != "candidate")
                    self._log("ค้น username", f"ชั้น {depth}: {', '.join('@' + u for u in level[:8])}"
                              + (f" และอีก {len(level) - 8}" if len(level) > 8 else "")
                              + f" บน {len(self.sites)} เว็บ" + (f" ({len(level) - typed_n} ชื่อเป็นชื่อใกล้เคียง)"
                                                                 if len(level) > typed_n else ""))
                    for ev in self._drain():
                        yield ev

                    tasks = [asyncio.create_task(guarded(site, u, depth))
                             for u in level for site in self.sites
                             # a guessed spelling on a platform we can't check = nothing to show
                             if not (site.check == "manual" and self.queries[u.lower()]["query"] == "candidate")]
                    next_level: list[str] = []
                    try:
                        for fut in asyncio.as_completed(tasks):
                            result = await fut
                            q = self.queries[result.username.lower()]
                            result.query, result.candidate_of = q["query"], q["candidate_of"]
                            key = self._key(result.site, result.username)
                            if result.status is Status.MANUAL and key in self._linked:
                                continue  # already confirmed through a profile link
                            if result.status is Status.FOUND:
                                result.evidence.append(self._origin(result.username))
                            self.results.append(result)
                            yield {"type": "result", **result.to_dict()}
                            if result.status is not Status.FOUND:
                                continue
                            self._log("พบบัญชี", f"{result.site} @{result.username}"
                                      + (" (cache)" if result.cached else f" HTTP {result.http_status}")
                                      + (f", เว็บไซต์ {result.info['website']}" if result.info.get("website") else ""),
                                      account_id(result.site, result.username))
                            found = discover_usernames(result, self.all_sites)
                            for ev in self._handle_discoveries(found, account_id(result.site, result.username),
                                                               f"{result.site} (@{result.username})",
                                                               f"{result.username} @ {result.site}", depth,
                                                               next_level):
                                yield ev
                            if cfg.domains and depth < cfg.depth:
                                self._queue_domains(result)
                            for ev in self._drain():
                                yield ev
                    finally:
                        for t in tasks:
                            t.cancel()
                    if self._domain_queue:
                        async for ev in self._expand_domains(session, depth, next_level):
                            yield ev
                        for ev in self._drain():
                            yield ev
                    level = next_level

                if cfg.archive:
                    manual = [r for r in self.results if r.status is Status.MANUAL and r.depth == 0][:20]
                    if manual:
                        yield {"type": "progress", "message": "กำลังค้น IG/FB/TikTok/X ใน Wayback Machine..."}
                        for r in await archive_lookup(session, manual):
                            self._log("archive.org", f"เคยเก็บหน้า {r.site} @{r.username} ({r.info['archived']})",
                                      account_id(r.site, r.username))
                            yield {"type": "result", **r.to_dict()}
                if search_task:
                    if not search_task.done():
                        yield {"type": "progress", "message": "กำลังค้นใน DuckDuckGo / Bing..."}
                    self.search.update(await search_task)
                    for q in self.search["queries"]:
                        self._log("search engine", f"#{q.get('n', '')} {q.get('engine') or '-'}: {q['query']} → "
                                  + (f"{q['count']} ผล" if q["status"] == "ok" else q["status"]))
                    yield {"type": "search", **self.search}
                    for ev in self._apply_search():
                        yield ev
                hashes: dict = {}
                if cfg.avatars and avatars.available():
                    yield {"type": "progress", "message": "กำลังเทียบรูปโปรไฟล์..."}
                    hashes = await avatars.hash_avatars(session, [r.to_dict() for r in self.results])
                    self._log("เทียบรูปโปรไฟล์", f"ดึงรูปได้ {len(hashes)} รูป")
            finally:
                if search_task and not search_task.done():
                    search_task.cancel()
                if self.history:  # also when the search is stopped half way
                    try:
                        self.history.commit()
                    except sqlite3.Error:
                        pass

        for r in self.results:
            for node in self._via.get(self._key(r.site, r.username), []):
                if node not in r.via and node != account_id(r.site, r.username):
                    r.via.append(node)
        dicts = [r.to_dict() for r in self.results]
        hits = self.search["hits"]
        options = {k: getattr(cfg, k) for k in ("depth", "variants", "numbers", "web_search", "domains", "cache")}
        self.connections = find_connections(dicts, hashes)
        self.identity = identity_summary(dicts, usernames, avatars.match_hashes(dicts, hashes), self.connections,
                                         hits)
        scores = {account_id(i["site"], i["username"]): i["score"] for i in self.identity}
        self.clusters = identity_clusters(dicts, self.connections, self.domains, scores)
        self._log("เทียบความเชื่อมโยง", f"{len(self.connections)} คู่ที่น่าสนใจ, รวมได้ {len(self.clusters)} กลุ่มตัวตน")
        # contradictions lower the groups' and the accounts' confidence before anything is reported
        self.contradictions = contra.detect(dicts, self.clusters, self.identity, self.domains)
        apply_contradictions(self.identity, contra.penalties(self.contradictions, self.clusters))
        for c in self.contradictions:
            self._log("⚠ หลักฐานขัดแย้ง", f"{c['scope_label']}: {c['message']}")
        self.entities = find_entities(dicts, self.clusters, self.identity, usernames)
        self.graph = build_graph(dicts, self.queries, self.domains, self.connections, hits)
        seen: dict[tuple[str, str], dict[str, Any]] = {}
        history_changes: list[dict[str, Any]] = []
        username_history: list[dict[str, Any]] = []
        if self.history:
            try:
                rec = self.history.record_run(usernames, dicts, hashes, self.stats(), started=run_started,
                                              options=options, domains=self.domains, hits=hits, graph=self.graph)
                self.run_id, self.changes, seen = rec["run_id"], rec["changes"], rec["seen"]
                names = sorted({r["username"] for r in dicts if r["status"] == "found"} | set(usernames))
                history_changes = self.history.changes_for(names)
                username_history = self.history.username_history({handle_core(u) for u in usernames}, handle_core)
                self._log("บันทึกฐานข้อมูล", f"ครั้งที่ #{self.run_id}: เปลี่ยนแปลง {len(self.changes)} รายการ")
            except sqlite3.Error as e:
                yield {"type": "progress", "message": f"บันทึกประวัติไม่ได้: {e}"}
        self.findings = build_findings(dicts, self.identity, self.domains, hits, seen, self.queries)
        self.timeline = build_timeline(dicts, history_changes or self.changes, seen, self.domains, run_started,
                                       username_history)
        self.plan = make_plan(usernames, dicts, queries=self.queries, domains=self.domains, identity=self.identity,
                              search=self.search, contradictions=self.contradictions, skipped=self.skipped,
                              options=options)
        self._log("วางแผนขั้นต่อไป", f"แนะนำ {len(self.plan)} ขั้น" + (f": {self.plan[0]['title']}" if self.plan else ""))
        self.summary = summary(usernames, dicts, self.identity, self.findings, self.clusters, self.changes,
                               hits, self.domains)
        self.summary.update(contradictions=len(self.contradictions), entities=len(self.entities),
                            fp_high=sum(1 for i in self.identity if i.get("fp_risk") == "HIGH"),
                            next_steps=len(self.plan))
        for ev in self._drain():
            yield ev
        done = {"type": "done", "stats": self.stats(), "identity": self.identity,
                "connections": self.connections, "clusters": self.clusters, "entities": self.entities,
                "contradictions": self.contradictions, "plan": self.plan, "replay": self.replay,
                "domains": self.domains, "graph": self.graph, "queries": list(self.queries.values()),
                "findings": self.findings, "timeline": self.timeline, "changes": self.changes, "search": self.search,
                "summary": self.summary, "run_id": self.run_id, "started": run_started, "usernames": usernames,
                "options": options, "elapsed": round(time.perf_counter() - started, 1)}
        if self.history and self.run_id:
            try:  # the whole run, so a case / the replay can reopen it without searching again
                self.history.save_payload(self.run_id, {"results": dicts, "done": done})
            except sqlite3.Error:
                pass
        yield done

    def stats(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Status}
        for r in self.results:
            counts[r.status.value] += 1
        counts["linked"] = sum(1 for r in self.results if r.linked)
        counts["usernames"] = len({r.username.lower() for r in self.results})
        counts["candidates_found"] = sum(1 for r in self.results
                                         if r.status is Status.FOUND and r.query == "candidate")
        counts["domains"] = len(self.domains)
        counts["connections"] = len(self.connections)
        counts["cached"] = self.cache_hits
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
