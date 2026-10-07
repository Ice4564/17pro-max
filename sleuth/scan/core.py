"""Event-driven scan engine (SpiderFoot style).

A scan starts from one *root* event (a domain, IP, email or username).
Every event is offered to the modules that watch its type; modules emit
new events, which are offered to modules again, until nothing new is found.
Scope rules and budgets keep the scan from wandering across the internet.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from ..engine import SearchConfig, make_session, read_body
from ..similarity import WEBMAIL  # noqa: F401  (re-exported for scan modules)

# event type -> (Thai label, group)
EVENT_TYPES: dict[str, tuple[str, str]] = {
    "DOMAIN_NAME": ("โดเมน", "infra"),
    "INTERNET_NAME": ("ซับโดเมน / โฮสต์", "infra"),
    "IP_ADDRESS": ("IP address", "infra"),
    "IPV6_ADDRESS": ("IPv6 address", "infra"),
    "DNS_MX": ("Mail server (MX)", "infra"),
    "DNS_NS": ("Name server (NS)", "infra"),
    "DNS_TXT": ("DNS TXT record", "infra"),
    "SPF_RECORD": ("SPF record", "security"),
    "DMARC_RECORD": ("DMARC record", "security"),
    "DOMAIN_REGISTRAR": ("ผู้รับจดโดเมน", "infra"),
    "DOMAIN_REGISTERED": ("วันจดโดเมน", "infra"),
    "DOMAIN_EXPIRES": ("วันหมดอายุโดเมน", "infra"),
    "NETBLOCK_OWNER": ("เจ้าของเครือข่าย IP", "infra"),
    "ASN": ("ASN / ผู้ให้บริการ", "infra"),
    "GEOINFO": ("ตำแหน่งทางภูมิศาสตร์", "infra"),
    "OPEN_PORT": ("พอร์ตที่เปิด", "security"),
    "VULNERABILITY": ("ช่องโหว่ (CVE)", "security"),
    "SSL_CERT": ("SSL certificate", "security"),
    "SSL_CERT_INVALID": ("SSL certificate ไม่ถูกต้อง", "security"),
    "WEB_TITLE": ("ชื่อหน้าเว็บ", "web"),
    "WEB_SERVER": ("Web server", "web"),
    "WEB_TECH": ("เทคโนโลยีที่ใช้", "web"),
    "WEB_HEADERS_MISSING": ("Security header ที่ขาด", "security"),
    "SECURITY_TXT": ("security.txt", "security"),
    "LINKED_DOMAIN": ("โดเมนที่ลิงก์ออกไป", "web"),
    "WAYBACK": ("Wayback Machine", "web"),
    "EMAIL": ("อีเมล", "identity"),
    "USERNAME": ("Username", "identity"),
    "SOCIAL_PROFILE": ("โปรไฟล์โซเชียล", "identity"),
    "ACCOUNT": ("บัญชีที่พบ", "identity"),
    "GRAVATAR": ("Gravatar", "identity"),
    "PGP_KEY": ("PGP key", "identity"),
    "HUMAN_NAME": ("ชื่อคน", "identity"),
    "WEB_MENTION": ("หน้าเว็บที่กล่าวถึง", "identity"),
}


EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+\.)+[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def detect_target(raw: str) -> tuple[str, str]:
    """Return ``(event_type, normalised_value)`` for a user-supplied target."""
    t = raw.strip()
    try:
        ip = ipaddress.ip_address(t)
        return ("IPV6_ADDRESS" if ip.version == 6 else "IP_ADDRESS"), str(ip)
    except ValueError:
        pass
    if EMAIL_RE.match(t):
        return "EMAIL", t.lower()
    host = re.sub(r"^[a-z]+://", "", t.lower()).split("/")[0].split(":")[0]
    if "." in host and DOMAIN_RE.match(host):
        return "DOMAIN_NAME", host.removeprefix("www.")
    return "USERNAME", t.lstrip("@")


@dataclass
class Event:
    type: str
    data: str
    module: str
    parent: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    depth: int = 0
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    ts: float = field(default_factory=time.time)

    def child(self, type_: str, data: str, module: str, **extra: Any) -> "Event":
        return Event(type_, str(data), module, parent=self.id, extra=extra, depth=self.depth + 1)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "type": self.type, "data": self.data, "module": self.module,
                "parent": self.parent, "extra": self.extra, "depth": self.depth, "ts": self.ts}


@dataclass
class ScanConfig:
    timeout: float = 15.0
    concurrency: int = 20
    max_depth: int = 5
    max_events: int = 3000
    # budgets: how many items of each kind may be processed
    budgets: dict[str, int] = field(default_factory=lambda: {
        "resolve": 150,     # hostnames to resolve
        "web": 15,          # hosts whose web page we fetch
        "ssl": 15,          # hosts whose certificate we read
        "ip": 25,           # IPs to enrich (geo, rdap, ports)
        "username": 5,      # usernames to search on all sites
        "email": 25,        # emails to enrich
        "search": 3,        # usernames / emails to look up in search engines
    })


class Context:
    """What a module can see and do while handling an event."""

    def __init__(self, scanner: "Scanner") -> None:
        self._scanner = scanner
        self.cfg = scanner.cfg
        self.session: aiohttp.ClientSession = scanner.session  # type: ignore[assignment]
        self.root = scanner.root
        self.scope_domain = scanner.scope_domain

    def in_scope(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        d = self.scope_domain
        return bool(d) and (host == d or host.endswith("." + d))

    def take(self, budget: str, key: str, ns: str = "") -> bool:
        """Consume one unit of a budget for ``key`` (each key counts once).

        ``ns`` gives a module its own allowance of the same budget size.
        """
        used = self._scanner.budget_used.setdefault(f"{budget}:{ns}", set())
        if key in used:
            return False
        if len(used) >= self.cfg.budgets.get(budget, 0):
            return False
        used.add(key)
        return True

    def seen(self, type_: str, data: str) -> bool:
        return (type_, data.lower()) in self._scanner.seen

    async def get(self, url: str, *, json: bool = False, timeout: float | None = None,
                  headers: dict[str, str] | None = None, allow_redirects: bool = True) -> tuple[int, Any, dict]:
        """GET helper returning ``(status, body, headers)``; body is text or parsed JSON."""
        async with self.session.get(
            url, headers=headers, allow_redirects=allow_redirects,
            timeout=aiohttp.ClientTimeout(total=timeout or self.cfg.timeout),
        ) as r:
            raw = await read_body(r, 3_000_000)
            try:
                encoding = r.get_encoding()
            except Exception:
                encoding = "utf-8"
            text = raw.decode(encoding or "utf-8", errors="replace")
            if json:
                import json as _json
                try:
                    return r.status, _json.loads(text), dict(r.headers)
                except ValueError:
                    return r.status, None, dict(r.headers)
            return r.status, text, dict(r.headers)


class Module:
    """Base class for scan modules."""

    name = "base"
    title = ""
    description = ""
    category = "infra"  # infra | web | identity | security
    group = ""  # username | social | domain | email | image | search (see modules/__init__.py)
    watches: tuple[str, ...] = ()
    default = True

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        if False:  # pragma: no cover - makes this an async generator
            yield event

    def info(self) -> dict[str, Any]:
        return {"name": self.name, "title": self.title, "description": self.description,
                "category": self.category, "group": self.group, "watches": list(self.watches),
                "default": self.default, "plugin": getattr(self, "plugin", None)}


class Scanner:
    def __init__(self, target: str, modules: list[Module], cfg: ScanConfig | None = None) -> None:
        self.cfg = cfg or ScanConfig()
        self.modules = modules
        rtype, value = detect_target(target)
        self.root = Event(rtype, value, "root")
        if rtype == "DOMAIN_NAME":
            self.scope_domain: str | None = value
        elif rtype == "EMAIL" and value.split("@")[1] not in WEBMAIL:
            self.scope_domain = value.split("@")[1]
        else:
            self.scope_domain = None
        self.events: list[Event] = []
        self.seen: set[tuple[str, str]] = set()
        self.budget_used: dict[str, set[str]] = {}
        self.modules_run: set[str] = set()
        self.errors: list[dict[str, str]] = []
        self.session: aiohttp.ClientSession | None = None
        self._tasks: set[asyncio.Task] = set()
        self._out: asyncio.Queue = asyncio.Queue()
        self._sem = asyncio.Semaphore(self.cfg.concurrency)

    # ---- public ------------------------------------------------------
    async def run(self) -> AsyncIterator[dict[str, Any]]:
        started = time.time()
        main = asyncio.create_task(self._main())
        try:
            while True:
                msg = await self._out.get()
                if msg is None:
                    break
                yield msg
            await main
        finally:
            main.cancel()
            for t in list(self._tasks):
                t.cancel()

        from .correlate import correlate
        findings = correlate(self)
        for f in findings:
            yield {"type": "finding", **f}
        yield {"type": "done", "elapsed": round(time.time() - started, 1),
               "counts": self.counts(), "findings": len(findings), "errors": len(self.errors)}

    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for e in self.events:
            c[e.type] = c.get(e.type, 0) + 1
        return c

    # ---- internals ---------------------------------------------------
    async def _main(self) -> None:
        cfg = SearchConfig(timeout=self.cfg.timeout, concurrency=self.cfg.concurrency * 2)
        async with make_session(cfg) as session:
            self.session = session
            await self._out.put({"type": "start", "target": self.root.data, "target_type": self.root.type,
                                 "modules": [m.name for m in self.modules]})
            await self.emit(self.root)
            while self._tasks:
                await asyncio.wait(set(self._tasks))
        await self._out.put(None)

    async def emit(self, event: Event) -> None:
        key = (event.type, event.data.strip().lower())
        if not event.data.strip() or key in self.seen or len(self.events) >= self.cfg.max_events:
            return
        if event.type == "INTERNET_NAME" and key[1] == self.scope_domain:
            return  # the root domain is already a DOMAIN_NAME event
        self.seen.add(key)
        self.events.append(event)
        await self._out.put({"type": "event", "event": event.to_dict()})
        if event.depth >= self.cfg.max_depth:
            return
        for module in self.modules:
            if event.type in module.watches:
                task = asyncio.create_task(self._run_module(module, event))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)

    async def _run_module(self, module: Module, event: Event) -> None:
        ctx = Context(self)
        async with self._sem:
            self.modules_run.add(module.name)
            try:
                async for new in module.handle(event, ctx):
                    await self.emit(new)
            except asyncio.CancelledError:
                raise
            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                self._error(module, event, f"network: {type(e).__name__} {e}".strip())
            except Exception as e:  # a broken module must never kill the scan
                self._error(module, event, f"{type(e).__name__}: {e}")

    def _error(self, module: Module, event: Event, msg: str) -> None:
        err = {"module": module.name, "event": f"{event.type}:{event.data}", "error": msg[:300]}
        self.errors.append(err)
        self._out.put_nowait({"type": "module_error", **err})
