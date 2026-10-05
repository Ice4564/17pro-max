"""Site database: loading, validation and URL helpers."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .linker import NOT_HANDLES

DATA_FILE = Path(__file__).parent / "data" / "sites.json"

CHECK_TYPES = ("status_code", "message", "response_url", "manual")

# Path segments that are never real usernames when we try to recognise a
# profile link on another site (used by recursive search).
RESERVED_NAMES = {
    "about", "account", "api", "app", "apps", "assets", "blog", "careers",
    "contact", "dashboard", "docs", "download", "en", "explore", "faq",
    "features", "feed", "help", "hashtag", "home", "i", "intent", "jobs",
    "legal", "login", "logout", "p", "pricing", "privacy", "register",
    "search", "settings", "share", "signin", "signup", "static", "status",
    "support", "terms", "th", "tos", "watch", "www", "results", "explore",
    "notifications", "messages", "company", "pages", "groups", "events",
} | NOT_HANDLES


@dataclass
class Site:
    name: str
    url: str
    main: str
    check: str = "status_code"
    probe: str | None = None
    error_msg: list[str] = field(default_factory=list)
    presence_msg: list[str] = field(default_factory=list)
    error_url: str | None = None
    regex: str | None = None
    method: str = "GET"
    json_body: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    ok_codes: list[int] = field(default_factory=lambda: [200])
    tags: list[str] = field(default_factory=list)
    claimed: str = "blue"
    extract: bool = True
    owner_links: bool = False  # every external link on the page belongs to the owner (link-in-bio sites)
    disabled: bool = False

    # ---- construction -------------------------------------------------
    @classmethod
    def from_dict(cls, name: str, d: dict[str, Any]) -> "Site":
        def as_list(v: Any) -> list[str]:
            if v is None:
                return []
            return [v] if isinstance(v, str) else list(v)

        check = d.get("check", "status_code")
        if check not in CHECK_TYPES:
            raise ValueError(f"{name}: unknown check type {check!r}")
        if "{}" not in d["url"]:
            raise ValueError(f"{name}: url must contain '{{}}'")
        if check == "message" and not d.get("error_msg"):
            raise ValueError(f"{name}: check 'message' needs error_msg")
        return cls(
            name=name,
            url=d["url"],
            main=d.get("main") or _main_from_url(d["url"]),
            check=check,
            probe=d.get("probe"),
            error_msg=as_list(d.get("error_msg")),
            presence_msg=as_list(d.get("presence_msg")),
            error_url=d.get("error_url"),
            regex=d.get("regex"),
            method=d.get("method", "GET").upper(),
            json_body=d.get("json"),
            headers=dict(d.get("headers", {})),
            ok_codes=list(d.get("ok_codes", [200])),
            tags=[t.lower() for t in d.get("tags", [])],
            claimed=d.get("claimed", "blue"),
            extract=bool(d.get("extract", True)),
            owner_links=bool(d.get("owner_links", False)),
            disabled=bool(d.get("disabled", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"url": self.url, "main": self.main, "check": self.check}
        if self.probe:
            d["probe"] = self.probe
        if self.error_msg:
            d["error_msg"] = self.error_msg if len(self.error_msg) > 1 else self.error_msg[0]
        if self.presence_msg:
            d["presence_msg"] = self.presence_msg
        if self.error_url:
            d["error_url"] = self.error_url
        if self.regex:
            d["regex"] = self.regex
        if self.method != "GET":
            d["method"] = self.method
        if self.json_body is not None:
            d["json"] = self.json_body
        if self.headers:
            d["headers"] = self.headers
        if self.ok_codes != [200]:
            d["ok_codes"] = self.ok_codes
        d["tags"] = self.tags
        d["claimed"] = self.claimed
        if not self.extract:
            d["extract"] = False
        if self.owner_links:
            d["owner_links"] = True
        if self.disabled:
            d["disabled"] = True
        return d

    # ---- username helpers ---------------------------------------------
    @cached_property
    def _regex(self) -> re.Pattern[str] | None:
        return re.compile(self.regex) if self.regex else None

    def valid(self, username: str) -> bool:
        if not username or any(c.isspace() for c in username):
            return False
        return self._regex is None or bool(self._regex.fullmatch(username))

    def profile_url(self, username: str) -> str:
        return self.url.replace("{}", quote(username, safe=""))

    def probe_url(self, username: str) -> str:
        return (self.probe or self.url).replace("{}", quote(username, safe=""))

    def body(self, username: str) -> Any:
        if self.json_body is None:
            return None
        return _fill(copy.deepcopy(self.json_body), username)

    # ---- profile-link recognition (for recursive search) ---------------
    @cached_property
    def _link_regex(self) -> re.Pattern[str]:
        template = re.sub(r"^https?://", "", self.url)
        template = re.sub(r"^www\.", "", template).rstrip("/")
        prefix, _, suffix = template.partition("{}")
        # A placeholder followed by "." is a subdomain: no dots allowed.
        charset = r"[A-Za-z0-9_\-]" if suffix.startswith(".") else r"[A-Za-z0-9_.\-]"
        pattern = (
            r"^(?:https?://)?(?:www\.|m\.|mobile\.)?"
            + re.escape(prefix)
            + rf"({charset}{{2,40}})"
            + re.escape(suffix)
            + r"/?(?:[?#].*)?$"
        )
        return re.compile(pattern, re.IGNORECASE)

    def match_link(self, link: str) -> str | None:
        """Return the username if ``link`` is a profile URL on this site."""
        m = self._link_regex.match(link.strip())
        if not m:
            return None
        username = m.group(1).strip(".")
        if username.lower() in RESERVED_NAMES or not self.valid(username):
            return None
        return username


def _fill(obj: Any, username: str) -> Any:
    if isinstance(obj, str):
        return obj.replace("{}", username)
    if isinstance(obj, list):
        return [_fill(x, username) for x in obj]
    if isinstance(obj, dict):
        return {k: _fill(v, username) for k, v in obj.items()}
    return obj


def _main_from_url(url: str) -> str:
    m = re.match(r"^(https?://)([^/]+)", url)
    host = m.group(2).replace("{}.", "") if m else url
    return f"{m.group(1) if m else 'https://'}{host}/"


def load_sites(path: str | Path | None = None, include_disabled: bool = False) -> list[Site]:
    path = Path(path) if path else DATA_FILE
    raw = json.loads(path.read_text(encoding="utf-8"))
    sites = [Site.from_dict(name, d) for name, d in raw.items() if not name.startswith("$")]
    if not include_disabled:
        sites = [s for s in sites if not s.disabled]
    return sorted(sites, key=lambda s: s.name.lower())


def save_sites(sites: list[Site], path: str | Path | None = None) -> None:
    path = Path(path) if path else DATA_FILE
    data = {s.name: s.to_dict() for s in sorted(sites, key=lambda s: s.name.lower())}
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def filter_sites(
    sites: list[Site],
    names: list[str] | None = None,
    tags: list[str] | None = None,
    exclude_tags: list[str] | None = None,
) -> list[Site]:
    out = sites
    if names:
        wanted = {n.lower() for n in names}
        out = [s for s in out if s.name.lower() in wanted]
    if tags:
        wanted_tags = {t.lower() for t in tags}
        out = [s for s in out if wanted_tags & set(s.tags)]
    if exclude_tags:
        bad = {t.lower() for t in exclude_tags}
        out = [s for s in out if not bad & set(s.tags)]
    return out


def all_tags(sites: list[Site]) -> list[str]:
    return sorted({t for s in sites for t in s.tags})
