"""Pull public profile information out of a found page (HTML or JSON).

Works without third-party parsers: meta/OpenGraph tags, JSON-LD, embedded
JSON blobs (e.g. Next.js ``__NEXT_DATA__``) and JSON API responses.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

MAX_VALUE_LEN = 300

# canonical field -> keys that commonly hold it (lower-case, no separators)
FIELD_KEYS: dict[str, tuple[str, ...]] = {
    "name": ("name", "displayname", "fullname", "realname", "nickname"),
    "username": ("username", "login", "handle", "uniqueid"),
    "bio": ("bio", "about", "aboutme", "description", "summary", "tagline"),
    "location": ("location", "country", "city", "address"),
    "website": ("website", "blog", "homepage", "websiteurl", "personalwebsite"),
    "avatar": ("avatarurl", "avatar", "profileimageurl", "profilepic", "profilepicture", "profileimage",
               "picture", "image", "photo"),
    "created": ("createdat", "created", "joined", "joinedat", "registered", "datejoined", "creationdate", "memberssince"),
    "followers": ("followers", "followerscount", "followercount", "subscribers"),
    "following": ("following", "followingcount", "friendscount"),
    "twitter": ("twitterusername", "twitter"),
    "github": ("githubusername", "github"),
}
_KEY_TO_FIELD = {k: f for f, keys in FIELD_KEYS.items() for k in keys}

META_FIELDS = {
    "og:title": "name",
    "twitter:title": "name",
    "profile:username": "username",
    "og:description": "bio",
    "twitter:description": "bio",
    "description": "bio",
    "og:image": "avatar",
    "twitter:image": "avatar",
}

URL_RE = re.compile(r"https?://[^\s\"'<>\\]+")


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, str] = {}
        self.title = ""
        self.me_links: list[str] = []
        self.links: list[str] = []
        self.json_blobs: list[str] = []
        self._in_title = False
        self._script_json = False
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta":
            key = (a.get("property") or a.get("name") or a.get("itemprop") or "").lower()
            if key and a.get("content") and key not in self.meta:
                self.meta[key] = a["content"]
        elif tag == "title":
            self._in_title = True
        elif tag in ("a", "link") and a.get("href"):
            rel = a.get("rel", "").lower().split()
            if "me" in rel:
                self.me_links.append(a["href"])
            elif tag == "a":
                self.links.append(a["href"])
        elif tag == "script":
            t = a.get("type", "").lower()
            if "json" in t:
                self._script_json = True
                self._buf = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "script" and self._script_json:
            self._script_json = False
            self.json_blobs.append("".join(self._buf))

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        elif self._script_json:
            self._buf.append(data)


def _norm_key(key: str) -> str:
    return re.sub(r"[^a-z]", "", key.lower())


def _clean(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        v = " ".join(unescape(value).split())
        return v[:MAX_VALUE_LEN] if v else None
    return None


def _maybe_date(value: str) -> str:
    """Turn unix timestamps into ISO dates; leave other values untouched."""
    if value.isdigit():
        n = int(value)
        if n > 10**12:  # milliseconds
            n //= 1000
        if 10**8 < n < 10**10:
            return datetime.fromtimestamp(n, tz=timezone.utc).strftime("%Y-%m-%d")
    return value


def _walk_json(obj: Any, info: dict[str, str], links: list[str], depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            field = _KEY_TO_FIELD.get(_norm_key(str(key)))
            if field and field not in info:
                if isinstance(value, dict):  # e.g. {"avatar": {"url": ...}}
                    value = value.get("url") or value.get("name") or value.get("text")
                cleaned = _clean(value)
                if cleaned:
                    info[field] = cleaned
            if _norm_key(str(key)) in ("sameas", "links", "sociallinks", "urls"):
                for v in value if isinstance(value, list) else [value]:
                    if isinstance(v, str) and v.startswith("http"):
                        links.append(v)
                    elif isinstance(v, dict):
                        u = v.get("url") or v.get("href")
                        if isinstance(u, str) and u.startswith("http"):
                            links.append(u)
            _walk_json(value, info, links, depth + 1)
    elif isinstance(obj, list):
        for item in obj[:50]:
            _walk_json(item, info, links, depth + 1)
    elif isinstance(obj, str) and obj.startswith("http") and len(obj) < 300:
        links.append(obj)


def _external(links: list[str], base_url: str) -> list[str]:
    base_host = _host(base_url, keep_port=True)
    out: list[str] = []
    seen: set[str] = set()
    for link in links:
        link = unescape(link).strip()
        if link.startswith("//"):
            link = "https:" + link
        if not link.startswith("http"):
            continue
        host = _host(link, keep_port=True)
        if not host or host == base_host or host.endswith("." + base_host):
            continue
        if re.search(r"\.(png|jpe?g|gif|svg|webp|css|js|woff2?|ico)(\?|$)", link, re.I):
            continue
        key = link.rstrip("/").lower()
        if key not in seen:
            seen.add(key)
            out.append(link)
    return out[:60]


def _host(url: str, keep_port: bool = False) -> str:
    host = urlparse(url).netloc.lower()
    host = host if keep_port else host.split(":")[0]
    return host[4:] if host.startswith("www.") else host


def extract(text: str, content_type: str, base_url: str) -> tuple[dict[str, str], list[str], list[str]]:
    """Return ``(info, strong_links, all_links)``.

    ``strong_links`` come from places that describe the profile owner
    (rel="me", JSON-LD sameAs, API fields) and are safe for recursion;
    ``all_links`` additionally contains every external anchor on the page.
    """
    info: dict[str, str] = {}
    strong: list[str] = []
    text = text or ""

    stripped = text.lstrip()
    if "json" in content_type or stripped[:1] in ("{", "["):
        try:
            _walk_json(json.loads(stripped), info, strong)
            return _finish(info), _external(strong, base_url), _external(strong, base_url)
        except ValueError:
            pass

    parser = _PageParser()
    try:
        parser.feed(text[:2_000_000])
        parser.close()
    except Exception:  # malformed HTML: use whatever was parsed so far
        pass

    # JSON-LD and embedded JSON first: they're the most structured source.
    for blob in parser.json_blobs:
        try:
            _walk_json(json.loads(blob), info, strong)
        except ValueError:
            continue

    for key, field in META_FIELDS.items():
        if field not in info and parser.meta.get(key):
            cleaned = _clean(parser.meta[key])
            if cleaned:
                info[field] = cleaned
    if "name" not in info and parser.title.strip():
        info["name"] = _clean(parser.title) or ""

    if "avatar" in info:
        info["avatar"] = urljoin(base_url, info["avatar"])

    strong.extend(urljoin(base_url, h) for h in parser.me_links)
    all_links = strong + [urljoin(base_url, h) for h in parser.links]
    return _finish(info), _external(strong, base_url), _external(all_links, base_url)


def _finish(info: dict[str, str]) -> dict[str, str]:
    if "created" in info:
        created = _maybe_date(info["created"])
        info["created"] = created[:10] if re.match(r"^\d{4}-\d{2}-\d{2}T", created) else created
    if info.get("location", "").startswith("http"):  # e.g. .../country/TH
        info["location"] = info["location"].rstrip("/").rsplit("/", 1)[-1]
    return {k: v for k, v in info.items() if v}


_NAME_SEPARATORS = (" | ", " - ", " — ", " – ", " · ")


def clean_info(info: dict[str, str], site_name: str, site_main: str, username: str) -> dict[str, str]:
    """Remove site boilerplate (page titles, generic descriptions)."""
    brand_words = {re.sub(r"[^a-z0-9]", "", site_name.lower())}
    host = _host(site_main).split(".")
    if len(host) >= 2:
        brand_words.add(host[-2])
    brand_words.discard("")
    user = username.lower()

    def mentions_brand(text: str) -> bool:
        flat = re.sub(r"[^a-z0-9]", "", text.lower())
        return any(b in flat for b in brand_words)

    out = dict(info)
    name = out.get("name")
    if name:
        for sep in _NAME_SEPARATORS:
            name = name.split(sep)[0]
        name = re.sub(r"^(profile|user|member)\s*:\s*", "", name, flags=re.I)
        name = re.sub(r"[\u2019']s\s+(profile|gists|pastebin|page|channel|blog)\b.*$", "", name, flags=re.I)
        name = re.sub(r"\s+(on|in|at|\u0e43\u0e19|\u0e1a\u0e19)\s+\S+$", "", name, flags=re.I)
        name = name.strip(" -|·")
        if not name or (mentions_brand(name) and user not in name.lower()):
            out.pop("name")
        else:
            out["name"] = name
    bio = out.get("bio")
    if bio and mentions_brand(bio) and user not in bio.lower():
        out.pop("bio")
    return out
