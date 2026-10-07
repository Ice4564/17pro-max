"""Second opinion on a "found" answer.

Many sites answer HTTP 200 for any URL (soft 404s, SPA shells, redirects to
the home page). After a site's own rule says FOUND, we look at the page
itself before believing it:

    title        - "Page not found", "404", "ไม่พบ" ...
    redirect     - did we end up on a page without the username (home, login)?
    canonical    - <link rel=canonical> / og:url (warning only: some sites point
                   it at the root even on real profiles)
    username     - does the page mention the username at all?
    profile      - profile-specific markers (og:type=profile, JSON-LD Person,
                   the site's own presence_msg, a non-empty JSON API answer)

Each check is recorded so reports can show *why* a result was trusted.
"""

from __future__ import annotations

import json
import re
from html import unescape
from typing import Any, TYPE_CHECKING
from urllib.parse import unquote, urlparse

if TYPE_CHECKING:  # pragma: no cover
    from .engine import Status, _Response
    from .sites import Site

SCAN_BYTES = 600_000

SOFT_404 = re.compile(
    r"\b(?:404|page not found|not found|doesn[’']?t exist|does not exist|no such (?:user|page|account)|"
    r"user(?:name)? not found|profile not found|account (?:not found|suspended|deactivated)|"
    r"this page (?:isn[’']?t|is not) available|nothing here|error)\b|ไม่พบ(?:หน้า|ผู้ใช้|บัญชี)?",
    re.I,
)
# Where sites send you when the profile doesn't exist.
DEAD_END_PATHS = re.compile(r"^/?(?:$|index\.\w+$|home/?$|login|signin|sign_in|signup|register|"
                            r"404|error|search|explore|users/?$|accounts/login)", re.I)

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_META = re.compile(r"<meta\b[^>]*>", re.I)
_LINK = re.compile(r"<link\b[^>]*>", re.I)
_ATTR = re.compile(r"""([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')""")
_LD_TYPE = re.compile(r"\"@type\"\s*:\s*\"(Person|ProfilePage|Organization)\"")


def _attrs(tag: str) -> dict[str, str]:
    return {m.group(1).lower(): unescape(m.group(2) if m.group(2) is not None else m.group(3))
            for m in _ATTR.finditer(tag)}


def page_markers(text: str) -> dict[str, str]:
    """title, canonical, og:url, og:type and JSON-LD type from raw HTML."""
    head = text[:SCAN_BYTES]
    out: dict[str, str] = {}
    m = _TITLE.search(head)
    if m:
        out["title"] = " ".join(unescape(m.group(1)).split())[:200]
    for tag in _META.findall(head):
        a = _attrs(tag)
        key = (a.get("property") or a.get("name") or "").lower()
        if key in ("og:url", "og:type", "og:title", "profile:username") and key not in out and a.get("content"):
            out[key] = a["content"].strip()
    for tag in _LINK.findall(head):
        a = _attrs(tag)
        if "canonical" in a.get("rel", "").lower().split() and a.get("href") and "canonical" not in out:
            out["canonical"] = a["href"].strip()
    m = _LD_TYPE.search(head)
    if m:
        out["ld_type"] = m.group(1)
    return out


def _mentions(text: str, username: str) -> bool:
    u = username.lower()
    low = text[:SCAN_BYTES].lower()
    return u in low or u in unescape(low) or u in unquote(low)


def _check(name: str, ok: bool | None, detail: str) -> dict[str, Any]:
    return {"check": name, "ok": ok, "detail": detail}


def _path_has_user(url: str, username: str) -> bool:
    p = urlparse(url)
    hay = unquote(p.netloc + p.path + "?" + p.query).lower()
    return username.lower() in hay


def verify(site: "Site", username: str, resp: "_Response", status: "Status") -> tuple["Status", str | None, list[dict]]:
    """Return ``(status, error, checks)``; only ever *downgrades* a FOUND."""
    from .engine import Status

    checks: list[dict[str, Any]] = []
    if status is not Status.FOUND or not site.verify:
        return status, None, checks
    # Sites whose own rule only looks at the HTTP status are the ones that
    # need the page-level checks; "message" sites already read the page.
    weak_rule = site.check in ("status_code", "response_url")
    text = resp.text or ""
    is_json = "json" in resp.content_type or text.lstrip()[:1] in ("{", "[")

    if is_json:
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if data in (None, {}, [], "") or (isinstance(data, dict) and set(data) <= {"data", "result", "results"}
                                          and all(v in (None, {}, []) for v in data.values())):
            if text.strip():
                checks.append(_check("profile", False, "API ตอบข้อมูลว่าง"))
                return Status.NOT_FOUND, None, checks
        checks.append(_check("profile", True, "API ส่งข้อมูลโปรไฟล์กลับมา"))
        if _mentions(text, username):
            checks.append(_check("username", True, "ข้อมูลจาก API มี username"))
        return status, None, checks

    if not text.strip():  # HEAD probes, empty bodies: nothing to look at
        return status, None, checks

    marks = page_markers(text)

    # 1. redirect away from the profile URL. Only the site's own front/login
    # page means "missing": /users/<id> or a blog that moved to its own
    # domain are normal for existing accounts.
    asked = site.probe_url(username)
    if resp.url and resp.url.rstrip("/") != asked.rstrip("/") and _path_has_user(asked, username):
        final = urlparse(resp.url)
        if _path_has_user(resp.url, username):
            checks.append(_check("redirect", True, "redirect ไปหน้าที่ยังมี username"))
        elif final.netloc.lower() == urlparse(asked).netloc.lower() and DEAD_END_PATHS.match(final.path or "/"):
            checks.append(_check("redirect", False, f"ถูกพาไปหน้า {final.path or '/'} ของเว็บ (ไม่ใช่โปรไฟล์)"))
            return Status.NOT_FOUND, None, checks
        else:
            checks.append(_check("redirect", None, f"redirect ไป {final.netloc}{final.path}"))
            if final.netloc.lower() != urlparse(asked).netloc.lower():
                return status, None, checks  # moved to another domain: the site rule decides

    # 2. title says "not found"
    title = marks.get("title") or marks.get("og:title") or ""
    if title:
        # drop the username first so a user called "error404" isn't a soft 404
        if SOFT_404.search(re.sub(re.escape(username), " ", title, flags=re.I)):
            checks.append(_check("title", False, f"title: \"{title[:80]}\""))
            return Status.NOT_FOUND, None, checks
        checks.append(_check("title", True if username.lower() in title.lower() else None, f"title: \"{title[:80]}\""))

    # 3. canonical / og:url
    canon = marks.get("canonical") or marks.get("og:url")
    if canon:
        cpath = urlparse(canon).path
        if _path_has_user(canon, username):
            checks.append(_check("canonical", True, "canonical URL มี username"))
        elif not cpath.strip("/"):
            # some sites do this on real profiles too, so it's only a warning;
            # the username check below decides
            checks.append(_check("canonical", False, f"canonical ชี้ไปหน้าแรก ({canon[:80]})"))
        else:
            checks.append(_check("canonical", None, f"canonical: {canon[:80]}"))

    # 4. profile markers
    profile_bits = []
    if marks.get("og:type", "").lower() in ("profile", "og:profile", "profile.user"):
        profile_bits.append("og:type=profile")
    if marks.get("ld_type") in ("Person", "ProfilePage"):
        profile_bits.append(f"JSON-LD {marks['ld_type']}")
    if marks.get("profile:username"):
        profile_bits.append("profile:username")
    if site.presence_msg:
        profile_bits.append("ข้อความเฉพาะหน้าโปรไฟล์ของเว็บนี้")
    if profile_bits:
        checks.append(_check("profile", True, ", ".join(profile_bits)))

    # 5. the page must at least mention the username
    if _mentions(text, username):
        checks.append(_check("username", True, "หน้าเว็บมี username"))
    else:
        checks.append(_check("username", False, "หน้าเว็บไม่มี username เลย"))
        if weak_rule and not profile_bits:
            return Status.UNKNOWN, "ตอบ 200 แต่หน้าเว็บไม่มี username (อาจเป็นหน้า default)", checks

    return status, None, checks
