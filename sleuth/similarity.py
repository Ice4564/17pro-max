"""Pairwise similarity between found accounts ("possible connection").

Compares public profile data of every pair of found accounts and explains
the score signal by signal:

    Possible connection  82%
      ✓ username similarity
      ✓ same external website
      ✓ similar bio
      ✗ different avatar

The score combines independent signals as ``1 - Π(1 - p)`` and is then
reduced by contradicting signals. It is a lead for a human to check, never
proof that two accounts belong to the same person.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from itertools import combinations
from typing import Any
from urllib.parse import urlparse

from .avatars import MAX_DISTANCE, distance

MIN_CONFIDENCE = 35
MAX_PAIRS = 40
DIFFERENT_AVATAR = 20  # bits; above this the pictures are clearly different

# Links that show up on many unrelated profile pages (app stores, the
# platforms' own social accounts, CDNs): sharing one says nothing.
JUNK_HOSTS = re.compile(
    r"(^|\.)(apple\.com|google\.com|googleapis\.com|gstatic\.com|microsoft\.com|mozilla\.org|w3\.org|"
    r"schema\.org|creativecommons\.org|cloudflare\.com|gravatar\.com|wikipedia\.org|wikimedia\.org|"
    r"apps\.apple\.com|play\.google\.com|onelink\.me|app\.link|bit\.ly|goo\.gl|t\.co|jsdelivr\.net|"
    r"unpkg\.com|fonts\.googleapis\.com|doubleclick\.net|googletagmanager\.com|facebook\.net)$", re.I)

# Free mail providers: sharing one of these domains says nothing about a person.
WEBMAIL = {
    "gmail.com", "googlemail.com", "hotmail.com", "outlook.com", "live.com", "yahoo.com",
    "icloud.com", "me.com", "proton.me", "protonmail.com", "aol.com", "gmx.com", "yandex.ru",
    "mail.ru", "hotmail.co.th", "yahoo.co.th", "qq.com", "163.com",
}
EMAIL_IN_TEXT = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})(?![\w-])")
# Addresses that appear on many unrelated pages (platform support, examples).
JUNK_EMAIL = re.compile(r"^(?:no-?reply|support|help|info|privacy|abuse|admin|webmaster|example|test|"
                        r"press|legal|security|contact|feedback|hello)@|@(?:example\.|sentry\.|wixpress\.)", re.I)


def emails_in_text(text: str) -> set[str]:
    out = set()
    for m in EMAIL_IN_TEXT.findall(text or ""):
        e = m.lower().strip(".")
        if not JUNK_EMAIL.search(e) and not e.endswith((".png", ".jpg", ".gif", ".webp", ".svg")):
            out.add(e)
    return out


def emails_of(r: dict[str, Any]) -> set[str]:
    """E-mail addresses the owner published on a profile (info fields, bio, mailto: links)."""
    texts = [v for v in (r.get("info") or {}).values() if isinstance(v, str)]
    texts += [u[7:] for u in r.get("links", []) if isinstance(u, str) and u.lower().startswith("mailto:")]
    texts += list(r.get("emails", []))
    out: set[str] = set()
    for t in texts:
        out |= emails_in_text(t)
    return out


def _key(r: dict[str, Any]) -> tuple[str, str]:
    return r["site"].lower(), r["username"].lower()


def _norm_user(u: str) -> str:
    return re.sub(r"[^a-z0-9]", "", u.lower())


def _norm_text(t: str) -> str:
    return re.sub(r"[^\w]", "", t.lower(), flags=re.UNICODE)


def _tokens(t: str) -> set[str]:
    return {w for w in re.findall(r"\w+", t.lower(), flags=re.UNICODE) if len(w) >= 3}


def _ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio() if a and b else 0.0


def _host(url: str) -> str:
    h = urlparse(url if "://" in url else "https://" + url).netloc.lower().split(":")[0]
    return h[4:] if h.startswith("www.") else h


def _norm_url(url: str) -> str:
    p = urlparse(url if "://" in url else "https://" + url)
    return (_host(url) + p.path).rstrip("/").lower()


def _owner_links(r: dict[str, Any]) -> set[str]:
    """Accounts and sites the owner published on this profile.

    Uses the website field and the owner-published handles that discovery
    already filtered (rel="me", link-in-bio lists, bio mentions). Raw page
    links are not used: they are mostly the platform's own footer, status
    page and CDN links, which every profile on that platform shares.
    """
    out = {d.lower() for d in r.get("discovered", [])}
    w = r.get("info", {}).get("website", "")
    if w and not JUNK_HOSTS.search(_host(w)):
        out.add(_norm_url(w))
    return out


def _brand(site: str) -> str:
    return re.sub(r"[^a-z0-9]", "", site.lower().split()[0]) if site.strip() else ""


def _website_host(r: dict[str, Any]) -> str:
    w = r.get("info", {}).get("website", "")
    h = _host(w) if w else ""
    return "" if not h or JUNK_HOSTS.search(h) else h


def _signal(name: str, label: str, ok: bool | None, detail: str = "", p: float = 0.0,
            penalty: float = 1.0) -> dict[str, Any]:
    return {"name": name, "label": label, "ok": ok, "detail": detail, "p": p, "penalty": penalty}


def _direct_link(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """``a`` names ``b`` as one of its owner's accounts (or the other way round)."""
    def names(x: dict[str, Any], y: dict[str, Any]) -> bool:
        tag = f"{y['site']}: {y['username']}".lower()
        if any(d.lower() == tag for d in x.get("discovered", [])):
            return True
        src = f"{x['site']} (@{x['username']})".lower()
        return bool(y.get("linked")) and any(src in e.lower() for e in y.get("evidence", []))
    return names(a, b) or names(b, a)


def compare(a: dict[str, Any], b: dict[str, Any],
            hashes: dict[tuple[str, str], int] | None = None) -> dict[str, Any]:
    """Score one pair of found accounts and list the signals behind it."""
    hashes = hashes or {}
    ia, ib = a.get("info", {}), b.get("info", {})
    signals: list[dict[str, Any]] = []

    if _direct_link(a, b):
        signals.append(_signal("link", "ลิงก์ถึงกันโดยตรง", True, "โปรไฟล์หนึ่งลิงก์ไปอีกบัญชี", p=0.9))

    ua, ub = _norm_user(a["username"]), _norm_user(b["username"])
    if ua and ua == ub:
        signals.append(_signal("username", "username เหมือนกัน", True,
                               f"@{a['username']} / @{b['username']}", p=0.25))
    elif _ratio(ua, ub) >= 0.8:
        signals.append(_signal("username", "username คล้ายกัน", True,
                               f"@{a['username']} / @{b['username']} ({_ratio(ua, ub):.0%})", p=0.12))
    else:
        signals.append(_signal("username", "username ต่างกัน", False, f"@{a['username']} / @{b['username']}"))

    na, nb = ia.get("name", "").strip(), ib.get("name", "").strip()
    if na and nb:
        ka, kb = _norm_text(na), _norm_text(nb)
        full = len(na.split()) >= 2 and len(ka) >= 5
        if ka == kb:
            signals.append(_signal("name", "ชื่อที่แสดงตรงกัน", True, f"\"{na}\"", p=0.45 if full else 0.15))
        elif _ratio(ka, kb) >= 0.85:
            signals.append(_signal("name", "ชื่อที่แสดงคล้ายกัน", True, f"\"{na}\" / \"{nb}\"", p=0.25 if full else 0.1))
        else:
            signals.append(_signal("name", "ชื่อที่แสดงต่างกัน", False, f"\"{na}\" / \"{nb}\"", penalty=0.85))

    # Platform boilerplate ("sky123 has 12 repositories…") repeats the username:
    # take it out so only what the person wrote is compared.
    strip = re.compile("|".join(re.escape(u) for u in {a["username"], b["username"]} if u), re.I)
    ba, bb = strip.sub(" ", ia.get("bio", "")).strip(), strip.sub(" ", ib.get("bio", "")).strip()
    if len(ba) >= 20 and len(bb) >= 20:
        ta, tb = _tokens(ba), _tokens(bb)
        jac = len(ta & tb) / len(ta | tb) if ta | tb else 0.0
        sim = max(jac, _ratio(_norm_text(ba), _norm_text(bb)))
        if sim >= 0.5:
            signals.append(_signal("bio", "bio คล้ายกัน", True, f"{sim:.0%}", p=0.35))
        elif sim >= 0.25:
            signals.append(_signal("bio", "bio คล้ายกันบางส่วน", True, f"{sim:.0%}", p=0.15))
        else:
            signals.append(_signal("bio", "bio ต่างกัน", False, f"{sim:.0%}"))

    wa, wb = _website_host(a), _website_host(b)
    shared = _owner_links(a) & _owner_links(b)
    if wa and wa == wb:
        signals.append(_signal("website", "เว็บไซต์ภายนอกเดียวกัน", True, wa, p=0.6))
    elif shared:
        ex = sorted(shared)[0]
        signals.append(_signal("website", "ลิงก์ไปบัญชี/เว็บเดียวกัน", True,
                               ex + (f" (+{len(shared) - 1})" if len(shared) > 1 else ""), p=0.5))
    elif wa and wb:
        signals.append(_signal("website", "เว็บไซต์ต่างกัน", False, f"{wa} / {wb}", penalty=0.9))

    ea, eb = emails_of(a), emails_of(b)
    if ea & eb:
        signals.append(_signal("email", "อีเมลเดียวกัน", True, sorted(ea & eb)[0], p=0.7))
    else:
        da = {e.split("@")[1] for e in ea} - WEBMAIL
        db = {e.split("@")[1] for e in eb} - WEBMAIL
        # an address on the domain the other profile lists as its website
        cross = (da & ({wb} if wb else set())) | (db & ({wa} if wa else set()))
        if da & db:
            signals.append(_signal("email", "อีเมลโดเมนเดียวกัน", True, "@" + sorted(da & db)[0], p=0.4))
        elif cross:
            signals.append(_signal("email", "อีเมลอยู่บนโดเมนเว็บของอีกบัญชี", True, "@" + sorted(cross)[0], p=0.45))
        elif ea and eb:
            signals.append(_signal("email", "อีเมลต่างกัน", False, f"{sorted(ea)[0]} / {sorted(eb)[0]}"))

    ha, hb = hashes.get(_key(a)), hashes.get(_key(b))
    if ha is not None and hb is not None:
        d = distance(ha, hb)
        if d <= MAX_DISTANCE:
            signals.append(_signal("avatar", "รูปโปรไฟล์เหมือนกัน", True, f"ต่างกัน {d}/64 bit", p=0.6))
        elif d >= DIFFERENT_AVATAR:
            signals.append(_signal("avatar", "รูปโปรไฟล์ต่างกัน", False, f"ต่างกัน {d}/64 bit", penalty=0.9))
        else:
            signals.append(_signal("avatar", "รูปโปรไฟล์ใกล้เคียง", None, f"ต่างกัน {d}/64 bit"))

    la, lb = _norm_text(ia.get("location", "")), _norm_text(ib.get("location", ""))
    if la and lb:
        if la == lb or (min(len(la), len(lb)) >= 4 and (la in lb or lb in la)):
            signals.append(_signal("location", "ที่อยู่/ประเทศตรงกัน", True, ia["location"], p=0.15))
        else:
            signals.append(_signal("location", "ที่อยู่ต่างกัน", False, f"{ia['location']} / {ib['location']}",
                                   penalty=0.9))

    miss = 1.0
    penalty = 1.0
    for s in signals:
        miss *= 1 - s["p"]
        penalty *= s["penalty"]
    score = round(min(0.99, (1 - miss) * penalty) * 100)
    return {
        "a": {"site": a["site"], "username": a["username"], "url": a["url"]},
        "b": {"site": b["site"], "username": b["username"], "url": b["url"]},
        "confidence": score,
        "signals": [{k: v for k, v in s.items() if k not in ("p", "penalty")} for s in signals],
    }


def connections(results: list[dict[str, Any]], hashes: dict[tuple[str, str], int] | None = None,
                min_confidence: int = MIN_CONFIDENCE, limit: int = MAX_PAIRS) -> list[dict[str, Any]]:
    """Pairs of found accounts that look related, strongest first.

    A pair is only listed when something beyond the username matches (and,
    for identical usernames, beyond the display name too): accounts that
    merely share a handle are already grouped by it.
    """
    found = [r for r in results if r["status"] == "found"]
    seen: set[tuple[str, str]] = set()
    uniq = []
    for r in found:
        if _key(r) not in seen:
            seen.add(_key(r))
            uniq.append(r)
    out = []
    for a, b in combinations(uniq[:150], 2):
        # GitHub vs GitHub Gist with the same username: one account, two pages
        if _norm_user(a["username"]) == _norm_user(b["username"]) and _brand(a["site"]) == _brand(b["site"]):
            continue
        c = compare(a, b, hashes)
        if c["confidence"] < min_confidence:
            continue
        # Same handle + same display name is what fan/impersonation accounts look like too
        # (and the identity summary already groups it): ask for something more.
        weak = {"username", "name"} if _norm_user(a["username"]) == _norm_user(b["username"]) else {"username"}
        if not any(s["ok"] and s["name"] not in weak for s in c["signals"]):
            continue
        out.append(c)
    out.sort(key=lambda c: -c["confidence"])
    return out[:limit]
