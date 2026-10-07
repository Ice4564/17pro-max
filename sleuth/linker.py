"""Cross-platform account linking.

Instagram, Facebook, TikTok and X block automated existence checks, so we
link accounts the way human investigators do: by following evidence the
owner published themselves (profile links, link-in-bio pages, "IG: @name"
mentions in bios) and by comparing display names across found accounts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Platform names here match the site names in data/sites.json.
SOCIAL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^https?://(?:www\.)?instagram\.com/([A-Za-z0-9_.]{1,30})/?(?:[?#].*)?$", re.I), "Instagram"),
    (re.compile(r"^https?://(?:www\.)?instagr\.am/([A-Za-z0-9_.]{1,30})/?$", re.I), "Instagram"),
    (re.compile(r"^https?://(?:www\.|m\.|web\.|mbasic\.)?(?:facebook|fb)\.com/([A-Za-z0-9.]{5,50})/?(?:[?#].*)?$", re.I), "Facebook"),
    (re.compile(r"^https?://(?:www\.|m\.)?tiktok\.com/@([A-Za-z0-9_.]{2,24})/?(?:[?#].*)?$", re.I), "TikTok"),
    (re.compile(r"^https?://(?:www\.|mobile\.)?(?:twitter|x)\.com/@?([A-Za-z0-9_]{1,15})/?(?:[?#].*)?$", re.I), "X (Twitter)"),
    (re.compile(r"^https?://(?:www\.)?threads\.(?:net|com)/@([A-Za-z0-9_.]{1,30})/?(?:[?#].*)?$", re.I), "Threads"),
    (re.compile(r"^https?://(?:[a-z]{2,3}\.)?linkedin\.com/(?:in|company)/([A-Za-z0-9_\-%]{2,100})/?(?:[?#].*)?$", re.I), "LinkedIn"),
]

# Path segments that are pages, not profiles.
NOT_HANDLES = {
    "sharer", "share", "sharer.php", "intent", "home", "home.php", "profile.php", "pages", "groups", "watch",
    "hashtag", "explore", "tr", "plugins", "dialog", "login", "signup", "people", "embed", "p", "reel",
    "reels", "stories", "tv", "about", "help", "policies", "privacy", "legal", "settings", "accounts",
    "search", "i", "messages", "notifications", "events", "marketplace", "gaming", "video", "videos",
    "photo", "photos", "permalink.php", "story.php", "tag", "discover", "music", "live", "foryou",
}

# "IG: @name", "tiktok @name", "เฟส: name" in profile bios.
_KEYWORDS = {
    "Instagram": r"ig|insta|instagram|ไอจี",
    "TikTok": r"tiktok|tik\s?tok|tt|ติ๊กต็อก|ติ๊กต๊อก|ติกตอก",
    "Facebook": r"fb|facebook|เฟส|เฟซ|เฟสบุ๊ค|เฟซบุ๊ก",
    "X (Twitter)": r"twitter|x|ทวิต|ทวิตเตอร์",
    "Threads": r"threads",
}
BIO_MENTION = [
    (re.compile(rf"(?:(?<![A-Za-z0-9])|^)(?:{kw})\s*(?:[:：|\-–]\s*@?|@)\s*([A-Za-z0-9_.]{{2,30}})", re.I), platform)
    for platform, kw in _KEYWORDS.items()
]
URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>]+|(?:www\.)?(?:instagram|tiktok|facebook|twitter|x|threads)\.(?:com|net)/[^\s\"'<>]+", re.I)


@dataclass(frozen=True)
class SocialLink:
    platform: str
    handle: str
    url: str
    how: str  # "link" or "bio"


def match_social(url: str) -> tuple[str, str] | None:
    """Return ``(platform, handle)`` if ``url`` is a big-platform profile link."""
    url = url.strip()
    if not url.startswith("http"):
        url = "https://" + url
    for pattern, platform in SOCIAL_PATTERNS:
        m = pattern.match(url)
        if m:
            handle = m.group(1).strip(".")
            if handle.lower() not in NOT_HANDLES and not handle.isdigit():
                return platform, handle
    return None


def profile_url(platform: str, handle: str) -> str:
    return {
        "Instagram": f"https://www.instagram.com/{handle}/",
        "Facebook": f"https://www.facebook.com/{handle}",
        "TikTok": f"https://www.tiktok.com/@{handle}",
        "X (Twitter)": f"https://x.com/{handle}",
        "Threads": f"https://www.threads.net/@{handle}",
        "LinkedIn": f"https://www.linkedin.com/in/{handle}",
    }.get(platform, handle)


def find_social(links: list[str], bio: str = "") -> list[SocialLink]:
    """Big-platform handles from profile links and bio text."""
    out: dict[tuple[str, str], SocialLink] = {}
    candidates = list(links) + URL_IN_TEXT.findall(bio or "")
    for link in candidates:
        hit = match_social(link)
        if hit:
            platform, handle = hit
            out.setdefault((platform, handle.lower()), SocialLink(platform, handle, profile_url(platform, handle), "link"))
    for pattern, platform in BIO_MENTION:
        for m in pattern.finditer(bio or ""):
            handle = m.group(1).strip(".")
            if len(handle) >= 2 and handle.lower() not in NOT_HANDLES:
                out.setdefault((platform, handle.lower()),
                               SocialLink(platform, handle, profile_url(platform, handle), "bio"))
    return list(out.values())


@dataclass(frozen=True)
class Candidate:
    """A spelling of the searched username that the person *might* also use.

    Candidates are guesses, never the username the user typed: results for
    them are labelled as such and start at low confidence.
    """
    username: str
    rule: str  # human-readable reason, e.g. "ใส่ตัวคั่นระหว่างตัวอักษรกับตัวเลข"


_SEPARATORS = ("_", ".", "-")


def candidates(username: str, limit: int = 8) -> list[Candidate]:
    """Likely alternative spellings, most plausible first.

    sky123   -> sky_123, sky.123, sky-123, sky, sky1234, 123sky
    john.doe -> johndoe, john_doe, john-doe
    """
    base = username.strip()
    out: list[Candidate] = []
    parts = [p for p in re.split(r"[._\-]+", base) if p]
    if len(parts) > 1:
        out.append(Candidate("".join(parts), "ตัดตัวคั่นออก"))
        out += [Candidate(sep.join(parts), f"เปลี่ยนตัวคั่นเป็น \"{sep}\"") for sep in _SEPARATORS]
    # one letter block and one digit block: sky123 / 123sky
    m = re.fullmatch(r"([^\W\d_]+)(\d+)|(\d+)([^\W\d_]+)", base)
    if m:
        left, right = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        out += [Candidate(left + sep + right, "ใส่ตัวคั่นระหว่างตัวอักษรกับตัวเลข") for sep in _SEPARATORS]
    letters = re.sub(r"\d+$", "", base).rstrip("._-")
    digits = base[len(base.rstrip("0123456789")):]
    if digits and len(letters) >= 3:
        out.append(Candidate(letters, "ตัดตัวเลขท้ายออก"))
    # 123 -> 1234: an ascending run that people often extend
    if len(digits) >= 2 and digits[-1] != "9" and all(int(b) - int(a) == 1 for a, b in zip(digits, digits[1:])):
        out.append(Candidate(base + str(int(digits[-1]) + 1), "ต่อเลขเรียง"))
    if m:
        out.append(Candidate(right + left, "สลับตำแหน่งตัวอักษรกับตัวเลข"))

    seen = {base.lower()}
    uniq: list[Candidate] = []
    for c in out:
        if c.username.lower() not in seen and len(c.username) >= 3:
            seen.add(c.username.lower())
            uniq.append(c)
    return uniq[:limit]


def variants(username: str, limit: int = 8) -> list[str]:
    """Candidate spellings as plain strings (see :func:`candidates`)."""
    return [c.username for c in candidates(username, limit)]


def normalise_name(name: str) -> str:
    return re.sub(r"[^\w]", "", name.lower(), flags=re.UNICODE)


CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


STRONG_CONNECTION = 70  # % from similarity.connections() that counts as a real lead
HIGH, MEDIUM = 70, 45   # score thresholds for the high / medium labels

# How much each piece of evidence says on its own (0-1). Scores combine as
# 1 - prod(1 - p): independent hints add up, but never reach 100.
BASE_P = {"input": 0.25, "discovered": 0.35, "candidate": 0.10}
P_LINKED = 0.85          # the owner linked this account from another profile / site
P_NAME = 0.40            # same full name as another found account
P_AVATAR_LINKED = 0.80   # same picture as an account the owner linked
P_AVATAR = 0.40          # same picture as another found account
P_INDEXED = 0.15         # a search engine has the profile page indexed


def level(score: int) -> str:
    return "high" if score >= HIGH else "medium" if score >= MEDIUM else "low"


def combine(ps: list[float]) -> int:
    miss = 1.0
    for p in ps:
        miss *= 1 - max(0.0, min(p, 0.99))
    return round(min(0.99, 1 - miss) * 100)


def identity_summary(results: list[dict], searched: list[str],
                     avatar_matches: dict[tuple[str, str], list[str]] | None = None,
                     connections: list[dict] | None = None,
                     search_hits: list[dict] | None = None) -> list[dict]:
    """Score every found account 0-100 for "belongs to the searched person".

    Each account gets a list of signals (owner link, same full name, same
    picture, strong pairwise connection, search-engine index, how its
    username was obtained) that combine into ``score``; ``confidence`` is
    the label for it:

    high   (>= 70) the owner linked it, or its picture matches an owner-linked
                   account, or several independent signals agree
    medium (>= 45) same full name or picture as another account, or a strong
                   "possible connection"
    low            only the username matches (always the case for a guessed
                   candidate spelling with no other evidence)
    """
    found = [r for r in results if r["status"] == "found"]

    def name_key(r: dict) -> str:
        """A display name only counts as evidence if it's a real full name
        (at least two words): "Selena" or "selenagomez" match far too many people."""
        raw = r.get("info", {}).get("name", "").strip()
        n = normalise_name(raw)
        if len(raw.split()) < 2 or len(n) < 5:
            return ""
        return n

    names: dict[str, set[str]] = {}
    for r in found:
        n = name_key(r)
        if n:
            names.setdefault(n, set()).add(r["site"])
    avatar_matches = avatar_matches or {}
    linked_labels = {f"{r['site']} (@{r['username']})" for r in found if r.get("linked")}
    best_link: dict[tuple[str, str], dict] = {}
    for c in connections or []:
        for me, other in (("a", "b"), ("b", "a")):
            k = (c[me]["site"].lower(), c[me]["username"].lower())
            if k not in best_link or c["confidence"] > best_link[k]["confidence"]:
                best_link[k] = {"confidence": c["confidence"], "other": c[other]}
    indexed: dict[tuple[str, str], str] = {}
    for h in search_hits or []:
        if h.get("platform") and h.get("handle"):
            indexed.setdefault((h["platform"].lower(), h["handle"].lower()), h.get("engine", ""))
    out = []
    for r in found:
        k = (r["site"].lower(), r["username"].lower())
        evidence = list(r.get("evidence", []))
        query = r.get("query", "input")
        signals = [{"label": {"input": "username ตรงกับที่ค้น", "discovered": "username ที่เจ้าของเปิดเผยไว้",
                              "candidate": "username ที่ระบบเดา"}.get(query, query), "p": BASE_P.get(query, 0.25)}]
        if r.get("linked"):
            signals.append({"label": "เจ้าของลิงก์ไว้เอง", "p": P_LINKED})
        n = name_key(r)
        others = names.get(n, set()) - {r["site"]} if n else set()
        if others:
            evidence.append(f"ชื่อ \"{r['info']['name']}\" ตรงกับบัญชีบน {', '.join(sorted(others)[:4])}")
            signals.append({"label": "ชื่อจริงตรงกับบัญชีอื่น", "p": P_NAME})
        same_pic = avatar_matches.get(k, [])
        if same_pic:
            evidence.append(f"รูปโปรไฟล์เหมือนกับ {', '.join(same_pic[:4])}")
            strong = bool(linked_labels & set(same_pic))
            signals.append({"label": "รูปเหมือนบัญชีที่เจ้าของลิงก์ไว้" if strong else "รูปเหมือนบัญชีอื่น",
                            "p": P_AVATAR_LINKED if strong else P_AVATAR})
        link = best_link.get(k)
        if link:
            o = link["other"]
            if link["confidence"] >= STRONG_CONNECTION:
                evidence.append(f"อาจเชื่อมโยงกับ {o['site']} (@{o['username']}) {link['confidence']}%")
            weight = 0.6 if link["confidence"] >= STRONG_CONNECTION else 0.25
            signals.append({"label": f"คล้ายกับ {o['site']} @{o['username']} {link['confidence']}%",
                            "p": link["confidence"] / 100 * weight})
        if k in indexed:
            signals.append({"label": f"{indexed[k]} มีหน้าโปรไฟล์นี้ในผลค้นหา", "p": P_INDEXED})
        score = combine([s["p"] for s in signals])
        out.append({"site": r["site"], "username": r["username"], "url": r["url"], "confidence": level(score),
                    "score": score, "signals": [{"label": s["label"], "points": round(s["p"] * 100)} for s in signals],
                    "evidence": evidence, "linked": bool(r.get("linked")), "depth": r.get("depth", 0),
                    "query": query, "candidate_of": r.get("candidate_of")})
    out.sort(key=lambda x: (CONFIDENCE_ORDER[x["confidence"]], -x["score"], x["depth"], x["site"].lower()))
    return out
