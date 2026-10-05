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


def variants(username: str, limit: int = 4) -> list[str]:
    """Common spellings of the same handle: john.doe -> johndoe, john_doe, john-doe."""
    base = username.strip()
    parts = [p for p in re.split(r"[._\-]+", base) if p]
    out: list[str] = []
    if len(parts) > 1:
        out += ["".join(parts), "_".join(parts), ".".join(parts), "-".join(parts)]
    stripped = re.sub(r"\d+$", "", base)
    if stripped and stripped != base and len(stripped) >= 3:
        out.append(stripped)
    seen = {base.lower()}
    uniq = []
    for v in out:
        if v.lower() not in seen and len(v) >= 3:
            seen.add(v.lower())
            uniq.append(v)
    return uniq[:limit]


def normalise_name(name: str) -> str:
    return re.sub(r"[^\w]", "", name.lower(), flags=re.UNICODE)


CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def identity_summary(results: list[dict], searched: list[str],
                     avatar_matches: dict[tuple[str, str], list[str]] | None = None) -> list[dict]:
    """Rank found accounts by how likely they belong to the searched person.

    high   = the owner linked it (profile link / bio mention) or confirmed by user,
             or its profile picture matches a high-confidence account
    medium = same full name or same profile picture as another found account
    low    = only the username matches
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
    out = []
    for r in found:
        evidence = list(r.get("evidence", []))
        conf = "low"
        if r.get("linked"):
            conf = "high"
        n = name_key(r)
        others = names.get(n, set()) - {r["site"]} if n else set()
        if others:
            evidence.append(f"ชื่อ \"{r['info']['name']}\" ตรงกับบัญชีบน {', '.join(sorted(others)[:4])}")
            if conf == "low":
                conf = "medium"
        same_pic = avatar_matches.get((r["site"].lower(), r["username"].lower()), [])
        if same_pic:
            evidence.append(f"รูปโปรไฟล์เหมือนกับ {', '.join(same_pic[:4])}")
            conf = "high" if (conf == "high" or linked_labels & set(same_pic)) else "medium"
        out.append({"site": r["site"], "username": r["username"], "url": r["url"], "confidence": conf,
                    "evidence": evidence, "linked": bool(r.get("linked")), "depth": r.get("depth", 0)})
    out.sort(key=lambda x: (CONFIDENCE_ORDER[x["confidence"]], x["depth"], x["site"].lower()))
    return out
