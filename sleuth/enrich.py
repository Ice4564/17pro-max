"""Account enrichment: tie the analysis / imaging / crypto / regional helpers
to the accounts a search already found.

Produces a small, report-friendly ``intel`` block from public profile data:

* ``languages`` the languages used in confident bios
* ``images``    distinct real avatars with reverse-image-search links
* ``crypto``    ENS names / ETH addresses published in profiles
* ``phones``    Thai phone numbers published in profiles
* ``bots``      a per-account bot-likelihood heuristic (only when a profile
                exposes follower / following / created data)

Everything here is computed from data already fetched; it issues no network
requests of its own.
"""

from __future__ import annotations

import re
from typing import Any

from .analysis import detect_bot, detect_languages
from .crypto import extract_ens_from_text, extract_eth_addresses_from_text
from .evidence import account_id
from .history import parse_count
from .imaging import reverse_search_urls
from .regional import extract_thai_phones

# Generic/placeholder avatars that say nothing about a person.
_PLACEHOLDER = re.compile(
    r"missing\.png|default[_.-]?(avatar|profile|user|img|image|photo|pic|\.(?:png|jpe?g|svg|webp))|"
    r"avatar[_-]?default|no[_-]?avatar|/(?:meta|assets?|static|images?|img)/default|"
    r"placeholder|anonymous|identicon|gravatar\.com/avatar/0{16}", re.I)


def _texts(info: dict[str, Any]) -> str:
    return " ".join(str(info.get(k, "")) for k in ("bio", "name", "location", "website", "username"))


def enrich(results: list[dict[str, Any]], confident_keys: set[tuple[str, str]] | None = None) -> dict[str, Any]:
    """Return an ``intel`` block for the found accounts.

    ``confident_keys`` (lower-case ``(site, username)``) limits language /
    avatar aggregation to accounts believed to be the target, so one
    unrelated look-alike does not pollute the summary. Crypto, phones and
    per-account bot scores are reported for every found account.
    """
    found = [r for r in results if r.get("status") == "found"]
    confident = confident_keys if confident_keys is not None else {
        (r["site"].lower(), r["username"].lower()) for r in found}

    languages: dict[str, int] = {}
    images: list[dict[str, Any]] = []
    seen_avatars: set[str] = set()
    crypto: dict[tuple[str, str], dict[str, Any]] = {}
    phones: dict[str, dict[str, Any]] = {}
    bots: dict[str, dict[str, Any]] = {}

    for r in found:
        info = r.get("info") or {}
        key = (r["site"].lower(), r["username"].lower())
        label = f"{r['site']} @{r['username']}"
        aid = account_id(r["site"], r["username"])
        is_confident = key in confident

        bio = str(info.get("bio", "")).strip()
        if is_confident and bio:
            for lang in detect_languages(bio):
                if lang not in ("unknown",):
                    languages[lang] = languages.get(lang, 0) + 1

        avatar = str(info.get("avatar", ""))
        if is_confident and avatar.startswith("http") and not _PLACEHOLDER.search(avatar) and avatar not in seen_avatars:
            seen_avatars.add(avatar)
            images.append({"url": avatar, "site": r["site"], "username": r["username"],
                           "account_url": r.get("url", ""), "reverse": reverse_search_urls(avatar)})

        blob = _texts(info)
        for name in extract_ens_from_text(blob):
            crypto.setdefault(("ens", name.lower()), {"type": "ens", "value": name, "sources": []})["sources"].append(label)
        for addr in extract_eth_addresses_from_text(blob):
            crypto.setdefault(("eth", addr.lower()), {"type": "eth", "value": addr, "sources": []})["sources"].append(label)
        for phone in extract_thai_phones(blob):
            phones.setdefault(phone, {"number": phone, "sources": []})["sources"].append(label)

        # bot heuristic only when the profile actually exposes the needed signals
        if any(info.get(k) for k in ("followers", "following", "created")):
            acct = {"avatar": avatar, "bio": bio, "username": r["username"], "created": info.get("created", ""),
                    "followers": parse_count(info.get("followers")) or 0,
                    "following": parse_count(info.get("following")) or 0,
                    "verified": bool(info.get("verified"))}
            score = detect_bot(acct)
            if score.score >= 40:  # only surface suspicious/likely-bot
                bots[aid] = {"site": r["site"], "username": r["username"], "url": r.get("url", ""),
                             "score": score.score, "label": score.label, "signals": score.signals}

    return {
        "languages": [{"lang": k, "count": v} for k, v in sorted(languages.items(), key=lambda x: -x[1])],
        "images": images,
        "crypto": list(crypto.values()),
        "phones": list(phones.values()),
        "bots": list(bots.values()),
    }


def intel_counts(intel: dict[str, Any]) -> dict[str, int]:
    return {"languages": len(intel.get("languages", [])), "images": len(intel.get("images", [])),
            "crypto": len(intel.get("crypto", [])), "phones": len(intel.get("phones", [])),
            "likely_bots": len(intel.get("bots", []))}
