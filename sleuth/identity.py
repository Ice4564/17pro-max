"""Identity correlation: group found accounts that look like one person.

Pairwise evidence comes from three places:

* owner links      a profile (or the owner's website) links to the other account
* connections      similarity.compare(): username, name, bio, website, e-mail,
                   picture and location signals, scored 0-100
* shared e-mail    the same address published on both profiles

Accounts are joined strongest-evidence-first (Kruskal); a cluster's
confidence is its *weakest* joining link, so a 95% cluster means every
member is tied in by at least 95% evidence. Like everything else here it
is a lead for a person to check, not proof.
"""

from __future__ import annotations

from typing import Any

from .evidence import account_id, domain_id
from .similarity import emails_of

MIN_EDGE = 55  # % below which a pairwise connection does not join two accounts
LINK_STRENGTH = 90  # the owner linked one account from the other


def _edges(found: list[dict[str, Any]], connections: list[dict[str, Any]],
           domains: list[dict[str, Any]]) -> list[tuple[int, str, str, str]]:
    ids = {account_id(r["site"], r["username"]) for r in found}
    edges: list[tuple[int, str, str, str]] = []
    # owner links: account -> account, or account -> website -> account
    domain_via = {domain_id(d["domain"]): d.get("via", []) for d in domains if d.get("personal")}
    for r in found:
        me = account_id(r["site"], r["username"])
        for src in r.get("via", []):
            if src in ids and src != me:
                edges.append((LINK_STRENGTH, src, me, "ลิงก์จากโปรไฟล์"))
            for owner in domain_via.get(src, []):
                if owner in ids and owner != me:
                    edges.append((LINK_STRENGTH - 5, owner, me, f"ลิงก์ผ่านเว็บไซต์ {src.split(':', 1)[1]}"))
    for c in connections:
        if c["confidence"] >= MIN_EDGE:
            a = account_id(c["a"]["site"], c["a"]["username"])
            b = account_id(c["b"]["site"], c["b"]["username"])
            why = ", ".join(s["label"] for s in c["signals"] if s["ok"]) or "ข้อมูลโปรไฟล์คล้ายกัน"
            edges.append((int(c["confidence"]), a, b, why))
    by_email: dict[str, list[str]] = {}
    for r in found:
        for e in emails_of(r):
            by_email.setdefault(e, []).append(account_id(r["site"], r["username"]))
    for e, accts in by_email.items():
        for other in accts[1:]:
            edges.append((80, accts[0], other, f"อีเมลเดียวกัน {e}"))
    return edges


def clusters(results: list[dict[str, Any]], connections: list[dict[str, Any]] | None = None,
             domains: list[dict[str, Any]] | None = None,
             scores: dict[str, int] | None = None) -> list[dict[str, Any]]:
    """Groups of two or more found accounts that probably belong to one person."""
    found = [r for r in results if r["status"] == "found"]
    by_id = {account_id(r["site"], r["username"]): r for r in found}
    parent = {i: i for i in by_id}

    def root(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    weakest: dict[str, int] = {}
    reasons: dict[str, list[str]] = {}
    for strength, a, b, why in sorted(_edges(found, connections or [], domains or []), key=lambda e: -e[0]):
        if a not in parent or b not in parent:
            continue
        ra, rb = root(a), root(b)
        if ra == rb:
            reasons.setdefault(ra, []).append(why)
            continue
        parent[rb] = ra
        weakest[ra] = min(strength, weakest.get(ra, 100), weakest.get(rb, 100))
        reasons[ra] = reasons.get(ra, []) + reasons.pop(rb, []) + [why]
        weakest.pop(rb, None)

    groups: dict[str, list[str]] = {}
    for i in by_id:
        groups.setdefault(root(i), []).append(i)
    scores = scores or {}
    out = []
    for r, members in groups.items():
        if len(members) < 2:
            continue
        members.sort(key=lambda m: (-scores.get(m, 0), m))
        accts = [{"id": m, "site": by_id[m]["site"], "username": by_id[m]["username"], "url": by_id[m]["url"],
                  "score": scores.get(m)} for m in members]
        why: list[str] = []
        for w in reasons.get(r, []):
            if w not in why:
                why.append(w)
        names = sorted({by_id[m].get("info", {}).get("name", "") for m in members} - {""}, key=len)
        out.append({"accounts": accts, "confidence": weakest.get(r, 0), "reasons": why[:8],
                    "names": names[:5], "usernames": sorted({a["username"] for a in accts}, key=str.lower)})
    out.sort(key=lambda c: (-len(c["accounts"]) * c["confidence"], -c["confidence"]))
    for n, c in enumerate(out, 1):
        c["id"] = f"identity-{n}"
    return out
