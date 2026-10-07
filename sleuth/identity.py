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

import re
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


# ---- entity resolution ------------------------------------------------------------
_PREFIX = re.compile(r"^(?:real|the|its|im|iam|official)[._-]?(?=[a-z0-9]{3,})")
_SUFFIX = re.compile(r"(?:[._-](?:official|th|x+|\d{1,2})|(?<=\d)(?:official|th|x+)|official|_+)$")


def handle_core(username: str) -> str:
    """The handle without decoration: ice4564, Ice4564, ice_4564, ice4564x, real.ice4564 -> ice4564.

    Suffixes like x / th are only removed after a digit or a separator, so
    "alex" stays "alex".
    """
    u = username.strip().lstrip("@").lower()
    for _ in range(2):
        u2 = _SUFFIX.sub("", u)
        u2 = _PREFIX.sub("", u2)
        if len(re.sub(r"[._-]", "", u2)) < 3 or u2 == u:
            break
        u = u2
    return re.sub(r"[._-]", "", u)


def entities(results: list[dict[str, Any]], clusters_: list[dict[str, Any]], identity: list[dict[str, Any]],
             typed: list[str] | None = None) -> list[dict[str, Any]]:
    """Possible identities: handle families, merged when evidence links them.

    1. usernames that are spellings of one handle form a family
       (ice4564 / Ice4564 / ice_4564 / ice4564x);
    2. families whose accounts sit in the same evidence cluster are one entity
       (GitHub ice4564 links to Instagram ice.photos -> both families merge).

    An entity built only from spelling has at most 40 confidence: a shared
    handle is how two strangers look too.
    """
    found = [r for r in results if r["status"] == "found"]
    scores = {(i["site"].lower(), i["username"].lower()): i for i in identity}
    fam_of: dict[str, str] = {}
    for r in found:
        fam_of[r["username"].lower()] = handle_core(r["username"])
    for u in typed or []:
        fam_of.setdefault(u.lower(), handle_core(u))
    parent = {f: f for f in set(fam_of.values())}

    def root(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for c in clusters_:
        fams = {fam_of.get(a["username"].lower()) for a in c["accounts"]} - {None}
        fams_l = sorted(fams)
        for f in fams_l[1:]:
            parent[root(f)] = root(fams_l[0])
    groups: dict[str, dict[str, Any]] = {}
    for r in found:
        g = groups.setdefault(root(fam_of[r["username"].lower()]), {"accounts": [], "usernames": set(), "families": set()})
        g["accounts"].append(r)
        g["usernames"].add(r["username"])
        g["families"].add(fam_of[r["username"].lower()])
    typed_l = {u.lower() for u in typed or []}
    out = []
    for key, g in groups.items():
        ids = {account_id(r["site"], r["username"]) for r in g["accounts"]}
        linked = [c for c in clusters_ if ids & {a["id"] for a in c["accounts"]}]
        spellings = sorted(g["usernames"], key=str.lower)
        reasons = []
        if len({u.lower() for u in spellings}) > 1:
            reasons.append("username ตระกูลเดียวกัน: " + " ≈ ".join(spellings[:6]))
        elif spellings:
            reasons.append(f"ใช้ username @{spellings[0]} เหมือนกันบน {len(g['accounts'])} เว็บ")
        for c in linked:
            reasons += [f"{w} ({c['confidence']}%)" for w in c["reasons"][:3]]
        if linked:
            confidence = max(c["confidence"] for c in linked)
        else:
            top = max((scores.get((r["site"].lower(), r["username"].lower()), {}).get("score", 0) for r in g["accounts"]),
                      default=0)
            confidence = min(40, top)
        contradictions = [x for c in linked for x in c.get("contradictions", [])]
        accounts = sorted(({"id": account_id(r["site"], r["username"]), "site": r["site"], "username": r["username"],
                            "url": r["url"],
                            "score": scores.get((r["site"].lower(), r["username"].lower()), {}).get("score", 0)}
                           for r in g["accounts"]), key=lambda a: (-a["score"], a["site"].lower()))
        out.append({"core": key, "aliases": spellings, "families": sorted(g["families"]), "accounts": accounts,
                    "confidence": confidence, "evidence_based": bool(linked), "reasons": reasons[:10],
                    "clusters": [c["id"] for c in linked], "contradictions": contradictions,
                    "typed": bool(typed_l & {u.lower() for u in spellings})})
    out.sort(key=lambda e: (not e["typed"], not e["evidence_based"], -e["confidence"], -len(e["accounts"])))
    for n, e in enumerate(out, 1):
        e["id"] = f"entity-{n}"
        e["title"] = f"Possible identity #{n}"
    return out
