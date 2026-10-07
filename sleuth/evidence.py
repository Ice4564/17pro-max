"""Evidence: how every finding was reached, and what supports it.

* :func:`build_graph`     nodes are usernames (typed, guessed or discovered),
                          found accounts, personal domains, e-mail addresses
                          and search-engine leads; edges say why two nodes are
                          connected, so a report can show the chain
                          username -> profile -> link -> domain -> e-mail
* :func:`build_findings`  one record per finding::

                              Finding
                              +-- Source        how it was found
                              +-- URL
                              +-- Evidence      every fact that supports it
                              +-- First seen    first time Sleuth saw it (history)
                              +-- Last checked
                              +-- Confidence    0-100
* :func:`build_timeline`  dated events: accounts created, archived, first
                          seen, profile changes
"""

from __future__ import annotations

from typing import Any

from .similarity import emails_of


def user_id(username: str) -> str:
    return "user:" + username.lower()


def account_id(site: str, username: str) -> str:
    return f"acct:{site.lower()}/{username.lower()}"


def domain_id(domain: str) -> str:
    return "domain:" + domain.lower()


def email_id(email: str) -> str:
    return "email:" + email.lower()


def lead_id(platform: str, handle: str) -> str:
    return f"lead:{platform.lower()}/{handle.lower()}"


def build_graph(results: list[dict[str, Any]], queries: dict[str, dict[str, Any]],
                domains: list[dict[str, Any]], connections: list[dict[str, Any]],
                hits: list[dict[str, Any]] | None = None, max_leads: int = 15) -> dict[str, list]:
    """Return ``{"nodes": [...], "edges": [...]}`` (JSON-serialisable)."""
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def node(nid: str, **attrs: Any) -> None:
        nodes.setdefault(nid, {"id": nid, **attrs})

    def edge(src: str, dst: str, kind: str, label: str, evidence: list[str] | None = None) -> None:
        """Every edge says why it exists: ``evidence`` lists the facts behind it."""
        if src != dst and src in nodes and dst in nodes:
            e = edges.setdefault((src, dst, kind), {"source": src, "target": dst, "kind": kind, "label": label,
                                                    "evidence": []})
            for x in evidence or [label]:
                if x and x not in e["evidence"]:
                    e["evidence"].append(x)

    for q in queries.values():
        node(user_id(q["username"]), type="username", label=q["username"], query=q["query"],
             depth=q.get("depth", 0))
    for d in domains:
        node(domain_id(d["domain"]), type="domain", label=d["domain"], status=d.get("status"))

    found = [r for r in results if r["status"] == "found"]
    for r in found:
        node(account_id(r["site"], r["username"]), type="account", label=f"{r['site']} @{r['username']}",
             site=r["site"], username=r["username"], url=r["url"], linked=bool(r.get("linked")))

    for q in queries.values():
        uid = user_id(q["username"])
        if q.get("candidate_of"):
            edge(user_id(q["candidate_of"]), uid, "candidate", q.get("rule") or "รูปแบบใกล้เคียง",
                 [f"ระบบเดาชื่อนี้จาก @{q['candidate_of']}: {q.get('rule') or 'รูปแบบใกล้เคียง'} (ไม่ใช่หลักฐานว่าเป็นคนเดียวกัน)"])
        for src in q.get("from", []):
            why = (q.get("from_why") or {}).get(src) or q.get("why")
            src_label = nodes[src]["label"] if src in nodes else src
            edge(src, uid, "mentions", "ระบุ username นี้",
                 [f"@{q['username']}: {why}" if why else f"{src_label} ระบุ username @{q['username']}"])

    for r in found:
        aid = account_id(r["site"], r["username"])
        if not r.get("linked"):
            checks = [f"{'✓' if c.get('ok') else '✗' if c.get('ok') is False else '·'} {c['check']}: {c.get('detail', '')}"
                      for c in r.get("checks", [])]
            edge(user_id(r["username"]), aid, "found", "พบบัญชี",
                 [f"{r['site']} ตอบว่ามีบัญชี @{r['username']}" + (f" (HTTP {r['http_status']})" if r.get("http_status") else ""),
                  *checks])
        for src in r.get("via", []):
            src_label = nodes[src]["label"] if src in nodes else src
            why = [e for e in r.get("evidence", []) if src_label.split(" @")[0].lower() in e.lower()]
            edge(src, aid, "links", "ลิงก์ไปยังบัญชีนี้", why or [f"{src_label} ลิงก์ไปที่ {r['url']}"])

    for d in domains:
        did = domain_id(d["domain"])
        for src in d.get("via", []):
            edge(src, did, "website", "ลิงก์ไปเว็บไซต์",
                 [f"ช่องเว็บไซต์ในโปรไฟล์ชี้ไป {d.get('url', d['domain'])}", *([d["note"]] if d.get("note") else [])])

    for c in connections:
        a = account_id(c["a"]["site"], c["a"]["username"])
        b = account_id(c["b"]["site"], c["b"]["username"])
        edge(a, b, "similar", f"อาจเชื่อมโยงกัน {c['confidence']}%",
             [f"{'✓' if x['ok'] else '✗' if x['ok'] is False else '·'} {x['label']}" + (f" ({x['detail']})" if x.get("detail") else "")
              for x in c["signals"]])

    # e-mail addresses published on profiles and on the owner's websites
    for r in found:
        for e in sorted(emails_of(r)):
            node(email_id(e), type="email", label=e)
            edge(account_id(r["site"], r["username"]), email_id(e), "email", "ระบุอีเมลในโปรไฟล์",
                 [f"โปรไฟล์ {r['site']} @{r['username']} มีอีเมล {e}"])
    for d in domains:
        for e in d.get("emails", []):
            node(email_id(e), type="email", label=e)
            edge(domain_id(d["domain"]), email_id(e), "email", "อีเมลบนเว็บไซต์", [f"หน้าเว็บ {d['domain']} มีอีเมล {e}"])

    # search engines: indexed profiles of found accounts, and profile leads we could not check
    leads = 0
    for h in hits or []:
        if not h.get("platform") or not h.get("handle"):
            continue
        src = user_id(h["username"])
        aid = account_id(h["platform"], h["handle"])
        sources = [f"{x['engine']} อันดับ {x['rank']}: {x['query']}" for x in h.get("found_by", [])] or \
            [f"{h['engine']} อันดับ {h['rank']}: {h['query']}"]
        if aid in nodes:
            edge(src, aid, "search", f"พบใน {h['engine']}", sources)
        elif leads < max_leads and (h.get("same_handle") or h.get("mentions")):
            leads += 1
            lid = lead_id(h["platform"], h["handle"])
            node(lid, type="lead", label=f"{h['platform']} @{h['handle']}", url=h["url"], engine=h["engine"])
            edge(src, lid, "search", f"{h['engine']}: {h['query']}", sources)

    out_edges = list(edges.values())
    for n, e in enumerate(out_edges, 1):
        e["id"] = f"edge-{n}"
        e["n"] = n
    return {"nodes": list(nodes.values()), "edges": out_edges}


# ---- findings ------------------------------------------------------------
INFO_KEYS = ("name", "bio", "location", "website", "created", "followers", "following")
KIND_ORDER = {"account": 0, "email": 1, "domain": 2, "lead": 3, "mention": 4}


def _level(score: int) -> str:
    return "high" if score >= 70 else "medium" if score >= 45 else "low"


# How far a kind of source can be trusted on its own (Source Reliability).
RELIABILITY = {
    "check": "HIGH",       # the platform itself answered (official profile page / API)
    "profile": "HIGH",     # data shown on that official profile
    "email": "HIGH",       # published by the owner on a profile or their own site
    "link": "HIGH",        # the owner's own link
    "origin": "HIGH",
    "archive": "MEDIUM",   # archive.org snapshot: real page, but maybe outdated
    "search": "MEDIUM",    # a search engine's index: second-hand
    "correlation": "MEDIUM",  # Sleuth's own inference from the above
    "note": "LOW",
}
SOURCE_TH = {"HIGH": "สูง", "MEDIUM": "กลาง", "LOW": "ต่ำ"}


def _item(kind: str, text: str, url: str | None = None, ok: bool | None = True,
          reliability: str | None = None) -> dict[str, Any]:
    return {"type": kind, "text": text, "url": url, "ok": ok, "reliability": reliability or RELIABILITY.get(kind, "MEDIUM")}


def build_findings(results: list[dict[str, Any]], identity: list[dict[str, Any]],
                   domains: list[dict[str, Any]] | None = None, hits: list[dict[str, Any]] | None = None,
                   seen: dict[tuple[str, str], dict[str, Any]] | None = None,
                   queries: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Every finding with its source, evidence, first seen, last checked and confidence."""
    domains, hits, seen, queries = domains or [], hits or [], seen or {}, queries or {}
    ident = {(i["site"].lower(), i["username"].lower()): i for i in identity}
    hits_by_acct: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for h in hits:
        if h.get("platform") and h.get("handle"):
            hits_by_acct.setdefault((h["platform"].lower(), h["handle"].lower()), []).append(h)
    out: list[dict[str, Any]] = []
    used_hits: set[str] = set()

    def search_items(k: tuple[str, str]) -> list[dict[str, Any]]:
        items = []
        for h in hits_by_acct.get(k, []):
            used_hits.add(h["url"])
            items.append(_item("search", f"{h['engine']} พบหน้านี้จากคำค้น {h['query']}", h["url"]))
        return items

    for r in results:
        k = (r["site"].lower(), r["username"].lower())
        info = r.get("info") or {}
        if r["status"] == "found":
            i = ident.get(k, {})
            q = queries.get(r["username"].lower(), {})
            if r.get("linked"):
                via = [v.split(":", 1)[1] for v in r.get("via", [])[:3]]
                source = "เจ้าของลิงก์ไว้จาก " + (", ".join(via) or "โปรไฟล์อื่น")
            elif r.get("query") == "candidate":
                source = f"ตรวจ username ที่ระบบเดา ({q.get('rule') or 'รูปแบบใกล้เคียง'}) กับเว็บ {r['site']}"
            elif r.get("query") == "discovered":
                source = f"ตรวจ username ที่เจอจาก {q.get('source') or 'โปรไฟล์อื่น'} กับเว็บ {r['site']}"
            else:
                source = f"ตรวจกับเว็บ {r['site']} โดยตรง" + (f" (HTTP {r['http_status']})" if r.get("http_status") else "")
            ev = [_item("origin", e) for e in r.get("evidence", [])]
            ev += [_item("check", f"{c['check']}: {c.get('detail', '')}".rstrip(": "), ok=c.get("ok"))
                   for c in r.get("checks", [])]
            ev += [_item("profile", f"{key}: {info[key]}", info[key] if key == "website" else None)
                   for key in INFO_KEYS if info.get(key)]
            ev += [_item("email", f"อีเมล: {e}") for e in sorted(emails_of(r))]
            if info.get("archived"):
                ev.append(_item("archive", f"archive.org เก็บหน้าโปรไฟล์ไว้ ({info['archived']})", info.get("archive_url")))
            ev += search_items(k)
            ev += [_item("correlation", f"{s['label']} ({s['points']:+d})", ok=s["points"] >= 0)
                   for s in i.get("signals", [])[1:] if s["points"] or s.get("kind") == "contradiction"]
            when = seen.get(k, {})
            if r.get("linked"):
                source_type, reliability = "owner_link", "HIGH"
            elif any(c.get("check") == "profile" and c.get("ok") for c in r.get("checks", [])):
                source_type, reliability = "official_profile", "HIGH"
            else:
                source_type, reliability = "site_check", "MEDIUM"
            out.append({"id": account_id(r["site"], r["username"]), "kind": "account",
                        "source_type": source_type, "reliability": reliability, "fp_risk": i.get("fp_risk"),
                        "fp_why": i.get("fp_why", []), "signals": i.get("signals", []),
                        "title": f"{r['site']} @{r['username']}", "site": r["site"], "username": r["username"],
                        "url": r["url"], "source": source, "evidence": ev,
                        "first_seen": when.get("first_seen") or r.get("checked_at", ""),
                        "last_checked": when.get("last_checked") or r.get("checked_at", ""),
                        "cached": bool(r.get("cached")),
                        "confidence": i.get("score", 0), "level": i.get("confidence", "low")})
        elif r["status"] == "manual" and (info.get("archived") or k in hits_by_acct):
            ev, conf = [], 10
            if info.get("archived"):
                ev.append(_item("archive", f"archive.org เก็บหน้าโปรไฟล์ไว้ (ล่าสุด {info['archived']})",
                                info.get("archive_url")))
                conf += 15
            found_in_search = search_items(k)
            if found_in_search:
                conf = max(conf, 25)
            ev += found_in_search
            ev.append(_item("note", "เว็บนี้บล็อกการตรวจอัตโนมัติ ต้องเปิดลิงก์ยืนยันเอง", ok=None))
            out.append({"id": account_id(r["site"], r["username"]), "kind": "lead", "source_type": "unverified",
                        "reliability": "MEDIUM" if found_in_search or info.get("archived") else "LOW",
                        "title": f"{r['site']} @{r['username']} (ยังไม่ยืนยัน)", "site": r["site"],
                        "username": r["username"], "url": r["url"], "source": "archive.org / search engine",
                        "evidence": ev, "first_seen": r.get("checked_at", ""), "last_checked": r.get("checked_at", ""),
                        "confidence": conf, "level": "low"})

    for d in domains:
        ev = [_item("origin", f"ระบุในโปรไฟล์ {d.get('source', '')}")]
        if d.get("title"):
            ev.append(_item("profile", f"ชื่อหน้าเว็บ: {d['title']}"))
        if d.get("note"):
            ev.append(_item("note", d["note"], ok=bool(d.get("personal"))))
        ev += [_item("link", f"ลิงก์ไป {x}") for x in d.get("found_links", [])]
        ev += [_item("email", f"อีเมล: {e}") for e in d.get("emails", [])]
        if d.get("status") != "ok":
            ev.append(_item("note", f"เปิดไม่ได้: {d.get('error') or d.get('status')}", ok=False))
        conf = 60 if d.get("personal") else 25
        out.append({"id": domain_id(d["domain"]), "kind": "domain", "source_type": "personal_website" if d.get("personal") else "website",
                    "reliability": "HIGH" if d.get("personal") else "LOW", "title": d["domain"], "url": d.get("url", ""),
                    "source": f"เว็บไซต์ที่ระบุใน {d.get('source', '')}", "evidence": ev,
                    "first_seen": d.get("checked_at", ""), "last_checked": d.get("checked_at", ""),
                    "confidence": conf, "level": _level(conf)})

    emails: dict[str, dict[str, Any]] = {}
    for r in results:
        if r["status"] != "found":
            continue
        for e in emails_of(r):
            rec = emails.setdefault(e, {"sources": [], "conf": 0, "when": r.get("checked_at", "")})
            rec["sources"].append(f"{r['site']} @{r['username']}")
            rec["conf"] = max(rec["conf"], ident.get((r["site"].lower(), r["username"].lower()), {}).get("score", 0))
    for d in domains:
        for e in d.get("emails", []):
            rec = emails.setdefault(e, {"sources": [], "conf": 0, "when": d.get("checked_at", "")})
            rec["sources"].append(f"เว็บไซต์ {d['domain']}")
            rec["conf"] = max(rec["conf"], 60 if d.get("personal") else 20)
    for e, rec in emails.items():
        out.append({"id": email_id(e), "kind": "email", "title": e, "url": "mailto:" + e, "source_type": "published",
                    "reliability": "HIGH" if rec["conf"] >= 45 else "MEDIUM",
                    "source": "เผยแพร่บน " + ", ".join(rec["sources"][:4]),
                    "evidence": [_item("origin", f"พบบน {s}") for s in rec["sources"]],
                    "first_seen": rec["when"], "last_checked": rec["when"],
                    "confidence": rec["conf"], "level": _level(rec["conf"])})

    for h in hits:
        if h["url"] in used_hits or not (h.get("mentions") or h.get("same_handle")):
            continue
        conf = 30 if h.get("same_handle") else 15
        if h.get("platform"):
            fid, kind, title = lead_id(h["platform"], h["handle"]), "lead", f"{h['platform']} @{h['handle']}"
        else:
            fid, kind, title = "web:" + h["url"], "mention", h.get("title") or h["url"]
        ev = [_item("search", h.get("title") or h["url"], h["url"])]
        if h.get("snippet"):
            ev.append(_item("search", h["snippet"]))
        found_by = h.get("found_by") or [{"engine": h["engine"], "query": h["query"], "rank": h["rank"]}]
        ev += [_item("search", f"พบโดย {x['engine']} คำค้น #{x.get('query_n', '?')} {x['query']} (อันดับ {x['rank']})")
               for x in found_by]
        out.append({"id": fid, "kind": kind, "title": title, "url": h["url"], "found_by": found_by,
                    "source_type": "search_result" if kind == "lead" else "unverified_page",
                    "reliability": "MEDIUM" if kind == "lead" else "LOW",
                    "source": f"{h['engine']} · คำค้น {h['query']} (อันดับ {h['rank']})"
                              + (f" · ซ้ำอีก {len(found_by) - 1} ครั้ง" if len(found_by) > 1 else ""), "evidence": ev,
                    "first_seen": h.get("checked_at", ""), "last_checked": h.get("checked_at", ""),
                    "confidence": conf, "level": "low"})

    out.sort(key=lambda f: (KIND_ORDER.get(f["kind"], 9), -f["confidence"], f["title"].lower()))
    return out


# ---- timeline ------------------------------------------------------------
def _date(value: str) -> str:
    """The value if it starts with an ISO date (sortable as text), else ''."""
    v = (value or "").strip()
    if len(v) >= 10 and v[4] == "-" and v[7] == "-" and v[:4].isdigit():
        return v
    return ""


def build_timeline(results: list[dict[str, Any]], changes: list[dict[str, Any]] | None = None,
                   seen: dict[tuple[str, str], dict[str, Any]] | None = None,
                   domains: list[dict[str, Any]] | None = None, run_started: str = "",
                   usernames: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Dated events about the target, oldest first.

    ``usernames`` (from the history database) adds when each spelling of the
    target's handle was first seen: 2025 ice4564, 2026-01 ice4564x ...
    """
    seen = seen or {}
    items: list[dict[str, Any]] = []

    def add(date: str, kind: str, title: str, detail: str = "", site: str = "", url: str = "",
            node: str = "") -> None:
        d = _date(date)
        if d:
            items.append({"date": d, "kind": kind, "title": title, "detail": detail, "site": site, "url": url,
                          "node": node})

    first_by_day: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for r in results:
        info = r.get("info") or {}
        node = account_id(r["site"], r["username"])
        label = f"{r['site']} @{r['username']}"
        if r["status"] == "found":
            add(info.get("created", ""), "created", f"สร้างบัญชี {label}", "", r["site"], r["url"], node)
            first = seen.get((r["site"].lower(), r["username"].lower()), {}).get("first_seen")
            if first and run_started and first < run_started:
                first_by_day.setdefault(first[:10], []).append((first, r))
        if info.get("archived"):
            add(info["archived"], "archived", f"archive.org เก็บหน้า {label}", "", r["site"],
                info.get("archive_url", r["url"]), node)
    # one entry per day: a first search typically "first sees" dozens of accounts at once
    for _day, rows in first_by_day.items():
        when = min(f for f, _ in rows)
        if len(rows) == 1:
            r = rows[0][1]
            add(when, "first_seen", f"Sleuth พบ {r['site']} @{r['username']} ครั้งแรก", "", r["site"], r["url"],
                account_id(r["site"], r["username"]))
        else:
            names = ", ".join(f"{r['site']} @{r['username']}" for _, r in rows[:8])
            add(when, "first_seen", f"Sleuth พบ {len(rows)} บัญชีครั้งแรก",
                names + (f" และอีก {len(rows) - 8}" if len(rows) > 8 else ""))
    done: set[tuple[str, ...]] = set()
    for c in changes or []:
        k = (c["site"].lower(), c["username"].lower(), c["field"], c.get("detected_at", ""))
        if k in done:
            continue
        done.add(k)
        verb = {"added": "เพิ่ม", "removed": "ลบ", "changed": "เปลี่ยน"}.get(c["kind"], "เปลี่ยน")
        add(c.get("detected_at", ""), "change", f"{c['site']} @{c['username']}: {verb}{c.get('label') or c['field']}",
            f"{c.get('old') or '—'} → {c.get('new') or '—'}", c["site"], c.get("url", ""),
            account_id(c["site"], c["username"]))
    for u in usernames or []:
        if u.get("first_seen") and (not run_started or u["first_seen"] < run_started):
            add(u["first_seen"], "username", f"username: @{u['username']}",
                f"พบบน {u.get('accounts', 0)} เว็บ" + (f" · ล่าสุด {u['last_seen'][:10]}" if u.get("last_seen") else ""))
    if run_started:
        n = sum(1 for r in results if r["status"] == "found")
        add(run_started, "run", "ค้นหาครั้งนี้", f"พบ {n} บัญชี" + (f", ตามเว็บไซต์ {len(domains)} เว็บ" if domains else ""))
    items.sort(key=lambda x: x["date"])
    return items


def summary(usernames: list[str], results: list[dict[str, Any]], identity: list[dict[str, Any]],
            findings: list[dict[str, Any]], clusters: list[dict[str, Any]], changes: list[dict[str, Any]],
            hits: list[dict[str, Any]], domains: list[dict[str, Any]]) -> dict[str, Any]:
    """Numbers for the dashboard."""
    levels = {"high": 0, "medium": 0, "low": 0}
    for i in identity:
        levels[i["confidence"]] += 1
    found = [r for r in results if r["status"] == "found"]
    linked = {(r["site"].lower(), r["username"].lower()) for r in found if r.get("linked")}
    linked |= {(a["site"].lower(), a["username"].lower()) for c in clusters for a in c["accounts"]}
    return {
        "targets": usernames,
        "accounts_found": len(found),
        "linked_accounts": len(linked),  # owner-linked or tied to another account by evidence
        "identities": len(clusters),
        "evidence": sum(len(f["evidence"]) for f in findings),
        "findings": len(findings),
        "high": levels["high"], "medium": levels["medium"], "low": levels["low"],
        "changes": len(changes),
        "search_hits": len(hits),
        "domains": len(domains),
        "emails": sum(1 for f in findings if f["kind"] == "email"),
        "leads": sum(1 for f in findings if f["kind"] in ("lead", "mention")),
        "manual": sum(1 for r in results if r["status"] == "manual"),
    }
