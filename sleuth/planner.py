"""Smart search planner: decide what to search next from the evidence so far.

Instead of firing every possible query, look at what the last run found and
propose the steps that follow from it::

    Target: ice4564
    found:  GitHub ice4564, Reddit ice4564x, website example.com
    next:   - search username variants          (handle found, variants not tried)
            - follow the links on GitHub         (profile lists links, depth was 0)
            - scan the domain example.com        (personal website)
            - search "ice4564" "example.com"      (username + domain)

Each step has ``why`` (the evidence that suggests it) and an ``action`` the
web UI / assistant can run: ``search`` (usernames + options), ``scan``
(domain / email), ``query`` (search-engine queries) or ``open`` (a URL to
check by hand).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .similarity import emails_of
from .websearch import build_query

PRIORITY = {"high": 0, "medium": 1, "low": 2}


def plan(usernames: list[str], results: list[dict[str, Any]], *, queries: dict[str, dict[str, Any]] | None = None,
         domains: list[dict[str, Any]] | None = None, identity: list[dict[str, Any]] | None = None,
         search: dict[str, Any] | None = None, contradictions: list[dict[str, Any]] | None = None,
         skipped: list[dict[str, Any]] | None = None, options: dict[str, Any] | None = None,
         limit: int = 10) -> list[dict[str, Any]]:
    queries, domains, identity = queries or {}, domains or [], identity or []
    search, options = search or {}, options or {}
    found = [r for r in results if r["status"] == "found"]
    searched = {u.lower() for u in queries} | {u.lower() for u in usernames}
    steps: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    def step(sid: str, priority: str, title: str, why: str, action: dict[str, Any]) -> None:
        if sid not in seen_ids:
            seen_ids.add(sid)
            steps.append({"id": sid, "priority": priority, "title": title, "why": why, "action": action})

    typed_found = [r for r in found if r.get("query", "input") == "input"]
    by_user: dict[str, list[str]] = {}
    for r in typed_found:
        by_user.setdefault(r["username"], []).append(r["site"])

    # 1. the handle exists: people who have one usually have spellings of it too
    if not options.get("variants"):
        for u, sites in by_user.items():
            step(f"variants:{u.lower()}", "medium", f"ค้น username ใกล้เคียงของ @{u}",
                 f"พบ @{u} บน {len(sites)} เว็บ ({', '.join(sites[:3])}) แต่ยังไม่ได้ลองชื่อใกล้เคียง",
                 {"type": "search", "usernames": [u], "options": {"variants": True}})

    # 2. usernames the owner published that the run had no budget/depth left for
    for d in skipped or []:
        if d["username"].lower() not in searched:
            step(f"follow:{d['username'].lower()}", "high", f"ค้น @{d['username']} ต่อ",
                 f"{d['why']} แต่ยังไม่ได้ค้น (เกินจำนวนชั้น/โควตา)",
                 {"type": "search", "usernames": [d["username"]], "options": {}})

    # 3. profiles list links but the run did not follow them (depth 0)
    if options.get("depth", 1) == 0:
        with_links = [r for r in found if r.get("discovered") or (r.get("info") or {}).get("website")]
        if with_links:
            names = ", ".join(f"{r['site']}" for r in with_links[:3])
            step("follow-links", "high", f"ตรวจลิงก์จาก {names}",
                 f"{len(with_links)} โปรไฟล์มีลิงก์ไปบัญชี/เว็บอื่น แต่รอบนี้ปิดการค้นต่อ (ชั้น 0)",
                 {"type": "search", "usernames": usernames, "options": {"depth": 1}})

    # 4. personal websites: scan the domain, and look for the handle on / with it
    websites: dict[str, str] = {}
    for d in domains:
        if d.get("personal") or d.get("status") != "ok":
            websites.setdefault(d["domain"], d.get("source", ""))
    for r in found:
        w = (r.get("info") or {}).get("website", "")
        if w.startswith("http") and not options.get("domains", True):
            websites.setdefault(urlparse(w).netloc.lower().removeprefix("www."), f"{r['site']} @{r['username']}")
    main = usernames[0] if usernames else ""
    for dom, src in list(websites.items())[:3]:
        step(f"scan:{dom}", "high", f"ตรวจโดเมน {dom}", f"เว็บไซต์ที่ระบุใน {src}: ดู DNS, WHOIS, อีเมล, เทคโนโลยี",
             {"type": "scan", "target": dom})
        if main:
            step(f"query-domain:{dom}", "medium", f"ค้น \"{main}\" + {dom}",
                 f"หาหน้าที่พูดถึงทั้ง @{main} และโดเมน {dom}",
                 {"type": "query", "queries": [{"query": f'"{main}" "{dom}"', "username": main, "label": "username + domain"},
                                               {"query": f'site:{dom} "{main}"', "username": main, "label": "ในโดเมน"}]})

    # 5. e-mail addresses published by the owner
    emails = sorted({e for r in found for e in emails_of(r)} | {e for d in domains for e in d.get("emails", [])})
    for e in emails[:3]:
        step(f"scan:{e}", "high", f"ตรวจอีเมล {e}", "อีเมลที่เจ้าของเผยแพร่: หา Gravatar, PGP key, โดเมนอีเมล",
             {"type": "scan", "target": e})

    # 6. a real name on a trusted account: search the name with the handle
    for i in identity:
        if i["confidence"] == "low":
            continue
        r = next((x for x in found if x["site"] == i["site"] and x["username"] == i["username"]), None)
        name = ((r or {}).get("info") or {}).get("name", "").strip()
        if len(name.split()) >= 2:
            step(f"name:{name.lower()}", "medium", f"ค้นชื่อ \"{name}\"",
                 f"ชื่อจริงบน {i['site']} (ความมั่นใจ {i['score']}) อาจพาไปบัญชีที่ใช้ username อื่น",
                 {"type": "query", "queries": [
                     {"query": build_query(name, keywords=f'"{i["username"]}"'), "username": i["username"], "label": "ชื่อ + username"},
                     {"query": build_query(name, "linkedin"), "username": i["username"], "label": "ชื่อ LinkedIn"},
                     {"query": build_query(name, "facebook"), "username": i["username"], "label": "ชื่อ Facebook"}]})
            break

    # 7. blocked platforms that archive.org / a search engine say exist: worth opening
    for r in results:
        info = r.get("info") or {}
        if r["status"] == "manual" and (info.get("archived") or info.get("indexed")):
            src = "archive.org" if info.get("archived") else info["indexed"]
            step(f"open:{r['site'].lower()}/{r['username'].lower()}", "medium", f"เปิดตรวจ {r['site']} @{r['username']}",
                 f"{src} มีหน้าโปรไฟล์นี้ น่าจะมีบัญชีจริง ต้องยืนยันด้วยตา", {"type": "open", "url": r["url"]})

    # 8. search engines found profiles under other handles
    for h in (search.get("hits") or [])[:40]:
        if h.get("platform") and h.get("handle") and not h.get("same_handle") and h.get("mentions") \
                and h["handle"].lower() not in searched:
            step(f"follow:{h['handle'].lower()}", "medium", f"ค้น @{h['handle']} ({h['platform']})",
                 f"{h['engine']} เจอหน้า {h['platform']} @{h['handle']} ที่พูดถึง @{h['username']}",
                 {"type": "search", "usernames": [h["handle"]], "options": {}})

    # 9. never used search engines on this target
    if not options.get("web_search") and usernames:
        step("websearch", "low", "ค้นใน search engine", "รอบนี้ยังไม่ได้ค้น \"username\" site:... ใน DuckDuckGo/Bing",
             {"type": "search", "usernames": usernames, "options": {"websearch": True}})

    # 10. contradictions: look before trusting the group
    for c in contradictions or []:
        step(f"contradiction:{c['field']}:{c.get('scope')}", "high", f"ตรวจหลักฐานที่ขัดแย้ง: {c['label']}",
             c["message"], {"type": "open_tab", "tab": "overview"})

    steps.sort(key=lambda s: PRIORITY[s["priority"]])
    for n, s in enumerate(steps[:limit], 1):
        s["n"] = n
    return steps[:limit]
