"""Command-line interface."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path

from . import __version__, report
from .engine import SearchConfig, Searcher, Status
from .mutations import parse_range
from .sites import all_tags, filter_sites, load_sites, save_sites

BANNER = r"""
   ____  _            _   _
  / ___|| | ___ _   _| |_| |__
  \___ \| |/ _ \ | | | __| '_ \
   ___) | |  __/ |_| | |_| | | |
  |____/|_|\___|\__,_|\__|_| |_|   v{version}
  username OSINT across {count} sites
"""


class C:
    """ANSI colours (disabled with --no-color or when not a TTY)."""
    on = True

    @classmethod
    def wrap(cls, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if cls.on else s

    green = classmethod(lambda c, s: c.wrap("32", s))
    red = classmethod(lambda c, s: c.wrap("31", s))
    yellow = classmethod(lambda c, s: c.wrap("33", s))
    cyan = classmethod(lambda c, s: c.wrap("36", s))
    dim = classmethod(lambda c, s: c.wrap("2", s))
    bold = classmethod(lambda c, s: c.wrap("1", s))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sleuth",
        description="Find accounts by username across many sites (Sherlock + Maigret style).",
    )
    p.add_argument("usernames", nargs="*", help="one or more usernames to search")
    g = p.add_argument_group("site selection")
    g.add_argument("-s", "--site", action="append", dest="sites", metavar="NAME", help="only check this site (repeatable)")
    g.add_argument("-t", "--tags", help="only sites with these tags, comma separated (e.g. coding,gaming)")
    g.add_argument("--exclude-tags", help="skip sites with these tags")
    g.add_argument("--db", metavar="FILE", help="use a custom sites.json")
    g.add_argument("--list-sites", action="store_true", help="list sites and tags, then exit")

    g = p.add_argument_group("search")
    g.add_argument("-d", "--depth", type=int, default=1, help="recursive depth for usernames found in profiles (0 = off, default 1)")
    g.add_argument("--max-new", type=int, default=10, help="max extra usernames from recursion (default 10)")
    g.add_argument("-v", "--variants", "--candidates", "--mutations", action="store_true", dest="variants",
                   help="also try username mutations (ice4564 -> ice_4564, ice.4564, ice4564x, ice4564th); shown separately")
    g.add_argument("--max-candidates", type=int, default=12, help="mutations per username (default 12)")
    g.add_argument("-n", "--numbers", metavar="FROM-TO",
                   help="also try the name with a number appended: --numbers 1-10 -> ice1 ... ice10 (max 100)")
    g.add_argument("--show-mutations", action="store_true", help="print the mutations of each username, then exit")
    g.add_argument("-w", "--web-search", action="store_true",
                   help='also search DuckDuckGo/Bing for "username" site:instagram.com ... and keep the hits as evidence')
    g.add_argument("--max-search", type=int, default=6, help="search-engine queries per username (default 6)")
    g.add_argument("--no-domains", action="store_true", help="don't follow personal websites found in profiles")
    g.add_argument("--max-domains", type=int, default=5, help="max personal websites to follow (default 5)")
    g.add_argument("--no-extract", action="store_true", help="don't parse profile info")
    g.add_argument("--timeout", type=float, default=12, help="seconds per request (default 12)")
    g.add_argument("-c", "--concurrency", type=int, default=40, help="parallel requests (default 40)")
    g.add_argument("--retries", type=int, default=1, help="retries on network errors (default 1)")
    g.add_argument("--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    g.add_argument("--tor", action="store_true", help="route through Tor (socks5://127.0.0.1:9050, needs aiohttp-socks)")
    g.add_argument("--rate", type=float, default=0.3, metavar="SEC",
                   help="min seconds between two requests to the same host (default 0.3, 0 = off)")

    g = p.add_argument_group("history, cache and profile changes (~/.sleuth/history.db)")
    g.add_argument("--no-cache", action="store_true", help="ask every site again instead of reusing recent answers")
    g.add_argument("--cache-ttl", type=float, default=6, metavar="HOURS", help="reuse answers this recent (default 6)")
    g.add_argument("--clear-cache", action="store_true", help="empty the answer cache, then exit")
    g.add_argument("--no-history", action="store_true", help="don't save this search (no snapshots, no change tracking)")
    g.add_argument("--changes", action="store_true",
                   help="show recorded profile changes (for the given usernames, or all), then exit")
    g.add_argument("--runs", action="store_true", help="list saved username searches, then exit")
    g.add_argument("--replay", type=int, metavar="RUN", help="show what the engine did in a saved run, step by step")
    g.add_argument("--intel", metavar="TEXT", help="search everything the local database knows (accounts, domains, "
                                                   "emails, URLs, relationships)")

    g = p.add_argument_group("watchlist and cases")
    g.add_argument("--watch-add", metavar="USERNAME", action="append", help="re-check this username on a schedule")
    g.add_argument("--watch-interval", type=float, default=24, metavar="HOURS", help="for --watch-add (default 24)")
    g.add_argument("--watch-remove", metavar="USERNAME", action="append", help="stop watching a username")
    g.add_argument("--watch-list", action="store_true", help="show the watchlist")
    g.add_argument("--watch-run", action="store_true",
                   help="check due watchlist targets once (for Task Scheduler / cron) and print changes")
    g.add_argument("--alerts", action="store_true", help="show unseen watchlist alerts and mark them seen")
    g.add_argument("--cases", action="store_true", help="list investigation cases")
    g.add_argument("--case", metavar="NAME", help="save this search into a case (created if missing)")

    g = p.add_argument_group("output")
    g.add_argument("-a", "--print-all", action="store_true", help="also print not-found and unknown results")
    g.add_argument("-o", "--output", metavar="DIR", default="reports", help="folder for reports (default ./reports)")
    g.add_argument("-f", "--format", default="",
                   help="report formats, comma separated: txt,csv,json,md,html,pdf or 'all' (pdf needs Chrome/Edge)")
    g.add_argument("--no-color", action="store_true", help="disable colours")

    g = p.add_argument_group("scan (SpiderFoot-style: domain, IP, email or username)")
    g.add_argument("--scan", metavar="TARGET", help="full OSINT scan of a domain, IP, email or username")
    g.add_argument("-m", "--modules", help="scan modules to use, comma separated (default: all)")
    g.add_argument("--list-modules", action="store_true", help="list scan modules, then exit")
    g.add_argument("--history", action="store_true", help="show saved scans, then exit")
    g.add_argument("--no-save", action="store_true", help="don't save the scan to the history database")

    g = p.add_argument_group("tools")
    g.add_argument("--web", action="store_true", help="start the web interface")
    g.add_argument("--menu", action="store_true",
                   help="interactive menu (also shown when sleuth runs with no arguments in a terminal)")
    g.add_argument("--no-intro", action="store_true", help="skip the loading animation before the menu")
    g.add_argument("--host", default="127.0.0.1", help="web host (default 127.0.0.1)")
    g.add_argument("--port", type=int, default=8787, help="web port (default 8787)")
    g.add_argument("--no-browser", action="store_true", help="don't open the browser automatically with --web")
    g.add_argument("--self-check", action="store_true", help="test every site's detection rule against the live site")
    g.add_argument("--disable-broken", action="store_true", help="with --self-check: mark failing sites disabled in the DB")
    g.add_argument("--version", action="version", version=f"sleuth {__version__}")

    g = p.add_argument_group("v3 OSINT tools (advanced)")
    g.add_argument("--dorks", metavar="TARGET", help="generate Google dorks for a target (username, email, name, or domain)")
    g.add_argument("--deepsearch", metavar="TARGET", help="deep search: Reddit, 4chan, GitHub, GitLab, pastes, academic")
    g.add_argument("--iocs", metavar="TEXT", help="extract IOCs (IPs, hashes, URLs, emails, domains) from text or @file")
    g.add_argument("--stix", metavar="FILE", help="export search results JSON to STIX 2.1 bundle")
    g.add_argument("--misp", metavar="FILE", help="export search results JSON to MISP event")
    g.add_argument("--maltego", metavar="FILE", help="export search results JSON to Maltego XML")
    g.add_argument("--privacy", metavar="FILE", help="privacy risk assessment from search results JSON")
    g.add_argument("--remediation", action="store_true", help="show remediation guides for reducing online exposure")
    g.add_argument("--forensics", metavar="URL", help="forensic analysis of an image URL (steganography, ELA, faces, deepfake)")
    g.add_argument("--behavior", metavar="FILE", help="behavioral analysis from search results JSON")
    g.add_argument("--auto-investigate", metavar="FILE", help="auto-investigation planner from search results JSON")
    g.add_argument("--playbooks", action="store_true", help="list investigation playbooks, then exit")
    g.add_argument("--playbook", metavar="CATEGORY", help="show a specific playbook (missing_person, fraud, identity_theft, threat_assessment, due_diligence)")
    g.add_argument("--archive", metavar="URL", help="check archives (Wayback, archive.today, Google Cache) for a URL")
    g.add_argument("--infra", metavar="DOMAIN", help="infrastructure intel: CT logs, DNS, subdomains, WHOIS, Shodan")
    g.add_argument("--graph", metavar="FILE", help="generate network graph JSON from search results")
    g.add_argument("--notes", action="store_true", help="manage case notes (interactive)")
    g.add_argument("--annotations", action="store_true", help="manage result annotations (interactive)")
    g.add_argument("--custody", action="store_true", help="show chain of custody log")
    g.add_argument("--schedules", action="store_true", help="list scheduled scans")
    g.add_argument("--feeds", action="store_true", help="monitor RSS/Atom feeds for keywords (interactive)")
    return p


def _config(args: argparse.Namespace) -> SearchConfig:
    proxy = "socks5://127.0.0.1:9050" if args.tor else args.proxy
    return SearchConfig(timeout=args.timeout, concurrency=max(1, args.concurrency), retries=max(0, args.retries),
                        proxy=proxy, extract=not args.no_extract, depth=max(0, args.depth),
                        max_usernames=max(0, args.max_new), variants=args.variants,
                        max_candidates=max(0, args.max_candidates), domains=not args.no_domains,
                        max_domains=max(0, args.max_domains), web_search=args.web_search,
                        max_search_queries=max(0, args.max_search), cache=not args.no_cache,
                        cache_ttl=max(0.0, args.cache_ttl) * 3600, host_interval=max(0.0, args.rate),
                        numbers=parse_range(getattr(args, "numbers", None)))


def _print_result(r: dict, print_all: bool) -> None:
    st = r["status"]
    if st == "found":
        candidate = r.get("query") == "candidate"
        tag = C.cyan("[=]") if r.get("linked") else C.yellow("[~]") if candidate else C.green("[+]")
        note = C.yellow(f"  (candidate: เดาจาก {r.get('candidate_of')})") if candidate else ""
        print(f"  {tag} {C.bold(r['site'])}: {r['url']}{note}")
        if print_all and r.get("checks"):
            print(f"      {C.dim('verified:')} " + "  ".join(f"{_mark(c['ok'])} {c['check']}" for c in r["checks"]))
        if r.get("linked"):
            print(f"      {C.dim('เชื่อมโยง:')} {'; '.join(r.get('evidence', []))}")
        info = r.get("info", {})
        for key in ("name", "bio", "location", "website", "created", "followers"):
            if key in info:
                val = info[key] if len(info[key]) <= 100 else info[key][:97] + "..."
                print(f"      {C.dim(key + ':')} {val}")
    elif print_all and st == "not_found":
        print(f"  {C.red('[-]')} {r['site']}: {C.dim('not found')}")
    elif print_all and st == "unknown":
        print(f"  {C.yellow('[?]')} {r['site']}: {C.dim(r.get('error') or 'unknown')}")


def _mark(ok: bool | None) -> str:
    return C.green("✓") if ok else C.red("✗") if ok is False else C.dim("·")


CONF_LABEL = {"high": "สูง", "medium": "กลาง", "low": "ต่ำ"}


def _formats(value: str) -> list[str]:
    if value == "all":
        extra = (["pdf"] if report.find_browser() else [])
        try:
            import openpyxl  # noqa: F401
            extra.append("xlsx")
        except ImportError:
            pass
        return list(report.FORMATS) + extra
    return [f.strip().lower() for f in value.split(",") if f.strip()]


def _open_history(args: argparse.Namespace):
    if getattr(args, "no_history", False):
        return None
    from .history import History
    try:
        return History()
    except Exception as e:  # read-only home folder etc.: search still works
        print(C.yellow(f"history disabled: {e}"))
        return None


def _print_changes(changes: list[dict]) -> None:
    verb = {"added": "เพิ่ม", "removed": "ลบ", "changed": "เปลี่ยน"}
    for c in changes:
        when = (c.get("detected_at") or "")[:16].replace("T", " ")
        print(f"  {C.yellow('[Δ]')} {C.bold(c['site'])} @{c['username']}: {verb.get(c['kind'], c['kind'])}"
              f"{c.get('label') or c['field']}  {C.dim(when)}")
        if c["field"] == "avatar":
            print(f"      {C.dim('รูปโปรไฟล์เปลี่ยน')}")
        else:
            old, new = str(c.get("old") or "—"), str(c.get("new") or "—")
            print(f"      {C.dim('เดิม:')} {old[:120]}\n      {C.dim('ใหม่:')} {new[:120]}")


async def run_search(args: argparse.Namespace, sites, all_sites) -> int:
    history = _open_history(args)
    try:
        return await _run_search(args, sites, all_sites, history)
    finally:
        if history:
            history.close()


async def _run_search(args: argparse.Namespace, sites, all_sites, history) -> int:
    searcher = Searcher(sites, _config(args), all_sites=all_sites, history=history)
    done_count: dict[str, int] = {}
    total = len(sites)
    is_tty = sys.stdout.isatty()

    async for ev in searcher.run(args.usernames):
        if ev["type"] == "start":
            if ev.get("query") == "candidate":
                print(f"\n{C.yellow('[~]')} Candidate {C.bold(ev['username'])} {C.dim('(' + ev['source'] + ')')}")
            else:
                depth = f" (depth {ev['depth']}, from {ev['source']})" if ev["source"] else ""
                print(f"\n{C.cyan('[*]')} Checking {C.bold(ev['username'])} on {ev['total']} sites{depth}")
        elif ev["type"] == "domain":
            if is_tty:
                print("\r\033[K", end="")
            links = ", ".join(ev["found_links"]) or C.dim("no profile links")
            state = C.green("ok") if ev["status"] == "ok" else C.yellow(ev["error"] or ev["status"])
            print(f"  {C.cyan('[@]')} website {C.bold(ev['domain'])} {C.dim('from ' + ev['source'])} [{state}]: {links}")
        elif ev["type"] == "discovered":
            print(f"  {C.cyan('[>]')} new username {C.bold(ev['username'])} {C.dim('from ' + ev['source'])}")
        elif ev["type"] == "result":
            if is_tty:
                print("\r\033[K", end="")
            _print_result(ev, args.print_all)
            done_count[ev["username"]] = done_count.get(ev["username"], 0) + 1
            if is_tty and C.on:
                print(C.dim(f"  ... {done_count[ev['username']]}/{total} checked for {ev['username']}"), end="", flush=True)
        elif ev["type"] == "done":
            if is_tty:
                print("\r\033[K", end="")
            results = [r.to_dict() for r in searcher.results]
            manual = [r for r in results if r["status"] == "manual"]
            if manual:
                print(f"\n{C.bold('ตรวจเอง')} {C.dim('(เว็บเหล่านี้บล็อกการตรวจอัตโนมัติ เปิดลิงก์ในเบราว์เซอร์ที่ login ไว้)')}:")
                for r in sorted(manual, key=lambda r: (not r["info"].get("archived"), r["username"].lower(), r["site"])):
                    print(f"  {C.yellow('[?]')} {r['site']:<12} {r['url']}")
                    if r["info"].get("archived"):
                        print(f"      {C.cyan('archive.org เคยเก็บหน้านี้ไว้ ' + r['info']['archived'])}: "
                              f"{r['info']['archive_url']}")
            strong = [i for i in ev["identity"] if i["confidence"] != "low"]
            if strong:
                print(f"\n{C.bold('บัญชีที่น่าจะเป็นคนเดียวกัน')}:")
                for i in strong:
                    print(f"  [{CONF_LABEL[i['confidence']]}] {i['site']}: {i['url']}\n"
                          f"        {C.dim('; '.join(i['evidence']))}")
            if ev.get("connections"):
                print(f"\n{C.bold('Possible connections')} "
                      f"{C.dim('(ไม่ได้ยืนยันว่าเป็นคนเดียวกัน ใช้เป็นแนวทางตรวจต่อ)')}:")
                for c in ev["connections"][:10]:
                    print(f"  {C.bold(str(c['confidence']) + '%'):>6} {c['a']['site']} @{c['a']['username']}"
                          f"  <->  {c['b']['site']} @{c['b']['username']}")
                    print("        " + "   ".join(f"{_mark(x['ok'])} {x['label']}" for x in c["signals"]))
            clusters = ev.get("clusters", [])
            if clusters:
                print(f"\n{C.bold('ตัวตนที่น่าจะเป็นคนเดียวกัน')} {C.dim('(ตัวเลข = หลักฐานที่อ่อนที่สุดที่เชื่อมกัน)')}:")
            for c in clusters[:5]:
                print(f"  {C.bold(str(c['confidence']) + '%'):>6} " +
                      ", ".join(f"{a['site']} @{a['username']}" for a in c["accounts"]))
                print(f"        {C.dim('เพราะ: ' + '; '.join(c['reasons'][:4]))}")
            search = ev.get("search") or {}
            if search.get("engines"):
                hits = [h for h in search.get("hits", []) if h.get("mentions") or h.get("same_handle")]
                blocked = [e["name"] for e in search["engines"] if e["blocked"]]
                print(f"\n{C.bold('Search engine')}: {len(hits)} หน้าที่กล่าวถึง username"
                      + (C.yellow(f" (ถูกบล็อก: {', '.join(blocked)})") if blocked else ""))
                for h in hits[:8]:
                    print(f"  {C.cyan('[s]')} {h['url']}  {C.dim(h['engine'] + ': ' + h['query'])}")
            if ev.get("changes"):
                print(f"\n{C.bold('โปรไฟล์ที่เปลี่ยนไปจากครั้งก่อน')}:")
                _print_changes(ev["changes"])
            for e in ev.get("entities", [])[:3]:
                if e is ev["entities"][0]:
                    print(f"\n{C.bold('Entity resolution')}:")
                print(f"  {C.bold(e['title'])} ({e['confidence']}%): " + ", ".join(e["aliases"][:6]))
                print("    " + ", ".join(f"{a['site']}" for a in e["accounts"][:10]) +
                      (f" +{len(e['accounts']) - 10}" if len(e["accounts"]) > 10 else ""))
                print(f"    {C.dim('เพราะ: ' + '; '.join(e['reasons'][:3]))}")
            for x in ev.get("contradictions", []):
                if x is ev["contradictions"][0]:
                    print(f"\n{C.red('⚠ Contradictory evidence detected')} "
                          f"{C.dim('อย่าเพิ่งสรุปว่าบัญชีเหล่านี้เป็นคนเดียวกัน')}")
                print(f"  {C.yellow(x['label'])} ({x['scope_label']}): {x['message']}")
                for v in x["values"][:6]:
                    print(f"      {v['source']}: {v['value']}")
            if ev.get("plan"):
                print(f"\n{C.bold('Next searches')} {C.dim('(วางแผนจากหลักฐานที่เจอ)')}:")
                for st in ev["plan"][:8]:
                    print(f"  {st['n']}. [{st['priority']}] {st['title']}\n      {C.dim(st['why'])}")
            sm = ev.get("summary") or {}
            if sm:
                print(f"\n{C.bold('Dashboard')}: {', '.join(sm['targets'])}\n"
                      f"  Accounts found  {sm['accounts_found']:>4}   Linked accounts {sm['linked_accounts']:>4}"
                      f"   Evidence {sm['evidence']:>5}\n"
                      f"  High confidence {sm['high']:>4}   Medium {sm['medium']:>4}   Low {sm['low']:>4}"
                      f"   Changes {sm['changes']:>3}")
            s = ev["stats"]
            print(f"\n{C.bold('Summary')}: {C.green(str(s['found']) + ' found')} ({s['linked']} linked), "
                  f"{s['not_found']} not found, {C.yellow(str(s['unknown']) + ' unknown')}, "
                  f"{s['manual']} to check manually, across {s['usernames']} username(s) in {ev['elapsed']}s")
            if s["candidates_found"]:
                print(C.dim(f"         {s['candidates_found']} found account(s) are candidate spellings, "
                            f"not the username you typed"))
            if s.get("cached"):
                print(C.dim(f"         {s['cached']} answer(s) reused from the cache (--no-cache to ask again)"))
            if ev.get("run_id"):
                print(C.dim(f"         saved as run #{ev['run_id']} (snapshots for change tracking)"))
                if getattr(args, "case", None) and history:
                    case = next((c for c in history.list_cases() if c["name"] == args.case), None)
                    cid = case["id"] if case else history.create_case(args.case)
                    history.update_case(cid, add_run=ev["run_id"])
                    print(C.dim(f"         added to case #{cid} {args.case}"))

    results = [r.to_dict() for r in searcher.results]
    formats = _formats(args.format)
    if formats:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        base = "_".join(args.usernames)[:60]
        meta = {"usernames": args.usernames, "date": datetime.now().strftime("%Y-%m-%d %H:%M"), "sites": total,
                "identity": searcher.identity, "connections": searcher.connections, "domains": searcher.domains,
                "queries": list(searcher.queries.values()), "graph": searcher.graph, "clusters": searcher.clusters,
                "findings": searcher.findings, "timeline": searcher.timeline, "changes": searcher.changes,
                "search": searcher.search, "summary": searcher.summary, "entities": searcher.entities,
                "contradictions": searcher.contradictions, "plan": searcher.plan, "replay": searcher.replay,
                "intel": searcher.intel}
        for fmt in formats:
            if fmt not in report.ALL_FORMATS:
                print(C.red(f"unknown format: {fmt}"))
                continue
            try:
                path = report.write(fmt, results, Path(args.output) / f"{base}_{stamp}.{fmt}", meta)
            except RuntimeError as e:  # pdf without Chrome/Edge
                print(C.yellow(str(e)))
                continue
            print(f"{C.cyan('[✓]')} Saved {fmt.upper()} report: {path}")
    return 0 if any(r["status"] == Status.FOUND.value for r in results) else 1


async def run_self_check(args: argparse.Namespace, sites, db_path) -> int:
    from .selfcheck import self_check

    print(f"{C.cyan('[*]')} Self-checking {len(sites)} sites...\n")

    def show(o):
        mark = C.green("OK  ") if o.ok else C.red("FAIL")
        print(f"  {mark} {o.site.name}" + (f"  {C.dim(o.note)}" if o.note else ""))

    outcomes = await self_check(sites, _config(args), on_result=show)
    bad = [o for o in outcomes if not o.ok]
    print(f"\n{len(outcomes) - len(bad)}/{len(outcomes)} sites OK")
    if bad and args.disable_broken:
        everything = load_sites(db_path, include_disabled=True)
        bad_names = {o.site.name for o in bad}
        for s in everything:
            if s.name in bad_names:
                s.disabled = True
        save_sites(everything, db_path)
        print(f"Disabled {len(bad)} sites in the database.")
    return 0 if not bad else 2


async def run_scan_cli(args: argparse.Namespace) -> int:
    from .scan import EVENT_TYPES, ScanConfig, Store, get_modules, run_scan
    from .scan import report as scan_report

    try:
        modules = get_modules(args.modules.split(",") if args.modules else None)
    except ValueError as e:
        print(C.red(str(e)))
        return 1
    store = None if args.no_save else Store()
    sev_color = {"high": C.red, "medium": C.yellow, "low": C.cyan, "info": C.dim}
    scan_id = None
    printed_findings = False
    try:
        async for msg in run_scan(args.scan, modules, ScanConfig(timeout=args.timeout), store):
            t = msg["type"]
            if t == "start":
                scan_id = msg["scan_id"]
                print(f"{C.cyan('[*]')} Scanning {C.bold(msg['target'])} ({msg['target_type']}) "
                      f"with {len(msg['modules'])} modules\n")
            elif t == "event" and msg["event"]["module"] != "root":
                ev = msg["event"]
                label = EVENT_TYPES.get(ev["type"], (ev["type"],))[0]
                print(f"  {C.green('+')} {C.dim(f'{label:<22}')} {ev['data']}")
            elif t == "module_error" and args.print_all:
                print(f"  {C.yellow('!')} {msg['module']}: {msg['error']}")
            elif t == "finding":
                if not printed_findings:
                    print(f"\n{C.bold('Findings')}:")
                    printed_findings = True
                color = sev_color.get(msg["severity"], C.dim)
                print(f"  {color('[' + msg['severity'].upper() + ']')} {C.bold(msg['title'])}\n"
                      f"      {C.dim(msg['detail'][:300])}")
            elif t == "done":
                total = sum(msg["counts"].values()) - 1
                print(f"\n{C.bold('Done')}: {total} items, {msg['findings']} findings, "
                      f"{msg['errors']} module errors in {msg['elapsed']}s")
    finally:
        if store and scan_id is not None:
            formats = _formats(args.format)
            scan = store.get_scan(scan_id)
            for fmt in [f for f in formats if f in ("html", "json")]:
                path = Path(args.output) / f"scan_{scan_id}_{scan['target'].replace('@', '_at_')[:50]}.{fmt}"
                path.parent.mkdir(parents=True, exist_ok=True)
                body = scan_report.to_html(scan) if fmt == "html" else scan_report.to_json(scan)
                path.write_text(body, encoding="utf-8")
                print(f"{C.cyan('[✓]')} Saved {fmt.upper()} report: {path}")
            print(C.dim(f"Saved as scan #{scan_id} in {store.path}"))
            store.close()
    return 0


def run_workspace_cli(args: argparse.Namespace) -> int:
    """Watchlist, alerts, cases, intelligence search and replay."""
    from .history import History
    h = History()
    try:
        for t in args.watch_add or []:
            h.watch_add(t, args.watch_interval, {"depth": args.depth, "websearch": args.web_search})
            print(f"{C.green('+')} เพิ่ม {t} ใน watchlist (ตรวจทุก {args.watch_interval:g} ชั่วโมง)")
        for t in args.watch_remove or []:
            print(f"{'-' if h.watch_remove(t) else '?'} {t}")
        if args.watch_list or args.watch_add:
            for w in h.watch_list():
                print(f"  {w['target']:<24} ทุก {w['interval_hours']:g} ชม.  ตรวจล่าสุด {(w['last_run'] or '-')[:16]}  "
                      f"ครั้งถัดไป {(w['next_run'] or '-')[:16]}  แจ้งเตือนใหม่ {w['unseen']}")
        if args.alerts:
            items = h.alerts(unseen_only=True)
            if not items:
                print("ไม่มีแจ้งเตือนใหม่")
            for a in items:
                print(f"{C.yellow('[!]')} {C.bold(a['target'])} {C.dim(a['created'][:16])}")
                _print_changes(a["changes"])
            h.mark_alerts_seen()
        if args.cases:
            for c in h.list_cases():
                print(f"#{c['id']:<4} {c['name']:<30} {', '.join(c['targets'])}  ({c['runs']} runs, {c['status']})")
        if args.intel:
            res = h.intel_search(args.intel)
            for kind, rows in res.items():
                if not rows:
                    continue
                print(C.bold(f"{kind} ({len(rows)})"))
                for r in rows[:15]:
                    label = {"accounts": lambda x: f"{x['site']} @{x['username']}  {x['url']}",
                             "usernames": lambda x: f"@{x['username']}  {x['accounts']} บัญชี  {(x['first_seen'] or '')[:10]}",
                             "domains": lambda x: f"{x['domain']}  {'personal ' if x['personal'] else ''}{', '.join(x['emails'])}",
                             "emails": lambda x: f"{x['email']}  จาก {', '.join(x['sources'][:3])}",
                             "urls": lambda x: f"{x['url']}  พบ {len(x['found_by'])} ครั้ง",
                             "relationships": lambda x: f"{x['src']} → {x['dst']} ({x['kind']})"}[kind](r)
                    print(f"  {label}")
        if args.replay:
            run = h.get_run(args.replay)
            if not run or not run.get("payload"):
                print(C.red(f"ไม่พบข้อมูลของ run #{args.replay}"))
                return 1
            for x in run["payload"]["done"].get("replay", []):
                print(f"  {x['t'][11:19]} +{x['s']:>5}s  {C.bold(x['action'])}  {x['detail']}")
    finally:
        h.close()
    return 0


def _load_results(path: str) -> list[dict]:
    """Load search results from a JSON file (list or dict with 'results')."""
    import json
    p = Path(path)
    if not p.exists():
        print(C.red(f"File not found: {path}"))
        return []
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "results" in data:
        return data["results"]
    return []


def run_v3_cli(args: argparse.Namespace) -> int:
    """Handle v3 OSINT tool commands."""
    if args.dorks:
        return _cmd_dorks(args)
    if args.deepsearch:
        return _cmd_deepsearch(args)
    if args.iocs:
        return _cmd_iocs(args)
    if args.stix:
        return _cmd_stix(args)
    if args.misp:
        return _cmd_misp(args)
    if args.maltego:
        return _cmd_maltego(args)
    if args.privacy:
        return _cmd_privacy(args)
    if args.remediation:
        return _cmd_remediation(args)
    if args.forensics:
        return _cmd_forensics(args)
    if args.behavior:
        return _cmd_behavior(args)
    if args.auto_investigate:
        return _cmd_auto_investigate(args)
    if args.playbooks:
        return _cmd_playbooks(args)
    if args.playbook:
        return _cmd_playbook_detail(args)
    if args.archive:
        return _cmd_archive(args)
    if args.infra:
        return _cmd_infra(args)
    if args.graph:
        return _cmd_graph(args)
    if args.notes:
        return _cmd_notes(args)
    if args.annotations:
        return _cmd_annotations(args)
    if args.custody:
        return _cmd_custody(args)
    if args.schedules:
        return _cmd_schedules(args)
    if args.feeds:
        return _cmd_feeds(args)
    return 0


def _cmd_dorks(args: argparse.Namespace) -> int:
    """Generate Google dorks for a target."""
    from .deepsearch import build_dorks
    dorks = build_dorks(args.dorks)
    print(f"{C.cyan('[*]')} {len(dorks)} dorks for {C.bold(args.dorks)}:\n")
    for d in dorks:
        print(f"  {C.bold('[' + d.category + ']')} {d.query}")
        print(f"    {C.dim(d.description)}")
        print(f"    {C.cyan(d.url)}\n")
    return 0


def _cmd_deepsearch(args: argparse.Namespace) -> int:
    """Deep search across forums, GitHub, pastes, etc."""
    import aiohttp
    from .deepsearch import deep_search

    async def _run():
        async with aiohttp.ClientSession() as session:
            return await deep_search(session, args.deepsearch)

    print(f"{C.cyan('[*]')} Deep searching for {C.bold(args.deepsearch)}...\n")
    result = asyncio.run(_run())
    for source, items in result.items():
        if source in ("target", "query"):
            continue
        if not items:
            continue
        print(f"\n{C.bold(source)} ({len(items)}):")
        for item in items[:10]:
            if isinstance(item, dict):
                title = item.get("title", item.get("url", str(item)))
                url = item.get("url", "")
                print(f"  {C.green('+')} {title}")
                if url:
                    print(f"    {C.cyan(url)}")
    return 0


def _cmd_iocs(args: argparse.Namespace) -> int:
    """Extract IOCs from text or @file."""
    from .threatintel import extract_iocs
    text = args.iocs
    if text.startswith("@"):
        p = Path(text[1:])
        if not p.exists():
            print(C.red(f"File not found: {p}"))
            return 1
        text = p.read_text(encoding="utf-8")
    iocs = extract_iocs(text)
    if not iocs:
        print(f"{C.yellow('[!]')} No IOCs found in the text.")
        return 0
    print(f"{C.cyan('[*]')} {len(iocs)} IOC(s) found:\n")
    by_type: dict[str, list[str]] = {}
    for ioc in iocs:
        by_type.setdefault(ioc["type"], []).append(ioc["value"])
    for ioc_type, values in by_type.items():
        print(f"  {C.bold(ioc_type)} ({len(values)}):")
        for v in values:
            print(f"    {C.green(v)}")
    return 0


def _cmd_stix(args: argparse.Namespace) -> int:
    """Export results to STIX 2.1."""
    from .threatintel import write_stix
    results = _load_results(args.stix)
    if not results:
        return 1
    out = str(Path(args.output) / f"stix_{datetime.now().strftime('%Y%m%d-%H%M%S')}.json")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    write_stix(results, out)
    print(f"{C.cyan('[+]')} STIX 2.1 bundle: {out}")
    return 0


def _cmd_misp(args: argparse.Namespace) -> int:
    """Export results to MISP."""
    from .threatintel import write_misp
    results = _load_results(args.misp)
    if not results:
        return 1
    out = str(Path(args.output) / f"misp_{datetime.now().strftime('%Y%m%d-%H%M%S')}.json")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    write_misp(results, out)
    print(f"{C.cyan('[+]')} MISP event: {out}")
    return 0


def _cmd_maltego(args: argparse.Namespace) -> int:
    """Export results to Maltego XML."""
    from .threatintel import write_maltego
    results = _load_results(args.maltego)
    if not results:
        return 1
    out = str(Path(args.output) / f"maltego_{datetime.now().strftime('%Y%m%d-%H%M%S')}.graph")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    write_maltego(results, out)
    print(f"{C.cyan('[+]')} Maltego graph: {out}")
    return 0


def _cmd_privacy(args: argparse.Namespace) -> int:
    """Privacy risk assessment."""
    from .counter import assess_privacy_risk, generate_remediation_plan
    results = _load_results(args.privacy)
    if not results:
        return 1
    assessment = assess_privacy_risk(results)
    print(f"\n{C.bold('Privacy Risk Assessment')}")
    print(f"  Score: {C.bold(str(assessment.score))}/100 ({assessment.level})")
    print(f"  Exposed data types: {', '.join(assessment.exposed_data_types) if assessment.exposed_data_types else 'none'}")
    print(f"\n  {C.bold('Risk factors')}:")
    for f in assessment.factors:
        sev = C.red(f.severity) if f.severity == "high" else C.yellow(f.severity) if f.severity == "medium" else C.dim(f.severity)
        print(f"    {sev} [{f.category}] {f.description} (+{f.points} pts)")
        print(f"       {C.dim('Fix: ' + f.remediation)}")
    if assessment.recommendations:
        print(f"\n  {C.bold('Recommendations')}:")
        for r in assessment.recommendations:
            print(f"    {C.yellow('-')} {r}")
    plan = generate_remediation_plan(results)
    if plan:
        print(f"\n  {C.bold('Remediation plan')} ({len(plan)} steps):")
        for step in plan:
            print(f"    [{step.get('priority', '?')}] {step.get('issue', step.get('guide', ''))}")
            print(f"       {C.dim(step.get('action', ''))}")
    return 0


def _cmd_remediation(args: argparse.Namespace) -> int:
    """Show remediation guides."""
    from .counter import REMEDIATION_GUIDES
    print(f"\n{C.bold('Remediation Guides')} ({len(REMEDIATION_GUIDES)} platforms):\n")
    for platform, guide in REMEDIATION_GUIDES.items():
        print(f"  {C.cyan(platform)}:")
        for action, instruction in guide.items():
            print(f"    {C.bold(action)}: {instruction}")
        print()
    return 0


def _cmd_forensics(args: argparse.Namespace) -> int:
    """Forensic analysis of an image URL."""
    import aiohttp
    from .forensics import analyze_avatar

    async def _run():
        async with aiohttp.ClientSession() as session:
            return await analyze_avatar(session, args.forensics)

    print(f"{C.cyan('[*]')} Forensic analysis of {args.forensics}...\n")
    result = asyncio.run(_run())
    if result.get("error"):
        print(f"  {C.red('Error:')} {result['error']}")
        return 1
    for key, val in result.items():
        if key == "url":
            continue
        if isinstance(val, dict):
            print(f"  {C.bold(key)}:")
            for k, v in val.items():
                if isinstance(v, list):
                    print(f"    {k}: {len(v)} items")
                else:
                    print(f"    {k}: {v}")
        else:
            print(f"  {C.bold(key)}: {val}")
    return 0


def _cmd_behavior(args: argparse.Namespace) -> int:
    """Behavioral analysis from search results."""
    from .behavior import build_behavioral_profile
    results = _load_results(args.behavior)
    if not results:
        return 1
    texts = []
    timestamps = []
    for r in results:
        if r.get("status") != "found":
            continue
        info = r.get("info", {})
        bio = info.get("bio", "")
        if bio:
            texts.append(bio)
        created = info.get("created", "")
        if created:
            timestamps.append(created)
    if not texts:
        print(f"{C.yellow('[!]')} No text content found in results to analyze.")
        return 0
    profile = build_behavioral_profile(texts, timestamps)
    print(f"\n{C.bold('Behavioral Profile')}\n")
    for key, val in profile.items():
        if isinstance(val, dict):
            print(f"  {C.bold(key)}:")
            for k, v in val.items():
                if isinstance(v, list):
                    print(f"    {k}: {', '.join(str(x) for x in v[:10])}")
                else:
                    print(f"    {k}: {v}")
        elif isinstance(val, list):
            print(f"  {C.bold(key)}: {len(val)} items")
        else:
            print(f"  {C.bold(key)}: {val}")
    return 0


def _cmd_auto_investigate(args: argparse.Namespace) -> int:
    """Auto-investigation planner."""
    from .realtime import AutoInvestigator
    results = _load_results(args.auto_investigate)
    if not results:
        return 1
    ai = AutoInvestigator()
    steps = ai.plan(results)
    print(f"\n{C.bold('Auto-Investigation Plan')} ({len(steps)} steps):\n")
    for i, step in enumerate(steps, 1):
        prio = C.red(str(step.priority)) if step.priority <= 3 else C.yellow(str(step.priority)) if step.priority <= 6 else C.dim(str(step.priority))
        print(f"  {C.bold(str(i) + '.')} [P{prio}] {step.action}")
        print(f"     target: {C.cyan(step.target)}")
        print(f"     {C.dim(step.reason)}")
    return 0


def _cmd_playbooks(args: argparse.Namespace) -> int:
    """List investigation playbooks."""
    from .casemgmt import PLAYBOOKS
    print(f"\n{C.bold('Investigation Playbooks')} ({len(PLAYBOOKS)}):\n")
    for key, pb in PLAYBOOKS.items():
        print(f"  {C.cyan(key):<22} {C.bold(pb.name)}")
        print(f"  {'':22} {C.dim(pb.description[:80])}")
        print(f"  {'':22} {C.dim(str(len(pb.steps)) + ' steps')}\n")
    return 0


def _cmd_playbook_detail(args: argparse.Namespace) -> int:
    """Show a specific playbook."""
    from .casemgmt import PLAYBOOKS
    pb = PLAYBOOKS.get(args.playbook)
    if not pb:
        print(C.red(f"Unknown playbook: {args.playbook}"))
        print(f"Available: {', '.join(PLAYBOOKS.keys())}")
        return 1
    print(f"\n{C.bold(pb.name)} ({pb.category})")
    print(f"  {C.dim(pb.description)}\n")
    for step in pb.steps:
        print(f"  {C.bold(str(step.step) + '.')} {step.title}")
        print(f"     {step.description}")
        if step.tools:
            print(f"     {C.dim('Tools: ' + ', '.join(step.tools))}")
        if step.expected_output:
            print(f"     {C.dim('Expected: ' + step.expected_output)}")
        print()
    if pb.legal_notes:
        print(f"  {C.yellow('! Legal:')} {pb.legal_notes}")
    return 0


def _cmd_archive(args: argparse.Namespace) -> int:
    """Check archives for a URL."""
    import aiohttp
    from .archive import check_archives, detect_deleted_content

    async def _run():
        async with aiohttp.ClientSession() as session:
            return await check_archives(session, args.archive)

    print(f"{C.cyan('[*]')} Checking archives for {args.archive}...\n")
    result = asyncio.run(_run())
    wb = result.wayback
    if wb.snapshots:
        print(f"  {C.green('[+]')} Wayback Machine: {len(wb.snapshots)} snapshots")
        for s in wb.snapshots[:5]:
            print(f"    {s.timestamp} {C.cyan(s.url)}")
    else:
        print(f"  {C.yellow('[!]')} Wayback Machine: no snapshots")
    if result.archive_today:
        print(f"  {C.green('[+]')} archive.today: {result.archive_today}")
    if result.google_cache:
        print(f"  {C.green('[+]')} Google Cache: {result.google_cache}")
    deletion = detect_deleted_content(wb.snapshots)
    if deletion.get("deleted"):
        print(f"\n  {C.red('! Deleted content detected:')} {deletion['reason']}")
    return 0


def _cmd_infra(args: argparse.Namespace) -> int:
    """Infrastructure intelligence scan."""
    import aiohttp
    from .infra_intel import infra_scan

    async def _run():
        async with aiohttp.ClientSession() as session:
            return await infra_scan(session, args.infra)

    print(f"{C.cyan('[*]')} Infrastructure scan of {C.bold(args.infra)}...\n")
    result = asyncio.run(_run())
    for key, val in result.items():
        if isinstance(val, list):
            print(f"  {C.bold(key)} ({len(val)}):")
            for item in val[:10]:
                if isinstance(item, dict):
                    print(f"    {C.green('+')} {item}")
                else:
                    print(f"    {C.green('+')} {item}")
        elif isinstance(val, dict):
            print(f"  {C.bold(key)}:")
            for k, v in val.items():
                print(f"    {k}: {v}")
        else:
            print(f"  {C.bold(key)}: {val}")
    return 0


def _cmd_graph(args: argparse.Namespace) -> int:
    """Generate network graph data."""
    import json
    from .viz import build_network_graph
    results = _load_results(args.graph)
    if not results:
        return 1
    graph = build_network_graph(results)
    out = str(Path(args.output) / f"graph_{datetime.now().strftime('%Y%m%d-%H%M%S')}.json")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")
    n_nodes = len(graph.get("nodes", []))
    n_links = len(graph.get("links", []))
    print(f"{C.cyan('[+]')} Network graph: {out}")
    print(f"  {n_nodes} nodes, {n_links} edges")
    return 0


def _cmd_notes(args: argparse.Namespace) -> int:
    """Interactive case notes management."""
    from .casemgmt import CaseNotes
    notes = CaseNotes()
    case_id = input(f"  {C.bold('Case ID')} (Enter = default): ").strip() or "default"
    while True:
        existing = notes.get_notes(case_id)
        print(f"\n{C.bold(f'Notes for case {case_id}')} ({len(existing)}):\n")
        for n in existing:
            pin = C.yellow("* ") if n.get("pinned") else "  "
            print(f"  {pin}#{n['id']} {n['author']}: {n['content'][:80]}  {C.dim(n.get('created', '')[:16])}")
        print(f"\n  {C.bold('Commands')}: add | search <query> | pin <id> | del <id> | back")
        cmd = input(f"  {C.bold('>')} ").strip()
        if not cmd or cmd in ("back", "exit", "0"):
            break
        elif cmd == "add":
            author = input("    author: ").strip() or "anonymous"
            content = input("    note: ").strip()
            if content:
                notes.add(case_id, author, content)
                print(f"  {C.green('+')} added")
        elif cmd.startswith("search "):
            q = cmd[7:]
            found = notes.search(case_id, q)
            for n in found:
                print(f"  #{n['id']} {n['author']}: {n['content'][:80]}")
        elif cmd.startswith("pin "):
            try:
                notes.pin(int(cmd[4:]))
                print(f"  {C.green('+')} pinned")
            except ValueError:
                print(C.red("  invalid ID"))
        elif cmd.startswith("del "):
            try:
                notes.delete(int(cmd[4:]))
                print(f"  {C.green('+')} deleted")
            except ValueError:
                print(C.red("  invalid ID"))
    return 0


def _cmd_annotations(args: argparse.Namespace) -> int:
    """Interactive annotations management."""
    from .casemgmt import ResultAnnotations
    ann = ResultAnnotations()
    while True:
        tags = ann.available_tags()
        print(f"\n{C.bold('Result Annotations')}\n")
        print(f"  {C.bold('Available tags')}:")
        for t in tags:
            print(f"    {C.cyan(t['name'])}: {t['description']}")
        print(f"\n  {C.bold('Commands')}: tag <result_key> <tag> <author> | view <result_key> | back")
        cmd = input(f"  {C.bold('>')} ").strip()
        if not cmd or cmd in ("back", "exit", "0"):
            break
        elif cmd.startswith("tag "):
            parts = cmd[4:].split()
            if len(parts) >= 3:
                ann.annotate(parts[0], parts[2], parts[1])
                print(f"  {C.green('+')} annotated")
            else:
                print(C.red("  usage: tag <result_key> <tag> <author>"))
        elif cmd.startswith("view "):
            key = cmd[5:]
            for a in ann.get_annotations(key):
                print(f"  {a['author']}: {a.get('tag', '')} - {a.get('note', '')}")
    return 0


def _cmd_custody(args: argparse.Namespace) -> int:
    """Show chain of custody log."""
    from .casemgmt import ChainOfCustody
    coc = ChainOfCustody()
    case_id = input(f"  {C.bold('Case ID')} (Enter = default): ").strip() or "default"
    chain = coc.get_chain(case_id)
    if not chain:
        print(f"  {C.yellow('[!]')} No custody records for case {case_id}")
        return 0
    print(f"\n{C.bold(f'Chain of Custody for case {case_id}')} ({len(chain)} entries):\n")
    for entry in chain:
        print(f"  {entry.get('timestamp', '')[:19]}  {C.bold(entry.get('actor', ''))}")
        print(f"    action: {entry.get('action', '')}")
        print(f"    detail: {entry.get('detail', '')}")
        print()
    verification = coc.verify_chain(case_id)
    ok = C.green("OK") if verification.get("valid") else C.red("FAIL")
    print(f"  {ok} Chain integrity: {verification.get('status', 'unknown')}")
    return 0


def _cmd_schedules(args: argparse.Namespace) -> int:
    """List scheduled scans."""
    from .realtime import scan_scheduler
    schedules = scan_scheduler._schedules
    if not schedules:
        print(f"  {C.yellow('[!]')} No scheduled scans.")
        print(f"  Use the web API or --auto-investigate to create schedules.")
        return 0
    print(f"\n{C.bold('Scheduled Scans')} ({len(schedules)}):\n")
    for s in schedules:
        last = s.last_run.strftime("%Y-%m-%d %H:%M") if s.last_run else "-"
        print(f"  {C.bold(s.target):<24} every {s.interval_hours}h  email: {s.email or '-'}  last: {last}")
    return 0


def _cmd_feeds(args: argparse.Namespace) -> int:
    """Interactive RSS/Atom feed monitor."""
    import aiohttp
    from .realtime import FeedMonitor, DEFAULT_FEEDS

    target = input(f"  {C.bold('Keyword to monitor')}: ").strip()
    if not target:
        return 0
    print(f"\n  {C.dim('Monitoring ' + str(len(DEFAULT_FEEDS)) + ' feeds for \"' + target + '\"...')}\n")

    async def _run():
        async with aiohttp.ClientSession() as session:
            results = []
            for feed_url in DEFAULT_FEEDS:
                fm = FeedMonitor(feed_url=feed_url, target=target)
                items = await fm.check(session)
                if items:
                    results.extend(items)
            return results

    items = asyncio.run(_run())
    if not items:
        print(f"  {C.yellow('[!]')} No mentions found.")
        return 0
    print(f"  {C.green('[+]')} {len(items)} mention(s) found:\n")
    for item in items:
        print(f"  {C.bold(item.title)}")
        print(f"    {C.cyan(item.link)}")
        print(f"    {C.dim(item.published)}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Thai text on Windows consoles
    args = build_parser().parse_args(argv)
    C.on = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    if os.name == "nt" and C.on:
        os.system("")  # enables ANSI escape handling in Windows terminals

    all_sites = load_sites(args.db)
    split = lambda v: [x.strip() for x in v.split(",") if x.strip()] if v else None
    sites = filter_sites(all_sites, args.sites, split(args.tags), split(args.exclude_tags))

    if args.list_sites:
        for s in sites:
            print(f"{s.name:<18} {s.main:<38} {', '.join(s.tags)}")
        print(f"\n{len(sites)} sites. Tags: {', '.join(all_tags(all_sites))}")
        return 0

    if args.list_modules:
        from .scan import get_modules
        from .scan.modules import PLUGIN_ERRORS, plugin_dirs
        for m in sorted(get_modules(), key=lambda m: (m.group, m.name)):
            plugin = getattr(m, "plugin", None)
            print(f"{m.group + '/' + m.name:<24} {m.title}" + (C.dim(f"  (plugin: {plugin})") if plugin else "") +
                  f"\n{'':<24} {m.description}\n{'':<24} watches: {', '.join(m.watches)}\n")
        print(C.dim("plugin folders: " + ", ".join(str(d) for d in plugin_dirs())))
        for e in PLUGIN_ERRORS:
            print(C.red("plugin error: " + e))
        return 0

    if args.show_mutations:
        from .mutations import mutations, numbered
        for u in args.usernames:
            print(C.bold(u))
            for c in mutations(u, max(1, args.max_candidates)):
                print(f"  {c.username:<28} {C.dim(c.rule)}")
            if args.numbers and parse_range(args.numbers):
                names = [c.username for c in numbered(u, *parse_range(args.numbers))]
                print(f"  {C.dim('เติมเลข:')} {', '.join(names)}")
        return 0

    # v3 OSINT tools
    if any((args.dorks, args.deepsearch, args.iocs, args.stix, args.misp, args.maltego,
            args.privacy, args.remediation, args.forensics, args.behavior,
            args.auto_investigate, args.playbooks, args.playbook, args.archive,
            args.infra, args.graph, args.notes, args.annotations, args.custody,
            args.schedules, args.feeds)):
        return run_v3_cli(args)

    if any((args.watch_add, args.watch_remove, args.watch_list, args.alerts, args.cases, args.intel,
            args.replay)):
        return run_workspace_cli(args)

    if args.watch_run:
        from .history import History
        from .watch import run_due
        h = History()

        def show(res: dict) -> None:
            if res.get("error"):
                print(f"{C.red('[!]')} {res['target']}: {res['error']}")
            elif res["changes"]:
                print(f"{C.yellow('[Δ]')} {C.bold(res['target'])}: {len(res['changes'])} การเปลี่ยนแปลง")
                _print_changes(res["changes"])
            else:
                print(f"{C.green('[=]')} {res['target']}: ไม่มีอะไรเปลี่ยน ({res.get('found', 0)} บัญชี)")
        try:
            done = asyncio.run(run_due(h, sites, all_sites, args.usernames or None, on_result=show))
            if not done:
                print("ไม่มี target ที่ถึงเวลาตรวจ (ใช้ --watch-list ดูรายการ)")
        finally:
            h.close()
        return 0

    if args.clear_cache or args.changes or args.runs:
        from .history import History
        h = History()
        try:
            if args.clear_cache:
                print(f"cleared {h.clear_cache()} cached answers from {h.path}")
            if args.runs:
                for r in h.list_runs(args.usernames[0] if len(args.usernames) == 1 else None):
                    st = r["stats"]
                    print(f"#{r['id']:<4} {r['started'][:16].replace('T', ' ')}  {', '.join(r['usernames']):<30} "
                          f"{st.get('found', 0)} found  {r['changes']} changes")
            if args.changes:
                changes = h.changes_for(args.usernames or None)
                if not changes:
                    print("no profile changes recorded yet (search the same username again later)")
                _print_changes(changes)
        finally:
            h.close()
        return 0

    if args.history:
        from .scan import Store
        for s in Store().list_scans():
            when = datetime.fromtimestamp(s["started"]).strftime("%Y-%m-%d %H:%M")
            total = sum(s["counts"].values())
            print(f"#{s['id']:<4} {when}  {s['status']:<9} {s['target']:<30} {total} items  {s['findings']}")
        return 0

    if args.scan:
        print(C.cyan(BANNER.format(version=__version__, count=len(all_sites))))
        try:
            return asyncio.run(run_scan_cli(args))
        except KeyboardInterrupt:
            print(C.yellow("\nStopped."))
            return 130

    if args.web:
        from .web import serve
        serve(args.host, args.port, args.db, open_browser=not args.no_browser)
        return 0

    if args.self_check:
        if args.disable_broken and args.db is None:
            from .sites import DATA_FILE
            db_path = DATA_FILE
        else:
            db_path = args.db
        sites_to_check = filter_sites(load_sites(args.db, include_disabled=True), args.sites,
                                      split(args.tags), split(args.exclude_tags))
        return asyncio.run(run_self_check(args, sites_to_check, db_path))

    if not args.usernames:
        from .menu import can_run, run_menu
        if args.menu or can_run():
            return run_menu(args, sites, all_sites)
        build_parser().print_help()
        return 1
    if not sites:
        print(C.red("No sites match your filters. Try --list-sites."))
        return 1

    print(C.cyan(BANNER.format(version=__version__, count=len(sites))))
    try:
        return asyncio.run(run_search(args, sites, all_sites))
    except KeyboardInterrupt:
        print(C.yellow("\nStopped."))
        return 130


if __name__ == "__main__":
    sys.exit(main())
