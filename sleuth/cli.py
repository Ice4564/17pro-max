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
    g.add_argument("-v", "--variants", action="store_true", help="also try similar spellings (john.doe -> johndoe, john_doe)")
    g.add_argument("--no-extract", action="store_true", help="don't parse profile info")
    g.add_argument("--timeout", type=float, default=12, help="seconds per request (default 12)")
    g.add_argument("-c", "--concurrency", type=int, default=40, help="parallel requests (default 40)")
    g.add_argument("--retries", type=int, default=1, help="retries on network errors (default 1)")
    g.add_argument("--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    g.add_argument("--tor", action="store_true", help="route through Tor (socks5://127.0.0.1:9050, needs aiohttp-socks)")

    g = p.add_argument_group("output")
    g.add_argument("-a", "--print-all", action="store_true", help="also print not-found and unknown results")
    g.add_argument("-o", "--output", metavar="DIR", default="reports", help="folder for reports (default ./reports)")
    g.add_argument("-f", "--format", default="", help="report formats, comma separated: txt,csv,json,html or 'all'")
    g.add_argument("--no-color", action="store_true", help="disable colours")

    g = p.add_argument_group("scan (SpiderFoot-style: domain, IP, email or username)")
    g.add_argument("--scan", metavar="TARGET", help="full OSINT scan of a domain, IP, email or username")
    g.add_argument("-m", "--modules", help="scan modules to use, comma separated (default: all)")
    g.add_argument("--list-modules", action="store_true", help="list scan modules, then exit")
    g.add_argument("--history", action="store_true", help="show saved scans, then exit")
    g.add_argument("--no-save", action="store_true", help="don't save the scan to the history database")

    g = p.add_argument_group("tools")
    g.add_argument("--web", action="store_true", help="start the web interface")
    g.add_argument("--host", default="127.0.0.1", help="web host (default 127.0.0.1)")
    g.add_argument("--port", type=int, default=8787, help="web port (default 8787)")
    g.add_argument("--no-browser", action="store_true", help="don't open the browser automatically with --web")
    g.add_argument("--self-check", action="store_true", help="test every site's detection rule against the live site")
    g.add_argument("--disable-broken", action="store_true", help="with --self-check: mark failing sites disabled in the DB")
    g.add_argument("--version", action="version", version=f"sleuth {__version__}")
    return p


def _config(args: argparse.Namespace) -> SearchConfig:
    proxy = "socks5://127.0.0.1:9050" if args.tor else args.proxy
    return SearchConfig(timeout=args.timeout, concurrency=max(1, args.concurrency), retries=max(0, args.retries),
                        proxy=proxy, extract=not args.no_extract, depth=max(0, args.depth),
                        max_usernames=max(0, args.max_new), variants=args.variants)


def _print_result(r: dict, print_all: bool) -> None:
    st = r["status"]
    if st == "found":
        tag = C.cyan("[=]") if r.get("linked") else C.green("[+]")
        print(f"  {tag} {C.bold(r['site'])}: {r['url']}")
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


CONF_LABEL = {"high": "สูง", "medium": "กลาง", "low": "ต่ำ"}


async def run_search(args: argparse.Namespace, sites, all_sites) -> int:
    searcher = Searcher(sites, _config(args), all_sites=all_sites)
    done_count: dict[str, int] = {}
    total = len(sites)
    is_tty = sys.stdout.isatty()

    async for ev in searcher.run(args.usernames):
        if ev["type"] == "start":
            depth = f" (depth {ev['depth']}, from {ev['source']})" if ev["source"] else ""
            print(f"\n{C.cyan('[*]')} Checking {C.bold(ev['username'])} on {ev['total']} sites{depth}")
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
            s = ev["stats"]
            print(f"\n{C.bold('Summary')}: {C.green(str(s['found']) + ' found')} ({s['linked']} linked), "
                  f"{s['not_found']} not found, {C.yellow(str(s['unknown']) + ' unknown')}, "
                  f"{s['manual']} to check manually, across {s['usernames']} username(s) in {ev['elapsed']}s")

    results = [r.to_dict() for r in searcher.results]
    formats = report.FORMATS if args.format == "all" else [f.strip() for f in args.format.split(",") if f.strip()]
    if formats:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        base = "_".join(args.usernames)[:60]
        meta = {"usernames": args.usernames, "date": datetime.now().strftime("%Y-%m-%d %H:%M"), "sites": total,
                "identity": searcher.identity}
        for fmt in formats:
            if fmt not in report.FORMATS:
                print(C.red(f"unknown format: {fmt}"))
                continue
            path = report.write(fmt, results, Path(args.output) / f"{base}_{stamp}.{fmt}", meta)
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
            formats = report.FORMATS if args.format == "all" else [f.strip() for f in args.format.split(",") if f.strip()]
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
        for m in get_modules():
            print(f"{m.name:<14} {m.title}\n{'':<14} {m.description}\n"
                  f"{'':<14} watches: {', '.join(m.watches)}\n")
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
