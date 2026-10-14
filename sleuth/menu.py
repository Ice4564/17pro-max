"""Interactive numbered menu, shown when ``sleuth`` runs with no arguments."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
import unicodedata

from . import __version__
from .cli import C, run_scan_cli, run_search, run_v3_cli

LOGO = [
    r"   ____  _            _   _     ",
    r"  / ___|| | ___ _   _| |_| |__  ",
    r"  \___ \| |/ _ \ | | | __| '_ \ ",
    r"   ___) | |  __/ |_| | |_| | | |",
    r"  |____/|_|\___|\__,_|\__|_| |_|",
]
GRADIENT = ("38;5;51", "38;5;45", "38;5;39", "38;5;33", "38;5;27")  # cyan -> blue
ACCENT = "38;5;45"
BOX_WIDTH = 76

MENU = [
    ("1", "เว็บ", "เปิดหน้าเว็บ Web UI ใช้งานง่ายที่สุด"),
    ("2", "คน", "ค้น username บนเกือบ 100 เว็บ + ตามลิงก์ต่อ"),
    ("3", "โดเมน", "สแกนโดเมน: DNS, ซับโดเมน, SSL, พอร์ต"),
    ("4", "อีเมล", "สแกนอีเมล: Gravatar, MX, โดเมน, username"),
    ("5", "ค้นลึก", "Deep Search: Google dorks, Reddit, GitHub, paste"),
    ("6", "อาร์ไคฟ์", "ตรวจอาร์ไคฟ์: Wayback, archive.today, ลบแล้ว?"),
    ("7", "โครงสร้าง", "Infra: CT logs, DNS, ซับโดเมน, WHOIS, Shodan"),
    ("8", "ฟอเรนซิก", "วิเคราะห์รูป: steganography, ELA, ใบหน้า, deepfake"),
    ("9", "พฤติกรรม", "วิเคราะห์พฤติกรรม: timezone, ตัวเขียน, emoji, สนใจ"),
    ("10", "ภัยคุกคาม", "Threat Intel: IOC, STIX, MISP, Maltego export"),
    ("11", "ความเป็นส่วนตัว", "ประเมินความเสี่ยง + คู่มือลดการรั่วไหล"),
    ("12", "เคส", "Case mgmt: playbooks, notes, custody, annotations"),
    ("13", "กราฟ", "สร้าง network graph จากผลค้น (D3.js)"),
    ("14", "อัตโนมัติ", "Auto-investigate + scheduled scans + RSS feeds"),
]

_ANSI = re.compile(r"\033\[[0-9;]*m")


# ---- drawing ---------------------------------------------------------------
def width(text: str) -> int:
    """Columns ``text`` takes in a terminal (Thai marks above/below take none)."""
    n = 0
    for ch in _ANSI.sub("", text):
        if unicodedata.category(ch) in ("Mn", "Me", "Cf"):
            continue
        n += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return n


def pad(text: str, cols: int) -> str:
    return text + " " * max(0, cols - width(text))


def paint(code: str, text: str) -> str:
    return C.wrap(code, text)


def box(lines: list[str], title: str = "") -> str:
    inner = BOX_WIDTH - 2
    edge = lambda s: paint(ACCENT, s)  # noqa: E731
    if title:
        label = f" {title} "
        top = edge("╭─") + C.bold(label) + edge("─" * max(0, inner - 1 - width(label)) + "╮")
    else:
        top = edge("╭" + "─" * inner + "╮")
    body = [edge("│") + pad("  " + line, inner) + edge("│") for line in lines]
    return "\n".join(["  " + top, *("  " + b for b in body), "  " + edge("╰" + "─" * inner + "╯")])


def clear() -> None:
    if C.on:
        print("\033[2J\033[H", end="")


def header(site_count: int, module_count: int) -> None:
    clear()
    print()
    for line, code in zip(LOGO, GRADIENT):
        print(paint(code, line) if C.on else line)
    print(C.dim(f"  v{__version__} · {site_count} เว็บ · {module_count} modules · OSINT จากข้อมูลสาธารณะ"))
    print()


SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
BAR_WIDTH = 34


def _key_pressed() -> bool:
    """True (and the key is consumed) if the user pressed a key: skips the intro."""
    try:
        import msvcrt
    except ImportError:  # not Windows: no skip, the intro is short anyway
        return False
    hit = False
    while msvcrt.kbhit():
        msvcrt.getwch()
        hit = True
    return hit


def _online() -> str:
    import socket
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=1.5).close()
        return "ออนไลน์"
    except OSError:
        return "ออฟไลน์ (ค้นได้เฉพาะเมื่อต่อเน็ต)"


def _bar(fraction: float) -> str:
    filled = round(BAR_WIDTH * fraction)
    cells = "".join(paint(GRADIENT[min(len(GRADIENT) - 1, i * len(GRADIENT) // BAR_WIDTH)], "█")
                    for i in range(filled))
    return cells + C.dim("░" * (BAR_WIDTH - filled)) + f" {C.bold(f'{round(fraction * 100):>3}%')}"


def boot(site_count: int, module_count: int) -> None:
    """Startup animation: logo reveal, then each engine "loading" with a progress bar.

    Takes about 4 seconds; any key (Windows) or Ctrl+C skips straight to the menu.
    """
    import time

    if not C.on or not sys.stdout.isatty():
        return
    stages = [
        ("โหลดฐานข้อมูลเว็บ", f"{site_count} เว็บ", 0.45),
        ("โหลด scan modules", f"{module_count} modules", 0.4),
        ("เตรียม Candidate engine", "sky123 -> sky_123, sky.123, 123sky", 0.35),
        ("เตรียม Verification", "title . redirect . canonical . username", 0.35),
        ("เตรียม Correlation engine", "username . ชื่อ . bio . เว็บไซต์ . รูป", 0.4),
        ("สร้าง Evidence graph", "username -> บัญชี -> โดเมน", 0.3),
        ("โหลด v3 OSINT tools", "dorks . forensics . behavior . threat intel", 0.35),
        ("โหลด Case management", "playbooks . notes . custody . annotations", 0.3),
        ("ตรวจการเชื่อมต่อ", None, 0.35),
    ]
    total = sum(s[2] for s in stages)
    frame = 0
    print("\033[?25l", end="")  # hide cursor
    try:
        clear()
        print()
        for line, code in zip(LOGO, GRADIENT):
            print(paint(code, line), flush=True)
            time.sleep(0.09)
        tagline = f"  v{__version__} · username OSINT · Candidate → Verification → Correlation"
        for ch in tagline:
            print(C.dim(ch), end="", flush=True)
            time.sleep(0.008)
        print("\n")
        print(C.dim("  กดปุ่มใดก็ได้เพื่อข้าม\n"))

        done = 0.0
        for label, detail, seconds in stages:
            start = time.perf_counter()
            if detail is None:  # a real check, done in the background while the spinner runs
                import concurrent.futures
                pool = concurrent.futures.ThreadPoolExecutor(1)
                job = pool.submit(_online)
            while (elapsed := time.perf_counter() - start) < seconds or (detail is None and not job.done()):
                if _key_pressed():
                    raise KeyboardInterrupt
                part = min(1.0, elapsed / seconds)
                spin = paint(ACCENT, SPINNER[frame % len(SPINNER)])
                print(f"\r\033[K  {spin} {pad(label, 26)} {_bar((done + part * seconds) / total)}", end="", flush=True)
                frame += 1
                time.sleep(0.05)
            if detail is None:
                detail = job.result()
                pool.shutdown(wait=False)
            done += seconds
            print(f"\r\033[K  {C.green('✓')} {pad(label, 26)} {C.dim(detail)}", flush=True)
        print(f"\n  {paint(ACCENT, '●')} {pad('พร้อมใช้งาน', 26)} {_bar(1.0)}", flush=True)
        time.sleep(0.6)
    except KeyboardInterrupt:
        pass
    finally:
        print("\033[?25h", end="", flush=True)  # show cursor


def menu_screen() -> None:
    lines = [""]
    for key, name, desc in MENU:
        lines.append(f"{paint(ACCENT, '[' + key + ']')}  {C.bold(pad(name, 7))}{C.dim(desc)}")
    lines += ["", f"{C.dim('[0]')}  {C.dim('ออก')}", ""]
    print(box(lines, "เมนูหลัก"))
    print()


# ---- input -----------------------------------------------------------------
def ask(prompt: str, default: str = "") -> str:
    hint = C.dim(f" [{default}]") if default else ""
    value = input(f"  {paint(ACCENT, '›')} {prompt}{hint}: ").strip()
    return value or default


def ask_yes(prompt: str, default: bool) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        v = input(f"  {paint(ACCENT, '›')} {prompt} {C.dim('[' + hint + ']')}: ").strip().lower()
        if not v:
            return default
        if v in ("y", "yes", "ใช่", "ช"):
            return True
        if v in ("n", "no", "ไม่", "ม"):
            return False
        print(C.yellow("    ตอบ y หรือ n"))


def ask_target(prompt: str, kind: str, example: str) -> str | None:
    from .scan import detect_target

    while True:
        raw = ask(prompt)
        if not raw:
            return None
        t, value = detect_target(raw)
        if t == kind:
            return value
        print(C.yellow(f"    ดูไม่เหมือน{ 'โดเมน' if kind == 'DOMAIN_NAME' else 'อีเมล' } ลองอีกครั้ง เช่น {example}"
                       f" (Enter ว่าง = กลับเมนู)"))


def section(title: str, note: str) -> None:
    print()
    print(box([C.dim(note)], title))
    print()


def pause() -> None:
    print()
    input(C.dim("  กด Enter เพื่อกลับเมนู..."))


# ---- actions ---------------------------------------------------------------
def do_web(args: argparse.Namespace) -> None:
    from .web import serve

    section("เว็บ", "เปิดเบราว์เซอร์ให้อัตโนมัติ · กด Ctrl+C เพื่อปิดแล้วกลับเมนู")
    try:
        serve(args.host, args.port, args.db, open_browser=True)
    except KeyboardInterrupt:
        pass
    except OSError as e:
        print(C.red(f"  เปิดเซิร์ฟเวอร์ไม่ได้: {e} (พอร์ต {args.port} อาจถูกใช้อยู่)"))
    pause()


def do_person(args: argparse.Namespace, sites, all_sites) -> None:
    section("ค้นหาคน", "ใส่ username ได้หลายชื่อ คั่นด้วยช่องว่าง เช่น  sky123  torvalds")
    raw = ask("username")
    names = [u.lstrip("@") for u in raw.replace(",", " ").split() if u.strip("@")]
    if not names:
        return
    args.usernames = list(dict.fromkeys(names))
    args.variants = ask_yes("ลองชื่อใกล้เคียงด้วยไหม (sky_123, sky123_, sky123x, sky123th…)", False)
    nums = ask("เติมเลขท้ายชื่อด้วยไหม เช่น 1-10 (Enter = ไม่เติม)", "")
    args.numbers = nums or None
    args.web_search = ask_yes("ค้นใน DuckDuckGo/Bing ด้วยไหม", True)
    depth = ask("ค้นต่อจากบัญชีที่เจอกี่ชั้น 0-2", "1")
    args.depth = int(depth) if depth in ("0", "1", "2") else 1
    args.format = "html,md,json" if ask_yes("บันทึกรายงาน HTML + Markdown + JSON", True) else ""
    print()
    try:
        asyncio.run(run_search(args, sites, all_sites))
    except KeyboardInterrupt:
        print(C.yellow("\n  หยุดแล้ว"))
    pause()


def do_scan(args: argparse.Namespace, kind: str) -> None:
    if kind == "DOMAIN_NAME":
        section("สแกนโดเมน", "เช่น  example.com  (ใส่ URL เต็มก็ได้ ระบบตัดให้เอง)")
        target = ask_target("โดเมน", kind, "example.com")
    else:
        section("สแกนอีเมล", "เช่น  name@example.com")
        target = ask_target("อีเมล", kind, "name@example.com")
    if not target:
        return
    args.scan = target
    args.format = "html,json" if ask_yes("บันทึกรายงาน HTML + JSON", True) else ""
    print()
    try:
        asyncio.run(run_scan_cli(args))
    except KeyboardInterrupt:
        print(C.yellow("\n  หยุดแล้ว"))
    pause()


def do_v3(args: argparse.Namespace, flag: str, title: str, note: str, prompt: str = "") -> None:
    """Generic v3 tool launcher: sets the appropriate flag and calls run_v3_cli."""
    section(title, note)
    if prompt:
        val = ask(prompt)
        if not val:
            return
        setattr(args, flag, val)
    else:
        setattr(args, flag, True)
    try:
        run_v3_cli(args)
    except KeyboardInterrupt:
        print(C.yellow("\n  หยุดแล้ว"))
    except Exception as e:
        print(C.red(f"  Error: {e}"))
    pause()


def do_deepsearch(args: argparse.Namespace) -> None:
    do_v3(args, "deepsearch", "ค้นลึก (Deep Search)",
          "ค้น username/email บน Reddit, 4chan, GitHub, GitLab, paste, academic",
          "target (username, email, หรือชื่อ)")


def do_archive(args: argparse.Namespace) -> None:
    do_v3(args, "archive", "ตรวจอาร์ไคฟ์ (Archive)",
          "ตรวจ Wayback Machine, archive.today, Google Cache ว่าเคยมีหน้านี้หรือไม่",
          "URL ที่ต้องการตรวจ")


def do_infra(args: argparse.Namespace) -> None:
    do_v3(args, "infra", "โครงสร้างพื้นฐาน (Infrastructure Intel)",
          "CT logs, DNS, ซับโดเมน, WHOIS, IP geolocation, Shodan",
          "โดเมน เช่น example.com")


def do_forensics(args: argparse.Namespace) -> None:
    do_v3(args, "forensics", "ฟอเรนซิก (Forensics)",
          "วิเคราะห์รูป: LSB steganography, Error Level Analysis, ใบหน้า, deepfake indicators",
          "URL ของรูปภาพ")


def do_behavior(args: argparse.Namespace) -> None:
    do_v3(args, "behavior", "พฤติกรรม (Behavioral Analysis)",
          "วิเคราะห์ timezone, ตัวเขียน (stylometry), emoji fingerprint, ความสนใจ",
          "ไฟล์ JSON ผลค้น (เช่น reports/user_*.json)")


def do_threatintel(args: argparse.Namespace) -> None:
    """Threat intelligence: IOC extraction + STIX/MISP/Maltego export."""
    section("ภัยคุกคาม (Threat Intel)", "สกัด IOC, export STIX/MISP/Maltego จากผลค้น")
    print(f"  {C.bold('เลือก:')}")
    print(f"    [1] สกัด IOC จากข้อความ")
    print(f"    [2] Export STIX 2.1 จาก JSON")
    print(f"    [3] Export MISP จาก JSON")
    print(f"    [4] Export Maltego จาก JSON")
    sub = ask("เลือก 1-4", "1")
    if sub == "1":
        text = ask("ข้อความหรือ @ไฟล์")
        if text:
            args.iocs = text
            run_v3_cli(args)
    elif sub in ("2", "3", "4"):
        fpath = ask("ไฟล์ JSON ผลค้น")
        if fpath:
            flag = {"2": "stix", "3": "misp", "4": "maltego"}[sub]
            setattr(args, flag, fpath)
            run_v3_cli(args)
    pause()


def do_privacy(args: argparse.Namespace) -> None:
    """Privacy risk assessment + remediation."""
    section("ความเป็นส่วนตัว (Privacy)", "ประเมินความเสี่ยงจากข้อมูลที่รั่วไหล + คู่มือลดการรั่วไหล")
    print(f"  {C.bold('เลือก:')}")
    print(f"    [1] ประเมินความเสี่ยงจาก JSON")
    print(f"    [2] ดูคู่มือลดการรั่วไหลทั้งหมด")
    sub = ask("เลือก 1-2", "1")
    if sub == "1":
        fpath = ask("ไฟล์ JSON ผลค้น")
        if fpath:
            args.privacy = fpath
            run_v3_cli(args)
    elif sub == "2":
        args.remediation = True
        run_v3_cli(args)
    pause()


def do_casemgmt(args: argparse.Namespace) -> None:
    """Case management: playbooks, notes, custody, annotations."""
    section("เคสการสอบสวน (Case Management)", "playbooks, notes, chain of custody, annotations")
    print(f"  {C.bold('เลือก:')}")
    print(f"    [1] ดู playbooks ทั้งหมด")
    print(f"    [2] ดู playbook เฉพาะ")
    print(f"    [3] จัดการ case notes")
    print(f"    [4] จัดการ annotations")
    print(f"    [5] ดู chain of custody")
    sub = ask("เลือก 1-5", "1")
    if sub == "1":
        args.playbooks = True
        run_v3_cli(args)
    elif sub == "2":
        cat = ask("หมวด (missing_person, fraud, identity_theft, threat_assessment, due_diligence)")
        if cat:
            args.playbook = cat
            run_v3_cli(args)
    elif sub == "3":
        args.notes = True
        run_v3_cli(args)
    elif sub == "4":
        args.annotations = True
        run_v3_cli(args)
    elif sub == "5":
        args.custody = True
        run_v3_cli(args)
    pause()


def do_graph(args: argparse.Namespace) -> None:
    do_v3(args, "graph", "กราฟ (Network Graph)",
          "สร้าง network graph JSON จากผลค้น (เปิดด้วย Web UI หรือ D3.js)",
          "ไฟล์ JSON ผลค้น")


def do_auto(args: argparse.Namespace) -> None:
    """Auto-investigation + scheduled scans + RSS feeds."""
    section("อัตโนมัติ (Automation)", "auto-investigate, scheduled scans, RSS feed monitor")
    print(f"  {C.bold('เลือก:')}")
    print(f"    [1] Auto-investigation planner จาก JSON")
    print(f"    [2] ดู scheduled scans")
    print(f"    [3] ตรวจ RSS/Atom feeds")
    sub = ask("เลือก 1-3", "1")
    if sub == "1":
        fpath = ask("ไฟล์ JSON ผลค้น")
        if fpath:
            args.auto_investigate = fpath
            run_v3_cli(args)
    elif sub == "2":
        args.schedules = True
        run_v3_cli(args)
    elif sub == "3":
        args.feeds = True
        run_v3_cli(args)
    pause()


def run_menu(args: argparse.Namespace, sites, all_sites) -> int:
    from .scan import get_modules

    module_count = len(get_modules())
    if not getattr(args, "no_intro", False):
        boot(len(all_sites), module_count)
    while True:
        header(len(all_sites), module_count)
        menu_screen()
        try:
            choice = input(f"  {C.bold('เลือก')}: ").strip()
            if choice in ("0", "q", "exit", "quit"):
                break
            if choice == "1":
                do_web(args)
            elif choice == "2":
                do_person(args, sites, all_sites)
            elif choice == "3":
                do_scan(args, "DOMAIN_NAME")
            elif choice == "4":
                do_scan(args, "EMAIL")
            elif choice == "5":
                do_deepsearch(args)
            elif choice == "6":
                do_archive(args)
            elif choice == "7":
                do_infra(args)
            elif choice == "8":
                do_forensics(args)
            elif choice == "9":
                do_behavior(args)
            elif choice == "10":
                do_threatintel(args)
            elif choice == "11":
                do_privacy(args)
            elif choice == "12":
                do_casemgmt(args)
            elif choice == "13":
                do_graph(args)
            elif choice == "14":
                do_auto(args)
            elif choice:
                input(C.yellow(f"  ไม่มีตัวเลือก \"{choice}\" กดเลข 0-14 นะ (Enter เพื่อลองใหม่)"))
        except (KeyboardInterrupt, EOFError):
            break
    print(C.dim("\n  ออกจากโปรแกรมแล้ว\n"))
    return 0


def can_run() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
