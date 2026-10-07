"""Export search results as TXT, CSV, JSON, Markdown, HTML or PDF.

The HTML report is self-contained (no scripts, no external files) and reads
like an investigator's file: a dashboard, the identities that look like one
person, every finding with its source / evidence / first seen / last checked
/ confidence, a timeline, profile changes since earlier runs, and the
evidence graph (click a node to jump to its evidence). PDF is the same page
printed by a local Chrome / Edge in headless mode.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

FORMATS = ("txt", "csv", "json", "md", "html")  # text formats render() produces
ALL_FORMATS = FORMATS + ("pdf",)  # pdf needs a local Chrome / Edge (see to_pdf)


def _found(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted((r for r in results if r["status"] == "found"),
                  key=lambda r: (r.get("depth", 0), r["username"].lower(), r["site"].lower()))


MARK = {True: "✓", False: "✗", None: "·"}
CONF_TH = {"high": "สูง", "medium": "กลาง", "low": "ต่ำ"}
KIND_TH = {"account": "บัญชี", "email": "อีเมล", "domain": "เว็บไซต์", "lead": "เบาะแส", "mention": "กล่าวถึง"}
TIMELINE_TH = {"created": "สร้างบัญชี", "archived": "archive.org", "first_seen": "พบครั้งแรก", "change": "เปลี่ยนแปลง",
               "run": "ค้นหา"}


def _day(value: str) -> str:
    return (value or "")[:16].replace("T", " ")


def _anchor(fid: str) -> str:
    return "f-" + re.sub(r"[^a-z0-9]+", "-", fid.lower()).strip("-")


def to_txt(results: list[dict[str, Any]], meta: dict[str, Any] | None = None) -> str:
    meta = meta or {}
    lines: list[str] = []
    for r in _found(results):
        mark = " (linked)" if r.get("linked") else ""
        if r.get("query") == "candidate":
            mark += f" (candidate: เดาจาก {r.get('candidate_of')})"
        lines.append(f"[{r['username']}] {r['site']}{mark}: {r['url']}")
        if r.get("checks"):
            lines.append("    verified: " + "  ".join(f"{MARK[c['ok']]} {c['check']}" for c in r["checks"]))
        for ev in r.get("evidence", []) if r.get("linked") else []:
            lines.append(f"    evidence: {ev}")
        for k, v in r.get("info", {}).items():
            lines.append(f"    {k}: {v}")
    manual = [r for r in results if r["status"] == "manual"]
    if manual:
        lines.append("\nCheck manually (site blocks automated checks):")
        lines.extend(f"    {r['site']}: {r['url']}" for r in manual)
    clusters = meta.get("clusters") or []
    if clusters:
        lines.append("\nIdentities (accounts that look like one person):")
        for c in clusters:
            lines.append(f"    {c['confidence']:>3}%  " + ", ".join(f"{a['site']} @{a['username']}" for a in c["accounts"]))
            lines.append(f"          because: {'; '.join(c['reasons'][:4])}")
    conns = meta.get("connections") or []
    if conns:
        lines.append("\nPossible connections (not proof that it is the same person):")
        for c in conns:
            lines.append(f"    {c['confidence']:>3}%  {c['a']['site']} @{c['a']['username']}  <->  "
                         f"{c['b']['site']} @{c['b']['username']}")
            lines.extend(f"          {MARK[x['ok']]} {x['label']}" + (f" ({x['detail']})" if x.get("detail") else "")
                         for x in c["signals"])
    domains = meta.get("domains") or []
    if domains:
        lines.append("\nPersonal websites:")
        for d in domains:
            lines.append(f"    {d['domain']} [{d['status']}] from {d.get('source', '')}: "
                         f"{', '.join(d.get('found_links', [])) or '-'}")
    changes = meta.get("changes") or []
    if changes:
        lines.append("\nProfile changes since the last run:")
        for c in changes:
            lines.append(f"    {c['site']} @{c['username']}: {c.get('label', c['field'])} "
                         f"{c.get('old') or '-'} -> {c.get('new') or '-'}")
    lines.append(f"\nTotal found: {len(_found(results))}")
    return "\n".join(lines) + "\n"


def to_csv(results: list[dict[str, Any]], meta: dict[str, Any] | None = None) -> str:
    findings = {f["id"]: f for f in (meta or {}).get("findings", [])}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["username", "query", "candidate_of", "site", "status", "url", "http_status", "elapsed", "checked_at",
                "confidence", "first_seen", "last_checked", "source",
                "verification", "evidence", "tags", "name", "bio", "location", "error"])
    for r in sorted(results, key=lambda r: (r["username"].lower(), r["status"] != "found", r["site"].lower())):
        info = r.get("info", {})
        checks = " ".join(f"{MARK[c['ok']]}{c['check']}" for c in r.get("checks", []))
        f = findings.get(f"acct:{r['site'].lower()}/{r['username'].lower()}", {})
        w.writerow([r["username"], r.get("query", "input"), r.get("candidate_of") or "", r["site"], r["status"],
                    r["url"], r.get("http_status") or "", r.get("elapsed", ""), r.get("checked_at", ""),
                    f.get("confidence", ""), f.get("first_seen", ""), f.get("last_checked", ""), f.get("source", ""),
                    checks, " | ".join(r.get("evidence", [])), " ".join(r.get("tags", [])), info.get("name", ""),
                    info.get("bio", ""), info.get("location", ""), r.get("error") or ""])
    return buf.getvalue()


def to_json(results: list[dict[str, Any]], meta: dict[str, Any] | None = None) -> str:
    clean = [{k: v for k, v in r.items() if k != "type"} for r in results]
    return json.dumps({"meta": meta or {}, "results": clean}, indent=2, ensure_ascii=False)


# ---- Markdown -------------------------------------------------------------
def _md(text: Any) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def to_md(results: list[dict[str, Any]], meta: dict[str, Any] | None = None) -> str:
    meta = meta or {}
    found = _found(results)
    usernames = sorted({r["username"] for r in results}, key=str.lower)
    s = meta.get("summary") or {}
    when = meta.get("date") or datetime.now().strftime("%Y-%m-%d %H:%M")
    out = [f"# Sleuth Report: {', '.join(meta.get('usernames') or usernames)}", "",
           f"_สร้างเมื่อ {when} · ข้อมูลจากหน้าสาธารณะ อาจมีผลผิดพลาด ควรตรวจสอบก่อนนำไปใช้_", "",
           "## สรุป", "", "| รายการ | จำนวน |", "|---|---:|",
           f"| บัญชีที่พบ | {s.get('accounts_found', len(found))} |",
           f"| บัญชีที่เชื่อมโยงกัน | {s.get('linked_accounts', 0)} |",
           f"| หลักฐาน | {s.get('evidence', 0)} |",
           f"| ความมั่นใจสูง | {s.get('high', 0)} |",
           f"| ความมั่นใจกลาง | {s.get('medium', 0)} |",
           f"| ความมั่นใจต่ำ | {s.get('low', 0)} |",
           f"| การเปลี่ยนแปลงของโปรไฟล์ | {s.get('changes', 0)} |", ""]
    clusters = meta.get("clusters") or []
    if clusters:
        out += ["## ตัวตนที่น่าจะเป็นคนเดียวกัน", ""]
        for c in clusters:
            out.append(f"### {c['confidence']}% · {', '.join(c['usernames'])}")
            out += [f"- [{_md(a['site'])} @{_md(a['username'])}]({a['url']})" +
                    (f" — {a['score']}" if a.get("score") is not None else "") for a in c["accounts"]]
            out += [f"  - เหตุผล: {_md(w)}" for w in c["reasons"][:6]]
            out.append("")
    findings = meta.get("findings") or []
    if findings:
        out += ["## หลักฐาน (Findings)", "",
                "| ความมั่นใจ | ประเภท | Finding | Source | First seen | Last checked |", "|---:|---|---|---|---|---|"]
        for f in findings:
            title = f"[{_md(f['title'])}]({f['url']})" if str(f.get("url", "")).startswith("http") else _md(f["title"])
            out.append(f"| {f['confidence']} | {KIND_TH.get(f['kind'], f['kind'])} | {title} | {_md(f['source'])} | "
                       f"{_day(f.get('first_seen', ''))} | {_day(f.get('last_checked', ''))} |")
        out.append("")
        for f in findings:
            if f["kind"] != "account":
                continue
            out.append(f"### {_md(f['title'])} ({f['confidence']}/100, {CONF_TH.get(f['level'], f['level'])})")
            out.append(f"- URL: {f['url']}")
            out.append(f"- Source: {_md(f['source'])}")
            out += [f"- {MARK.get(e.get('ok'), '·')} {_md(e['text'])}" for e in f["evidence"]]
            out.append("")
    timeline = meta.get("timeline") or []
    if timeline:
        out += ["## Timeline", ""]
        out += [f"- **{_day(t['date'])}** · {TIMELINE_TH.get(t['kind'], t['kind'])} · {_md(t['title'])}" +
                (f" — {_md(t['detail'])}" if t.get("detail") else "") for t in timeline]
        out.append("")
    changes = meta.get("changes") or []
    if changes:
        out += ["## การเปลี่ยนแปลงของโปรไฟล์ (เทียบกับครั้งก่อน)", ""]
        for c in changes:
            out.append(f"- **{_md(c['site'])} @{_md(c['username'])}** {_md(c.get('label', c['field']))}: "
                       f"{_md(c.get('old') or '—')} → {_md(c.get('new') or '—')}")
        out.append("")
    hits = (meta.get("search") or {}).get("hits") or []
    if hits:
        out += ["## ผลจาก search engine", ""]
        out += [f"- [{_md(h['title'] or h['url'])}]({h['url']}) — {h['engine']} · `{_md(h['query'])}`" for h in hits[:40]]
        out.append("")
    manual = [r for r in results if r["status"] == "manual"]
    if manual:
        out += ["## ต้องตรวจเอง", ""] + [f"- {r['site']}: {r['url']}" for r in manual] + [""]
    return "\n".join(out)


# ---- HTML -------------------------------------------------------------------
def _stat(value: Any, label: str, color: str = "") -> str:
    style = f' style="color:var(--{color})"' if color else ""
    return f'<div class="stat"><b{style}>{escape(str(value))}</b><span>{escape(label)}</span></div>'


def _finding_html(f: dict[str, Any]) -> str:
    items = "".join(
        f'<li class="{_ok_class(e.get("ok"))}">{MARK.get(e.get("ok"), "·")} '
        f'{_linkify_text(e["url"], e["text"]) if e.get("url") else escape(e["text"])}</li>'
        for e in f["evidence"])
    return (f'<details class="finding" id="{_anchor(f["id"])}"><summary>'
            f'<span class="score {escape(f["level"])}">{int(f["confidence"])}</span>'
            f'<span class="kind">{escape(KIND_TH.get(f["kind"], f["kind"]))}</span>'
            f'<b>{escape(f["title"])}</b></summary>'
            f'<dl class="fmeta"><dt>Source</dt><dd>{escape(f["source"])}</dd>'
            f'<dt>URL</dt><dd>{_linkify(f.get("url", ""))}</dd>'
            f'<dt>First seen</dt><dd>{escape(_day(f.get("first_seen", "")))}</dd>'
            f'<dt>Last checked</dt><dd>{escape(_day(f.get("last_checked", "")))}'
            f'{" (cache)" if f.get("cached") else ""}</dd>'
            f'<dt>Confidence</dt><dd>{int(f["confidence"])}/100 ({escape(CONF_TH.get(f["level"], f["level"]))})</dd></dl>'
            f'<ul class="ev">{items}</ul></details>')


def to_html(results: list[dict[str, Any]], meta: dict[str, Any] | None = None) -> str:
    meta = meta or {}
    found = _found(results)
    usernames = sorted({r["username"] for r in results}, key=str.lower)
    targets = meta.get("usernames") or (meta.get("summary") or {}).get("targets") or usernames
    unknown = [r for r in results if r["status"] == "unknown"]
    manual = [r for r in results if r["status"] == "manual"]
    when = meta.get("date") or datetime.now().strftime("%Y-%m-%d %H:%M")
    s = meta.get("summary") or {}
    identity = [i for i in meta.get("identity", []) if i.get("confidence") in ("high", "medium")]
    identity_html = "".join(
        f'<div class="idrow"><span class="conf {escape(i["confidence"])}">{CONF_TH[i["confidence"]]}'
        f'{" " + str(i["score"]) if i.get("score") is not None else ""}</span>'
        f'<div>{_linkify(i["url"])} <b>{escape(i["site"])}</b> @{escape(i["username"])}'
        f'<p>{escape(" · ".join(i.get("evidence", [])))}</p></div></div>'
        for i in identity)
    clusters = meta.get("clusters") or []
    cluster_html = "".join(
        f'<div class="conn"><span class="pct">{int(c["confidence"])}%</span>'
        f'{" · ".join(_linkify_text(a["url"], a["site"] + " @" + a["username"]) for a in c["accounts"])}'
        f'{"<p class=note>ชื่อ: " + escape(", ".join(c["names"])) + "</p>" if c.get("names") else ""}'
        f'<ul>{"".join("<li class=y>✓ " + escape(w) + "</li>" for w in c["reasons"][:8])}</ul></div>'
        for c in clusters)
    conn_html = "".join(_connection_html(c) for c in meta.get("connections") or [])
    domains = meta.get("domains") or []
    domain_rows = "".join(
        f"<tr><td>{_linkify(d['url'])}</td><td>{escape(d['status'])}{' · ' + escape(d['error']) if d.get('error') else ''}</td>"
        f"<td>{escape(d.get('source', ''))}</td><td>{escape(', '.join(d.get('found_links', [])) or '-')}"
        f"{'<br><small>' + escape(', '.join(d['emails'])) + '</small>' if d.get('emails') else ''}"
        f"{'<br><small>' + escape(d['note']) + '</small>' if d.get('note') else ''}</td></tr>"
        for d in domains)
    findings = meta.get("findings") or []
    findings_html = "".join(_finding_html(f) for f in findings)
    timeline = meta.get("timeline") or []
    timeline_html = "".join(
        f'<li class="t-{escape(t["kind"])}"><time>{escape(_day(t["date"]))}</time>'
        f'<span class="tk">{escape(TIMELINE_TH.get(t["kind"], t["kind"]))}</span> '
        f'{_linkify_text(t["url"], t["title"]) if t.get("url") else escape(t["title"])}'
        f'{" <small>" + escape(t["detail"]) + "</small>" if t.get("detail") else ""}</li>'
        for t in timeline)
    changes = meta.get("changes") or []
    change_rows = "".join(
        f"<tr><td>{_linkify_text(c.get('url', ''), c['site'] + ' @' + c['username'])}</td>"
        f"<td>{escape(c.get('label', c['field']))}</td><td>{escape(str(c.get('old') or '—'))}</td>"
        f"<td>{escape(str(c.get('new') or '—'))}</td><td>{escape(_day(c.get('old_seen') or ''))} → "
        f"{escape(_day(c.get('detected_at') or ''))}</td></tr>"
        for c in changes)
    search = meta.get("search") or {}
    hits = search.get("hits") or []
    hit_rows = "".join(
        f"<tr><td>{_linkify_text(h['url'], h.get('title') or h['url'])}<br><small>{escape(h.get('snippet', ''))}</small></td>"
        f"<td>{escape(h['engine'])}</td><td><code>{escape(h['query'])}</code></td>"
        f"<td>{'✓' if h.get('mentions') else ''}{' · ' + escape(h['platform']) if h.get('platform') else ''}</td></tr>"
        for h in hits[:60])
    engines = ", ".join(f"{e['name']}{' (ถูกบล็อก)' if e.get('blocked') else ''}" for e in search.get("engines", []))
    graph_svg = _graph_svg(meta.get("graph") or {}, {f["id"] for f in findings})
    manual_rows = "".join(
        f"<tr><td>{escape(r['site'])}</td><td>{escape(r['username'])}</td><td>{_linkify(r['url'])}</td>"
        f"<td>{escape(r.get('info', {}).get('indexed', '') or r.get('info', {}).get('archived', ''))}</td></tr>"
        for r in manual)

    cards = []
    for r in found:
        info = r.get("info", {})
        avatar = info.get("avatar", "")
        rows = "".join(
            f"<dt>{escape(k)}</dt><dd>{_linkify(v)}</dd>"
            for k, v in info.items() if k not in ("avatar",)
        )
        disc = "".join(f'<span class="chip">{escape(d)}</span>' for d in r.get("discovered", []))
        checks = "".join(f'<span class="ck {_ok_class(c["ok"])}" title="{escape(c["detail"])}">'
                         f'{MARK[c["ok"]]} {escape(c["check"])}</span>' for c in r.get("checks", []))
        q = r.get("query", "input")
        badge = (f' <span class="qb cand">candidate · เดาจาก {escape(str(r.get("candidate_of")))}</span>'
                 if q == "candidate" else
                 ' <span class="qb disc">เจอจากโปรไฟล์</span>' if q == "discovered" and not r.get("linked") else "")
        cards.append(f"""
      <article class="card" data-user="{escape(r['username'])}">
        <header>
          {'<img src="' + escape(avatar) + '" alt="" loading="lazy" referrerpolicy="no-referrer" onerror="this.remove()">' if avatar else '<div class="ph">' + escape(r['site'][:1]) + '</div>'}
          <div><h3>{escape(r['site'])}{' <span class="lk">เชื่อมโยง</span>' if r.get('linked') else ''}{badge}</h3>
          <a href="{escape(r['url'])}" target="_blank" rel="noopener noreferrer">{escape(r['url'])}</a></div>
        </header>
        <p class="meta">@{escape(r['username'])} · {' '.join('#' + escape(t) for t in r.get('tags', []))}{' · depth ' + str(r['depth']) if r.get('depth') else ''}</p>
        {'<p class="ev">' + escape(' · '.join(r.get('evidence', []))) + '</p>' if r.get('linked') or q != 'input' else ''}
        {'<p class="checks">' + checks + '</p>' if checks else ''}
        {'<dl>' + rows + '</dl>' if rows else ''}
        {'<p class="disc">Linked usernames: ' + disc + '</p>' if disc else ''}
      </article>""")

    unknown_rows = "".join(
        f"<tr><td>{escape(r['site'])}</td><td>{escape(r['username'])}</td><td>{escape(r.get('error') or '')}</td></tr>"
        for r in unknown
    )
    stats = (
        _stat(", ".join(targets), "เป้าหมาย") +
        _stat(s.get("accounts_found", len(found)), "บัญชีที่พบ", "ok") +
        _stat(s.get("linked_accounts", sum(1 for r in found if r.get("linked"))), "บัญชีที่เชื่อมโยงกัน", "link") +
        _stat(s.get("evidence", 0), "หลักฐาน") +
        _stat(s.get("high", 0), "ความมั่นใจสูง", "high") +
        _stat(s.get("medium", 0), "ความมั่นใจกลาง", "medium") +
        _stat(s.get("low", 0), "ความมั่นใจต่ำ") +
        _stat(s.get("changes", 0), "การเปลี่ยนแปลง", "warn") +
        _stat(len(unknown), "ตรวจไม่ได้")
    )

    return f"""<!doctype html>
<html lang="th">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sleuth Report</title>
<style>
:root {{ --bg:#f6f7f9; --panel:#fff; --text:#16181d; --muted:#5d6472; --line:#e3e6eb; --accent:#2f6fed; --ok:#14804a; --warn:#b45309; --bad:#c2410c; --link:#7a3fd1; --high:#c0262d; --medium:#a85a06; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0f1115; --panel:#171a21; --text:#e8eaef; --muted:#9aa3b2; --line:#272c36; --accent:#6f9bff; --ok:#3ccf83; --warn:#f0a44b; --bad:#f2865e; --link:#b48cff; --high:#ff7b84; --medium:#f2a54a; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:15px/1.5 system-ui,-apple-system,"Segoe UI","Noto Sans Thai",sans-serif; }}
main {{ max-width:1100px; margin:0 auto; padding:32px 16px 64px; }}
h1 {{ margin:0 0 4px; font-size:26px; }}
.sub {{ color:var(--muted); margin:0 0 24px; }}
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin-bottom:28px; }}
.stat {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px; min-width:0; }}
.stat b {{ display:block; font-size:24px; font-variant-numeric:tabular-nums; overflow-wrap:anywhere; }}
.stat span {{ color:var(--muted); font-size:13px; }}
.toc {{ display:flex; flex-wrap:wrap; gap:6px; margin:-12px 0 20px; }}
.toc a {{ border:1px solid var(--line); border-radius:99px; padding:3px 12px; font-size:13px; color:var(--accent); text-decoration:none; background:var(--panel); }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr)); gap:14px; }}
.card {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:16px; min-width:0; }}
.card header {{ display:flex; gap:12px; align-items:center; }}
.card img, .ph {{ width:44px; height:44px; border-radius:50%; object-fit:cover; flex:none; background:var(--line); display:grid; place-items:center; font-weight:700; color:var(--muted); }}
.card h3 {{ margin:0; font-size:16px; }}
.card header a {{ color:var(--accent); font-size:13px; word-break:break-all; }}
.meta {{ color:var(--muted); font-size:12px; margin:10px 0 0; }}
dl {{ display:grid; grid-template-columns:max-content 1fr; gap:4px 12px; margin:12px 0 0; font-size:13px; }}
dt {{ color:var(--muted); }} dd {{ margin:0; word-break:break-word; }}
dd a {{ color:var(--accent); }}
.chip {{ display:inline-block; border:1px solid var(--line); border-radius:99px; padding:1px 8px; margin:2px; font-size:12px; }}
.disc {{ font-size:13px; margin:10px 0 0; }}
h2 {{ font-size:18px; margin:36px 0 12px; }}
table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:10px; overflow:hidden; font-size:13px; }}
td, th {{ text-align:left; padding:8px 12px; border-bottom:1px solid var(--line); vertical-align:top; }}
td a {{ color:var(--accent); word-break:break-all; }}
details summary {{ cursor:pointer; color:var(--muted); }}
footer {{ color:var(--muted); font-size:12px; margin-top:40px; }}
.lk {{ font-size:11px; background:#f1eafc; color:#7a3fd1; border-radius:99px; padding:1px 7px; vertical-align:middle; }}
.ev {{ color:#7a3fd1; font-size:12px; margin:8px 0 0; }}
.idrow {{ display:flex; gap:10px; background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:10px 12px; margin-bottom:6px; }}
.idrow p {{ margin:2px 0 0; color:var(--muted); font-size:13px; }}
.idrow a {{ color:var(--accent); word-break:break-all; }}
.conf {{ font-size:11px; font-weight:700; border-radius:6px; padding:2px 8px; height:fit-content; white-space:nowrap; }}
.conf.high {{ background:#f1eafc; color:#7a3fd1; }} .conf.medium {{ background:#e5f5ec; color:#14804a; }}
.qb {{ font-size:11px; border-radius:99px; padding:1px 7px; vertical-align:middle; font-weight:600; }}
.qb.cand {{ background:#fff4e0; color:#a15c00; }} .qb.disc {{ background:#e8f0fe; color:#2f6fed; }}
.checks {{ margin:8px 0 0; display:flex; flex-wrap:wrap; gap:4px; }}
.ck {{ font-size:11px; border:1px solid var(--line); border-radius:6px; padding:0 6px; }}
.ck.y, .conn li.y, .finding li.y {{ color:var(--ok); }} .ck.n, .conn li.n, .finding li.n {{ color:var(--bad); }} .ck.u, .conn li.u, .finding li.u {{ color:var(--muted); }}
.conn {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:12px 14px; margin-bottom:8px; }}
.conn .pct {{ font-size:20px; font-weight:700; font-variant-numeric:tabular-nums; margin-right:10px; }}
.conn ul {{ list-style:none; padding:0; margin:8px 0 0; font-size:13px; columns:2 220px; }}
.conn a {{ color:var(--accent); word-break:break-all; }}
.note {{ color:var(--muted); font-size:13px; margin:-4px 0 12px; }}
.finding {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:10px 14px; margin-bottom:6px; }}
.finding:target {{ outline:2px solid var(--accent); }}
.finding summary {{ color:var(--text); display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
.finding .score {{ font-weight:700; font-variant-numeric:tabular-nums; min-width:34px; text-align:center; border-radius:6px; padding:1px 6px; background:var(--line); }}
.finding .score.high {{ color:var(--high); }} .finding .score.medium {{ color:var(--medium); }}
.finding .kind {{ font-size:12px; color:var(--muted); }}
.finding .fmeta {{ font-size:13px; }}
.finding ul {{ margin:10px 0 0; padding-left:4px; list-style:none; font-size:13px; }}
.finding li a {{ color:var(--accent); word-break:break-all; }}
.timeline {{ list-style:none; padding:0 0 0 14px; margin:0; border-left:2px solid var(--line); }}
.timeline li {{ position:relative; padding:4px 0 10px 12px; font-size:14px; }}
.timeline li::before {{ content:""; position:absolute; left:-20px; top:10px; width:10px; height:10px; border-radius:50%; background:var(--accent); }}
.timeline li.t-change::before {{ background:var(--warn); }} .timeline li.t-created::before {{ background:var(--ok); }}
.timeline time {{ font-variant-numeric:tabular-nums; color:var(--muted); margin-right:8px; font-size:13px; }}
.timeline .tk {{ font-size:12px; border:1px solid var(--line); border-radius:6px; padding:0 6px; }}
.timeline small {{ color:var(--muted); display:block; }}
.timeline a {{ color:var(--accent); }}
.graph {{ overflow-x:auto; background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:8px; }}
.graph svg text {{ fill:var(--text); font-size:11px; }}
.graph a:hover rect {{ stroke:var(--accent); stroke-width:2; }}
.graph .e {{ stroke:var(--muted); fill:none; opacity:.55; }} .graph .e.similar {{ stroke:var(--warn); stroke-dasharray:4 3; opacity:.8; }}
.graph .e.search {{ stroke:var(--accent); stroke-dasharray:2 3; }} .graph .e.email {{ stroke:var(--ok); }}
.graph .n rect {{ fill:var(--bg); stroke:var(--line); }} .graph .n.username rect {{ stroke:var(--accent); }}
.graph .n.domain rect {{ stroke:#7a3fd1; }} .graph .n.candidate rect {{ stroke:var(--warn); stroke-dasharray:3 2; }}
.graph .n.email rect {{ stroke:var(--ok); }} .graph .n.lead rect {{ stroke:var(--muted); stroke-dasharray:2 2; }}
@media print {{
  body {{ background:#fff; color:#000; font-size:12px; }}
  main {{ max-width:none; padding:0; }}
  .toc {{ display:none; }}
  .card, .finding, .conn, .stat, table {{ break-inside:avoid; border-color:#ccc; }}
  details {{ display:block; }} details > * {{ display:block; }}
  a {{ color:#000; }}
  .graph {{ overflow:visible; }}
}}
</style>
</head>
<body>
<main>
  <h1>Sleuth Report</h1>
  <p class="sub">เป้าหมาย: <b>{escape(', '.join(targets))}</b> · username ที่ค้นทั้งหมด {len(usernames)} ชื่อ · {escape(when)}</p>
  <section class="stats">{stats}</section>
  <nav class="toc">{''.join(f'<a href="#{a}">{t}</a>' for a, t, ok in (
      ("identities", "ตัวตน", clusters), ("evidence", "หลักฐาน", findings), ("graph", "Identity Graph", graph_svg),
      ("timeline", "Timeline", timeline), ("changes", "การเปลี่ยนแปลง", changes), ("search", "Search engine", hits),
      ("accounts", "บัญชีทั้งหมด", True)) if ok)}</nav>
  {'<h2 id="identities">ตัวตนที่น่าจะเป็นคนเดียวกัน</h2><p class="note">รวมบัญชีที่มีหลักฐานเชื่อมกัน (ลิงก์ถึงกัน ชื่อ/bio/รูป/อีเมล/เว็บไซต์ตรงกัน) ตัวเลข = หลักฐานที่อ่อนที่สุดที่เชื่อมบัญชีในกลุ่ม</p>' + cluster_html if cluster_html else ''}
  {'<h2>บัญชีที่น่าจะเป็นของเป้าหมาย</h2>' + identity_html if identity_html else ''}
  {'<h2>ความเชื่อมโยงที่เป็นไปได้ (Possible connections)</h2><p class="note">เทียบข้อมูลสาธารณะของบัญชีที่เจอทีละคู่ คะแนนสูงแปลว่าควรตรวจต่อ ไม่ได้ยืนยันว่าเป็นคนเดียวกัน</p>' + conn_html if conn_html else ''}
  {'<h2 id="evidence">หลักฐาน (Findings)</h2><p class="note">แต่ละรายการบอกว่าเจอจากอะไร (Source) หลักฐานที่รองรับ เห็นครั้งแรกเมื่อไร ตรวจล่าสุดเมื่อไร และความมั่นใจ 0–100</p>' + findings_html if findings_html else ''}
  {'<h2 id="graph">Identity Graph</h2><p class="note">username → บัญชี → ลิงก์/เว็บไซต์ → อีเมล/บัญชีถัดไป · เส้นประส้ม = อาจเชื่อมโยงกัน · เส้นประฟ้า = จาก search engine · กดกล่องเพื่อไปที่หลักฐาน</p><div class="graph">' + graph_svg + '</div>' if graph_svg else ''}
  {'<h2 id="timeline">Timeline</h2><ol class="timeline">' + timeline_html + '</ol>' if timeline_html else ''}
  {'<h2 id="changes">การเปลี่ยนแปลงของโปรไฟล์ (เทียบกับการค้นครั้งก่อน)</h2><table><tr><th>บัญชี</th><th>อะไรเปลี่ยน</th><th>เดิม</th><th>ใหม่</th><th>ช่วงเวลา</th></tr>' + change_rows + '</table>' if changes else ''}
  {'<h2 id="search">ผลจาก search engine</h2><p class="note">' + escape(engines) + '</p><table><tr><th>หน้า</th><th>Engine</th><th>คำค้น</th><th>กล่าวถึง</th></tr>' + hit_rows + '</table>' if hits else ''}
  <h2 id="accounts">บัญชีที่พบ</h2>
  <section class="grid">{''.join(cards) or '<p>No accounts found.</p>'}</section>
  {'<h2>เว็บไซต์ส่วนตัวที่ตามต่อ (domains)</h2><table><tr><th>URL</th><th>Status</th><th>From</th><th>Profiles / emails found</th></tr>' + domain_rows + '</table>' if domains else ''}
  {'<h2>ตรวจเอง (Instagram / Facebook / TikTok / X / Threads)</h2><table><tr><th>Site</th><th>Username</th><th>Link</th><th>เบาะแส</th></tr>' + manual_rows + '</table>' if manual else ''}
  {'<h2>Could not verify</h2><details><summary>' + str(len(unknown)) + ' sites (timeouts, blocks, errors)</summary><table><tr><th>Site</th><th>Username</th><th>Reason</th></tr>' + unknown_rows + '</table></details>' if unknown else ''}
  <footer>Generated by Sleuth. Results come from public pages and may contain false positives; verify before relying on them.</footer>
</main>
</body>
</html>
"""


def _ok_class(ok: bool | None) -> str:
    return "y" if ok else "n" if ok is False else "u"


def _connection_html(c: dict[str, Any]) -> str:
    def side(x: dict[str, Any]) -> str:
        return _linkify_text(x["url"], f"{x['site']} @{x['username']}")
    items = "".join(
        f'<li class="{_ok_class(s["ok"])}">{MARK[s["ok"]]} {escape(s["label"])}'
        f'{" <small>(" + escape(s["detail"]) + ")</small>" if s.get("detail") else ""}</li>'
        for s in c["signals"])
    return (f'<div class="conn"><span class="pct">{int(c["confidence"])}%</span>{side(c["a"])} ↔ {side(c["b"])}'
            f'<ul>{items}</ul></div>')


def _graph_svg(graph: dict[str, Any], linkable: set[str] | None = None, max_nodes: int = 120) -> str:
    """Layered left-to-right drawing: each node sits one column right of whatever led to it.

    Nodes that have a finding link to it (``#f-...``), so the static report is
    clickable without any script.
    """
    linkable = linkable or set()
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    edges = [e for e in graph.get("edges", []) if e["source"] in nodes and e["target"] in nodes]
    if not edges:
        return ""
    level = {nid: 0 for nid, n in nodes.items() if n["type"] == "username" and n.get("query") == "input"}
    flow = [e for e in edges if e["kind"] != "similar"]
    for _ in range(len(nodes)):  # column = fewest hops from a typed username
        changed = False
        for e in flow:
            if e["source"] in level and level.get(e["target"], 10**6) > level[e["source"]] + 1:
                level[e["target"]] = level[e["source"]] + 1
                changed = True
        if not changed:
            break
    shown = sorted(level, key=lambda n: (level[n], nodes[n]["type"], nodes[n]["label"].lower()))[:max_nodes]
    if not shown:
        return ""
    cols: dict[int, list[str]] = {}
    for nid in shown:
        cols.setdefault(level[nid], []).append(nid)
    col_w, row_h, box_w, box_h = 230, 30, 190, 22
    pos = {nid: (12 + c * col_w, 12 + i * row_h) for c, ids in cols.items() for i, nid in enumerate(ids)}
    width = 24 + (max(cols) + 1) * col_w
    height = 24 + max(len(v) for v in cols.values()) * row_h
    parts = []
    for e in edges:
        if e["source"] not in pos or e["target"] not in pos:
            continue
        (x1, y1), (x2, y2) = pos[e["source"]], pos[e["target"]]
        sy, ty = y1 + box_h / 2, y2 + box_h / 2
        if x2 <= x1:  # same column (e.g. "similar" pairs): loop around the right side
            sx, tx = x1 + box_w, x2 + box_w
            d = f"M{sx},{sy} C{sx + 30},{sy} {tx + 30},{ty} {tx},{ty}"
        else:
            sx, tx = x1 + box_w, x2
            mid = (sx + tx) / 2
            d = f"M{sx},{sy} C{mid},{sy} {mid},{ty} {tx},{ty}"
        parts.append(f'<path class="e {escape(e["kind"])}" d="{d}"><title>{escape(e["label"])}</title></path>')
    for nid in shown:
        n, (x, y) = nodes[nid], pos[nid]
        cls = n["type"] + (" candidate" if n.get("query") == "candidate" else "")
        label = {"username": "@", "domain": "🌐 ", "email": "✉ ", "lead": "? "}.get(n["type"], "") + n["label"]
        short = label if len(label) <= 28 else label[:27] + "…"
        box = (f'<g class="n {escape(cls)}"><rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="5"/>'
               f'<text x="{x + 8}" y="{y + 15}">{escape(short)}</text><title>{escape(label)}</title></g>')
        parts.append(f'<a href="#{_anchor(nid)}">{box}</a>' if nid in linkable else box)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" role="img" aria-label="evidence graph">{"".join(parts)}</svg>')


def _linkify_text(url: str, text: str) -> str:
    if (url or "").startswith(("http://", "https://")):
        return f'<a href="{escape(url)}" target="_blank" rel="noopener noreferrer">{escape(text)}</a>'
    return escape(text)


def _linkify(value: str) -> str:
    if (value or "").startswith(("http://", "https://")):
        return f'<a href="{escape(value)}" target="_blank" rel="noopener noreferrer">{escape(value)}</a>'
    return escape(value or "")


# ---- PDF ------------------------------------------------------------------------
def find_browser() -> str | None:
    """A local Chrome / Edge / Chromium that can print to PDF headlessly."""
    for name in ("msedge", "chrome", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
        path = shutil.which(name)
        if path:
            return path
    candidates = []
    for base in (os.environ.get("PROGRAMFILES(X86)"), os.environ.get("PROGRAMFILES"), os.environ.get("LOCALAPPDATA")):
        if base:
            candidates += [Path(base) / "Microsoft/Edge/Application/msedge.exe",
                           Path(base) / "Google/Chrome/Application/chrome.exe"]
    candidates += [Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
                   Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge")]
    return next((str(p) for p in candidates if p.is_file()), None)


def to_pdf(html: str, timeout: float = 90) -> bytes:
    """Print the HTML report to PDF with a headless browser (Thai text renders correctly).

    Raises RuntimeError when no Chrome/Edge is installed or printing fails.
    """
    browser = find_browser()
    if not browser:
        raise RuntimeError("ไม่พบ Chrome หรือ Edge สำหรับสร้าง PDF (เปิดรายงาน HTML แล้วกด Ctrl+P > Save as PDF แทนได้)")
    with tempfile.TemporaryDirectory(prefix="sleuth-pdf-") as tmp:
        src, out = Path(tmp) / "report.html", Path(tmp) / "report.pdf"
        src.write_text(html, encoding="utf-8")
        cmd = [browser, "--headless=new", "--disable-gpu", "--no-first-run", "--no-pdf-header-footer",
               f"--user-data-dir={Path(tmp) / 'profile'}", f"--print-to-pdf={out}", src.as_uri()]
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"สร้าง PDF ไม่สำเร็จ: {e}") from e
        if not out.is_file() or out.stat().st_size == 0:
            raise RuntimeError("สร้าง PDF ไม่สำเร็จ (เบราว์เซอร์ไม่ได้สร้างไฟล์)")
        return out.read_bytes()


def render(fmt: str, results: list[dict[str, Any]], meta: dict[str, Any] | None = None) -> str:
    if fmt == "txt":
        return to_txt(results, meta)
    if fmt == "csv":
        return to_csv(results, meta)
    if fmt == "json":
        return to_json(results, meta)
    if fmt == "md":
        return to_md(results, meta)
    if fmt == "html":
        return to_html(results, meta)
    raise ValueError(f"unknown format {fmt!r}")


def write(fmt: str, results: list[dict[str, Any]], path: Path, meta: dict[str, Any] | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "pdf":
        path.write_bytes(to_pdf(to_html(results, meta)))
        return path
    # utf-8-sig for CSV so Excel shows Thai text correctly
    path.write_text(render(fmt, results, meta), encoding="utf-8-sig" if fmt == "csv" else "utf-8")
    return path
