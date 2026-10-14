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
import time
from dataclasses import dataclass, field
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

FORMATS = ("txt", "csv", "json", "md", "html")  # text formats render() produces
ALL_FORMATS = FORMATS + ("pdf", "xlsx")  # pdf needs a local Chrome/Edge; xlsx needs openpyxl


# ---- redaction (hide PII before sharing a report) --------------------------------
import copy as _copy
import re as _re

_EMAIL_RE = _re.compile(r"([A-Za-z0-9])([A-Za-z0-9._%+-]*)(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_PHONE_RE = _re.compile(r"(?<![\w.])(\+?\d[\d\s().-]{6,}\d)(?![\w])")


def _mask_text(s: str) -> str:
    """Mask e-mail local parts and long digit runs (phones) inside free text."""
    if not isinstance(s, str) or not s:
        return s
    s = _EMAIL_RE.sub(lambda m: m.group(1) + "***" + m.group(3), s)
    s = _PHONE_RE.sub(lambda m: _re.sub(r"\d", "•", m.group(1)[:-2]) + m.group(1)[-2:], s)
    return s


def _scrub(obj: Any) -> Any:
    """Recursively mask e-mails and phone numbers in every string of a structure."""
    if isinstance(obj, str):
        return _mask_text(obj)
    if isinstance(obj, list):
        return [_scrub(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    return obj


def _redact(results: list[dict[str, Any]], meta: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return copies with avatars/images removed and every e-mail / phone masked.

    Used when a report is exported with ``meta["redact"]`` so it can be shared
    without handing over the target's contact details or face. Structural PII
    (avatar URLs, reverse-image links, mailto: links) is dropped; the recursive
    scrub then guarantees no e-mail or phone survives anywhere in the text.
    """
    results = _copy.deepcopy(results)
    meta = _copy.deepcopy(meta)
    for r in results:
        (r.get("info") or {}).pop("avatar", None)
    for f in meta.get("findings", []) or []:
        if f.get("kind") == "email":
            f["url"] = ""
        for e in f.get("evidence", []) or []:
            if isinstance(e, dict) and str(e.get("url", "")).startswith("mailto:"):
                e["url"] = ""
    intel = meta.get("intel")
    if isinstance(intel, dict):
        intel["images"] = []
    results = _scrub(results)
    meta = _scrub(meta)
    meta["_redacted"] = True
    return results, meta


def _maybe_redact(results, meta):
    meta = meta or {}
    return _redact(results, meta) if meta.get("redact") else (results, meta)


def _found(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted((r for r in results if r["status"] == "found"),
                  key=lambda r: (r.get("depth", 0), r["username"].lower(), r["site"].lower()))


MARK = {True: "✓", False: "✗", None: "·"}
CONF_TH = {"high": "สูง", "medium": "กลาง", "low": "ต่ำ"}
KIND_TH = {"account": "บัญชี", "email": "อีเมล", "domain": "เว็บไซต์", "lead": "เบาะแส", "mention": "กล่าวถึง"}
TIMELINE_TH = {"created": "สร้างบัญชี", "archived": "archive.org", "first_seen": "พบครั้งแรก", "change": "เปลี่ยนแปลง",
               "run": "ค้นหา", "username": "username"}
RISK_TH = {"LOW": "เสี่ยงผิดคนต่ำ", "MEDIUM": "เสี่ยงผิดคนกลาง", "HIGH": "เสี่ยงผิดคนสูง"}
PRIO_TH = {"high": "สำคัญ", "medium": "ควรทำ", "low": "เสริม"}


def _points(sig: dict[str, Any]) -> str:
    p = int(sig.get("points", 0))
    return f"+{p:02d}" if p > 0 else f"{p:03d}" if p < 0 else "-00"


def _breakdown_html(i: dict[str, Any]) -> str:
    rows = "".join(f'<li><b class="{"pos" if x["points"] > 0 else "neg" if x["points"] < 0 else "zero"}">{_points(x)}</b> '
                   f'{escape(x["label"])}</li>' for x in i.get("signals", []))
    risk = f' · <span class="risk {escape(i["fp_risk"])}">{RISK_TH[i["fp_risk"]]}</span>' if i.get("fp_risk") else ""
    return f'<ul class="bd">{rows}<li class="tot"><b>{int(i.get("score", 0))}</b> Confidence{risk}</li></ul>' if rows else ""


def _day(value: str) -> str:
    return (value or "")[:16].replace("T", " ")


def _anchor(fid: str) -> str:
    return "f-" + re.sub(r"[^a-z0-9]+", "-", fid.lower()).strip("-")


def to_txt(results: list[dict[str, Any]], meta: dict[str, Any] | None = None) -> str:
    results, meta = _maybe_redact(results, meta or {})
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
    results, meta = _maybe_redact(results, meta or {})
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
    results, meta = _maybe_redact(results, meta or {})
    clean = [{k: v for k, v in r.items() if k != "type"} for r in results]
    return json.dumps({"meta": meta, "results": clean}, indent=2, ensure_ascii=False)


# ---- Markdown -------------------------------------------------------------
def _md(text: Any) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def to_md(results: list[dict[str, Any]], meta: dict[str, Any] | None = None) -> str:
    results, meta = _maybe_redact(results, meta or {})
    found = _found(results)
    usernames = sorted({r["username"] for r in results}, key=str.lower)
    s = meta.get("summary") or {}
    when = meta.get("date") or datetime.now().strftime("%Y-%m-%d %H:%M")
    out = [f"# Sleuth Report: {', '.join(meta.get('usernames') or usernames)}", "",
           f"_สร้างเมื่อ {when} · ข้อมูลจากหน้าสาธารณะ อาจมีผลผิดพลาด ควรตรวจสอบก่อนนำไปใช้_", "",
           *(["> 🛡️ **ปิดบังข้อมูลส่วนตัวแล้ว** (ซ่อนอีเมล เบอร์โทร และรูปโปรไฟล์ เพื่อการแชร์)", ""] if meta.get("_redacted") else []),
           "## สรุป", "", "| รายการ | จำนวน |", "|---|---:|",
           f"| บัญชีที่พบ | {s.get('accounts_found', len(found))} |",
           f"| บัญชีที่เชื่อมโยงกัน | {s.get('linked_accounts', 0)} |",
           f"| หลักฐาน | {s.get('evidence', 0)} |",
           f"| ความมั่นใจสูง | {s.get('high', 0)} |",
           f"| ความมั่นใจกลาง | {s.get('medium', 0)} |",
           f"| ความมั่นใจต่ำ | {s.get('low', 0)} |",
           f"| การเปลี่ยนแปลงของโปรไฟล์ | {s.get('changes', 0)} |", ""]
    for c in meta.get("contradictions") or []:
        if c is meta["contradictions"][0]:
            out += ["## ⚠ Contradictory evidence detected", "",
                    "> อย่าเพิ่งสรุปว่าบัญชีเหล่านี้เป็นคนเดียวกัน", ""]
        out.append(f"- **{_md(c['label'])}** ({_md(c['scope_label'])}): {_md(c['message'])}")
        out += [f"  - {_md(v['source'])}: {_md(v['value'])}" for v in c["values"][:8]]
    if meta.get("contradictions"):
        out.append("")
    entities = meta.get("entities") or []
    if entities:
        out += ["## Entity resolution", ""]
        for e in entities[:10]:
            out.append(f"### {e['title']} · {e['confidence']}%" + ("" if e.get("evidence_based") else " (มีแค่ชื่อคล้ายกัน)"))
            out.append("- aliases: " + " ≈ ".join(f"`{_md(a)}`" for a in e["aliases"]))
            out += [f"- [{_md(a['site'])} @{_md(a['username'])}]({a['url']}) — {a['score']}" for a in e["accounts"][:20]]
            out += [f"  - เพราะ: {_md(w)}" for w in e["reasons"][:6]]
            out.append("")
    identity = [i for i in meta.get("identity") or [] if i.get("signals")][:15]
    if identity:
        out += ["## Confidence (ที่มาของคะแนน)", ""]
        for i in identity:
            out += [f"**{_md(i['site'])} @{_md(i['username'])}** — Confidence {i['score']}%"
                    + (f" · False-positive risk: {i['fp_risk']}" if i.get("fp_risk") else ""), "", "```"]
            out += [f"{_points(x)} {x['label']}" for x in i["signals"]]
            out += ["```", ""]
    plan = meta.get("plan") or []
    if plan:
        out += ["## Next searches", ""]
        out += [f"{x['n']}. **{_md(x['title'])}** ({PRIO_TH.get(x['priority'], x['priority'])}) — {_md(x['why'])}" for x in plan]
        out.append("")
    intel = meta.get("intel") or {}
    if any(intel.get(k) for k in ("languages", "images", "crypto", "phones", "bots")):
        out += ["## ข้อมูลเพิ่มเติม (จากโปรไฟล์)", ""]
        if intel.get("languages"):
            out.append("- ภาษาที่ใช้: " + ", ".join(f"{x['lang']} ({x['count']})" for x in intel["languages"]))
        for c in intel.get("crypto", []):
            out.append(f"- {c['type'].upper()}: `{_md(c['value'])}` — {_md(', '.join(c['sources'][:4]))}")
        for ph in intel.get("phones", []):
            out.append(f"- เบอร์โทร: {_md(ph['number'])} — {_md(', '.join(ph['sources'][:4]))}")
        for b in intel.get("bots", []):
            out.append(f"- {_md(b['site'])} @{_md(b['username'])}: {b['label']} ({b['score']}/100) — {_md('; '.join(b['signals'][:3]))}")
        if intel.get("images"):
            out += ["", "### ค้นรูปโปรไฟล์ซ้ำ (reverse image search)"]
            for im in intel["images"][:10]:
                links = " · ".join(f"[{name}]({url})" for name, url in im["reverse"].items())
                out.append(f"- {_md(im['site'])} @{_md(im['username'])}: {links}")
        out.append("")
    clusters = [] if entities else meta.get("clusters") or []
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
    edges = [e for e in (meta.get("graph") or {}).get("edges", []) if e.get("evidence") and e["kind"] != "found"]
    if edges:
        out += ["## Evidence graph: หลักฐานของแต่ละเส้น", "", "| # | จาก | ไป | ประเภท | หลักฐาน |", "|---:|---|---|---|---|"]
        out += [f"| {e.get('n', '')} | {_md(e['source'])} | {_md(e['target'])} | {_md(e['label'])} | {_md('; '.join(e['evidence'][:4]))} |"
                for e in edges[:80]]
        out.append("")
    replay = meta.get("replay") or []
    if replay:
        out += ["## Investigation replay", ""]
        out += [f"- `+{x['s']}s` **{_md(x['action'])}** {_md(x['detail'])}" for x in replay[:200]]
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
    results, meta = _maybe_redact(results, meta or {})
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
        f'<p>{escape(" · ".join(i.get("evidence", [])))}</p>{_breakdown_html(i)}</div></div>'
        for i in identity)
    entities = meta.get("entities") or []
    entity_html = "".join(
        f'<div class="conn"><span class="pct">{int(e["confidence"])}%</span><b>{escape(e["title"])}</b> '
        f'<code>{escape(" ≈ ".join(e["aliases"][:8]))}</code>'
        f'{"" if e.get("evidence_based") else " <small class=warnc>มีแค่ชื่อคล้ายกัน</small>"}'
        f'{" <small class=badc>⚠ ขัดแย้ง</small>" if e.get("contradictions") else ""}'
        f'<p class="note" style="margin:6px 0 0">{" · ".join(_linkify_text(a["url"], a["site"] + " " + str(a["score"])) for a in e["accounts"][:25])}</p>'
        f'<ul>{"".join("<li class=y>✓ " + escape(w) + "</li>" for w in e["reasons"][:8])}</ul></div>'
        for e in entities[:12])
    contra = meta.get("contradictions") or []
    contra_html = "".join(
        f'<div class="ci"><b>{escape(c["label"])}</b> · {escape(c["scope_label"])}<br>{escape(c["message"])}'
        f'<br><small>{escape(" · ".join(v["source"] + ": " + v["value"] for v in c["values"][:8]))}</small></div>'
        for c in contra)
    plan = meta.get("plan") or []
    plan_html = "".join(
        f'<li><span class="prio {escape(x["priority"])}">{PRIO_TH.get(x["priority"], x["priority"])}</span> '
        f'<b>{escape(x["title"])}</b><br><small>{escape(x["why"])}</small></li>' for x in plan)
    intel = meta.get("intel") or {}
    has_intel = any(intel.get(k) for k in ("languages", "images", "crypto", "phones", "bots"))
    intel_html = ""
    if has_intel:
        rows = []
        if intel.get("languages"):
            rows.append("<p><b>ภาษาที่ใช้:</b> " + escape(", ".join(f"{x['lang']} ({x['count']})" for x in intel["languages"])) + "</p>")
        for c in intel.get("crypto", []):
            rows.append(f'<p><b>{escape(c["type"].upper())}:</b> <code>{escape(c["value"])}</code> '
                        f'<small>{escape(", ".join(c["sources"][:4]))}</small></p>')
        for ph in intel.get("phones", []):
            rows.append(f'<p><b>เบอร์โทร:</b> {escape(ph["number"])} <small>{escape(", ".join(ph["sources"][:4]))}</small></p>')
        for b in intel.get("bots", []):
            rows.append(f'<p><b>{escape(b["site"])} @{escape(b["username"])}:</b> {escape(b["label"])} ({b["score"]}/100) '
                        f'<small>{escape("; ".join(b["signals"][:3]))}</small></p>')
        if intel.get("images"):
            imgs = "".join(
                f'<tr><td>{escape(im["site"])} @{escape(im["username"])}</td><td>'
                + " · ".join(f'<a href="{escape(u)}" target="_blank" rel="noopener noreferrer">{escape(n)}</a>'
                             for n, u in im["reverse"].items()) + "</td></tr>"
                for im in intel["images"][:12])
            rows.append('<table><tr><th>บัญชี</th><th>ค้นรูปซ้ำ (reverse image search)</th></tr>' + imgs + "</table>")
        intel_html = "".join(rows)
    replay = meta.get("replay") or []
    replay_rows = "".join(
        f'<tr><td>+{escape(str(x["s"]))}s</td><td>{escape(x["action"])}</td><td>{escape(x["detail"])}</td></tr>'
        for x in replay[:300])
    edge_rows = "".join(
        f'<tr id="edge-{e.get("n", "")}"><td>#{e.get("n", "")}</td><td>{escape(e["source"])} → {escape(e["target"])}</td>'
        f'<td>{escape(e["label"])}</td><td>{"<br>".join(escape(x) for x in e.get("evidence", [])[:6])}</td></tr>'
        for e in (meta.get("graph") or {}).get("edges", []) if e.get("evidence") and e["kind"] != "found")
    clusters = [] if entities else meta.get("clusters") or []
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
@media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{ --bg:#0f1115; --panel:#171a21; --text:#e8eaef; --muted:#9aa3b2; --line:#272c36; --accent:#6f9bff; --ok:#3ccf83; --warn:#f0a44b; --bad:#f2865e; --link:#b48cff; --high:#ff7b84; --medium:#f2a54a; }} }}
[data-theme="dark"] {{ --bg:#0f1115; --panel:#171a21; --text:#e8eaef; --muted:#9aa3b2; --line:#272c36; --accent:#6f9bff; --ok:#3ccf83; --warn:#f0a44b; --bad:#f2865e; --link:#b48cff; --high:#ff7b84; --medium:#f2a54a; }}
#theme-toggle {{ position:fixed; top:16px; right:16px; z-index:999; background:var(--panel); border:1px solid var(--line); border-radius:99px; padding:6px 14px; cursor:pointer; font-size:14px; color:var(--text); }}
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
.bd {{ list-style:none; padding:0; margin:6px 0 0; font:12px/1.5 ui-monospace,Consolas,monospace; }}
.bd b {{ display:inline-block; min-width:34px; text-align:right; }} .bd .pos {{ color:var(--ok); }} .bd .neg {{ color:var(--bad); }} .bd .zero {{ color:var(--muted); }}
.bd .tot {{ border-top:1px solid var(--line); margin-top:2px; }}
.risk {{ font-size:11px; font-weight:700; border-radius:6px; padding:0 6px; }} .risk.LOW {{ color:var(--ok); }} .risk.MEDIUM {{ color:var(--medium); }} .risk.HIGH {{ color:var(--high); }}
.warnbox {{ border:1px solid var(--high); border-radius:10px; padding:12px 16px; margin:0 0 18px; }}
.warnbox h2 {{ color:var(--high); margin:0 0 4px; }}
.warnbox .ci {{ padding:6px 0; border-top:1px solid var(--line); font-size:13px; }}
.plan {{ padding-left:20px; }} .plan li {{ margin-bottom:6px; }}
.prio {{ font-size:11px; font-weight:700; border-radius:6px; padding:0 6px; border:1px solid var(--line); }}
.prio.high {{ color:var(--high); }} .prio.medium {{ color:var(--medium); }}
.warnc {{ color:var(--warn); }} .badc {{ color:var(--high); }}
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
@media (max-width:640px) {{
  main {{ padding:16px 8px 48px; }}
  .grid {{ grid-template-columns:1fr; }}
  .stats {{ grid-template-columns:repeat(2,1fr); }}
  table {{ font-size:12px; }}
  td,th {{ padding:6px 8px; }}
  .conn ul {{ columns:1; }}
  h1 {{ font-size:22px; }} h2 {{ font-size:16px; }}
  #theme-toggle {{ top:8px; right:8px; padding:4px 10px; font-size:12px; }}
}}
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
<button id="theme-toggle" onclick="var d=document.documentElement;var c=d.getAttribute('data-theme');d.setAttribute('data-theme',c==='dark'?'light':'dark');localStorage.setItem('sleuth-theme',d.getAttribute('data-theme'));">🌓 Toggle theme</button>
<main>
  <h1>Sleuth Report</h1>
  <p class="sub">เป้าหมาย: <b>{escape(', '.join(targets))}</b> · username ที่ค้นทั้งหมด {len(usernames)} ชื่อ · {escape(when)}</p>
  {'<p class="note" style="border:1px solid var(--accent);border-radius:8px;padding:8px 12px;color:var(--text)">🛡️ ปิดบังข้อมูลส่วนตัวแล้ว — ซ่อนอีเมล เบอร์โทร และรูปโปรไฟล์ เพื่อให้แชร์รายงานได้ปลอดภัย</p>' if meta.get('_redacted') else ''}
  <section class="stats">{stats}</section>
  {'<section class="warnbox"><h2>⚠ Contradictory evidence detected</h2><p class="note" style="margin:0 0 6px">Do not treat these profiles as confirmed identity. อย่าเพิ่งสรุปว่าบัญชีเหล่านี้เป็นคนเดียวกัน</p>' + contra_html + '</section>' if contra_html else ''}
  <nav class="toc">{''.join(f'<a href="#{a}">{t}</a>' for a, t, ok in (
      ("identities", "ตัวตน", clusters or entities), ("plan", "Next searches", plan), ("evidence", "หลักฐาน", findings),
      ("enrichment", "ข้อมูลเพิ่มเติม", has_intel),
      ("graph", "Identity Graph", graph_svg), ("replay", "Replay", replay),
      ("timeline", "Timeline", timeline), ("changes", "การเปลี่ยนแปลง", changes), ("search", "Search engine", hits),
      ("accounts", "บัญชีทั้งหมด", True)) if ok)}</nav>
  {'<h2 id="identities">ตัวตนที่น่าจะเป็นคนเดียวกัน</h2><p class="note">รวมบัญชีที่มีหลักฐานเชื่อมกัน (ลิงก์ถึงกัน ชื่อ/bio/รูป/อีเมล/เว็บไซต์ตรงกัน) ตัวเลข = หลักฐานที่อ่อนที่สุดที่เชื่อมบัญชีในกลุ่ม</p>' + cluster_html if cluster_html else ''}
  {'<h2 id="identities">Entity resolution: ตัวตนที่เป็นไปได้</h2><p class="note">username ที่เป็นชื่อเดียวกันในรูปแบบต่าง ๆ รวมกับกลุ่มที่มีหลักฐานเชื่อมกัน · กลุ่มที่มีแค่ชื่อคล้ายกันได้คะแนนไม่เกิน 40</p>' + entity_html if entity_html else ''}
  {'<h2>บัญชีที่น่าจะเป็นของเป้าหมาย (ที่มาของคะแนน)</h2>' + identity_html if identity_html else ''}
  {'<h2 id="plan">Next searches</h2><p class="note">ขั้นต่อไปที่ระบบแนะนำจากหลักฐานที่เจอ</p><ol class="plan">' + plan_html + '</ol>' if plan_html else ''}
  {'<h2 id="enrichment">ข้อมูลเพิ่มเติม (จากโปรไฟล์)</h2><p class="note">วิเคราะห์จากข้อมูลสาธารณะที่ดึงมาแล้ว ไม่ได้ยิงเว็บเพิ่ม</p>' + intel_html if has_intel else ''}
  {'<h2>ความเชื่อมโยงที่เป็นไปได้ (Possible connections)</h2><p class="note">เทียบข้อมูลสาธารณะของบัญชีที่เจอทีละคู่ คะแนนสูงแปลว่าควรตรวจต่อ ไม่ได้ยืนยันว่าเป็นคนเดียวกัน</p>' + conn_html if conn_html else ''}
  {'<h2 id="evidence">หลักฐาน (Findings)</h2><p class="note">แต่ละรายการบอกว่าเจอจากอะไร (Source) หลักฐานที่รองรับ เห็นครั้งแรกเมื่อไร ตรวจล่าสุดเมื่อไร และความมั่นใจ 0–100</p>' + findings_html if findings_html else ''}
  {'<h2 id="graph">Identity Graph</h2><p class="note">username → บัญชี → ลิงก์/เว็บไซต์ → อีเมล/บัญชีถัดไป · เส้นประส้ม = อาจเชื่อมโยงกัน · เส้นประฟ้า = จาก search engine · กดกล่องเพื่อไปที่หลักฐาน</p><div class="graph">' + graph_svg + '</div>' if graph_svg else ''}
  {'<h2>หลักฐานของแต่ละเส้นในกราฟ</h2><table><tr><th>#</th><th>เส้น</th><th>ประเภท</th><th>หลักฐาน</th></tr>' + edge_rows + '</table>' if edge_rows else ''}
  {'<h2 id="replay">Investigation replay</h2><details><summary>' + str(len(replay)) + ' ขั้นตอนที่ระบบทำ</summary><table><tr><th>เวลา</th><th>ขั้น</th><th>รายละเอียด</th></tr>' + replay_rows + '</table></details>' if replay_rows else ''}
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
        title = f'#{e.get("n", "")} {e["label"]}: ' + "; ".join(e.get("evidence", [])[:3])
        path = f'<path class="e {escape(e["kind"])}" d="{d}"><title>{escape(title)}</title></path>'
        parts.append(f'<a href="#edge-{e["n"]}">{path}</a>' if e.get("n") and e["kind"] != "found" and e.get("evidence") else path)
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
    if fmt == "xlsx":
        data = to_xlsx(results, meta)
        if isinstance(data, bytes):
            import base64
            return base64.b64encode(data).decode("ascii")  # caller should use write() for binary
        return data
    raise ValueError(f"unknown format {fmt!r}")


def write(fmt: str, results: list[dict[str, Any]], path: Path, meta: dict[str, Any] | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "pdf":
        path.write_bytes(to_pdf(to_html(results, meta)))
        return path
    if fmt == "xlsx":
        data = to_xlsx(results, meta)
        if isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(data, encoding="utf-8")
        return path
    # utf-8-sig for CSV so Excel shows Thai text correctly
    path.write_text(render(fmt, results, meta), encoding="utf-8-sig" if fmt == "csv" else "utf-8")
    return path


def to_xlsx(results: list[dict[str, Any]], meta: dict[str, Any] | None = None) -> bytes:
    results, meta = _maybe_redact(results, meta or {})
    """Export results as an Excel workbook with multiple sheets.

    Requires openpyxl: pip install openpyxl
    Falls back to CSV if openpyxl is not installed.
    """
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        from openpyxl.utils import get_column_letter
    except ImportError:
        # Fallback: return CSV as bytes
        return to_csv(results, meta).encode("utf-8-sig")

    meta = meta or {}
    wb = Workbook()

    # Styles
    header_font = Font(bold=True, color="FFFFFF", size=11)
    header_fill = PatternFill("solid", fgColor="2F6FED")
    header_align = Alignment(horizontal="center", vertical="center", wrap_text=True)
    thin_border = Border(
        left=Side(style="thin"), right=Side(style="thin"),
        top=Side(style="thin"), bottom=Side(style="thin")
    )

    # Sheet 1: Accounts found
    ws1 = wb.active
    ws1.title = "Accounts"
    headers = ["Username", "Site", "Status", "URL", "Confidence", "Name", "Bio", "Location", "Tags", "HTTP Status", "Checked At"]
    ws1.append(headers)
    for cell in ws1[1]:
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_align
        cell.border = thin_border

    for r in sorted(results, key=lambda r: (r["username"].lower(), r["status"] != "found", r["site"].lower())):
        info = r.get("info", {})
        ws1.append([
            r["username"], r["site"], r["status"], r["url"],
            meta.get("findings", [{}])[0].get("confidence", "") if meta.get("findings") else "",
            info.get("name", ""), info.get("bio", ""), info.get("location", ""),
            " ".join(r.get("tags", [])), r.get("http_status", ""), r.get("checked_at", ""),
        ])

    # Color-code status column
    for row in ws1.iter_rows(min_row=2):
        for cell in row:
            cell.border = thin_border
        status_cell = row[2]
        if status_cell.value == "found":
            status_cell.fill = PatternFill("solid", fgColor="C6EFCE")
            status_cell.font = Font(color="006100")
        elif status_cell.value == "not found":
            status_cell.fill = PatternFill("solid", fgColor="FFC7CE")
            status_cell.font = Font(color="9C0006")
        elif status_cell.value == "manual":
            status_cell.fill = PatternFill("solid", fgColor="FFEB9C")
            status_cell.font = Font(color="9C6500")

    # Auto-width
    for col in range(1, len(headers) + 1):
        ws1.column_dimensions[get_column_letter(col)].width = 20

    # Sheet 2: Identity clusters
    clusters = meta.get("clusters") or meta.get("entities") or []
    if clusters:
        ws2 = wb.create_sheet("Identities")
        ws2.append(["Confidence", "Usernames", "Sites", "Reasons"])
        for cell in ws2[1]:
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_align

        for c in clusters:
            accounts = c.get("accounts", [])
            usernames = ", ".join(a.get("username", "") for a in accounts)
            sites = ", ".join(a.get("site", "") for a in accounts)
            reasons = "; ".join(c.get("reasons", [])[:5])
            ws2.append([c.get("confidence", 0), usernames, sites, reasons])

        for col in range(1, 5):
            ws2.column_dimensions[get_column_letter(col)].width = 30

    # Sheet 3: Findings (evidence)
    findings = meta.get("findings") or []
    if findings:
        ws3 = wb.create_sheet("Findings")
        ws3.append(["Confidence", "Kind", "Title", "Source", "URL", "First Seen", "Last Checked"])
        for cell in ws3[1]:
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_align

        for f in findings:
            ws3.append([
                f.get("confidence", 0), f.get("kind", ""), f.get("title", ""),
                f.get("source", ""), f.get("url", ""),
                f.get("first_seen", ""), f.get("last_checked", ""),
            ])

        for col in range(1, 8):
            ws3.column_dimensions[get_column_letter(col)].width = 25

    # Sheet 4: Timeline
    timeline = meta.get("timeline") or []
    if timeline:
        ws4 = wb.create_sheet("Timeline")
        ws4.append(["Date", "Kind", "Title", "Detail"])
        for cell in ws4[1]:
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_align

        for t in timeline:
            ws4.append([t.get("date", ""), t.get("kind", ""), t.get("title", ""), t.get("detail", "")])

        for col in range(1, 5):
            ws4.column_dimensions[get_column_letter(col)].width = 30

    # Sheet 5: Changes
    changes = meta.get("changes") or []
    if changes:
        ws5 = wb.create_sheet("Changes")
        ws5.append(["Site", "Username", "Field", "Old", "New", "Detected At"])
        for cell in ws5[1]:
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_align

        for c in changes:
            ws5.append([
                c.get("site", ""), c.get("username", ""),
                c.get("label", c.get("field", "")),
                c.get("old", ""), c.get("new", ""),
                c.get("detected_at", ""),
            ])

        for col in range(1, 7):
            ws5.column_dimensions[get_column_letter(col)].width = 25

    # Sheet 6: Search engine hits
    search = meta.get("search") or {}
    hits = search.get("hits") or []
    if hits:
        ws6 = wb.create_sheet("Search Engine")
        ws6.append(["Title", "URL", "Engine", "Query", "Snippet", "Mentions"])
        for cell in ws6[1]:
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_align

        for h in hits:
            ws6.append([
                h.get("title", ""), h.get("url", ""), h.get("engine", ""),
                h.get("query", ""), h.get("snippet", ""), "Yes" if h.get("mentions") else "No",
            ])

        for col in range(1, 7):
            ws6.column_dimensions[get_column_letter(col)].width = 25

    # Freeze headers on all sheets
    for ws in wb.worksheets:
        ws.freeze_panes = "A2"

    import io
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


# ---- Side-by-side comparison ------------------------------------------------

def _diff_html(diffs: list[dict[str, Any]]) -> str:
    """Render profile diffs as HTML."""
    parts = []
    for d in diffs:
        field = escape(str(d.get("field", "")))
        old = escape(str(d.get("old") or "—"))
        new = escape(str(d.get("new") or "—"))
        parts.append(f"<div>{field}: {old} → {new}</div>")
    return "".join(parts)


def to_comparison_html(
    results_a: list[dict[str, Any]],
    results_b: list[dict[str, Any]],
    meta_a: dict[str, Any] | None = None,
    meta_b: dict[str, Any] | None = None,
    label_a: str = "Scan A",
    label_b: str = "Scan B",
) -> str:
    """Generate a side-by-side comparison HTML report of two scans.

    Shows what accounts were added, removed, or changed between two runs.
    """
    meta_a = meta_a or {}
    meta_b = meta_b or {}
    found_a = {f"{r['site'].lower()}:{r['username'].lower()}": r for r in _found(results_a)}
    found_b = {f"{r['site'].lower()}:{r['username'].lower()}": r for r in _found(results_b)}

    added = {k: v for k, v in found_b.items() if k not in found_a}
    removed = {k: v for k, v in found_a.items() if k not in found_b}
    common = {k: (found_a[k], found_b[k]) for k in found_a if k in found_b}

    # Detect changed profiles
    changed = []
    for key, (old, new) in common.items():
        old_info = old.get("info", {})
        new_info = new.get("info", {})
        diffs = []
        for field in ("name", "bio", "location", "avatar", "followers", "following"):
            old_val = old_info.get(field, "")
            new_val = new_info.get(field, "")
            if old_val != new_val:
                diffs.append({"field": field, "old": old_val, "new": new_val})
        if diffs:
            changed.append({"account": old, "diffs": diffs})

    added_rows = "".join(
        f'<tr class="added"><td>+ {escape(r["site"])}</td><td>{escape(r["username"])}</td>'
        f'<td>{_linkify(r["url"])}</td><td>{escape(str(r.get("info", {}).get("name", "")))}</td></tr>'
        for r in added.values()
    )
    removed_rows = "".join(
        f'<tr class="removed"><td>- {escape(r["site"])}</td><td>{escape(r["username"])}</td>'
        f'<td>{_linkify(r["url"])}</td><td>{escape(str(r.get("info", {}).get("name", "")))}</td></tr>'
        for r in removed.values()
    )
    changed_rows = "".join(
        f'<tr class="changed"><td>~ {escape(c["account"]["site"])}</td><td>{escape(c["account"]["username"])}</td>'
        f'<td colspan="2">{_diff_html(c["diffs"])}</td></tr>'
        for c in changed
    )

    sa = meta_a.get("summary") or {}
    sb = meta_b.get("summary") or {}

    return f"""<!doctype html>
<html lang="th">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sleuth Comparison: {escape(label_a)} vs {escape(label_b)}</title>
<style>
:root {{ --bg:#f6f7f9; --panel:#fff; --text:#16181d; --muted:#5d6472; --line:#e3e6eb; --accent:#2f6fed; --ok:#14804a; --bad:#c2410c; --warn:#b45309; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0f1115; --panel:#171a21; --text:#e8eaef; --muted:#9aa3b2; --line:#272c36; --accent:#6f9bff; --ok:#3ccf83; --bad:#f2865e; --warn:#f0a44b; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:15px/1.5 system-ui,sans-serif; }}
main {{ max-width:1100px; margin:0 auto; padding:32px 16px; }}
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:24px; }}
.stat {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px; }}
.stat b {{ font-size:24px; }} .stat span {{ color:var(--muted); font-size:13px; }}
table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:10px; overflow:hidden; font-size:13px; margin-bottom:20px; }}
td,th {{ text-align:left; padding:8px 12px; border-bottom:1px solid var(--line); }}
tr.added {{ background:rgba(20,128,74,.08); }} tr.removed {{ background:rgba(194,65,12,.08); }} tr.changed {{ background:rgba(180,83,9,.08); }}
h2 {{ font-size:18px; margin:24px 0 8px; }}
a {{ color:var(--accent); }}
</style>
</head>
<body><main>
<h1>Sleuth Comparison Report</h1>
<p style="color:var(--muted)">{escape(label_a)} vs {escape(label_b)}</p>
<div class="stats">
  <div class="stat"><b>{len(found_a)}</b><span>Accounts in {escape(label_a)}</span></div>
  <div class="stat"><b>{len(found_b)}</b><span>Accounts in {escape(label_b)}</span></div>
  <div class="stat"><b style="color:var(--ok)">+{len(added)}</b><span>New accounts</span></div>
  <div class="stat"><b style="color:var(--bad)">-{len(removed)}</b><span>Removed accounts</span></div>
  <div class="stat"><b style="color:var(--warn)">~{len(changed)}</b><span>Changed profiles</span></div>
</div>
{'<h2>New accounts (found in second scan)</h2><table><tr><th>Site</th><th>Username</th><th>URL</th><th>Name</th></tr>' + added_rows + '</table>' if added_rows else ''}
{'<h2>Removed accounts (not found in second scan)</h2><table><tr><th>Site</th><th>Username</th><th>URL</th><th>Name</th></tr>' + removed_rows + '</table>' if removed_rows else ''}
{'<h2>Changed profiles</h2><table><tr><th>Site</th><th>Username</th><th>Changes</th></tr>' + changed_rows + '</table>' if changed_rows else ''}
{'<p style="color:var(--muted)">No differences found between scans.</p>' if not (added_rows or removed_rows or changed_rows) else ''}
</main></body></html>"""


# ---- Map visualization -------------------------------------------------------

def _map_html(locations: list[dict[str, Any]]) -> str:
    """Generate an embedded map showing GPS coordinates from EXIF or profile data.

    Uses OpenStreetMap embed (no API key required).
    """
    points = [(loc.get("lat"), loc.get("lon"), loc.get("label", "")) for loc in locations if loc.get("lat") and loc.get("lon")]
    if not points:
        return ""

    # Calculate center and zoom
    avg_lat = sum(p[0] for p in points) / len(points)
    avg_lon = sum(p[1] for p in points) / len(points)
    if len(points) == 1:
        zoom = 13
    else:
        lat_range = max(p[0] for p in points) - min(p[0] for p in points)
        lon_range = max(p[1] for p in points) - min(p[1] for p in points)
        zoom = 10 if (lat_range > 1 or lon_range > 1) else 12

    # Build marker list for Leaflet
    markers_js = "".join(
        f'L.marker([{p[0]}, {p[1]}]).addTo(map).bindPopup("{escape(p[2])}");'
        for p in points
    )

    return f"""
<div id="sleuth-map" style="width:100%;height:400px;border-radius:10px;overflow:hidden;border:1px solid var(--line);"></div>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
(function() {{
  var map = L.map('sleuth-map').setView([{avg_lat}, {avg_lon}], {zoom});
  L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
    attribution: '&copy; OpenStreetMap contributors', maxZoom: 18
  }}).addTo(map);
  {markers_js}
}})();
</script>"""


# ---- Dark mode toggle for HTML report ----------------------------------------

_DARK_MODE_SCRIPT = """
<script>
(function(){
  var stored = localStorage.getItem('sleuth-theme');
  if (stored === 'dark') document.documentElement.setAttribute('data-theme','dark');
  else if (stored === 'light') document.documentElement.setAttribute('data-theme','light');
  var btn = document.getElementById('theme-toggle');
  if (btn) btn.addEventListener('click', function(){
    var cur = document.documentElement.getAttribute('data-theme');
    var next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('sleuth-theme', next);
  });
})();
</script>
"""

_DARK_MODE_STYLES = """
[data-theme="light"] { --bg:#f6f7f9; --panel:#fff; --text:#16181d; --muted:#5d6472; --line:#e3e6eb; --accent:#2f6fed; --ok:#14804a; --warn:#b45309; --bad:#c2410c; --link:#7a3fd1; --high:#c0262d; --medium:#a85a06; }
[data-theme="dark"] { --bg:#0f1115; --panel:#171a21; --text:#e8eaef; --muted:#9aa3b2; --line:#272c36; --accent:#6f9bff; --ok:#3ccf83; --warn:#f0a44b; --bad:#f2865e; --link:#b48cff; --high:#ff7b84; --medium:#f2a54a; }
#theme-toggle { position:fixed; top:16px; right:16px; z-index:999; background:var(--panel); border:1px solid var(--line); border-radius:99px; padding:6px 14px; cursor:pointer; font-size:14px; color:var(--text); }
"""

# ---- Custom templates -------------------------------------------------------

def render_with_template(
    template_path: str,
    results: list[dict[str, Any]],
    meta: dict[str, Any] | None = None,
) -> str:
    """Render results using a custom HTML template.

    The template file should contain ``{{placeholder}}`` markers that will
    be replaced with data from the results. Supported placeholders:
    - ``{{title}}`` — scan target usernames
    - ``{{date}}`` — current date
    - ``{{stats}}`` — summary statistics
    - ``{{accounts}}`` — found accounts table
    - ``{{identities}}`` — identity clusters
    - ``{{findings}}`` — evidence findings
    - ``{{timeline}}`` — timeline events
    """
    meta = meta or {}
    from pathlib import Path as P
    template = P(template_path).read_text(encoding="utf-8")

    # Build replacement values
    found = _found(results)
    usernames = sorted({r["username"] for r in results}, key=str.lower)
    s = meta.get("summary") or {}
    when = meta.get("date") or datetime.now().strftime("%Y-%m-%d %H:%M")

    stats = f"Found: {len(found)} | Linked: {s.get('linked_accounts', 0)} | Evidence: {s.get('evidence', 0)}"

    accounts_html = "".join(
        f'<div class="account"><a href="{escape(r["url"])}">{escape(r["site"])} @{escape(r["username"])}</a></div>'
        for r in found
    )

    clusters = meta.get("clusters") or []
    identities_html = "".join(
        f'<div class="identity">{c.get("confidence", 0)}%: {escape(", ".join(a.get("username","") for a in c.get("accounts",[])))}</div>'
        for c in clusters
    )

    findings = meta.get("findings") or []
    findings_html = "".join(
        f'<div class="finding"><b>{escape(f.get("title",""))}</b> ({f.get("confidence",0)}/100) — {escape(f.get("source",""))}</div>'
        for f in findings
    )

    timeline = meta.get("timeline") or []
    timeline_html = "".join(
        f'<div class="event"><time>{escape(_day(t.get("date","")))}</time> {escape(t.get("title",""))}</div>'
        for t in timeline
    )

    replacements = {
        "title": escape(", ".join(meta.get("usernames") or usernames)),
        "date": escape(when),
        "stats": stats,
        "accounts": accounts_html,
        "identities": identities_html,
        "findings": findings_html,
        "timeline": timeline_html,
        "summary": escape(json.dumps(s, ensure_ascii=False)),
        "results": escape(json.dumps(results, ensure_ascii=False, default=str)),
        "meta": escape(json.dumps(meta, ensure_ascii=False, default=str)),
    }

    for key, value in replacements.items():
        template = template.replace("{{" + key + "}}", value)

    return template


# ---- Annotations ----------------------------------------------------------

@dataclass
class Annotation:
    """An investigator annotation on a finding or account."""

    target_id: str  # finding/account ID
    text: str
    author: str = "investigator"
    timestamp: float = field(default_factory=time.time)
    color: str = ""  # highlight color


def apply_annotations(html: str, annotations: list[Annotation]) -> str:
    """Insert annotation markers into an HTML report.

    Annotations are inserted as small colored notes next to the targeted
    finding's details element.
    """
    for ann in annotations:
        anchor = _anchor(ann.target_id)
        # Insert annotation after the matching element
        note = (
            f'<div class="annotation" style="border-left:3px solid {ann.color or "#f0a44b"};'
            f'padding:4px 12px;margin:4px 0;font-size:13px;color:var(--muted);">'
            f'<b>{escape(ann.author)}</b>: {escape(ann.text)} '
            f'<small>{escape(_day(str(ann.timestamp)))}</small></div>'
        )
        # Find the closing </details> for this anchor and insert before it
        import re as _re
        pattern = rf'(id="{_re.escape(anchor)}".*?)(</details>)'
        html = _re.sub(pattern, rf'\1{note}\2', html, flags=_re.DOTALL, count=1)
    return html
