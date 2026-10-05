"""Export search results as TXT, CSV, JSON or a self-contained HTML report."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

FORMATS = ("txt", "csv", "json", "html")


def _found(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted((r for r in results if r["status"] == "found"),
                  key=lambda r: (r.get("depth", 0), r["username"].lower(), r["site"].lower()))


def to_txt(results: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for r in _found(results):
        mark = " (linked)" if r.get("linked") else ""
        lines.append(f"[{r['username']}] {r['site']}{mark}: {r['url']}")
        for ev in r.get("evidence", []) if r.get("linked") else []:
            lines.append(f"    evidence: {ev}")
        for k, v in r.get("info", {}).items():
            lines.append(f"    {k}: {v}")
    manual = [r for r in results if r["status"] == "manual"]
    if manual:
        lines.append("\nCheck manually (site blocks automated checks):")
        lines.extend(f"    {r['site']}: {r['url']}" for r in manual)
    lines.append(f"\nTotal found: {len(_found(results))}")
    return "\n".join(lines) + "\n"


def to_csv(results: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["username", "site", "status", "url", "http_status", "elapsed", "tags", "name", "bio", "location", "error"])
    for r in sorted(results, key=lambda r: (r["username"].lower(), r["status"] != "found", r["site"].lower())):
        info = r.get("info", {})
        w.writerow([r["username"], r["site"], r["status"], r["url"], r.get("http_status") or "",
                    r.get("elapsed", ""), " ".join(r.get("tags", [])), info.get("name", ""),
                    info.get("bio", ""), info.get("location", ""), r.get("error") or ""])
    return buf.getvalue()


def to_json(results: list[dict[str, Any]], meta: dict[str, Any] | None = None) -> str:
    clean = [{k: v for k, v in r.items() if k != "type"} for r in results]
    return json.dumps({"meta": meta or {}, "results": clean}, indent=2, ensure_ascii=False)


def to_html(results: list[dict[str, Any]], meta: dict[str, Any] | None = None) -> str:
    meta = meta or {}
    found = _found(results)
    usernames = sorted({r["username"] for r in results}, key=str.lower)
    unknown = [r for r in results if r["status"] == "unknown"]
    manual = [r for r in results if r["status"] == "manual"]
    when = meta.get("date") or datetime.now().strftime("%Y-%m-%d %H:%M")
    conf_label = {"high": "สูง", "medium": "กลาง", "low": "ต่ำ"}
    identity = [i for i in meta.get("identity", []) if i.get("confidence") in ("high", "medium")]
    identity_html = "".join(
        f'<div class="idrow"><span class="conf {escape(i["confidence"])}">{conf_label[i["confidence"]]}</span>'
        f'<div>{_linkify(i["url"])} <b>{escape(i["site"])}</b> @{escape(i["username"])}'
        f'<p>{escape(" · ".join(i.get("evidence", [])))}</p></div></div>'
        for i in identity)
    manual_rows = "".join(
        f"<tr><td>{escape(r['site'])}</td><td>{escape(r['username'])}</td><td>{_linkify(r['url'])}</td></tr>"
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
        cards.append(f"""
      <article class="card" data-user="{escape(r['username'])}">
        <header>
          {'<img src="' + escape(avatar) + '" alt="" loading="lazy" referrerpolicy="no-referrer" onerror="this.remove()">' if avatar else '<div class="ph">' + escape(r['site'][:1]) + '</div>'}
          <div><h3>{escape(r['site'])}{' <span class="lk">เชื่อมโยง</span>' if r.get('linked') else ''}</h3>
          <a href="{escape(r['url'])}" target="_blank" rel="noopener noreferrer">{escape(r['url'])}</a></div>
        </header>
        <p class="meta">@{escape(r['username'])} · {' '.join('#' + escape(t) for t in r.get('tags', []))}{' · depth ' + str(r['depth']) if r.get('depth') else ''}</p>
        {'<p class="ev">' + escape(' · '.join(r.get('evidence', []))) + '</p>' if r.get('linked') else ''}
        {'<dl>' + rows + '</dl>' if rows else ''}
        {'<p class="disc">Linked usernames: ' + disc + '</p>' if disc else ''}
      </article>""")

    unknown_rows = "".join(
        f"<tr><td>{escape(r['site'])}</td><td>{escape(r['username'])}</td><td>{escape(r.get('error') or '')}</td></tr>"
        for r in unknown
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sleuth Report</title>
<style>
:root {{ --bg:#f6f7f9; --panel:#fff; --text:#16181d; --muted:#5d6472; --line:#e3e6eb; --accent:#2f6fed; --ok:#14804a; --warn:#b45309; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0f1115; --panel:#171a21; --text:#e8eaef; --muted:#9aa3b2; --line:#272c36; --accent:#6f9bff; --ok:#3ccf83; --warn:#f0a44b; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }}
main {{ max-width:1100px; margin:0 auto; padding:32px 16px 64px; }}
h1 {{ margin:0 0 4px; font-size:26px; }}
.sub {{ color:var(--muted); margin:0 0 24px; }}
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:28px; }}
.stat {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }}
.stat b {{ display:block; font-size:24px; font-variant-numeric:tabular-nums; }}
.stat span {{ color:var(--muted); font-size:13px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:14px; }}
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
td, th {{ text-align:left; padding:8px 12px; border-bottom:1px solid var(--line); }}
details summary {{ cursor:pointer; color:var(--muted); }}
footer {{ color:var(--muted); font-size:12px; margin-top:40px; }}
.lk {{ font-size:11px; background:#f1eafc; color:#7a3fd1; border-radius:99px; padding:1px 7px; vertical-align:middle; }}
.ev {{ color:#7a3fd1; font-size:12px; margin:8px 0 0; }}
.idrow {{ display:flex; gap:10px; background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:10px 12px; margin-bottom:6px; }}
.idrow p {{ margin:2px 0 0; color:var(--muted); font-size:13px; }}
.idrow a {{ color:var(--accent); word-break:break-all; }}
.conf {{ font-size:11px; font-weight:700; border-radius:6px; padding:2px 8px; height:fit-content; white-space:nowrap; }}
.conf.high {{ background:#f1eafc; color:#7a3fd1; }} .conf.medium {{ background:#e5f5ec; color:#14804a; }}
</style>
</head>
<body>
<main>
  <h1>Sleuth Report</h1>
  <p class="sub">Usernames: <b>{escape(', '.join(usernames))}</b> · {escape(when)}</p>
  <section class="stats">
    <div class="stat"><b style="color:var(--ok)">{len(found)}</b><span>accounts found</span></div>
    <div class="stat"><b>{len(results)}</b><span>checks made</span></div>
    <div class="stat"><b>{len(usernames)}</b><span>usernames searched</span></div>
    <div class="stat"><b style="color:var(--warn)">{len(unknown)}</b><span>could not verify</span></div>
  </section>
  {'<h2>บัญชีที่น่าจะเป็นคนเดียวกัน</h2>' + identity_html if identity_html else ''}
  <h2>Accounts found</h2>
  <section class="grid">{''.join(cards) or '<p>No accounts found.</p>'}</section>
  {'<h2>ตรวจเอง (Instagram / Facebook / TikTok / X / Threads)</h2><table><tr><th>Site</th><th>Username</th><th>Link</th></tr>' + manual_rows + '</table>' if manual else ''}
  {'<h2>Could not verify</h2><details><summary>' + str(len(unknown)) + ' sites (timeouts, blocks, errors)</summary><table><tr><th>Site</th><th>Username</th><th>Reason</th></tr>' + unknown_rows + '</table></details>' if unknown else ''}
  <footer>Generated by Sleuth. Results come from public pages and may contain false positives; verify before relying on them.</footer>
</main>
</body>
</html>
"""


def _linkify(value: str) -> str:
    if value.startswith(("http://", "https://")):
        return f'<a href="{escape(value)}" target="_blank" rel="noopener noreferrer">{escape(value)}</a>'
    return escape(value)


def render(fmt: str, results: list[dict[str, Any]], meta: dict[str, Any] | None = None) -> str:
    if fmt == "txt":
        return to_txt(results)
    if fmt == "csv":
        return to_csv(results)
    if fmt == "json":
        return to_json(results, meta)
    if fmt == "html":
        return to_html(results, meta)
    raise ValueError(f"unknown format {fmt!r}")


def write(fmt: str, results: list[dict[str, Any]], path: Path, meta: dict[str, Any] | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    # utf-8-sig for CSV so Excel shows Thai text correctly
    path.write_text(render(fmt, results, meta), encoding="utf-8-sig" if fmt == "csv" else "utf-8")
    return path
