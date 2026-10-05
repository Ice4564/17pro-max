"""Self-contained HTML and JSON reports for scans."""

from __future__ import annotations

import json
from datetime import datetime
from html import escape
from typing import Any

from .core import EVENT_TYPES

SEV_LABEL = {"high": "สูง", "medium": "กลาง", "low": "ต่ำ", "info": "ข้อมูล"}
GROUP_LABEL = {"security": "ความปลอดภัย", "infra": "โครงสร้างพื้นฐาน", "web": "เว็บไซต์", "identity": "ตัวตน / บัญชี"}


def to_json(scan: dict[str, Any]) -> str:
    return json.dumps(scan, indent=2, ensure_ascii=False)


def _link(text: str, url: str | None = None) -> str:
    url = url or text
    if url.startswith(("http://", "https://")):
        return f'<a href="{escape(url)}" target="_blank" rel="noopener noreferrer">{escape(text)}</a>'
    return escape(text)


def to_html(scan: dict[str, Any]) -> str:
    events = [e for e in scan["events"] if e["module"] != "root"]
    findings = scan.get("findings", [])
    started = datetime.fromtimestamp(scan["started"]).strftime("%Y-%m-%d %H:%M") if scan.get("started") else ""

    finding_html = "".join(f"""
      <div class="finding {escape(f['severity'])}">
        <span class="sev">{SEV_LABEL.get(f['severity'], f['severity'])}</span>
        <div><b>{escape(f['title'])}</b><p>{escape(f['detail'])}</p></div>
      </div>""" for f in findings) or "<p class='muted'>ไม่มี</p>"

    groups: dict[str, dict[str, list]] = {}
    for e in events:
        label, group = EVENT_TYPES.get(e["type"], (e["type"], "infra"))
        groups.setdefault(group, {}).setdefault(label, []).append(e)

    sections = []
    for group in ("security", "infra", "web", "identity"):
        if group not in groups:
            continue
        blocks = []
        for label, evs in sorted(groups[group].items()):
            rows = "".join(
                f"<li>{_link(e['data'], (e.get('extra') or {}).get('url'))}"
                f"<span class='src'>{escape(e['module'])}</span></li>" for e in evs[:300])
            blocks.append(f"<details open><summary>{escape(label)} <span class='n'>{len(evs)}</span></summary><ul>{rows}</ul></details>")
        sections.append(f"<h2>{GROUP_LABEL[group]}</h2>{''.join(blocks)}")

    return f"""<!doctype html>
<html lang="th"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sleuth Scan Report</title>
<style>
:root {{ --bg:#f6f7f9; --panel:#fff; --text:#16181d; --muted:#5d6472; --line:#e3e6eb; --accent:#2f6fed;
  --high:#c0262d; --medium:#b45309; --low:#2f6fed; --info:#5d6472; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0f1115; --panel:#171a21; --text:#e8eaef; --muted:#9aa3b2; --line:#272c36;
  --accent:#6f9bff; --high:#ff6b72; --medium:#f0a44b; --low:#6f9bff; --info:#9aa3b2; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:15px/1.55 "Segoe UI",system-ui,sans-serif; }}
main {{ max-width:1000px; margin:0 auto; padding:32px 16px 64px; }}
h1 {{ margin:0; font-size:26px; word-break:break-all; }}
.muted {{ color:var(--muted); }}
h2 {{ font-size:18px; margin:32px 0 10px; }}
.stats {{ display:flex; gap:10px; flex-wrap:wrap; margin:18px 0; }}
.stat {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:10px 16px; }}
.stat b {{ font-size:22px; display:block; }}
.finding {{ display:flex; gap:12px; background:var(--panel); border:1px solid var(--line); border-left:4px solid var(--info);
  border-radius:8px; padding:10px 14px; margin-bottom:8px; }}
.finding p {{ margin:2px 0 0; color:var(--muted); font-size:14px; word-break:break-word; }}
.finding .sev {{ font-size:12px; font-weight:700; min-width:44px; color:var(--info); }}
.finding.high {{ border-left-color:var(--high); }} .finding.high .sev {{ color:var(--high); }}
.finding.medium {{ border-left-color:var(--medium); }} .finding.medium .sev {{ color:var(--medium); }}
.finding.low {{ border-left-color:var(--low); }} .finding.low .sev {{ color:var(--low); }}
details {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; margin-bottom:8px; padding:8px 14px; }}
summary {{ cursor:pointer; font-weight:600; }}
.n {{ color:var(--muted); font-weight:400; font-size:13px; }}
ul {{ margin:8px 0 4px; padding-left:18px; }}
li {{ word-break:break-all; margin:2px 0; font-size:14px; }}
.src {{ color:var(--muted); font-size:11px; margin-left:8px; }}
a {{ color:var(--accent); }}
</style></head><body><main>
<p class="muted">Sleuth Scan Report · {escape(started)}</p>
<h1>{escape(scan['target'])}</h1>
<p class="muted">ประเภทเป้าหมาย: {escape(scan['target_type'])} · modules: {escape(scan.get('modules', ''))}</p>
<div class="stats">
  <div class="stat"><b>{len(events)}</b><span class="muted">ข้อมูลที่พบ</span></div>
  <div class="stat"><b style="color:var(--high)">{sum(f['severity'] == 'high' for f in findings)}</b><span class="muted">ความเสี่ยงสูง</span></div>
  <div class="stat"><b style="color:var(--medium)">{sum(f['severity'] == 'medium' for f in findings)}</b><span class="muted">ความเสี่ยงกลาง</span></div>
</div>
<h2>ข้อสรุป</h2>{finding_html}
{''.join(sections)}
<p class="muted" style="margin-top:40px;font-size:12px">ข้อมูลจากแหล่งสาธารณะ อาจไม่ครบหรือมี false positive ควรตรวจสอบก่อนนำไปใช้</p>
</main></body></html>
"""
