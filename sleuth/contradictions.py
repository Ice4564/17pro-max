"""Contradiction detector: evidence that says two accounts are *not* the same person.

Correlation adds up hints that accounts belong together; this module looks
for facts that disagree inside a group of supposedly-linked accounts:

* location   profiles in different countries (Bangkok vs Tokyo)
* name       two different full names
* timezone   a website's declared timezone in another region than the profiles
* created    an account "linked" to a person but created years before the
             person's other accounts existed is not a contradiction, so dates
             are not used

Any contradiction lowers the group's confidence and the report says so:
"Do not treat these profiles as confirmed identity."
"""

from __future__ import annotations

import re
from typing import Any

from .linker import normalise_name

# keyword -> country code. Lower-case; matched as whole words (or Thai substrings).
COUNTRIES: dict[str, list[str]] = {
    "TH": ["thailand", "thai", "bangkok", "chiang mai", "chiangmai", "phuket", "pattaya", "khon kaen", "nonthaburi",
           "ไทย", "ประเทศไทย", "กรุงเทพ", "เชียงใหม่", "ภูเก็ต", "ขอนแก่น", "นนทบุรี", "ชลบุรี", "bkk"],
    "JP": ["japan", "tokyo", "osaka", "kyoto", "yokohama", "日本", "東京", "大阪", "ญี่ปุ่น"],
    "US": ["usa", "united states", "u.s.", "new york", "nyc", "california", "san francisco", "los angeles", "seattle",
           "texas", "chicago", "boston", "portland", "oregon", "washington dc", "silicon valley", "bay area"],
    "GB": ["united kingdom", "england", "london", "manchester", "scotland", "britain"],
    "CN": ["china", "beijing", "shanghai", "shenzhen", "中国", "北京", "上海"],
    "KR": ["korea", "seoul", "busan", "한국", "서울", "เกาหลี"],
    "SG": ["singapore", "สิงคโปร์"],
    "MY": ["malaysia", "kuala lumpur"],
    "VN": ["vietnam", "viet nam", "hanoi", "ho chi minh", "saigon"],
    "ID": ["indonesia", "jakarta", "bali"],
    "PH": ["philippines", "manila"],
    "IN": ["india", "mumbai", "delhi", "bangalore", "bengaluru"],
    "DE": ["germany", "deutschland", "berlin", "munich", "hamburg"],
    "FR": ["france", "paris"],
    "CA": ["canada", "toronto", "vancouver", "montreal"],
    "AU": ["australia", "sydney", "melbourne", "brisbane"],
    "RU": ["russia", "moscow", "россия", "москва"],
    "BR": ["brazil", "brasil", "são paulo", "sao paulo", "rio de janeiro"],
    "NL": ["netherlands", "amsterdam"],
    "FI": ["finland", "helsinki"],
}
# IANA timezone prefix / name -> country (only unambiguous ones)
TIMEZONES = {
    "asia/bangkok": "TH", "asia/tokyo": "JP", "asia/seoul": "KR", "asia/shanghai": "CN", "asia/singapore": "SG",
    "asia/kuala_lumpur": "MY", "asia/ho_chi_minh": "VN", "asia/jakarta": "ID", "asia/manila": "PH",
    "asia/kolkata": "IN", "europe/london": "GB", "europe/berlin": "DE", "europe/paris": "FR",
    "europe/amsterdam": "NL", "europe/helsinki": "FI", "europe/moscow": "RU", "australia/sydney": "AU",
    "america/new_york": "US", "america/chicago": "US", "america/denver": "US", "america/los_angeles": "US",
    "america/toronto": "CA", "america/sao_paulo": "BR",
}
COUNTRY_TH = {"TH": "ไทย", "JP": "ญี่ปุ่น", "US": "สหรัฐฯ", "GB": "อังกฤษ", "CN": "จีน", "KR": "เกาหลีใต้",
              "SG": "สิงคโปร์", "MY": "มาเลเซีย", "VN": "เวียดนาม", "ID": "อินโดนีเซีย", "PH": "ฟิลิปปินส์",
              "IN": "อินเดีย", "DE": "เยอรมนี", "FR": "ฝรั่งเศส", "CA": "แคนาดา", "AU": "ออสเตรเลีย", "RU": "รัสเซีย",
              "BR": "บราซิล", "NL": "เนเธอร์แลนด์", "FI": "ฟินแลนด์"}

WARNING = "พบหลักฐานที่ขัดแย้งกัน อย่าเพิ่งสรุปว่าบัญชีเหล่านี้เป็นคนเดียวกัน"
CONTRADICTION_PENALTY = 25  # confidence points taken from a group per contradiction (max 2 counted)


def country_of(text: str) -> str | None:
    t = (text or "").lower()
    if not t.strip():
        return None
    for code, words in COUNTRIES.items():
        for w in words:
            if re.search(r"[^\x00-\x7f]", w):
                if w in t:
                    return code
            elif re.search(rf"(?<![a-z]){re.escape(w)}(?![a-z])", t):
                return code
    return None


def timezone_country(tz: str) -> str | None:
    return TIMEZONES.get((tz or "").strip().lower())


def _label(a: dict[str, Any]) -> str:
    return f"{a['site']} @{a['username']}"


def check_group(accounts: list[dict[str, Any]], domains: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Contradictions among accounts that are supposed to be one person."""
    out: list[dict[str, Any]] = []
    places: dict[str, list[tuple[str, str]]] = {}
    for a in accounts:
        loc = (a.get("info") or {}).get("location", "")
        c = country_of(loc)
        if c:
            places.setdefault(c, []).append((_label(a), loc))
    for d in domains or []:
        c = timezone_country(d.get("timezone", ""))
        if c:
            places.setdefault(c, []).append((f"เว็บไซต์ {d['domain']}", f"timezone {d['timezone']}"))
    if len(places) > 1:
        values = [{"source": src, "value": f"{val} ({COUNTRY_TH.get(code, code)})"}
                  for code, rows in places.items() for src, val in rows]
        out.append({"field": "location", "label": "ที่อยู่ / ประเทศไม่ตรงกัน", "severity": "high",
                    "values": values, "message": f"บัญชีในกลุ่มนี้ระบุ {len(places)} ประเทศ: "
                    + ", ".join(COUNTRY_TH.get(c, c) for c in places)})
    names: dict[str, list[tuple[str, str]]] = {}
    for a in accounts:
        raw = (a.get("info") or {}).get("name", "").strip()
        if len(raw.split()) >= 2 and len(normalise_name(raw)) >= 5:  # full names only: nicknames vary
            names.setdefault(normalise_name(raw), []).append((_label(a), raw))
    if len(names) > 1:
        # "Sky Walker" vs "Sky W. Walker" is the same name written differently
        keys = list(names)
        distinct = [k for k in keys if not any(k != o and (k in o or o in k) for o in keys)]
        if len(distinct) > 1:
            out.append({"field": "name", "label": "ชื่อจริงไม่ตรงกัน", "severity": "medium",
                        "values": [{"source": s, "value": v} for rows in names.values() for s, v in rows],
                        "message": "บัญชีในกลุ่มนี้ใช้ชื่อจริงต่างกัน " + " / ".join(rows[0][1] for rows in names.values())})
    return out


def detect(results: list[dict[str, Any]], clusters: list[dict[str, Any]], identity: list[dict[str, Any]],
           domains: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Contradictions per identity cluster, plus among the target's medium/high accounts.

    Mutates ``clusters``: adds ``contradictions``, lowers ``confidence`` and sets ``warning``.
    """
    by_key = {(r["site"].lower(), r["username"].lower()): r for r in results if r["status"] == "found"}
    personal = [d for d in domains or [] if d.get("personal")]
    found: list[dict[str, Any]] = []
    for c in clusters:
        accts = [by_key[(a["site"].lower(), a["username"].lower())] for a in c["accounts"]
                 if (a["site"].lower(), a["username"].lower()) in by_key]
        doms = [d for d in personal if any(a["id"] in d.get("via", []) for a in c["accounts"])]
        cons = check_group(accts, doms)
        c["contradictions"] = cons
        if cons:
            c["confidence_before"] = c["confidence"]
            c["confidence"] = max(0, c["confidence"] - CONTRADICTION_PENALTY * min(2, len(cons)))
            c["warning"] = WARNING
            for x in cons:
                found.append({**x, "scope": c["id"], "scope_label": f"ตัวตน #{c['id'].split('-')[-1]}"})
    # the accounts the summary already believes in (medium/high) should agree with each other too
    strong = [by_key[(i["site"].lower(), i["username"].lower())] for i in identity
              if i["confidence"] != "low" and (i["site"].lower(), i["username"].lower()) in by_key]
    if len(strong) > 1:
        for x in check_group(strong, personal):
            if not any(f["field"] == x["field"] and f["scope"] != "target" for f in found):
                found.append({**x, "scope": "target", "scope_label": "บัญชีที่ความมั่นใจกลาง-สูง"})
    return found


def penalties(contradictions: list[dict[str, Any]], clusters: list[dict[str, Any]]) -> dict[tuple[str, str], list[str]]:
    """(site, username) -> contradiction labels it is involved in, for per-account scores."""
    out: dict[tuple[str, str], list[str]] = {}
    for c in clusters:
        for x in c.get("contradictions", []):
            for a in c["accounts"]:
                out.setdefault((a["site"].lower(), a["username"].lower()), []).append(x["label"])
    return out
