"""Regional helpers: Thai phone normalization, regional search engines, Thai news.

Country-specific OSINT helpers that stay within public-information bounds:
- Thai phone number normalization + carrier / region hints
- Regional search-engine URL builders (Baidu, Yandex, Naver, ...) and a
  best-effort HTML parser
- Thai local-news search URL builders

No national-ID decoding or private-registry lookups live here: those risk
exposing personal data about third parties and are out of scope.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import quote, urlencode

import aiohttp

# ---- Thai phone normalization -------------------------------------------

# Mobile prefixes are number ranges shared by all carriers after number
# portability, so we report "mobile" rather than guessing a carrier.
TH_MOBILE_PREFIXES = ("06", "08", "09")

# Landline area codes -> province group (the ones we are confident about).
# Unknown codes are reported as a generic Thai landline rather than guessed.
TH_AREA_CODES = {
    "02": "กรุงเทพฯ และปริมณฑล",
    "032": "ราชบุรี, เพชรบุรี, ประจวบคีรีขันธ์",
    "034": "กาญจนบุรี, นครปฐม, สมุทรสาคร, สมุทรสงคราม",
    "035": "พระนครศรีอยุธยา, อ่างทอง, สุพรรณบุรี",
    "036": "ลพบุรี, สระบุรี, สิงห์บุรี",
    "037": "ปราจีนบุรี, สระแก้ว, นครนายก",
    "038": "ชลบุรี, ระยอง, ฉะเชิงเทรา",
    "039": "จันทบุรี, ตราด",
    "042": "อุดรธานี, หนองคาย, เลย, บึงกาฬ, นครพนม, สกลนคร",
    "043": "ขอนแก่น, มหาสารคาม, กาฬสินธุ์, ร้อยเอ็ด",
    "044": "นครราชสีมา, บุรีรัมย์, สุรินทร์, ชัยภูมิ",
    "045": "อุบลราชธานี, ศรีสะเกษ, ยโสธร, อำนาจเจริญ",
    "053": "เชียงใหม่, ลำพูน, เชียงราย",
    "054": "ลำปาง, แพร่, น่าน",
    "055": "พิษณุโลก, สุโขทัย, ตาก, อุตรดิตถ์, กำแพงเพชร",
    "056": "นครสวรรค์, เพชรบูรณ์, พิจิตร, อุทัยธานี, ชัยนาท",
    "073": "ปัตตานี, ยะลา, นราธิวาส",
    "074": "สงขลา, สตูล, พัทลุง",
    "075": "นครศรีธรรมราช, ตรัง, กระบี่",
    "076": "ภูเก็ต, พังงา",
    "077": "สุราษฎร์ธานี, ชุมพร, ระนอง",
}

THAI_PHONE_RE = re.compile(r"(?:\+?66|0)[\s-]?\d(?:[\s-]?\d){7,8}")


@dataclass
class ThaiPhoneInfo:
    """Parsed Thai phone number."""

    raw: str
    normalized: str = ""  # +66XXXXXXXXX
    national: str = ""     # 0XXXXXXXXX
    is_mobile: bool = False
    region: str | None = None
    valid: bool = False


def parse_thai_phone(raw: str) -> ThaiPhoneInfo:
    """Parse and normalize a Thai phone number (0812345678, +66812345678, 08-1234-5678...)."""
    cleaned = re.sub(r"[\s\-()]", "", raw.strip())
    info = ThaiPhoneInfo(raw=raw)

    if cleaned.startswith("+66"):
        national = "0" + cleaned[3:]
    elif cleaned.startswith("66") and not cleaned.startswith("660"):
        national = "0" + cleaned[2:]
    elif cleaned.startswith("0"):
        national = cleaned
    else:
        return info
    if not national[1:].isdigit() or not (9 <= len(national) <= 10):
        return info

    info.national = national
    info.normalized = "+66" + national[1:]
    info.valid = True

    if national[:2] in TH_MOBILE_PREFIXES and len(national) == 10:
        info.is_mobile = True
    else:
        info.region = TH_AREA_CODES.get(national[:3]) or TH_AREA_CODES.get(national[:2]) or "โทรศัพท์บ้าน (ไทย)"
    return info


def extract_thai_phones(text: str) -> list[str]:
    """Distinct normalized Thai phone numbers found in text."""
    out: dict[str, None] = {}
    for m in THAI_PHONE_RE.findall(text or ""):
        info = parse_thai_phone(m)
        if info.valid:
            out.setdefault(info.national, None)
    return list(out)


# ---- Regional search engines --------------------------------------------

@dataclass
class SearchEngineConfig:
    name: str
    region: str
    url_template: str  # contains {query}
    extra_params: dict[str, str] = field(default_factory=dict)
    user_agent: str = "Mozilla/5.0"


REGIONAL_ENGINES: dict[str, SearchEngineConfig] = {
    "baidu": SearchEngineConfig("Baidu", "China", "https://www.baidu.com/s?wd={query}", {"ie": "utf-8"}),
    "yandex": SearchEngineConfig("Yandex", "Russia", "https://yandex.com/search/?text={query}"),
    "naver": SearchEngineConfig("Naver", "Korea", "https://search.naver.com/search.naver?query={query}"),
    "seznam": SearchEngineConfig("Seznam", "Czech Republic", "https://search.seznam.cz/?q={query}"),
    "yahoo_jp": SearchEngineConfig("Yahoo Japan", "Japan", "https://search.yahoo.co.jp/search?p={query}"),
    "sogou": SearchEngineConfig("Sogou", "China", "https://www.sogou.com/web?query={query}"),
    "qwant": SearchEngineConfig("Qwant", "Europe", "https://www.qwant.com/?q={query}"),
}


def build_regional_search_url(engine: str, query: str) -> str | None:
    config = REGIONAL_ENGINES.get(engine)
    if not config:
        return None
    url = config.url_template.format(query=quote(query))
    if config.extra_params:
        url += "&" + urlencode(config.extra_params)
    return url


def regional_search_links(query: str) -> list[dict[str, str]]:
    """Every regional engine as an open-in-browser link (no scraping)."""
    out = []
    for key, cfg in REGIONAL_ENGINES.items():
        url = build_regional_search_url(key, query)
        if url:
            out.append({"engine": cfg.name, "region": cfg.region, "url": url})
    return out


async def search_regional(engine: str, query: str, session: aiohttp.ClientSession) -> list[dict[str, str]]:
    """Best-effort HTML parse of a regional engine's results (may be blocked)."""
    url = build_regional_search_url(engine, query)
    config = REGIONAL_ENGINES.get(engine)
    if not url or not config:
        return []
    try:
        async with session.get(url, headers={"User-Agent": config.user_agent},
                               timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status != 200:
                return []
            return _parse_regional_results(await r.text(), engine)
    except (aiohttp.ClientError, Exception):
        return []


def _parse_regional_results(html: str, engine: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    patterns = {
        "baidu": r'<h3[^>]*><a[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
        "yandex": r'<a[^>]*class="[^"]*[Oo]rganic[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
        "naver": r'<a[^>]*class="[^"]*link_tit[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
    }
    pat = patterns.get(engine)
    if pat:
        for m in re.finditer(pat, html, re.DOTALL):
            results.append({"url": m.group(1), "title": re.sub(r"<[^>]+>", "", m.group(2)).strip(), "engine": engine})
    if not results:
        for m in re.finditer(r'<a[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>', html, re.DOTALL):
            title = re.sub(r"<[^>]+>", "", m.group(2)).strip()
            if title and len(title) > 10 and not any(x in title.lower() for x in ("login", "sign up", "privacy")):
                results.append({"url": m.group(1), "title": title, "engine": engine})
    return results[:20]


# ---- Thai local news search ---------------------------------------------

THAI_NEWS_SOURCES = {
    "ThaiPBS": "https://www.thaipbs.or.th/news/searchresult?q={query}",
    "Bangkok Post": "https://search.bangkokpost.com/search/result?q={query}",
    "The Nation": "https://www.nationthailand.com/search?q={query}",
    "Khaosod": "https://www.khaosod.co.th/?s={query}",
    "Matichon": "https://www.matichon.co.th/?s={query}",
}


def thai_news_links(query: str) -> list[dict[str, str]]:
    return [{"source": name, "url": tpl.format(query=quote(query))} for name, tpl in THAI_NEWS_SOURCES.items()]
