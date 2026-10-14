"""v2 kept features: analysis, regional, imaging, crypto, enrichment, xlsx/comparison reports."""

from datetime import datetime, timedelta

from sleuth import __version__, report
from sleuth.analysis import (analyze_sentiment, analyze_temporal_patterns, compute_centrality, detect_bot,
                             detect_languages)
from sleuth.crypto import extract_ens_from_text, extract_eth_addresses_from_text
from sleuth.enrich import enrich, intel_counts
from sleuth.imaging import extract_exif, reverse_search_urls
from sleuth.regional import extract_thai_phones, parse_thai_phone, regional_search_links, thai_news_links


def test_version():
    assert __version__ >= "2.0.0"


# ---- analysis -------------------------------------------------------------------
def test_bot_detection():
    bot = detect_bot({"username": "user12345678", "bio": "", "avatar": "", "followers": 2, "following": 3000})
    human = detect_bot({"username": "alice", "bio": "Photographer in Bangkok, love coffee and cats",
                        "avatar": "https://x/a.jpg", "followers": 1200, "following": 300})
    assert bot.score > human.score and bot.label in ("Likely Bot", "Suspicious")
    assert human.label == "Likely Human"


def test_sentiment_and_language():
    assert analyze_sentiment("this is awesome and great, love it").sentiment == "positive"
    assert analyze_sentiment("terrible, worst, hate it").sentiment == "negative"
    assert "thai" in detect_languages("สวัสดีครับ") and "latin/english" in detect_languages("hello")
    assert "chinese" in detect_languages("你好")


def test_centrality():
    r = compute_centrality(["a", "b", "c", "d"], [("a", "b"), ("b", "c"), ("b", "d")])
    assert r.most_central == "b" and r.degree_centrality["b"] == 1.0


def test_temporal():
    base = datetime(2026, 1, 1, 14, 0, 0)
    ts = [(base + timedelta(days=i)).isoformat() for i in range(10)]
    p = analyze_temporal_patterns(ts)
    assert p.peak_hour == 14 and 0.0 <= p.activity_consistency <= 1.0


# ---- regional -------------------------------------------------------------------
def test_thai_phone():
    for raw in ("0812345678", "+66812345678", "08-1234-5678", "66 81 234 5678"):
        info = parse_thai_phone(raw)
        assert info.valid and info.national == "0812345678" and info.normalized == "+66812345678" and info.is_mobile
    bkk = parse_thai_phone("021234567")
    assert bkk.valid and not bkk.is_mobile and "กรุงเทพ" in bkk.region
    assert not parse_thai_phone("12345").valid
    assert parse_thai_phone("037123456").region.startswith("ปราจีนบุรี")   # corrected area code
    assert set(extract_thai_phones("โทร 081-234-5678 หรือ 0898765432")) == {"0812345678", "0898765432"}


def test_regional_links():
    engines = {e["engine"] for e in regional_search_links("ice4564")}
    assert {"Baidu", "Yandex", "Naver"} <= engines
    assert all(l["url"].startswith("http") for l in thai_news_links("test"))


def test_no_thai_id_module():
    import sleuth.regional as r
    assert not hasattr(r, "validate_thai_id") and not hasattr(r, "search_dbd")


# ---- imaging --------------------------------------------------------------------
def test_reverse_image_and_exif():
    urls = reverse_search_urls("https://example.com/a.jpg")
    assert set(urls) == {"google", "tineye", "yandex", "bing"} and all(u.startswith("http") for u in urls.values())
    assert not extract_exif(b"not an image").has_gps


# ---- crypto ---------------------------------------------------------------------
def test_crypto_extraction():
    assert extract_ens_from_text("reach me at vitalik.eth please") == ["vitalik.eth"]
    addr = "0x" + "a" * 40
    assert extract_eth_addresses_from_text(f"wallet {addr} here") == [addr]
    assert extract_eth_addresses_from_text("no address") == []


# ---- enrichment (integration) ---------------------------------------------------
def _acct(site, user, **info):
    return {"site": site, "username": user, "url": f"https://{site.lower()}/{user}", "status": "found", "info": info}


def test_enrich_ties_it_together():
    results = [
        _acct("GitHub", "ice", bio="เขียนเกมที่เชียงใหม่ ติดต่อ 081-234-5678 หรือ ice.eth",
              avatar="https://avatars.githubusercontent.com/u/1", followers="1,240", following="180"),
        _acct("Botlike", "spam99999", bio="", avatar="", followers="1", following="4000", created="2026-10-01"),
    ]
    intel = enrich(results)
    assert any(c["type"] == "ens" and c["value"] == "ice.eth" for c in intel["crypto"])
    assert intel["phones"][0]["number"] == "0812345678"
    assert "thai" in [x["lang"] for x in intel["languages"]]
    assert intel["images"] and "google" in intel["images"][0]["reverse"]
    # a site's default avatar must not be offered for reverse search
    default_av = enrich([_acct("X", "y", bio="hi", avatar="https://x.com/img/meta/default.png")])
    assert default_av["images"] == []
    assert any(b["username"] == "spam99999" and b["label"] in ("Likely Bot", "Suspicious") for b in intel["bots"])
    counts = intel_counts(intel)
    assert counts["crypto"] >= 1 and counts["phones"] == 1 and counts["likely_bots"] >= 1


def test_enrich_respects_confident_set():
    results = [_acct("A", "ice", bio="สวัสดี", avatar="https://x/a.jpg"),
               _acct("B", "someoneelse", bio="hello world", avatar="https://x/b.jpg")]
    intel = enrich(results, confident_keys={("a", "ice")})
    assert len(intel["images"]) == 1 and intel["images"][0]["site"] == "A"
    assert [x["lang"] for x in intel["languages"]] == ["thai"]   # B's bio excluded


# ---- reports --------------------------------------------------------------------
def test_xlsx_and_comparison():
    from sleuth.report import to_comparison_html, to_xlsx
    data = to_xlsx([_acct("GitHub", "ice", name="Ice")], {"usernames": ["ice"]})
    assert isinstance(data, (bytes, str))  # bytes with openpyxl, CSV str without
    assert "xlsx" in report.ALL_FORMATS
    html = to_comparison_html([_acct("GitHub", "ice")], [_acct("GitHub", "ice"), _acct("Reddit", "ice")])
    assert "Reddit" in html and "<script" not in html.split("<style>")[0] if "<style>" in html else True


def test_report_includes_enrichment():
    meta = {"usernames": ["ice"], "intel": {
        "languages": [{"lang": "thai", "count": 2}], "crypto": [{"type": "ens", "value": "ice.eth", "sources": ["GitHub @ice"]}],
        "phones": [{"number": "0812345678", "sources": ["GitHub @ice"]}], "bots": [],
        "images": [{"site": "GitHub", "username": "ice", "reverse": {"google": "https://g", "tineye": "https://t"}}]}}
    md = report.to_md([_acct("GitHub", "ice")], meta)
    assert "ข้อมูลเพิ่มเติม" in md and "ice.eth" in md and "0812345678" in md
    html = report.to_html([_acct("GitHub", "ice")], meta)
    assert 'id="enrichment"' in html and "ice.eth" in html and "reverse image" in html.lower()
