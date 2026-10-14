"""Tests for Sleuth v3.0.0 modules: archive, infra_intel, forensics, behavior,
deepsearch, threatintel, counter, viz, realtime, casemgmt."""

from datetime import datetime

from PIL import Image

from sleuth import __version__


# ---- version ------------------------------------------------------------

def test_version():
    assert __version__ >= "3.0.0" and __version__.startswith("3.")


# ---- archive ------------------------------------------------------------

def test_archive_url_builders():
    from sleuth.archive import wayback_url, google_cache_url

    assert "web.archive.org" in wayback_url("https://example.com")
    assert "20240101" in wayback_url("https://example.com", "20240101")
    assert "googleusercontent.com" in google_cache_url("https://example.com")


def test_archive_detect_deleted():
    from sleuth.archive import Snapshot, detect_deleted_content

    snaps = [Snapshot("https://x.com", "20240101000000", 200, "https://wb/x")]
    result = detect_deleted_content(snaps, "not_found")
    assert result["deleted"] is True

    result2 = detect_deleted_content(snaps, "found")
    assert result2["deleted"] is False

    result3 = detect_deleted_content([], "not_found")
    assert result3["deleted"] is False


# ---- infra_intel --------------------------------------------------------

def test_infra_validators():
    from sleuth.infra_intel import is_valid_ip, is_valid_domain

    assert is_valid_ip("192.168.1.1")
    assert is_valid_ip("::1")
    assert not is_valid_ip("not-an-ip")

    assert is_valid_domain("example.com")
    assert is_valid_domain("sub.example.co.uk")
    assert not is_valid_domain("not_a_domain")


def test_infra_dataclasses():
    from sleuth.infra_intel import CTRecord, ShodanResult, DNSRecord, Subdomain, WHOISInfo, IPGeoInfo

    ct = CTRecord(domain="example.com", issuer="Let's Encrypt")
    assert ct.domain == "example.com"

    sh = ShodanResult(ip="1.2.3.4")
    assert sh.ports == []

    dns = DNSRecord(type="A", value="1.2.3.4")
    assert dns.ttl == 0

    sub = Subdomain(name="www.example.com")
    assert sub.resolved is False

    whois = WHOISInfo(domain="example.com")
    assert whois.registrar == ""

    geo = IPGeoInfo(ip="1.2.3.4")
    assert geo.latitude == 0.0


# ---- forensics ----------------------------------------------------------

def test_forensics_steganography():
    from sleuth.forensics import detect_lsb_steganography

    img = Image.new("RGB", (64, 64), (128, 128, 128))
    result = detect_lsb_steganography(img)
    assert isinstance(result.has_hidden_data, bool)
    assert 0 <= result.confidence <= 100
    assert "R" in result.channels_checked


def test_forensics_ela():
    from sleuth.forensics import error_level_analysis

    img = Image.new("RGB", (64, 64), (128, 128, 128))
    result = error_level_analysis(img)
    assert isinstance(result.is_manipulated, bool)
    assert 0 <= result.manipulation_score <= 100
    assert len(result.error_levels) == 3  # R, G, B


def test_forensics_face_detection():
    from sleuth.forensics import detect_faces

    img = Image.new("RGB", (64, 64), (128, 128, 128))
    result = detect_faces(img)
    assert result.face_count >= 0
    assert isinstance(result.has_face, bool)
    assert 0.0 <= result.skin_ratio <= 1.0


def test_forensics_deepfake():
    from sleuth.forensics import detect_deepfake_indicators

    img = Image.new("RGB", (64, 64), (128, 128, 128))
    result = detect_deepfake_indicators(img)
    assert isinstance(result.is_likely_deepfake, bool)
    assert 0 <= result.confidence <= 100


def test_forensics_phash():
    from sleuth.forensics import phash

    img = Image.new("RGB", (64, 64), (128, 128, 128))
    h = phash(img)
    assert isinstance(h, int)
    assert h >= 0


def test_forensics_histogram():
    from sleuth.forensics import color_histogram, histogram_distance

    img = Image.new("RGB", (64, 64), (128, 128, 128))
    hist = color_histogram(img, bins=4)
    assert len(hist) == 12  # 4 bins * 3 channels

    dist = histogram_distance(hist, hist)
    assert dist == 0.0  # identical histograms


def test_forensics_full_analysis():
    from sleuth.forensics import full_forensic_analysis

    img = Image.new("RGB", (64, 64), (128, 128, 128))
    result = full_forensic_analysis(img)
    assert "steganography" in result
    assert "ela" in result
    assert "faces" in result
    assert "deepfake" in result
    assert "phash" in result
    assert "histogram" in result


# ---- behavior -----------------------------------------------------------

def test_behavior_timezone():
    from sleuth.behavior import infer_timezone

    ts = [datetime(2024, 1, 1, 10, 0), datetime(2024, 1, 2, 11, 0), datetime(2024, 1, 3, 12, 0)]
    result = infer_timezone(ts)
    assert -12 <= result.utc_offset <= 14
    assert 0 <= result.confidence <= 100


def test_behavior_heatmap():
    from sleuth.behavior import build_activity_heatmap

    ts = [datetime(2024, 1, 1, 10, 0), datetime(2024, 1, 2, 15, 0), datetime(2024, 1, 3, 20, 0)]
    result = build_activity_heatmap(ts)
    assert len(result.grid) == 7  # 7 days
    assert len(result.grid[0]) == 24  # 24 hours
    assert result.total_activity == 3
    assert result.most_active_period in ("morning", "afternoon", "evening", "night")


def test_behavior_writing_style():
    from sleuth.behavior import analyze_writing_style, compare_writing_styles

    ws = analyze_writing_style(["Hello world! This is a test.", "Another sentence here."])
    assert ws.avg_sentence_length > 0
    assert ws.avg_word_length > 0
    assert ws.signature.startswith("S")

    ws2 = analyze_writing_style(["Hello world! This is a test.", "Another sentence here."])
    sim = compare_writing_styles(ws, ws2)
    assert sim == 100.0  # identical styles


def test_behavior_emoji():
    from sleuth.behavior import analyze_emoji_usage, compare_emoji_fingerprints

    ef = analyze_emoji_usage(["Hello! 😊🎉", "Great! 😊🚀"])
    assert ef.total_emojis == 4
    assert ef.unique_emojis == 3
    assert "😊" in ef.signature

    ef2 = analyze_emoji_usage(["Hello! 😊🎉", "Great! 😊🚀"])
    sim = compare_emoji_fingerprints(ef, ef2)
    assert sim == 100.0  # identical


def test_behavior_interests():
    from sleuth.behavior import analyze_interests

    ip = analyze_interests(["#coding #python #ai", "love #gaming and #music"])
    assert len(ip.hashtags) > 0
    assert "tech" in ip.categories or "gaming" in ip.categories
    assert 0.0 <= ip.diversity_score <= 1.0


def test_behavior_profile_comparison():
    from sleuth.behavior import build_behavioral_profile, compare_profiles

    a = build_behavioral_profile(["Hello world! 😊", "#coding #python"])
    b = build_behavioral_profile(["Hello world! 😊", "#coding #python"])
    scores = compare_profiles(a, b)
    assert "overall" in scores
    assert scores["overall"] > 50.0


# ---- deepsearch ---------------------------------------------------------

def test_deepsearch_dorks_username():
    from sleuth.deepsearch import build_dorks

    dorks = build_dorks("testuser")
    assert len(dorks) >= 10
    categories = {d.category for d in dorks}
    assert "exact" in categories
    assert "intext" in categories
    assert "social" in categories


def test_deepsearch_dorks_email():
    from sleuth.deepsearch import build_dorks

    dorks = build_dorks("user@example.com")
    assert len(dorks) >= 10
    assert any("paste" in d.category for d in dorks)


def test_deepsearch_dorks_domain():
    from sleuth.deepsearch import build_dorks

    dorks = build_dorks("example.com")
    assert any(d.category == "domain" for d in dorks)
    assert any("admin" in d.description.lower() for d in dorks)


def test_deepsearch_dorks_phone():
    from sleuth.deepsearch import build_dorks

    dorks = build_dorks("081-234-5678")
    assert any(d.category == "phone" for d in dorks)


def test_deepsearch_url_builders():
    from sleuth.deepsearch import (
        google_scholar_url, orcid_search_url, researchgate_search_url,
        gist_search_url, discord_server_search_url, geosearch_urls,
    )

    assert "scholar.google.com" in google_scholar_url("test")
    assert "orcid.org" in orcid_search_url("test")
    assert "researchgate.net" in researchgate_search_url("test")
    assert "gist.github.com" in gist_search_url("test")
    assert "disboard.org" in discord_server_search_url("test")

    urls = geosearch_urls(13.7563, 100.5018)
    assert "twitter" in urls
    assert "flickr" in urls


# ---- threatintel --------------------------------------------------------

def test_threatintel_ioc_extraction():
    from sleuth.threatintel import extract_iocs

    text = "Contact user@example.com, visit https://example.com, IP 192.168.1.1, CVE-2024-1234, hash a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    iocs = extract_iocs(text)
    types = {i["type"] for i in iocs}
    assert "email" in types
    assert "url" in types
    assert "ipv4" in types
    assert "cve" in types
    assert "sha1" in types


def test_threatintel_stix():
    from sleuth.threatintel import to_stix

    results = [{"site": "Test", "username": "user", "url": "https://x.com",
                "status": "found", "info": {"name": "User", "email": "u@x.com"}}]
    bundle = to_stix(results)
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) >= 2  # identity + account


def test_threatintel_misp():
    from sleuth.threatintel import to_misp

    results = [{"site": "Test", "username": "user", "url": "https://x.com",
                "status": "found", "info": {"name": "User", "email": "u@x.com"}}]
    event = to_misp(results)
    assert "Event" in event
    assert len(event["Event"]["Attribute"]) >= 1


def test_threatintel_maltego():
    from sleuth.threatintel import to_maltego

    results = [{"site": "Test", "username": "user", "url": "https://x.com",
                "status": "found", "info": {"name": "User", "email": "u@x.com"}}]
    xml = to_maltego(results)
    assert "<?xml" in xml
    assert "MaltegoMessage" in xml
    assert "Entity" in xml


def test_threatintel_opencti():
    from sleuth.threatintel import to_opencti

    results = [{"site": "Test", "username": "user", "url": "https://x.com",
                "status": "found", "info": {"name": "User"}}]
    bundle = to_opencti(results, [{"a": "Test/user", "b": "Test2/user2", "score": 80}])
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) >= 1


def test_threatintel_write_files(tmp_path):
    from sleuth.threatintel import write_stix, write_misp, write_maltego

    results = [{"site": "Test", "username": "user", "url": "https://x.com",
                "status": "found", "info": {"name": "User"}}]
    stix_path = write_stix(results, str(tmp_path / "test.stix.json"))
    misp_path = write_misp(results, str(tmp_path / "test.misp.json"))
    maltego_path = write_maltego(results, str(tmp_path / "test.graph"))

    import os
    assert os.path.exists(stix_path)
    assert os.path.exists(misp_path)
    assert os.path.exists(maltego_path)


# ---- counter ------------------------------------------------------------

def test_counter_privacy_risk():
    from sleuth.counter import assess_privacy_risk

    results = [{"site": "Test", "username": "user", "url": "https://x.com",
                "status": "found", "info": {"name": "User", "email": "u@x.com", "location": "Bangkok"}}]
    risk = assess_privacy_risk(results)
    assert 0 <= risk.score <= 100
    assert risk.level in ("Critical", "High", "Moderate", "Low", "Minimal")
    assert len(risk.factors) > 0
    assert len(risk.recommendations) > 0


def test_counter_footprint():
    from sleuth.counter import check_footprint

    results = [{"site": "Test", "username": "user", "url": "https://x.com",
                "status": "found", "info": {"name": "User", "email": "u@x.com"}}]
    report = check_footprint(results)
    assert report.accounts_found == 1
    assert "email" in report.data_exposed


def test_counter_remediation():
    from sleuth.counter import generate_remediation_plan, get_remediation_guide

    results = [{"site": "Instagram", "username": "user", "url": "https://instagram.com/user",
                "status": "found", "info": {"name": "User", "email": "u@x.com"}}]
    plan = generate_remediation_plan(results)
    assert len(plan) > 0
    assert any(p["priority"] == "HIGH" for p in plan)

    guide = get_remediation_guide("instagram")
    assert "private" in guide


def test_counter_exposure_timeline():
    from sleuth.counter import build_exposure_timeline

    results = [{"site": "Test", "username": "user", "url": "https://x.com",
                "status": "found", "info": {"name": "User", "email": "u@x.com", "created": "2024-01-01"}}]
    timeline = build_exposure_timeline(results)
    assert len(timeline) > 0
    assert any(e.event_type == "account_created" for e in timeline)
    assert any(e.event_type == "email_exposed" for e in timeline)


# ---- viz ----------------------------------------------------------------

def test_viz_network_graph():
    from sleuth.viz import build_network_graph

    results = [{"site": "Test", "username": "user", "url": "https://x.com",
                "status": "found", "info": {"name": "User", "email": "u@x.com", "location": "Bangkok"}}]
    graph = build_network_graph(results)
    assert len(graph["nodes"]) >= 3  # account + name + email
    assert len(graph["links"]) >= 2


def test_viz_timeline():
    from sleuth.viz import build_timeline

    results = [{"site": "Test", "username": "user", "url": "https://x.com",
                "status": "found", "info": {"created": "2024-01-01"}}]
    timeline = build_timeline(results)
    assert len(timeline) >= 1
    assert any(e["category"] == "account" for e in timeline)


def test_viz_geo():
    from sleuth.viz import build_geo_data

    results = [{"site": "Test", "username": "user", "url": "https://x.com",
                "status": "found", "info": {"location": "Bangkok, Thailand"}}]
    points = build_geo_data(results)
    assert len(points) >= 1
    assert points[0]["lat"] != 0.0 or points[0]["lon"] != 0.0


def test_viz_activity_calendar():
    from sleuth.viz import build_activity_calendar

    # Use recent dates so they fall within the calendar window
    from datetime import timedelta
    now = datetime.now()
    ts = [now - timedelta(days=1), now - timedelta(days=2)]
    cal = build_activity_calendar(ts, weeks=4)
    assert len(cal["days"]) == 28  # 4 weeks * 7 days
    assert cal["total"] == 2
    assert 0 <= cal["max"] <= 2


def test_viz_dashboard():
    from sleuth.viz import build_dashboard_data

    results = [{"site": "Test", "username": "user", "url": "https://x.com",
                "status": "found", "info": {"name": "User", "email": "u@x.com"}}]
    data = build_dashboard_data(results)
    assert "summary" in data
    assert "graph" in data
    assert "timeline" in data
    assert "geo" in data
    assert data["summary"]["total_accounts"] == 1


# ---- realtime -----------------------------------------------------------

def test_realtime_alert_manager():
    from sleuth.realtime import AlertManager

    am = AlertManager()
    assert am.client_count == 0


def test_realtime_auto_investigator():
    from sleuth.realtime import AutoInvestigator

    ai = AutoInvestigator()
    results = [{"site": "Test", "username": "user", "url": "https://x.com",
                "status": "found", "info": {"bio": "Hello", "website": "https://x.com"}}]
    plan = ai.plan(results)
    assert len(plan) >= 5
    assert all(s.priority >= 1 for s in plan)
    # Check that steps are sorted by priority
    priorities = [s.priority for s in plan]
    assert priorities == sorted(priorities, reverse=True)


def test_realtime_scan_scheduler():
    from sleuth.realtime import ScanScheduler

    ss = ScanScheduler()
    ss.add("testuser", 24, email="test@example.com")
    assert len(ss.list_schedules()) == 1
    due = ss.get_due()
    assert len(due) == 1
    ss.remove("testuser")
    assert len(ss.list_schedules()) == 0


def test_realtime_feed_monitor():
    from sleuth.realtime import FeedMonitor

    fm = FeedMonitor("https://example.com/feed.xml", "testuser")
    assert fm.target == "testuser"
    assert fm.last_checked is None
    assert len(fm.seen_items) == 0


# ---- casemgmt -----------------------------------------------------------

def test_casemgmt_playbooks():
    from sleuth.casemgmt import list_playbooks, get_playbook

    pbs = list_playbooks()
    assert len(pbs) == 5
    categories = {p["category"] for p in pbs}
    assert "missing_person" in categories
    assert "fraud" in categories
    assert "identity_theft" in categories
    assert "threat_assessment" in categories
    assert "due_diligence" in categories

    fraud = get_playbook("fraud")
    assert len(fraud.steps) >= 5
    assert all(s.step > 0 for s in fraud.steps)


def test_casemgmt_custody(tmp_path):
    from sleuth.casemgmt import ChainOfCustody

    coc = ChainOfCustody(str(tmp_path / "custody.db"))
    coc.log("case1", "collected", "investigator1", "ev1", "Initial collection", b"test data")
    chain = coc.get_chain("case1")
    assert len(chain) == 1
    assert chain[0]["action"] == "collected"

    verification = coc.verify_chain("case1")
    assert verification["valid"] is True
    assert verification["entries"] == 1


def test_casemgmt_notes(tmp_path):
    from sleuth.casemgmt import CaseNotes

    notes = CaseNotes(str(tmp_path / "notes.db"))
    note_id = notes.add("case1", "investigator1", "Found new account on Instagram")
    all_notes = notes.get_notes("case1")
    assert len(all_notes) == 1
    assert all_notes[0]["content"] == "Found new account on Instagram"

    results = notes.search("case1", "Instagram")
    assert len(results) == 1

    notes.pin(note_id)
    pinned = notes.get_notes("case1")
    assert pinned[0]["pinned"] == 1

    notes.delete(note_id)
    assert len(notes.get_notes("case1")) == 0


def test_casemgmt_annotations(tmp_path):
    from sleuth.casemgmt import ResultAnnotations

    ra = ResultAnnotations(str(tmp_path / "anno.db"))
    tags = ResultAnnotations.available_tags()
    assert len(tags) >= 8
    assert any(t["name"] == "confirmed" for t in tags)

    ra.annotate("Instagram/user", "investigator1", "Confirmed as target", ["confirmed"], 95)
    annos = ra.get_annotations("Instagram/user")
    assert len(annos) == 1
    assert annos[0]["confidence"] == 95
    assert "confirmed" in annos[0]["tags"]
