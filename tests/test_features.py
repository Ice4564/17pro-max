"""Mutations, search engines, history/cache, correlation, evidence, reports, plugins, rate limits."""

import asyncio
import base64
import json
import time

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from sleuth import report, websearch
from sleuth.engine import HostLimiter, SearchConfig, Searcher, check_site, make_session
from sleuth.evidence import build_findings, build_timeline
from sleuth.history import History, diff_profile, parse_count
from sleuth.identity import clusters
from sleuth.linker import identity_summary
from sleuth.mutations import mutation_names, mutations
from sleuth.scan.modules import load_plugins
from sleuth.similarity import compare
from sleuth.sites import Site


async def _serve(app: web.Application):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"


# ---- mutations ----------------------------------------------------------------
def test_mutations_cover_common_padding():
    names = mutation_names("ice4564", 30)
    for want in ("ice_4564", "ice.4564", "ice4564x", "ice4564_", "ice4564th"):
        assert want in names
    assert "ice4564" not in names and len(names) == len({n.lower() for n in names})
    assert len(mutation_names("ice4564", 5)) == 5
    assert all(m.rule for m in mutations("ice4564"))
    assert mutation_names("ice4564")[:3] == ["ice_4564", "ice.4564", "ice-4564"]  # separators first


# ---- history: change tracker + cache ----------------------------------------------
def test_parse_count():
    assert parse_count("1,240") == 1240
    assert parse_count("1.2K") == 1200
    assert parse_count("3M") == 3_000_000
    assert parse_count("lots") is None


def test_diff_profile():
    old = {"bio": "hello", "followers": "1,240", "avatar": "https://cdn/x.jpg?sig=1"}
    new = {"bio": "hi there", "followers": "1,391", "avatar": "https://cdn/x.jpg?sig=2", "name": "Ice"}
    got = {c["field"]: c for c in diff_profile("found", old, None, "found", new, None)}
    assert got["bio"]["kind"] == "changed" and got["bio"]["new"] == "hi there"
    assert got["followers"]["old"] == "1,240" and got["followers"]["delta"] == 151
    assert got["name"]["kind"] == "added"
    assert "avatar" not in got                     # only the CDN signature changed
    pic = diff_profile("found", old, 0, "found", old, (1 << 30) - 1)
    assert [c["field"] for c in pic] == ["avatar"]  # the picture itself changed
    gone = diff_profile("found", old, None, "not_found", {}, None)
    assert gone[0]["field"] == "status" and gone[0]["kind"] == "removed"


def _res(site, user, status="found", **info):
    return {"site": site, "username": user, "url": f"https://{site}/{user}", "status": status, "info": info,
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())}


def test_history_records_changes_and_first_seen(tmp_path):
    h = History(tmp_path / "h.db")
    first = h.record_run(["ice"], [_res("GitHub", "ice", bio="old bio", followers="10")])
    assert first["changes"] == []
    seen1 = first["seen"][("github", "ice")]["first_seen"]
    second = h.record_run(["ice"], [_res("GitHub", "ice", bio="new bio", followers="12")])
    fields = {c["field"] for c in second["changes"]}
    assert fields == {"bio", "followers"}
    assert second["seen"][("github", "ice")]["first_seen"] == seen1
    assert len(h.changes_for(["ice"])) == 2
    assert h.list_runs("ice")[0]["changes"] == 2
    # cached answers are not new observations
    third = h.record_run(["ice"], [{**_res("GitHub", "ice", bio="whatever"), "cached": True}])
    assert third["changes"] == []
    h.close()


def test_cache_roundtrip_and_expiry(tmp_path):
    h = History(tmp_path / "h.db")
    h.put_cache("GitHub", "Ice", "sig1", {"status": "found"})
    assert h.cached("github", "ice", "sig1") == {"status": "found"}
    assert h.cached("github", "ice", "other-rule") is None
    assert h.cached("github", "ice", "sig1", ttl=-1) is None
    assert h.clear_cache() == 1
    h.close()


# ---- search engines ------------------------------------------------------------
DDG = """<div class="result results_links web-result"><div class="result__body">
<h2 class="result__title"><a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.instagram.com%2Fice4564%2F&amp;rut=x">ice (@ice4564) &bull; Instagram</a></h2>
<a class="result__snippet" href="#">Photos by <b>ice4564</b></a></div></div>
<div class="result results_links web-result"><div class="result__body">
<h2 class="result__title"><a class="result__a" href="https://example.com/blog">A blog</a></h2>
<a class="result__snippet" href="#">nothing related</a></div></div>"""


def test_parse_duckduckgo_and_classify():
    rows = websearch.parse_duckduckgo(DDG)
    assert rows[0][0] == "https://www.instagram.com/ice4564/" and "Instagram" in rows[0][1]
    hit = websearch.classify(websearch.Hit("DuckDuckGo", "q", "ice4564", *rows[0], rank=1))
    assert hit.platform == "Instagram" and hit.same_handle and hit.mentions
    other = websearch.classify(websearch.Hit("DuckDuckGo", "q", "ice4564", *rows[1], rank=2))
    assert not other.mentions and other.platform is None


def test_parse_bing_decodes_redirects():
    target = "https://github.com/ice4564"
    u = "a1" + base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
    html = (f'<li class="b_algo"><h2><a href="https://www.bing.com/ck/a?!&amp;p=1&amp;u={u}&amp;ntb=1">ice4564 - GitHub</a></h2>'
            '<div class="b_caption"><p>ice4564 has 3 repositories</p></div></li>')
    assert websearch.parse_bing(html) == [(target, "ice4564 - GitHub", "ice4564 has 3 repositories")]


def test_search_falls_back_when_blocked():
    async def go():
        app = web.Application()
        async def blocked(_):
            return web.Response(status=429, text="slow down")

        async def ok(_):
            return web.Response(text=DDG, content_type="text/html")

        app.router.add_get("/blocked", blocked)
        app.router.add_get("/ok", ok)
        runner, base = await _serve(app)
        try:
            engines = [websearch.Engine("A", base + "/blocked?q={q}", websearch.parse_duckduckgo),
                       websearch.Engine("B", base + "/ok?q={q}", websearch.parse_duckduckgo)]
            async with make_session(SearchConfig()) as s:
                return await websearch.search(s, ["ice4564"], max_queries=2, delay=0, engines=engines)
        finally:
            await runner.cleanup()

    out = asyncio.run(go())
    assert out["engines"][0]["blocked"] and not out["engines"][1]["blocked"]
    assert [q["engine"] for q in out["queries"]] == ["A", "B"]
    assert any(h["same_handle"] for h in out["hits"])
    assert len(out["hits"]) == 2                    # duplicates across queries are kept once


# ---- correlation -------------------------------------------------------------------
def _acct(site, user, **info):
    return {"site": site, "username": user, "url": f"https://{site}/{user}", "status": "found", "info": info,
            "links": [], "via": []}


def test_email_signal_and_clusters():
    a = _acct("GitHub", "ice4564", bio="contact: ice@icemail.dev")
    b = _acct("Dev.to", "frozen_one", bio="mail me ice@icemail.dev")
    c = _acct("Reddit", "random", name="Someone Else")
    sig = {s["name"]: s for s in compare(a, b)["signals"]}
    assert sig["email"]["ok"] and "ice@icemail.dev" in sig["email"]["detail"]
    groups = clusters([a, b, c], [compare(a, b) | {"confidence": 75}])
    assert len(groups) == 1 and {x["site"] for x in groups[0]["accounts"]} == {"GitHub", "Dev.to"}
    assert groups[0]["confidence"] >= 75 and groups[0]["reasons"]


def test_identity_scores_are_0_to_100():
    res = [dict(_acct("A", "ice"), query="input"), dict(_acct("B", "ice2"), query="candidate"),
           dict(_acct("IG", "ice.ig"), query="discovered", linked=True)]
    by = {i["site"]: i for i in identity_summary(res, ["ice"])}
    assert by["IG"]["confidence"] == "high" and by["IG"]["score"] >= 70
    assert by["A"]["confidence"] == "low" and 0 < by["A"]["score"] < 45
    assert by["B"]["score"] < by["A"]["score"]
    assert by["IG"]["signals"][0]["points"] > 0


# ---- evidence -----------------------------------------------------------------------------
def test_findings_have_source_evidence_and_dates():
    r = dict(_acct("GitHub", "ice"), checks=[{"check": "username", "ok": True, "detail": "x"}],
             evidence=["username ตรงกับที่ค้น"], checked_at="2026-10-07T10:00:00+00:00", query="input")
    r["info"] = {"bio": "mail ice@icemail.dev", "created": "2019-04-01"}
    ident = identity_summary([r], ["ice"])
    seen = {("github", "ice"): {"first_seen": "2026-01-01T00:00:00+00:00", "last_checked": "2026-10-07T10:00:00+00:00"}}
    hits = [{"engine": "DuckDuckGo", "query": '"ice"', "username": "ice", "url": "https://github.com/ice",
             "title": "ice", "snippet": "", "rank": 1, "mentions": True, "platform": "GitHub", "handle": "ice",
             "same_handle": True, "checked_at": ""}]
    fs = build_findings([r], ident, [], hits, seen)
    acct = next(f for f in fs if f["kind"] == "account")
    for k in ("source", "url", "evidence", "first_seen", "last_checked", "confidence"):
        assert acct[k] or k == "confidence"
    assert acct["first_seen"].startswith("2026-01-01")
    types = {e["type"] for e in acct["evidence"]}
    assert {"origin", "check", "profile", "email", "search"} <= types
    assert any(f["kind"] == "email" and f["title"] == "ice@icemail.dev" for f in fs)
    tl = build_timeline([r], [{"site": "GitHub", "username": "ice", "field": "bio", "kind": "changed", "old": "a",
                               "new": "b", "detected_at": "2026-05-01T00:00:00+00:00", "label": "Bio"}], seen,
                        run_started="2026-10-07T10:00:00+00:00")
    assert [t["kind"] for t in tl] == ["created", "first_seen", "change", "run"]
    # many accounts first seen on the same day collapse into one entry
    many = [dict(_acct(f"S{i}", "ice"), checked_at="2026-10-07T10:00:00+00:00") for i in range(5)]
    seen_many = {(f"s{i}", "ice"): {"first_seen": f"2026-01-01T00:00:0{i}+00:00"} for i in range(5)}
    tl = build_timeline(many, [], seen_many, run_started="2026-10-07T10:00:00+00:00")
    firsts = [t for t in tl if t["kind"] == "first_seen"]
    assert len(firsts) == 1 and "5 บัญชี" in firsts[0]["title"]


# ---- engine: cache, history, rate limit --------------------------------------------------------
def test_search_uses_cache_and_tracks_changes(tmp_path):
    bio = {"v": "first bio"}
    calls = {"n": 0}

    async def profile(req):
        calls["n"] += 1
        if req.match_info["u"] != "ice4564":
            return web.Response(status=404, text="no")
        return web.Response(text=f'<title>ice4564</title><meta property="og:description" content="{bio["v"]}">'
                                 f'<p>@ice4564</p>', content_type="text/html")

    async def go():
        app = web.Application()
        app.router.add_get("/p/{u}", profile)
        runner, base = await _serve(app)
        sites = [Site.from_dict("Prof", {"url": base + "/p/{}"})]

        async def run(cache):
            h = History(tmp_path / "h.db")
            try:
                s = Searcher(sites, SearchConfig(timeout=5, retries=0, archive=False, avatars=False, depth=0,
                                                 cache=cache), history=h)
                return [e async for e in s.run(["ice4564"])][-1]
            finally:
                h.close()

        try:
            first = await run(cache=True)
            n = calls["n"]
            again = await run(cache=True)
            n_again = calls["n"]
            bio["v"] = "a brand new bio"
            fresh = await run(cache=False)
            return first, n, again, n_again, fresh
        finally:
            await runner.cleanup()

    first, n, again, n_again, fresh = asyncio.run(go())
    assert first["run_id"] and first["changes"] == []
    assert n_again == n and again["stats"]["cached"] == 1          # answered from the cache
    assert calls["n"] == n + 1                                     # --no-cache asks the site again
    assert [c["field"] for c in fresh["changes"]] == ["bio"]
    acct = next(f for f in fresh["findings"] if f["kind"] == "account")
    assert acct["first_seen"] == next(f for f in first["findings"] if f["kind"] == "account")["first_seen"]
    assert fresh["summary"]["changes"] == 1 and fresh["summary"]["accounts_found"] == 1
    assert any(t["kind"] == "change" for t in fresh["timeline"])


def test_host_limiter_spaces_requests():
    async def go():
        lim = HostLimiter(0.2)
        t0 = time.monotonic()
        await lim.wait("a.com")
        await lim.wait("a.com")
        await lim.wait("b.com")  # other hosts are not slowed down
        return time.monotonic() - t0

    took = asyncio.run(go())
    assert 0.18 <= took < 0.5


def test_429_is_retried_after_backoff():
    hits = {"n": 0}

    async def flaky(req):
        hits["n"] += 1
        if hits["n"] == 1:
            return web.Response(status=429, headers={"Retry-After": "0.5"}, text="slow")
        return web.Response(text="<title>ice</title><p>@ice</p>", content_type="text/html")

    async def go():
        app = web.Application()
        app.router.add_get("/u/{u}", flaky)
        runner, base = await _serve(app)
        try:
            cfg = SearchConfig(timeout=5, retries=1)
            async with make_session(cfg) as s:
                return await check_site(s, Site.from_dict("Flaky", {"url": base + "/u/{}"}), "ice", cfg,
                                        limiter=HostLimiter(0))
        finally:
            await runner.cleanup()

    r = asyncio.run(go())
    assert hits["n"] == 2 and r.status.value == "found"


# ---- reports -------------------------------------------------------------------------------------
def _meta():
    r = dict(_acct("GitHub", "ice"), evidence=["username ตรงกับที่ค้น"], checked_at="2026-10-07T10:00:00+00:00")
    ident = identity_summary([r], ["ice"])
    findings = build_findings([r], ident)
    graph = {"nodes": [{"id": "user:ice", "type": "username", "label": "ice", "query": "input"},
                       {"id": "acct:github/ice", "type": "account", "label": "GitHub @ice"}],
             "edges": [{"source": "user:ice", "target": "acct:github/ice", "kind": "found", "label": "พบบัญชี"}]}
    meta = {"usernames": ["ice"], "identity": ident, "findings": findings, "graph": graph,
            "timeline": [{"date": "2026-10-07T10:00:00", "kind": "run", "title": "ค้นหาครั้งนี้", "detail": "",
                          "site": "", "url": "", "node": ""}],
            "changes": [{"site": "GitHub", "username": "ice", "url": r["url"], "field": "bio", "kind": "changed",
                         "old": "a", "new": "b", "label": "Bio", "detected_at": "2026-10-07"}],
            "summary": {"targets": ["ice"], "accounts_found": 1, "linked_accounts": 0, "evidence": 3, "high": 0,
                        "medium": 0, "low": 1, "changes": 1}}
    return [r], meta


def test_markdown_and_html_reports():
    results, meta = _meta()
    md = report.to_md(results, meta)
    assert "# Sleuth Report: ice" in md and "## หลักฐาน (Findings)" in md and "## Timeline" in md
    assert "a → b" in md
    html = report.to_html(results, meta)
    assert 'id="f-acct-github-ice"' in html and 'href="#f-acct-github-ice"' in html   # graph node -> evidence
    assert "First seen" in html and "การเปลี่ยนแปลงของโปรไฟล์" in html
    assert "<script" not in html


def test_pdf_without_browser_explains(monkeypatch):
    monkeypatch.setattr(report, "find_browser", lambda: None)
    try:
        report.to_pdf("<p>x</p>")
    except RuntimeError as e:
        assert "Chrome" in str(e)
    else:
        raise AssertionError("expected RuntimeError")


# ---- plugins -------------------------------------------------------------------------------------
PLUGIN = '''
from sleuth.scan.core import Module

class Mastodon(Module):
    name = "mastodon_test"
    title = "Mastodon"
    watches = ("USERNAME",)

    async def handle(self, event, ctx):
        yield event.child("SOCIAL_PROFILE", "https://mastodon.social/@" + event.data, self.name)
'''


def test_plugins_load_from_folders(tmp_path):
    (tmp_path / "social").mkdir()
    (tmp_path / "social" / "mastodon.py").write_text(PLUGIN, encoding="utf-8")
    (tmp_path / "broken.py").write_text("raise RuntimeError('boom')", encoding="utf-8")
    (tmp_path / "dupe.py").write_text(PLUGIN.replace("mastodon_test", "accounts"), encoding="utf-8")
    (tmp_path / "_helper.py").write_text("raise SystemExit", encoding="utf-8")   # skipped
    classes, errors = load_plugins([tmp_path])
    assert [c.name for c in classes] == ["mastodon_test"]
    assert classes[0].group == "social" and classes[0]().info()["plugin"].endswith("mastodon.py")
    assert any("boom" in e for e in errors) and any("already used" in e for e in errors)


# ---- web API ---------------------------------------------------------------------------------------
def test_web_api_mutations_history_and_markdown(tmp_path):
    from sleuth.web import create_app

    async def go():
        client = TestClient(TestServer(create_app(history=str(tmp_path / "h.db"))))
        await client.start_server()
        try:
            muts = await (await client.get("/api/mutations?u=ice4564")).json()
            hist = await (await client.get("/api/history?u=ice4564")).json()
            results, meta = _meta()
            resp = await client.post("/api/report/md", json={"results": results, **meta})
            md = await resp.text()
            return muts, hist, resp.status, md
        finally:
            await client.close()

    muts, hist, status, md = asyncio.run(go())
    assert {"ice_4564", "ice4564x"} <= {m["username"] for m in muts}
    assert hist["enabled"] and hist["runs"] == []
    assert status == 200 and "Findings" in md
    json.dumps(muts)
