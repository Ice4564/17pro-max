"""Planner, entity resolution, contradictions, explainability, dedup, history DB, cases, watchlist, replay."""

import asyncio

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from sleuth import contradictions as contra, report, websearch
from sleuth.engine import SearchConfig, Searcher, make_session
from sleuth.evidence import build_graph
from sleuth.history import History, diff_profile
from sleuth.identity import clusters, entities, handle_core
from sleuth.linker import apply_contradictions, explain, identity_summary
from sleuth.planner import plan
from sleuth.sites import Site
from sleuth.watch import run_due


def _acct(site, user, query="input", **info):
    return {"site": site, "username": user, "url": f"https://{site.lower()}.example/{user}", "status": "found",
            "info": info, "links": [], "via": [], "query": query, "evidence": [], "checks": []}


async def _serve(app):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"


# ---- 16 explainability ---------------------------------------------------------------
def test_points_add_up_to_the_score():
    score, rows = explain([{"label": "a", "p": 0.25}, {"label": "b", "p": 0.4}, {"label": "c", "p": 0.6}])
    assert sum(r["points"] for r in rows) == score and rows[0]["label"] == "c"
    ident = identity_summary([_acct("A", "ice", name="Ice Cold"), _acct("B", "ice2", name="Ice Cold")], ["ice"])
    for i in ident:
        assert sum(x["points"] for x in i["signals"]) == i["score"]
        assert i["fp_risk"] in ("LOW", "MEDIUM", "HIGH")


def test_contradiction_points_are_negative():
    ident = identity_summary([_acct("A", "ice4564", name="Ice Cold")], ["ice4564"])
    before = ident[0]["score"]
    apply_contradictions(ident, {("a", "ice4564"): ["ที่อยู่ / ประเทศไม่ตรงกัน"]})
    neg = [x for x in ident[0]["signals"] if x["points"] < 0]
    assert neg and ident[0]["score"] == before + neg[0]["points"] and ident[0]["fp_risk"] == "HIGH"


# ---- 12 entity resolution ---------------------------------------------------------------
def test_handle_core_groups_spellings():
    assert {handle_core(u) for u in ("ice4564", "Ice4564", "ice_4564", "ice4564x", "real.ice4564")} == {"ice4564"}
    assert handle_core("alex") == "alex"


def test_entities_merge_families_through_evidence():
    gh = _acct("GitHub", "ice4564")
    rd = _acct("Reddit", "ice4564x")
    ig = dict(_acct("Instagram", "ice.photos", query="discovered"), linked=True, via=["acct:github/ice4564"])
    other = _acct("Chess", "someoneelse")
    res = [gh, rd, ig, other]
    ident = identity_summary(res, ["ice4564"])
    cl = clusters(res, [], [])
    ents = entities(res, cl, ident, ["ice4564"])
    first = ents[0]
    assert {a["site"] for a in first["accounts"]} == {"GitHub", "Reddit", "Instagram"}
    assert "ice4564x" in first["aliases"] and first["evidence_based"]
    assert any("ตระกูลเดียวกัน" in r for r in first["reasons"])
    lone = next(e for e in ents if e["aliases"] == ["someoneelse"])
    assert not lone["evidence_based"] and lone["confidence"] <= 40


# ---- 13 contradictions --------------------------------------------------------------------------
def test_contradiction_detector():
    a = _acct("GitHub", "ice", location="Bangkok, Thailand", name="Ice Cold")
    b = _acct("Profile", "ice_", location="Tokyo, Japan", name="Ice Cold")
    cl = [{"id": "identity-1", "accounts": [{"id": "acct:github/ice", "site": "GitHub", "username": "ice"},
                                            {"id": "acct:profile/ice_", "site": "Profile", "username": "ice_"}],
           "confidence": 80, "reasons": []}]
    found = contra.detect([a, b], cl, [], [{"domain": "x.dev", "personal": True, "timezone": "America/New_York",
                                            "via": ["acct:github/ice"]}])
    loc = next(c for c in found if c["field"] == "location")
    assert {"TH", "JP"} <= {k for k in ("TH", "JP", "US") if contra.COUNTRY_TH[k] in loc["message"]}
    assert "สหรัฐฯ" in loc["message"]                      # the website's timezone counts too
    assert cl[0]["confidence"] < 80 and cl[0]["warning"]
    assert contra.country_of("กรุงเทพมหานคร") == "TH" and contra.country_of("Alexandria") is None


# ---- 15 dedup ------------------------------------------------------------------------------------
def test_same_url_from_many_queries_is_one_hit():
    page = ('<div class="result results_links"><h2><a class="result__a" href="https://www.example.com/ice/">Ice</a></h2>'
            '<a class="result__snippet" href="#">ice4564</a></div>')

    async def go():
        app = web.Application()

        async def ok(_):
            return web.Response(text=page, content_type="text/html")
        app.router.add_get("/s", ok)
        runner, base = await _serve(app)
        try:
            eng = [websearch.Engine("E", base + "/s?q={q}", websearch.parse_duckduckgo)]
            async with make_session(SearchConfig()) as s:
                return await websearch.search(s, ["ice4564"], max_queries=3, delay=0, engines=eng)
        finally:
            await runner.cleanup()

    out = asyncio.run(go())
    assert len(out["hits"]) == 1 and len(out["hits"][0]["found_by"]) == 3
    assert websearch.url_key("https://www.Example.com/ice/?utm_source=x") == websearch.url_key("http://example.com/ice")
    assert websearch.build_query("ice", "instagram", "bkk", "2025-01-01") == '"ice" bkk site:instagram.com after:2025-01-01'


# ---- 14 evidence graph ---------------------------------------------------------------------------
def test_every_edge_carries_evidence():
    r = dict(_acct("GitHub", "ice"), checks=[{"check": "username", "ok": True, "detail": "x"}], http_status=200)
    g = build_graph([r], {"ice": {"username": "ice", "query": "input", "from": []}}, [], [])
    e = g["edges"][0]
    assert e["id"] == "edge-1" and e["n"] == 1 and any("HTTP 200" in x for x in e["evidence"])


# ---- 11 planner ------------------------------------------------------------------------------------
def test_planner_picks_steps_from_evidence():
    gh = dict(_acct("GitHub", "ice4564", website="https://example.com", bio="mail ice@example.com"),
              discovered=["Reddit: ice4564x"])
    steps = plan(["ice4564"], [gh], domains=[{"domain": "example.com", "personal": True, "status": "ok", "source": "GitHub"}],
                 skipped=[{"username": "ice4564x", "why": "ลิงก์จากโปรไฟล์ GitHub", "source": "acct:github/ice4564"}],
                 options={"depth": 0, "variants": False, "web_search": False})
    kinds = {s["id"].split(":")[0] for s in steps}
    assert {"variants", "follow", "follow-links", "scan", "query-domain", "websearch"} <= kinds
    assert all(s["why"] and s["action"]["type"] for s in steps)
    assert steps[0]["priority"] == "high"
    q = next(s for s in steps if s["id"].startswith("query-domain"))
    assert '"ice4564" "example.com"' in [x["query"] for x in q["action"]["queries"]]


# ---- 17 / 19 / 20 history: new accounts, link + username changes, intel ------------------------------
def test_link_and_username_changes():
    old = {"links": ["Instagram: ice", "GitHub: ice4564"]}
    new = {"links": ["Instagram: ice.new", "GitHub: ice4564", "TikTok: ice_tt"]}
    got = {(c["field"], c["kind"]) for c in diff_profile("found", old, None, "found", new, None)}
    assert ("username", "changed") in got and ("links", "added") in got


def _r(site, user, status="found", **info):
    return {"site": site, "username": user, "url": f"https://{site}/{user}", "status": status, "info": info,
            "checked_at": "2026-10-07T10:00:00+00:00"}


def test_intel_db_cases_watchlist_and_new_accounts(tmp_path):
    h = History(tmp_path / "h.db")
    h.record_run(["ice"], [_r("GitHub", "ice", bio="mail ice@ice.dev")],
                 domains=[{"domain": "ice.dev", "personal": True, "emails": ["ice@ice.dev"], "via": []}],
                 hits=[{"engine": "Bing", "query": '"ice"', "rank": 1, "url": "https://x.com/ice", "username": "ice",
                        "mentions": True, "found_by": [{"engine": "Bing", "query": '"ice"', "rank": 1}]}],
                 graph={"edges": [{"source": "user:ice", "target": "acct:github/ice", "kind": "found", "label": "พบ",
                                   "evidence": ["HTTP 200"]}]})
    second = h.record_run(["ice"], [_r("GitHub", "ice", bio="mail ice@ice.dev"), _r("Reddit", "ice")],
                          hits=[{"engine": "DuckDuckGo", "query": '"ice" site:x.com', "rank": 2, "url": "https://www.x.com/ice/",
                                 "username": "ice", "mentions": True}])
    assert [c["field"] for c in second["changes"]] == ["account"]          # Reddit is new
    found = h.intel_search("ice")
    assert found["domains"][0]["domain"] == "ice.dev" and found["emails"][0]["email"] == "ice@ice.dev"
    assert len(found["urls"]) == 1 and len(found["urls"][0]["found_by"]) == 2   # same URL across runs: one row
    assert found["relationships"][0]["evidence"] == ["HTTP 200"]
    assert h.username_history({"ice"}, lambda u: u.lower())[0]["username"] == "ice"
    # cases
    cid = h.create_case("Case #001", ["ice"])
    h.save_payload(second["run_id"], {"results": [], "done": {"summary": {"accounts_found": 2}, "timeline": []}})
    h.update_case(cid, notes="ดูต่อ", add_run=second["run_id"])
    case = h.get_case(cid)
    assert case["notes"] == "ดูต่อ" and case["runs"][0]["summary"]["accounts_found"] == 2 and case["changes"]
    assert h.get_run(second["run_id"])["payload"]["done"]["summary"]["accounts_found"] == 2
    # watchlist
    h.watch_add("ice", 6)
    assert [w["target"] for w in h.watch_due()] == ["ice"]
    h.watch_done("ice", second["run_id"], second["changes"])
    assert h.watch_due() == [] and h.alerts(unseen_only=True)[0]["changes"][0]["field"] == "account"
    assert h.mark_alerts_seen() == 1 and h.alerts(unseen_only=True) == []
    h.close()


# ---- 19 watch runner + 23 replay, end to end ----------------------------------------------------------
def test_watch_run_reports_only_changes(tmp_path):
    state = {"bio": "hello"}

    async def go():
        app = web.Application()

        async def prof(req):
            u = req.match_info["u"]
            if u != "ice4564":
                return web.Response(status=404, text="no")
            return web.Response(text=f'<title>{u}</title><meta property="og:description" content="{state["bio"]} world">'
                                     f'<p>@{u}</p>', content_type="text/html")
        app.router.add_get("/p/{u}", prof)
        runner, base = await _serve(app)
        h = History(tmp_path / "h.db")
        sites = [Site.from_dict("P", {"url": base + "/p/{}"})]
        try:
            h.watch_add("ice4564", 1, {"depth": 0, "avatars": False})
            first = await run_due(h, sites, sites)
            state["bio"] = "changed"
            second = await run_due(h, sites, sites, ["ice4564"])
            alerts = h.alerts()
            run = h.get_run(second[0]["run_id"])
            return first, second, alerts, run
        finally:
            h.close()
            await runner.cleanup()

    first, second, alerts, run = asyncio.run(go())
    assert first[0]["changes"] == [] and [c["field"] for c in second[0]["changes"]] == ["bio"]
    assert len(alerts) == 1
    replay = run["payload"]["done"]["replay"]
    assert [x["action"] for x in replay][:2] == ["ค้น username", "พบบัญชี"] and replay[-1]["action"] == "วางแผนขั้นต่อไป"


# ---- web API -------------------------------------------------------------------------------------------
def test_workspace_api(tmp_path):
    from sleuth.web import create_app

    async def go():
        client = TestClient(TestServer(create_app(history=str(tmp_path / "h.db"))))
        await client.start_server()
        try:
            cid = (await (await client.post("/api/cases", json={"name": "Case A", "targets": ["ice"]})).json())["id"]
            await client.patch(f"/api/cases/{cid}", json={"notes": "n1"})
            case = await (await client.get(f"/api/cases/{cid}")).json()
            await client.post("/api/watch", json={"target": "@ice", "interval_hours": 12})
            watch = await (await client.get("/api/watch")).json()
            intel = await (await client.get("/api/intel?q=ice")).json()
            q = await (await client.post("/api/query", json={"username": "ice", "platform": "github", "dry_run": True})).json()
            page = await client.get("/workspace")
            md = await (await client.post("/api/report/md", json={
                "results": [], "usernames": ["ice"],
                "contradictions": [{"label": "ที่อยู่ไม่ตรงกัน", "scope_label": "x", "message": "m", "values": []}],
                "plan": [{"n": 1, "title": "ค้นต่อ", "why": "เพราะ", "priority": "high", "action": {}}]})).text()
            return case, watch, intel, q, page.status, md
        finally:
            await client.close()

    case, watch, intel, q, status, md = asyncio.run(go())
    assert case["notes"] == "n1" and case["targets"] == ["ice"]
    assert watch["items"][0]["target"] == "ice" and watch["items"][0]["interval_hours"] == 12
    assert "accounts" in intel["results"] and intel["stats"]["cases"] == 1
    assert q["queries"][0]["query"] == '"ice" site:github.com' and "google.com" in q["links"][0]["google"]
    assert status == 200 and "Contradictory evidence" in md and "Next searches" in md


def test_html_report_has_new_sections():
    meta = {"contradictions": [{"label": "ชื่อจริงไม่ตรงกัน", "scope_label": "x", "message": "m", "values": []}],
            "entities": [{"title": "Possible identity #1", "confidence": 70, "aliases": ["ice", "ice_"], "accounts": [],
                          "reasons": ["r"], "evidence_based": True, "contradictions": []}],
            "plan": [{"n": 1, "title": "t", "why": "w", "priority": "high", "action": {}}],
            "replay": [{"s": 0.1, "action": "ค้น username", "detail": "d"}],
            "graph": {"nodes": [{"id": "a", "type": "username", "label": "a", "query": "input"},
                                {"id": "b", "type": "account", "label": "b"}],
                      "edges": [{"source": "a", "target": "b", "kind": "links", "label": "ลิงก์", "evidence": ["e1"], "n": 1}]}}
    html = report.to_html([], meta)
    for text in ("Contradictory evidence detected", "Possible identity #1", "Next searches", "Investigation replay",
                 'id="edge-1"', 'href="#edge-1"'):
        assert text in html
    assert "<script" not in html
