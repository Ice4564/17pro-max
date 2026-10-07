"""Offline tests: a local aiohttp server pretends to be several sites."""

import asyncio
import json

from aiohttp import web

from sleuth import report
from sleuth.engine import SearchConfig, Searcher, Status
from sleuth.extractor import extract
from sleuth.sites import Site, load_sites

PROFILE_HTML = """<html><head>
<title>Alice (@alice) | Status</title>
<meta property="og:title" content="Alice Example">
<meta property="og:description" content="I build things">
<meta property="og:image" content="/avatars/alice.png">
<script type="application/ld+json">{"@type":"Person","name":"Alice Example","address":"Bangkok",
 "sameAs":["https://msg.test/alice_alt"]}</script>
</head><body>
<a rel="me nofollow" href="https://code.test/alice-code">code</a>
<a href="https://ads.example.com/whatever">ad</a>
</body></html>"""


def make_app() -> web.Application:
    known = {"alice", "alice-code", "alice_alt"}

    async def code(req):  # status_code site
        return web.Response(text=PROFILE_HTML if req.match_info["u"] in known else "nope",
                            status=200 if req.match_info["u"] in known else 404, content_type="text/html")

    async def msg(req):  # message site: always 200
        u = req.match_info["u"]
        return web.Response(text=f"profile of {u}" if u in known else "Sorry, no such user.", content_type="text/html")

    async def redir(req):  # response_url site
        if req.match_info["u"] in known:
            return web.Response(text=f"profile of {req.match_info['u']}")
        raise web.HTTPFound("/missing")

    async def api(req):  # JSON API, POST
        body = await req.json()
        u = body["user"]
        if u in known:
            return web.json_response({"data": {"login": u, "followers_count": 42, "created_at": 1500000000}})
        return web.json_response({"data": None})

    async def missing(req):
        return web.Response(text="missing")

    async def waf(req):
        return web.Response(text="<title>Just a moment...</title>", status=403, content_type="text/html")

    app = web.Application()
    app.router.add_get("/code/{u}", code)
    app.router.add_get("/msg/{u}", msg)
    app.router.add_get("/r/{u}", redir)
    app.router.add_get("/missing", missing)
    app.router.add_post("/api", api)
    app.router.add_get("/waf/{u}", waf)
    return app


def make_sites(base: str) -> list[Site]:
    raw = {
        "Code": {"url": base + "/code/{}", "check": "status_code"},
        "Msg": {"url": base + "/msg/{}", "check": "message", "error_msg": "no such user"},
        "Redir": {"url": base + "/r/{}", "check": "response_url", "regex": "^[a-z_-]+$"},
        "Api": {"url": base + "/u/{}", "probe": base + "/api", "method": "POST",
                "json": {"user": "{}"}, "check": "message", "error_msg": "\"data\": null"},
        "Waf": {"url": base + "/waf/{}", "check": "status_code"},
    }
    sites = [Site.from_dict(k, v) for k, v in raw.items()]
    # pretend profile links to code.test / msg.test belong to our sites
    sites.append(Site.from_dict("CodeHost", {"url": "https://code.test/{}", "check": "status_code"}))
    sites.append(Site.from_dict("MsgHost", {"url": "https://msg.test/{}", "check": "status_code"}))
    return sites


async def _run(usernames, depth=0):
    runner = web.AppRunner(make_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    try:
        all_sites = make_sites(base)
        searchable = all_sites[:5]
        s = Searcher(searchable, SearchConfig(timeout=5, depth=depth, retries=0, archive=False, avatars=False), all_sites=all_sites)
        events = [ev async for ev in s.run(usernames)]
        return events
    finally:
        await runner.cleanup()


def by_site(events, username):
    return {e["site"]: e for e in events if e["type"] == "result" and e["username"] == username}


def test_detection_methods():
    events = asyncio.run(_run(["alice", "nobody"]))
    a, n = by_site(events, "alice"), by_site(events, "nobody")
    for name in ("Code", "Msg", "Redir", "Api"):
        assert a[name]["status"] == "found", name
        assert n[name]["status"] == "not_found", name
    assert a["Waf"]["status"] == "unknown" and "anti-bot" in a["Waf"]["error"]
    assert events[-1]["type"] == "done"


def test_regex_marks_illegal():
    events = asyncio.run(_run(["Bad.Name"]))
    assert by_site(events, "Bad.Name")["Redir"]["status"] == "illegal"


def test_extraction_and_recursion():
    events = asyncio.run(_run(["alice"], depth=1))
    code = by_site(events, "alice")["Code"]
    assert code["info"]["name"] == "Alice Example"
    assert code["info"]["bio"] == "I build things"
    assert code["info"]["location"] == "Bangkok"
    assert code["info"]["avatar"].endswith("/avatars/alice.png")
    discovered = {e["username"] for e in events if e["type"] == "discovered"}
    assert discovered == {"alice-code", "alice_alt"}  # ad link ignored
    assert by_site(events, "alice-code")["Code"]["status"] == "found"
    api = by_site(events, "alice")["Api"]
    assert api["info"]["followers"] == "42" and api["info"]["created"] == "2017-07-14"


def test_extract_json_and_links():
    info, strong, _ = extract(json.dumps({"user": {"display_name": "Bob", "bio": "hi",
                                                  "links": ["https://github.com/bob"]}}),
                              "application/json", "https://example.org/api")
    assert info == {"name": "Bob", "bio": "hi"}
    assert strong == ["https://github.com/bob"]


def test_match_link():
    gh = Site.from_dict("GitHub", {"url": "https://github.com/{}", "regex": "^[a-zA-Z0-9-]{1,39}$"})
    assert gh.match_link("https://www.github.com/octocat/") == "octocat"
    assert gh.match_link("https://github.com/login") is None
    assert gh.match_link("https://github.com/octocat/repo") is None
    tb = Site.from_dict("Tumblr", {"url": "https://{}.tumblr.com/"})
    assert tb.match_link("https://staff.tumblr.com") == "staff"


def test_bundled_database_loads():
    sites = load_sites(include_disabled=True)
    assert len(sites) > 50
    assert len({s.name for s in sites}) == len(sites)
    for s in sites:
        assert s.valid(s.claimed), f"{s.name}: claimed username fails its own regex"


def test_reports_render():
    events = asyncio.run(_run(["alice"]))
    results = [e for e in events if e["type"] == "result"]
    for fmt in report.FORMATS:
        out = report.render(fmt, results)
        assert "alice" in out
    assert "<script" not in report.to_html(results).split("<style>")[0]
