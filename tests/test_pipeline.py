"""Candidate -> verification -> recursion (profiles + domains) -> correlation."""

import asyncio
import json

from aiohttp import web

from sleuth import report
from sleuth.engine import SearchConfig, Searcher
from sleuth.similarity import compare, connections
from sleuth.sites import Site

PROFILE = """<html><head><title>{u} on Code</title>
<link rel="canonical" href="{base}/code/{u}">
<meta property="og:title" content="Sky Walker">
<meta property="og:description" content="Building tiny games and pixel art tools in Bangkok">
<script type="application/json">{{"user": {{"website": "{home}/"}}}}</script>
</head><body><h1>@{u}</h1><a rel="me" href="{home}/">my site</a></body></html>"""

HOME = """<html><head><title>Sky's homepage</title></head><body>
<a href="https://www.instagram.com/sky.pixels/">Instagram</a>
<a href="{base}/code/skypixel">Code</a>
<a href="{base}/code/sky123">my main Code account</a>
</body></html>"""


async def _serve(app: web.Application):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"


async def _search(usernames, **cfg):
    sites_app, home_app = web.Application(), web.Application()
    known = {"sky123", "sky_123", "skypixel"}
    urls = {}

    async def code(req):
        u = req.match_info["u"]
        if u not in known:
            return web.Response(status=404, text="no")
        home = urls["home"] if u == "sky123" else "https://example.invalid"
        return web.Response(text=PROFILE.format(u=u, base=urls["base"], home=home), content_type="text/html")

    async def soft404(req):  # answers 200 for everyone
        u = req.match_info["u"]
        if u in known:
            return web.Response(text=f"<title>{u}</title><p>{u}</p>", content_type="text/html")
        return web.Response(text="<title>Page not found</title>", content_type="text/html")

    async def shell(req):  # SPA shell: 200 and the same page for any username
        return web.Response(text="<title>App</title><div id=root></div>", content_type="text/html")

    async def to_home(req):  # missing users get redirected to the front page
        u = req.match_info["u"]
        if u in known:
            return web.Response(text=f"<title>{u}</title>", content_type="text/html")
        raise web.HTTPFound("/")

    async def front(req):
        return web.Response(text="<title>Welcome</title>", content_type="text/html")

    async def home(req):
        return web.Response(text=HOME.format(base=urls["base"]), content_type="text/html")

    sites_app.router.add_get("/code/{u}", code)
    sites_app.router.add_get("/soft/{u}", soft404)
    sites_app.router.add_get("/shell/{u}", shell)
    sites_app.router.add_get("/redir/{u}", to_home)
    sites_app.router.add_get("/", front)
    home_app.router.add_get("/", home)
    r1, base = await _serve(sites_app)
    r2, urls["home"] = await _serve(home_app)
    urls["base"] = base
    try:
        sites = [
            Site.from_dict("Code", {"url": base + "/code/{}"}),
            Site.from_dict("Soft", {"url": base + "/soft/{}"}),
            Site.from_dict("Shell", {"url": base + "/shell/{}"}),
            Site.from_dict("Redir", {"url": base + "/redir/{}"}),
            Site.from_dict("Instagram", {"url": "https://www.instagram.com/{}/", "check": "manual"}),
        ]
        s = Searcher(sites, SearchConfig(timeout=5, retries=0, archive=False, avatars=False, **cfg))
        events = [e async for e in s.run(usernames)]
        return s, events
    finally:
        await r1.cleanup()
        await r2.cleanup()


def _final(s):
    return {(r.site, r.username): r for r in s.results}


def test_http_200_is_not_enough():
    s, _ = asyncio.run(_search(["sky123", "ghost999"], depth=0))
    f = _final(s)
    assert f[("Soft", "ghost999")].status.value == "not_found"       # title says "Page not found"
    assert f[("Shell", "ghost999")].status.value == "unknown"        # page never mentions the username
    assert f[("Shell", "sky123")].status.value == "unknown"
    assert f[("Redir", "ghost999")].status.value == "not_found"      # bounced to the front page
    ok = f[("Code", "sky123")]
    assert ok.status.value == "found" and ok.checked_at
    passed = {c["check"] for c in ok.checks if c["ok"]}
    assert {"canonical", "username"} <= passed


def test_candidates_are_labelled_and_kept_separate():
    s, events = asyncio.run(_search(["sky123"], depth=0, variants=True))
    f = _final(s)
    typed, guess = f[("Code", "sky123")], f[("Code", "sky_123")]
    assert typed.query == "input" and typed.candidate_of is None
    assert guess.query == "candidate" and guess.candidate_of == "sky123"
    assert "ระบบเดา" in guess.evidence[0]
    assert ("Instagram", "sky_123") not in f      # no manual checks for guesses
    assert ("Instagram", "sky123") in f
    ident = {(i["site"], i["username"]): i for i in events[-1]["identity"]}
    assert ident[("Code", "sky_123")]["query"] == "candidate"
    starts = {e["username"]: e["query"] for e in events if e["type"] == "start"}
    assert starts["sky123"] == "input" and starts["sky_123"] == "candidate"


def test_recursion_through_personal_domain():
    s, events = asyncio.run(_search(["sky123"], depth=1))
    f = _final(s)
    domains = [e for e in events if e["type"] == "domain"]
    assert len(domains) == 1 and domains[0]["status"] == "ok"
    assert set(domains[0]["found_links"]) == {"Instagram: sky.pixels", "Code: skypixel", "Code: sky123"}
    assert domains[0]["personal"]                                     # links back to Code/sky123
    ig = f[("Instagram", "sky.pixels")]
    assert ig.linked and "เว็บไซต์ 127.0.0.1" in ig.evidence[0]
    assert f[("Code", "skypixel")].status.value == "found"           # followed at depth 1
    graph = events[-1]["graph"]
    edges = {(e["source"], e["target"]) for e in graph["edges"]}
    assert ("user:sky123", "acct:code/sky123") in edges
    assert ("acct:code/sky123", "domain:127.0.0.1") in edges
    assert ("domain:127.0.0.1", "user:skypixel") in edges
    assert ("domain:127.0.0.1", "acct:instagram/sky.pixels") in edges


def test_depth_zero_skips_domains():
    _, events = asyncio.run(_search(["sky123"], depth=0))
    assert not [e for e in events if e["type"] == "domain"]


def _acct(site, user, **info):
    links = info.pop("links", [])
    return {"site": site, "username": user, "url": f"https://{site}/{user}", "status": "found",
            "info": info, "links": links}


def test_similarity_explains_score():
    a = _acct("GitHub", "sky123", name="Sky Walker", bio="Building tiny games and pixel art tools",
              website="https://sky.dev")
    b = _acct("Dev.to", "sky_123", name="Sky Walker", bio="Building tiny games & pixel-art tools",
              website="https://sky.dev/blog")
    c = compare(a, b, {("github", "sky123"): 0, ("dev.to", "sky_123"): (1 << 40) - 1})
    sig = {x["name"]: x["ok"] for x in c["signals"]}
    assert sig == {"username": True, "name": True, "bio": True, "website": True, "avatar": False}
    assert 80 <= c["confidence"] < 99                 # different avatar pulls it down
    same = compare(a, b)
    assert same["confidence"] > c["confidence"]


def test_username_only_pairs_are_not_connections():
    a, b = _acct("A", "sky123"), _acct("B", "sky123")
    assert connections([a, b]) == []
    fan1, fan2 = _acct("A", "selena", name="Selena Gomez"), _acct("B", "selena", name="Selena Gomez")
    assert connections([fan1, fan2]) == []           # same handle + same name: not enough on its own
    other = _acct("C", "sg_music", name="Selena Gomez")
    assert len(connections([fan1, other])) == 1      # different handle, same full name: worth a look
    junk = dict(_acct("C", "zed", links=["https://play.google.com/store"]))
    other = dict(_acct("D", "qux", links=["https://play.google.com/store"]))
    assert connections([junk, other]) == []          # app-store links prove nothing


def test_reports_include_evidence():
    s, events = asyncio.run(_search(["sky123"], depth=1, variants=True))
    done = events[-1]
    results = [r.to_dict() for r in s.results]
    meta = {"identity": done["identity"], "connections": done["connections"], "domains": done["domains"],
            "graph": done["graph"], "queries": done["queries"]}
    data = json.loads(report.to_json(results, meta))
    rec = next(r for r in data["results"] if r["site"] == "Code" and r["username"] == "sky123")
    for field in ("site", "username", "status", "url", "checked_at", "evidence", "checks", "query"):
        assert field in rec
    assert data["meta"]["graph"]["edges"]
    html = report.to_html(results, meta)
    assert "candidate" in html and "127.0.0.1" in html
    assert "<script" not in html.split("<style>")[0]
