"""Cross-platform linking: link-in-bio pages, bio mentions, variants, identity."""

import asyncio
import json

from aiohttp import web

from sleuth.engine import SearchConfig, Searcher
from sleuth.linker import find_social, identity_summary, match_social, variants
from sleuth.sites import Site

TREE = """<html><head><meta property="og:title" content="Alice Example"></head><body>
<script id="__NEXT_DATA__" type="application/json">{json}</script></body></html>"""


def make_app():
    links = {"props": {"links": [
        {"url": "https://www.instagram.com/alice.ig/"},
        {"url": "https://www.tiktok.com/@alice_tt"},
        {"url": "https://www.facebook.com/sharer/sharer.php?u=x"},   # not a profile
    ]}, "bio": "fb: alice.fb.page | twitter @alice_x"}

    async def tree(req):
        if req.match_info["u"] != "alice":
            return web.Response(status=404, text="no")
        return web.Response(text=TREE.format(json=json.dumps(links)), content_type="text/html")

    async def code(req):
        u = req.match_info["u"]
        if u in ("alice", "alice.ig", "aliceig"):
            return web.Response(text=f'<meta property="og:title" content="Alice Example"><p>@{u}</p>',
                                content_type="text/html")
        return web.Response(status=404, text="no")

    app = web.Application()
    app.router.add_get("/tree/{u}", tree)
    app.router.add_get("/code/{u}", code)
    return app


async def _search(usernames, **cfg):
    runner = web.AppRunner(make_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    try:
        sites = [
            Site.from_dict("Tree", {"url": base + "/tree/{}"}),
            Site.from_dict("Code", {"url": base + "/code/{}"}),
            Site.from_dict("Instagram", {"url": "https://www.instagram.com/{}/", "check": "manual"}),
            Site.from_dict("TikTok", {"url": "https://www.tiktok.com/@{}", "check": "manual"}),
            Site.from_dict("Facebook", {"url": "https://www.facebook.com/{}", "check": "manual",
                                        "regex": "^[A-Za-z0-9.]{5,50}$"}),
        ]
        s = Searcher(sites, SearchConfig(timeout=5, retries=0, archive=False, avatars=False, **cfg))
        events = [e async for e in s.run(usernames)]
        return s, events
    finally:
        await runner.cleanup()


def test_link_in_bio_finds_instagram_tiktok_facebook():
    s, events = asyncio.run(_search(["alice"], depth=1))
    final = {(r.site, r.username): r for r in s.results}
    ig = final[("Instagram", "alice.ig")]
    assert ig.status.value == "found" and ig.linked
    assert ig.evidence == ["ลิงก์จากโปรไฟล์ Tree (@alice)"]
    assert final[("TikTok", "alice_tt")].linked
    fb = final[("Facebook", "alice.fb.page")]
    assert fb.linked and "bio" in fb.evidence[0]
    # the manual placeholder for the searched username is still offered
    assert final[("Instagram", "alice")].status.value == "manual"
    # the IG handle is followed on the other sites
    assert final[("Code", "alice.ig")].status.value == "found"
    ident = {(i["site"], i["username"]): i for i in events[-1]["identity"]}
    assert ident[("Instagram", "alice.ig")]["confidence"] == "high"
    assert ident[("Code", "alice")]["confidence"] == "medium"   # same full name as Tree


def test_variants_search():
    s, _ = asyncio.run(_search(["alice.ig"], depth=0, variants=True))
    found = {(r.site, r.username) for r in s.results if r.status.value == "found"}
    assert ("Code", "aliceig") in found


def test_helpers():
    assert match_social("https://twitter.com/jack") == ("X (Twitter)", "jack")
    assert match_social("instagram.com/natgeo") == ("Instagram", "natgeo")
    assert match_social("https://www.instagram.com/p/abc123/") is None
    assert match_social("https://m.facebook.com/profile.php?id=4") is None
    got = {(s.platform, s.handle, s.how) for s in find_social([], "IG: @nat.geo ✦ ติ๊กต็อก @natgeo_tt ✦ เฟส: NatGeoTH")}
    assert got == {("Instagram", "nat.geo", "bio"), ("TikTok", "natgeo_tt", "bio"), ("Facebook", "NatGeoTH", "bio")}
    assert variants("john.doe") == ["johndoe", "john_doe", "john-doe"]
    assert variants("alice") == []
    assert variants("bob123") == ["bob_123", "bob.123", "bob-123", "bob", "bob1234", "123bob"]
    assert variants("123sky") == ["123_sky", "123.sky", "123-sky", "sky123"]
    assert variants("bob129") == ["bob_129", "bob.129", "bob-129", "bob", "129bob"]  # not a run: no 1210


def test_identity_names_must_be_full_names():
    res = [
        {"site": "A", "username": "selena", "url": "a", "status": "found", "info": {"name": "Selena"}},
        {"site": "B", "username": "selena", "url": "b", "status": "found", "info": {"name": "Selena"}},
        {"site": "C", "username": "sg", "url": "c", "status": "found", "info": {"name": "Selena Gomez"}},
        {"site": "D", "username": "selenag", "url": "d", "status": "found", "info": {"name": "Selena Gomez"}},
    ]
    conf = {i["site"]: i["confidence"] for i in identity_summary(res, ["selena"])}
    assert conf == {"A": "low", "B": "low", "C": "medium", "D": "medium"}


def test_avatar_hash_matches_resized_copy():
    import io
    from PIL import Image, ImageDraw
    from sleuth.avatars import dhash

    def png(size, shift=0):
        img = Image.new("RGB", (200, 200), "white")
        d = ImageDraw.Draw(img)
        d.ellipse((40 + shift, 30, 160 + shift, 150), fill="navy")
        d.rectangle((20, 150, 120, 190), fill="orange")
        buf = io.BytesIO(); img.resize((size, size)).save(buf, "PNG")
        return buf.getvalue()

    a, b = dhash(png(200)), dhash(png(64))           # same picture, different size
    c = dhash(png(200, shift=-35))                     # different picture
    assert bin(a ^ b).count("1") <= 6
    assert bin(a ^ c).count("1") > 6
    flat = io.BytesIO(); Image.new("RGB", (50, 50), "gray").save(flat, "PNG")
    assert dhash(flat.getvalue()) is None             # placeholder avatars are ignored
