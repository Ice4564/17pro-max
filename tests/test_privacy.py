"""Category B: data retention (purge) and report redaction."""

from sleuth import report
from sleuth.history import History


def _r(site, user, status="found", **info):
    return {"site": site, "username": user, "url": f"https://{site}/{user}", "status": status, "info": info,
            "checked_at": "2026-10-07T10:00:00+00:00"}


def test_purge_target_removes_everything(tmp_path):
    h = History(tmp_path / "h.db")
    h.record_run(["ice"], [_r("GitHub", "ice", bio="hi"), _r("Reddit", "ice")])
    h.record_run(["bob"], [_r("GitHub", "bob")])
    h.watch_add("ice", 24)
    h.watch_done("ice", 1, [{"field": "bio", "site": "GitHub", "username": "ice", "kind": "changed", "old": "a", "new": "b"}])
    assert h.list_runs("ice") and h.intel_search("ice")["accounts"]
    deleted = h.purge_target("ice")
    assert deleted.get("runs", 0) >= 1 and "accounts" in deleted
    assert h.list_runs("ice") == [] and h.intel_search("ice")["accounts"] == []
    assert [w["target"] for w in h.watch_list()] == [] and h.alerts() == []
    assert h.list_runs("bob"), "unrelated target must survive"      # bob untouched
    h.close()


def test_purge_old_and_wipe(tmp_path):
    h = History(tmp_path / "h.db")
    h.record_run(["ice"], [_r("GitHub", "ice")], started="2000-01-01T00:00:00+00:00")
    h.record_run(["bob"], [_r("GitHub", "bob")])  # today
    old = h.purge_older_than(365)
    assert old.get("runs", 0) == 1 and len(h.list_runs()) == 1   # only the ancient run removed
    h.create_case("C", ["bob"]); h.watch_add("bob", 24)
    h.wipe()
    assert h.list_runs() == [] and h.list_cases() == [] and h.watch_list() == []
    assert h.intel_stats()["accounts"] == 0
    h.close()


def test_redaction_hides_pii():
    results = [_r("GitHub", "ice", bio="mail me ice@skymail.dev or call 081-234-5678",
                  avatar="https://x/a.jpg", name="Ice Cold")]
    meta = {"usernames": ["ice"],
            "findings": [{"id": "email:ice@skymail.dev", "kind": "email", "title": "ice@skymail.dev",
                          "url": "mailto:ice@skymail.dev", "source": "เผยแพร่บน GitHub @ice",
                          "first_seen": "", "last_checked": "",
                          "evidence": [{"type": "origin", "text": "พบบน GitHub ice@skymail.dev", "url": None, "ok": True}],
                          "confidence": 60, "level": "medium"}],
            "intel": {"images": [{"site": "GitHub", "username": "ice", "reverse": {"google": "g"}}],
                      "phones": [{"number": "0812345678", "sources": ["GitHub"]}], "crypto": [], "languages": [], "bots": []},
            "redact": True}
    for fmt in ("json", "md", "html", "csv", "txt"):
        out = report.render(fmt, results, meta)
        assert "ice@skymail.dev" not in out, f"{fmt} leaked the e-mail"
        assert "0812345678" not in out, f"{fmt} leaked the phone"
        assert "https://x/a.jpg" not in out, f"{fmt} leaked the avatar"
    html = report.to_html(results, meta)
    assert "ปิดบังข้อมูล" in html and "i***@skymail.dev" in html   # banner + masked form shown
    # without redact, the data is present
    meta["redact"] = False
    assert "ice@skymail.dev" in report.to_json(results, meta)


def test_web_purge_and_redact_endpoints(tmp_path):
    import asyncio
    from aiohttp.test_utils import TestClient, TestServer
    from sleuth.web import create_app

    async def go():
        client = TestClient(TestServer(create_app(history=str(tmp_path / "h.db"))))
        await client.start_server()
        try:
            h = client.app["history"]
            h.record_run(["ice"], [_r("GitHub", "ice", bio="x")])
            del_resp = await (await client.delete("/api/target/ice")).json()
            md = await (await client.post("/api/report/md", json={
                "results": [_r("GitHub", "ice", bio="ice@skymail.dev")], "usernames": ["ice"], "redact": True})).text()
            return del_resp, md
        finally:
            await client.close()

    deleted, md = asyncio.run(go())
    assert "deleted" in deleted
    assert "ice@skymail.dev" not in md
