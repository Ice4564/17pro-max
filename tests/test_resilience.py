"""C: external-API modules degrade gracefully (no key / network failure = empty, never a crash).
   D: API-key settings store (env + file), values never leaked."""

import asyncio

import aiohttp
import pytest

from sleuth import settings


# ---- D: settings store ----------------------------------------------------------
def test_keys_from_file_and_env(tmp_path, monkeypatch):
    kf = tmp_path / "keys.json"
    monkeypatch.setattr(settings, "KEYS_FILE", kf)
    assert settings.load_keys() == {} and settings.get_key("shodan") is None
    settings.save_keys({"shodan": "abc123", "github": "", "unknown_x": "y"})
    assert settings.get_key("shodan") == "abc123" and "unknown_x" not in settings.load_keys()
    st = settings.status()
    assert st["shodan"]["set"] and st["shodan"]["source"] == "file" and "abc123" not in str(st)   # no value leak
    monkeypatch.setenv("SLEUTH_SHODAN_KEY", "env-wins")
    assert settings.get_key("shodan") == "env-wins" and settings.status()["shodan"]["source"] == "env"
    settings.save_keys({"shodan": ""})   # removal
    monkeypatch.delenv("SLEUTH_SHODAN_KEY")
    assert settings.get_key("shodan") is None


# ---- C: graceful degradation ----------------------------------------------------
def test_infra_scan_survives_total_network_failure():
    from sleuth.infra_intel import infra_scan

    async def go():
        # a session pointed at a dead port: every request raises
        async with aiohttp.ClientSession() as s:
            return await infra_scan(s, "nonexistent.invalid", shodan_key=None)

    r = asyncio.run(go())  # must not raise
    assert r["domain"] == "nonexistent.invalid"
    assert r["ct_records"] == [] and r["subdomains"] == [] and isinstance(r["dns"], dict)


def _no_intel(r) -> bool:
    """True if the result carries no actual data (any string error field is fine)."""
    if r is None or r == [] or r == {} or r == "":
        return True
    if isinstance(r, list):
        return len(r) == 0
    if isinstance(r, dict):
        return all(not v for v in r.values())
    d = getattr(r, "__dict__", None)          # dataclass: every collection field empty
    if d is not None:
        return all(not v for v in d.values() if isinstance(v, (list, tuple, dict, set)))
    return False


@pytest.mark.parametrize("call", [
    lambda s: __import__("sleuth.infra_intel", fromlist=["shodan_lookup"]).shodan_lookup(s, "8.8.8.8", api_key=None),
    lambda s: __import__("sleuth.infra_intel", fromlist=["dns_all_records"]).dns_all_records(s, "x.invalid"),
    lambda s: __import__("sleuth.archive", fromlist=["wayback_snapshots"]).wayback_snapshots(s, "http://x.invalid/u"),
    lambda s: __import__("sleuth.deepsearch", fromlist=["search_reddit"]).search_reddit(s, "zzqqx"),
])
def test_network_calls_return_empty_without_crashing(call):
    async def go():
        async with aiohttp.ClientSession() as s:
            return await call(s)

    assert _no_intel(asyncio.run(go()))       # the point: no exception escapes, no data invented


def test_shodan_without_key_does_not_call_network():
    from sleuth.infra_intel import shodan_lookup

    async def go():
        async with aiohttp.ClientSession() as s:
            return await shodan_lookup(s, "8.8.8.8", api_key=None)

    r = asyncio.run(go())
    assert not r.ports and not r.services and "key" in r.error.lower()


def test_web_settings_endpoint_never_returns_values(tmp_path, monkeypatch):
    from aiohttp.test_utils import TestClient, TestServer
    from sleuth.web import create_app

    monkeypatch.setattr(settings, "KEYS_FILE", tmp_path / "keys.json")

    async def go():
        client = TestClient(TestServer(create_app()))
        await client.start_server()
        try:
            await client.post("/api/settings", json={"keys": {"shodan": "secret-value-123"}})
            got = await (await client.get("/api/settings")).json()
            return got
        finally:
            await client.close()

    got = asyncio.run(go())
    assert got["status"]["shodan"]["set"] and "secret-value-123" not in str(got)
