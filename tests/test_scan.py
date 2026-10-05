"""Offline tests for the SpiderFoot-style scan engine (fake modules, no network)."""

import asyncio

from sleuth.scan import ScanConfig, Scanner, Store, detect_target, run_scan
from sleuth.scan.core import Module
from sleuth.scan.modules.web import decode_cfemail, match_social
from sleuth.scan.report import to_html


class FakeDNS(Module):
    name = "dns"
    watches = ("DOMAIN_NAME", "INTERNET_NAME")

    async def handle(self, event, ctx):
        if event.type == "DOMAIN_NAME":
            yield event.child("INTERNET_NAME", "www." + event.data, self.name)
            yield event.child("INTERNET_NAME", "evil.other.com", self.name)  # out of scope
            yield event.child("INTERNET_NAME", event.data, self.name)        # the root itself
        if ctx.in_scope(event.data):
            yield event.child("IP_ADDRESS", "93.184.216.34", self.name)       # duplicate across hosts


class FakeEmailSec(Module):
    name = "emailsec"
    watches = ("DOMAIN_NAME",)

    async def handle(self, event, ctx):
        yield event.child("SPF_RECORD", "v=spf1 +all", self.name, all="+")


class FakePorts(Module):
    name = "internetdb"
    watches = ("IP_ADDRESS",)

    async def handle(self, event, ctx):
        yield event.child("OPEN_PORT", f"{event.data}:3306", self.name, port=3306)
        yield event.child("VULNERABILITY", "CVE-2099-0001", self.name)


class Broken(Module):
    name = "broken"
    watches = ("DOMAIN_NAME",)

    async def handle(self, event, ctx):
        raise ValueError("boom")
        yield  # pragma: no cover


def collect(target, modules):
    async def go():
        return [m async for m in Scanner(target, modules, ScanConfig()).run()]
    return asyncio.run(go())


def test_detect_target():
    assert detect_target("https://www.Example.com/path") == ("DOMAIN_NAME", "example.com")
    assert detect_target("8.8.8.8") == ("IP_ADDRESS", "8.8.8.8")
    assert detect_target("2001:4860::8888")[0] == "IPV6_ADDRESS"
    assert detect_target("Bob@Example.com") == ("EMAIL", "bob@example.com")
    assert detect_target("@torvalds") == ("USERNAME", "torvalds")


def test_event_flow_scope_dedupe_and_errors():
    msgs = collect("example.com", [FakeDNS(), FakeEmailSec(), FakePorts(), Broken()])
    events = [m["event"] for m in msgs if m["type"] == "event"]
    data = [(e["type"], e["data"]) for e in events]
    assert ("INTERNET_NAME", "www.example.com") in data
    assert ("INTERNET_NAME", "example.com") not in data          # root not duplicated
    assert data.count(("IP_ADDRESS", "93.184.216.34")) == 1      # deduplicated
    assert ("OPEN_PORT", "93.184.216.34:3306") in data           # chained through IP
    evil = [e for e in events if e["data"] == "evil.other.com"][0]
    assert not [e for e in events if e["parent"] == evil["id"]]  # out of scope: not expanded
    errors = [m for m in msgs if m["type"] == "module_error"]
    assert errors and errors[0]["module"] == "broken"            # scan survives a broken module
    rules = {m["rule"] for m in msgs if m["type"] == "finding"}
    assert {"spf_plus_all", "no_dmarc", "cves", "risky_ports", "subdomains"} <= rules
    assert msgs[-1]["type"] == "done"


def test_store_roundtrip_and_report(tmp_path):
    store = Store(tmp_path / "scans.db")

    async def go():
        return [m async for m in run_scan("example.com", [FakeDNS(), FakePorts()], ScanConfig(), store)]

    msgs = asyncio.run(go())
    scan_id = msgs[0]["scan_id"]
    scan = store.get_scan(scan_id)
    assert scan["status"] == "finished"
    assert len(scan["events"]) == len([m for m in msgs if m["type"] == "event"])
    assert scan["findings"]
    assert store.list_scans()[0]["id"] == scan_id
    html = to_html(scan)
    assert "example.com" in html and "CVE-2099-0001" in html
    assert store.delete_scan(scan_id) and store.get_scan(scan_id) is None
    store.close()


def test_web_helpers():
    # "a@b.co" obfuscated with key 0x42
    key = 0x42
    encoded = f"{key:02x}" + "".join(f"{ord(c) ^ key:02x}" for c in "a@b.co")
    assert decode_cfemail(encoded) == "a@b.co"
    assert match_social("https://twitter.com/ThePSF") == ("X (Twitter)", "ThePSF")
    assert match_social("https://www.facebook.com/sharer") is None
    assert match_social("https://github.com/python") == ("GitHub", "python")
