"""Identity modules: emails, usernames and the accounts that belong to them."""

from __future__ import annotations

import hashlib
import re
from collections.abc import AsyncIterator
from urllib.parse import quote

from ...engine import SearchConfig, Searcher
from ...sites import load_sites
from ..core import WEBMAIL, Context, Event, Module

GENERIC_LOCAL_PARTS = {
    "info", "admin", "contact", "support", "sales", "hello", "noreply", "no-reply", "help", "office",
    "mail", "email", "webmaster", "postmaster", "hostmaster", "abuse", "security", "privacy", "billing",
    "hr", "jobs", "careers", "marketing", "press", "media", "team", "service", "cs", "enquiry", "inquiry",
    "feedback", "legal", "news", "newsletter", "booking", "reservations", "orders", "account", "accounts",
}


class EmailParse(Module):
    name = "email_parse"
    title = "แยกข้อมูลจากอีเมล"
    description = "ใช้ส่วนหน้า @ ของอีเมลเป็น username และเก็บโดเมนของอีเมล"
    category = "identity"
    watches = ("EMAIL",)

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        local, _, domain = event.data.lower().partition("@")
        handle = local.split("+")[0]
        if (handle not in GENERIC_LOCAL_PARTS and 3 <= len(handle) <= 30
                and re.fullmatch(r"[a-z0-9._-]+", handle) and not handle.isdigit()):
            yield event.child("USERNAME", handle, self.name, source=f"email {event.data}")
        if event.type == "EMAIL" and event.module == "root" and domain not in WEBMAIL:
            yield event.child("DOMAIN_NAME", domain, self.name)
        elif not ctx.in_scope(domain) and domain not in WEBMAIL:
            yield event.child("LINKED_DOMAIN", domain, self.name, source=event.data)


class Gravatar(Module):
    name = "gravatar"
    title = "Gravatar"
    description = "โปรไฟล์ Gravatar ที่ผูกกับอีเมล (ชื่อ, รูป, บัญชีโซเชียลที่ลิงก์ไว้)"
    category = "identity"
    watches = ("EMAIL",)

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        if not ctx.take("email", event.data, ns=self.name):
            return
        md5 = hashlib.md5(event.data.strip().lower().encode()).hexdigest()
        status, data, _ = await ctx.get(f"https://en.gravatar.com/{md5}.json", json=True, timeout=15)
        if status != 200 or not isinstance(data, dict) or not data.get("entry"):
            return
        e = data["entry"][0]
        yield event.child("GRAVATAR", e.get("profileUrl") or f"https://gravatar.com/{md5}", self.name,
                          avatar=e.get("thumbnailUrl"), display_name=e.get("displayName"))
        name = (e.get("name") or {}).get("formatted") or e.get("displayName")
        if name:
            yield event.child("HUMAN_NAME", name, self.name, source="Gravatar")
        if e.get("preferredUsername"):
            yield event.child("USERNAME", e["preferredUsername"], self.name, source="Gravatar")
        for acc in e.get("accounts", []):
            if acc.get("url"):
                yield event.child("SOCIAL_PROFILE", acc["url"], self.name, platform=acc.get("shortname"),
                                  handle=acc.get("username"))
                if acc.get("username"):
                    yield event.child("USERNAME", acc["username"], self.name, source=f"Gravatar {acc.get('shortname')}")


class PGPKey(Module):
    name = "pgp"
    title = "PGP keyserver"
    description = "อีเมลนี้มี PGP key บน keys.openpgp.org หรือไม่ (มีแปลว่าอีเมลใช้งานจริงและยืนยันแล้ว)"
    category = "identity"
    watches = ("EMAIL",)

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        if not ctx.take("email", event.data, ns=self.name):
            return
        url = f"https://keys.openpgp.org/vks/v1/by-email/{quote(event.data)}"
        status, text, _ = await ctx.get(url, timeout=15)
        if status == 200 and "BEGIN PGP PUBLIC KEY" in text:
            yield event.child("PGP_KEY", f"keys.openpgp.org: {event.data}", self.name, url=url)


class Accounts(Module):
    name = "accounts"
    title = "ค้นบัญชีจาก username"
    description = "เอา username ไปค้นบนทุกเว็บในฐานข้อมูล (ระบบเดียวกับโหมดค้น username)"
    category = "identity"
    watches = ("USERNAME",)

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        username = event.data.strip().lstrip("@")
        # the scan's own target is always searched; extra usernames use the budget
        if event.module != "root" and not ctx.take("username", username.lower()):
            return
        sites = load_sites()
        searcher = Searcher(sites, SearchConfig(timeout=ctx.cfg.timeout, depth=0, concurrency=30))
        async for ev in searcher.run([username]):
            if ev["type"] != "result" or ev["status"] != "found":
                continue
            if ev.get("linked"):
                # e.g. an Instagram/TikTok/Facebook link published on a found profile
                yield event.child("SOCIAL_PROFILE", ev["url"], self.name, platform=ev["site"],
                                  handle=ev["username"], evidence=ev.get("evidence", []))
                if ev["username"].lower() != username.lower():
                    yield event.child("USERNAME", ev["username"], self.name, source=f"{ev['site']} link")
            else:
                yield event.child("ACCOUNT", ev["url"], self.name, site=ev["site"], username=username,
                                  info=ev.get("info", {}), tags=ev.get("tags", []))
