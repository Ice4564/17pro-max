"""DNS, subdomain discovery and email-security modules.

DNS lookups go through DNS-over-HTTPS (Cloudflare, falling back to Google),
so no extra DNS library is needed and results don't depend on the local
resolver.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from urllib.parse import quote

from ..core import Context, Event, Module

DOH_SERVERS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")
RR_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}


async def doh(ctx: Context, name: str, rtype: str) -> list[str]:
    """Resolve ``name`` and return the record data strings for ``rtype``."""
    last_error: Exception | None = None
    for server in DOH_SERVERS:
        try:
            status, data, _ = await ctx.get(
                f"{server}?name={quote(name)}&type={rtype}", json=True, timeout=10,
                headers={"Accept": "application/dns-json"},
            )
        except Exception as e:  # try the next resolver
            last_error = e
            continue
        if status != 200 or not isinstance(data, dict):
            continue
        want = RR_TYPES[rtype]
        out = []
        for ans in data.get("Answer", []) or []:
            if ans.get("type") == want:
                out.append(str(ans.get("data", "")).strip())
        return out
    if last_error:
        raise last_error
    return []


def _host(value: str) -> str:
    return value.strip().rstrip(".").lower()


class DNSResolve(Module):
    name = "dns"
    title = "DNS records"
    description = "หา IP (A/AAAA), mail server (MX), name server (NS) และ TXT records ผ่าน DNS-over-HTTPS"
    category = "infra"
    watches = ("DOMAIN_NAME", "INTERNET_NAME")

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        host = _host(event.data)
        if event.type == "INTERNET_NAME" and not ctx.take("resolve", host):
            return
        a, aaaa = await asyncio.gather(doh(ctx, host, "A"), doh(ctx, host, "AAAA"))
        for ip in a:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                yield event.child("IP_ADDRESS", ip, self.name, host=host)
        for ip in aaaa:
            yield event.child("IPV6_ADDRESS", ip, self.name, host=host)
        if event.type != "DOMAIN_NAME":
            return
        mx, ns, txt = await asyncio.gather(doh(ctx, host, "MX"), doh(ctx, host, "NS"), doh(ctx, host, "TXT"))
        for rec in mx:
            parts = rec.split()
            yield event.child("DNS_MX", _host(parts[-1]), self.name, priority=parts[0] if len(parts) > 1 else "")
        for rec in ns:
            yield event.child("DNS_NS", _host(rec), self.name)
        for rec in txt:
            yield event.child("DNS_TXT", rec.strip('"').replace('" "', ""), self.name)


class EmailSecurity(Module):
    name = "emailsec"
    title = "Email security (SPF/DMARC)"
    description = "ตรวจ SPF และ DMARC ของโดเมน ซึ่งป้องกันการปลอมอีเมล"
    category = "security"
    watches = ("DOMAIN_NAME",)

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        domain = _host(event.data)
        txt, dmarc = await asyncio.gather(doh(ctx, domain, "TXT"), doh(ctx, f"_dmarc.{domain}", "TXT"))
        for rec in txt:
            rec = rec.strip('"').replace('" "', "")
            if rec.lower().startswith("v=spf1"):
                policy = re.search(r"([~\-+?])all\b", rec)
                yield event.child("SPF_RECORD", rec, self.name, all=policy.group(1) if policy else None)
        for rec in dmarc:
            rec = rec.strip('"').replace('" "', "")
            if rec.lower().startswith("v=dmarc1"):
                policy = re.search(r"\bp=(\w+)", rec)
                yield event.child("DMARC_RECORD", rec, self.name, policy=policy.group(1).lower() if policy else None)


class CertTransparency(Module):
    name = "crt"
    title = "Certificate Transparency"
    description = "หาซับโดเมนจากประวัติการออก SSL certificate (crt.sh และ CertSpotter)"
    category = "infra"
    watches = ("DOMAIN_NAME",)

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        domain = _host(event.data)
        names: set[str] = set()
        errors = []
        try:
            status, data, _ = await ctx.get(f"https://crt.sh/?q=%25.{quote(domain)}&output=json",
                                            json=True, timeout=45)
            if status == 200 and isinstance(data, list):
                for row in data:
                    names.update(str(row.get("name_value", "")).split("\n"))
        except Exception as e:
            errors.append(f"crt.sh: {type(e).__name__}")
        try:
            status, data, _ = await ctx.get(
                f"https://api.certspotter.com/v1/issuances?domain={quote(domain)}"
                "&include_subdomains=true&expand=dns_names", json=True, timeout=30)
            if status == 200 and isinstance(data, list):
                for row in data:
                    names.update(row.get("dns_names", []))
        except Exception as e:
            errors.append(f"certspotter: {type(e).__name__}")
        if not names and len(errors) == 2:
            raise RuntimeError("; ".join(errors))
        for name in sorted(names):
            host = _host(name).removeprefix("*.")
            if host != domain and ctx.in_scope(host) and "@" not in host:
                yield event.child("INTERNET_NAME", host, self.name)


class HackerTargetHosts(Module):
    name = "hackertarget"
    title = "HackerTarget host search"
    description = "หาซับโดเมนจากฐานข้อมูล passive DNS ของ HackerTarget (ฟรีวันละประมาณ 50 ครั้ง)"
    category = "infra"
    watches = ("DOMAIN_NAME",)

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        domain = _host(event.data)
        status, text, _ = await ctx.get(f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}", timeout=25)
        if status != 200 or "," not in text:
            if "API count exceeded" in text:
                raise RuntimeError("HackerTarget daily quota exceeded")
            return
        for line in text.splitlines():
            host = _host(line.split(",")[0])
            if host != domain and ctx.in_scope(host):
                yield event.child("INTERNET_NAME", host, self.name)
