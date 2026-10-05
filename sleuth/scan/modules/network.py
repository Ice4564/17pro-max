"""Registration data, IP intelligence and TLS certificate modules."""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from collections.abc import AsyncIterator
from datetime import datetime, timezone

from ..core import Context, Event, Module


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _vcard_name(entity: dict) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] == "fn" and item[3]:
            return str(item[3])
    return None


class RDAPDomain(Module):
    name = "rdap_domain"
    title = "WHOIS / RDAP (โดเมน)"
    description = "ผู้รับจด วันจด และวันหมดอายุของโดเมน จากระบบ RDAP (WHOIS รุ่นใหม่)"
    category = "infra"
    watches = ("DOMAIN_NAME",)

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        status, data, _ = await ctx.get(f"https://rdap.org/domain/{event.data}", json=True, timeout=20)
        if status != 200 or not isinstance(data, dict):
            return  # many ccTLDs (e.g. .th) have no public RDAP
        for ev in data.get("events", []):
            action, date = ev.get("eventAction"), str(ev.get("eventDate", ""))[:10]
            if action == "registration" and date:
                yield event.child("DOMAIN_REGISTERED", date, self.name)
            elif action == "expiration" and date:
                yield event.child("DOMAIN_EXPIRES", date, self.name)
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                name = _vcard_name(ent)
                if name:
                    yield event.child("DOMAIN_REGISTRAR", name, self.name)
        for ns in data.get("nameservers", []):
            if ns.get("ldhName"):
                yield event.child("DNS_NS", ns["ldhName"].lower().rstrip("."), self.name)


class RDAPNetwork(Module):
    name = "rdap_ip"
    title = "WHOIS / RDAP (IP)"
    description = "หาว่า IP นี้อยู่ในเครือข่ายของใคร (ช่วง IP และองค์กรเจ้าของ)"
    category = "infra"
    watches = ("IP_ADDRESS", "IPV6_ADDRESS")

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        if not _is_public(event.data) or not ctx.take("ip", event.data, ns=self.name):
            return
        status, data, _ = await ctx.get(f"https://rdap.org/ip/{event.data}", json=True, timeout=20)
        if status != 200 or not isinstance(data, dict):
            return
        owner = None
        for ent in data.get("entities", []):
            if {"registrant", "administrative"} & set(ent.get("roles", [])):
                owner = _vcard_name(ent)
                if owner:
                    break
        cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in data.get("cidr0_cidrs", [])]
        rng = cidrs[0] if cidrs else f"{data.get('startAddress', '')} - {data.get('endAddress', '')}"
        label = owner or data.get("name") or "unknown"
        yield event.child("NETBLOCK_OWNER", f"{label} ({rng})", self.name, ip=event.data,
                          network=data.get("name"), country=data.get("country"))


class IPGeo(Module):
    name = "ipgeo"
    title = "IP geolocation"
    description = "ประเทศ เมือง และผู้ให้บริการ (ASN) ของ IP จาก ipwho.is"
    category = "infra"
    watches = ("IP_ADDRESS", "IPV6_ADDRESS")

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        if not _is_public(event.data) or not ctx.take("ip", event.data, ns=self.name):
            return
        status, d, _ = await ctx.get(f"https://ipwho.is/{event.data}", json=True, timeout=15)
        if status != 200 or not isinstance(d, dict) or not d.get("success"):
            return
        place = ", ".join(x for x in (d.get("city"), d.get("region"), d.get("country")) if x)
        if place:
            yield event.child("GEOINFO", place, self.name, ip=event.data, country_code=d.get("country_code"),
                              lat=d.get("latitude"), lon=d.get("longitude"))
        conn = d.get("connection") or {}
        if conn.get("asn"):
            yield event.child("ASN", f"AS{conn['asn']} {conn.get('org') or conn.get('isp') or ''}".strip(),
                              self.name, ip=event.data, isp=conn.get("isp"))


class ShodanInternetDB(Module):
    name = "internetdb"
    title = "Shodan InternetDB"
    description = "พอร์ตที่เปิด ซอฟต์แวร์ และช่องโหว่ CVE ที่ Shodan เคยสแกนพบ (ข้อมูล passive เราไม่ได้สแกนเอง)"
    category = "security"
    watches = ("IP_ADDRESS",)

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        if not _is_public(event.data) or not ctx.take("ip", event.data, ns=self.name):
            return
        status, d, _ = await ctx.get(f"https://internetdb.shodan.io/{event.data}", json=True, timeout=15)
        if status != 200 or not isinstance(d, dict):
            return
        for port in d.get("ports", []):
            yield event.child("OPEN_PORT", f"{event.data}:{port}", self.name, ip=event.data, port=port)
        for cve in d.get("vulns", []):
            yield event.child("VULNERABILITY", cve, self.name, ip=event.data,
                              url=f"https://nvd.nist.gov/vuln/detail/{cve}")
        for cpe in d.get("cpes", []):
            # cpe:/a:vendor:product:version -> "product version"
            parts = cpe.removeprefix("cpe:/").split(":")
            label = " ".join(parts[2:4] if len(parts) > 2 else parts[1:]).replace("_", " ")
            yield event.child("WEB_TECH", label, self.name, ip=event.data, cpe=cpe)
        for host in d.get("hostnames", []):
            if ctx.in_scope(host):
                yield event.child("INTERNET_NAME", host.lower(), self.name)


class SSLCert(Module):
    name = "sslcert"
    title = "SSL certificate"
    description = "อ่าน certificate ของเว็บ: ผู้ออก วันหมดอายุ และชื่อโฮสต์อื่นใน certificate"
    category = "security"
    watches = ("DOMAIN_NAME", "INTERNET_NAME")

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        host = event.data.lower()
        if not ctx.take("ssl", host):
            return
        context = ssl.create_default_context()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 443, ssl=context, server_hostname=host), timeout=10)
        except ssl.SSLCertVerificationError as e:
            yield event.child("SSL_CERT_INVALID", f"{host}: {e.verify_message}", self.name, host=host)
            return
        except (OSError, asyncio.TimeoutError):
            return  # no HTTPS on this host
        try:
            cert = writer.get_extra_info("peercert") or {}
        finally:
            writer.close()
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
        yield event.child("SSL_CERT", f"{host} · {issuer.get('organizationName') or issuer.get('commonName')} · "
                          f"หมดอายุ {expires:%Y-%m-%d}", self.name, host=host, expires=f"{expires:%Y-%m-%d}",
                          days_left=days, issuer=issuer.get("organizationName"))
        for kind, name in cert.get("subjectAltName", ()):
            name = name.lower().removeprefix("*.")
            if kind == "DNS" and name != host and ctx.in_scope(name):
                yield event.child("INTERNET_NAME", name, self.name)
