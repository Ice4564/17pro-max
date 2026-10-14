"""Infrastructure intelligence: CT logs, Shodan, DNS history, subdomains,
WHOIS history, ASN & IP geolocation.

All lookups use public APIs that don't require authentication unless noted.
API-key functions gracefully degrade when no key is provided.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import aiohttp

# ---- constants ----------------------------------------------------------

CRT_SH = "https://crt.sh/"
SHODAN_API = "https://api.shodan.io"
DNSGOOGLE = "https://dns.google/resolve"
HACKERTARGET = "https://api.hackertarget.com"
IPINFO = "https://ipinfo.io"

# ---- data classes -------------------------------------------------------


@dataclass
class CTRecord:
    """A Certificate Transparency log entry."""

    domain: str
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    cert_id: int = 0


@dataclass
class ShodanResult:
    """Shodan lookup result for an IP."""

    ip: str
    ports: list[int] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    org: str = ""
    isp: str = ""
    location: str = ""
    hostnames: list[str] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class DNSRecord:
    """A single DNS record."""

    type: str
    value: str
    ttl: int = 0


@dataclass
class Subdomain:
    """A discovered subdomain."""

    name: str
    source: str = ""
    ip: str = ""
    resolved: bool = False


@dataclass
class WHOISInfo:
    """WHOIS lookup result."""

    domain: str
    registrar: str = ""
    created: str = ""
    updated: str = ""
    expires: str = ""
    name_servers: list[str] = field(default_factory=list)
    registrant: str = ""
    emails: list[str] = field(default_factory=list)
    raw: str = ""


@dataclass
class IPGeoInfo:
    """IP geolocation and network info."""

    ip: str
    city: str = ""
    region: str = ""
    country: str = ""
    org: str = ""
    asn: str = ""
    hostname: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = ""


# ========================================================================
# 1. Certificate Transparency (crt.sh)
# ========================================================================

async def ct_search(
    session: aiohttp.ClientSession,
    query: str,
    *,
    limit: int = 100,
) -> list[CTRecord]:
    """Search Certificate Transparency logs via crt.sh.

    *query* can be a domain (``example.com``), wildcard (``%.example.com``),
    or an email/identity to find in SAN fields.
    """
    params = {"q": query, "output": "json"}
    try:
        async with session.get(
            CRT_SH, params=params,
            timeout=aiohttp.ClientTimeout(total=45),
        ) as resp:
            if resp.status != 200:
                return []
            text = await resp.text()
            # crt.sh sometimes returns JSON with trailing commas / newlines
            text = re.sub(r",\s*]", "]", text)
            text = re.sub(r",\s*}", "}", text)
            data = json.loads(text)
    except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):
        return []

    records: list[CTRecord] = []
    seen: set[str] = set()
    for entry in data[:limit]:
        name = entry.get("name_value", "").split("\n")[0].lower()
        if name in seen:
            continue
        seen.add(name)
        records.append(CTRecord(
            domain=name,
            issuer=entry.get("issuer_name", ""),
            not_before=entry.get("not_before", ""),
            not_after=entry.get("not_after", ""),
            cert_id=entry.get("id", 0),
        ))
    return records


async def ct_find_domains_for_email(
    session: aiohttp.ClientSession,
    email: str,
) -> list[str]:
    """Find domains whose certificates reference *email* in SAN fields."""
    records = await ct_search(session, email)
    domains: set[str] = set()
    for r in records:
        if "@" not in r.domain:
            domains.add(r.domain)
    return sorted(domains)


# ========================================================================
# 2. Shodan
# ========================================================================

async def shodan_lookup(
    session: aiohttp.ClientSession,
    ip: str,
    *,
    api_key: str | None = None,
) -> ShodanResult:
    """Look up an IP on Shodan. Requires an API key for full results.

    Without a key, returns basic info only (using the free endpoint).
    """
    if api_key:
        url = f"{SHODAN_API}/shodan/host/{ip}"
        params = {"key": api_key}
    else:
        # Free endpoint — limited but no key needed
        url = f"{SHODAN_API}/shodan/host/{ip}"
        params = {}

    try:
        async with session.get(
            url, params=params,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            if resp.status == 404:
                return ShodanResult(ip=ip, error="no results")
            if resp.status == 401:
                return ShodanResult(ip=ip, error="API key required")
            if resp.status != 200:
                return ShodanResult(ip=ip, error=f"HTTP {resp.status}")
            data = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        return ShodanResult(ip=ip, error=str(e))

    return ShodanResult(
        ip=ip,
        ports=data.get("ports", []),
        services=[
            {"port": p, "service": data.get("data", [{}])[0].get("product", "")}
            for p in data.get("ports", [])
        ],
        org=data.get("org", ""),
        isp=data.get("isp", ""),
        location=f"{data.get('city', '')}, {data.get('country_name', '')}",
        hostnames=data.get("hostnames", []),
        vulnerabilities=list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", []),
    )


async def shodan_search_domains(
    session: aiohttp.ClientSession,
    domains: list[str],
    *,
    api_key: str | None = None,
) -> dict[str, ShodanResult]:
    """Look up Shodan info for all IPs resolved from *domains*."""
    results: dict[str, ShodanResult] = {}
    for domain in domains:
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            continue
        results[domain] = await shodan_lookup(session, ip, api_key=api_key)
    return results


# ========================================================================
# 3. DNS resolution & history
# ========================================================================

async def dns_resolve(
    session: aiohttp.ClientSession,
    name: str,
    *,
    record_type: str = "A",
) -> list[DNSRecord]:
    """Resolve DNS records via Google DNS-over-HTTPS."""
    params = {"name": name, "type": record_type}
    try:
        async with session.get(
            DNSGOOGLE, params=params,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return []

    records: list[DNSRecord] = []
    for ans in data.get("Answer", []):
        records.append(DNSRecord(
            type=ans.get("type", 0) == 1 and "A" or ans.get("type", 0) == 28 and "AAAA" or "TXT",
            value=ans.get("data", ""),
            ttl=ans.get("TTL", 0),
        ))
    return records


async def dns_all_records(
    session: aiohttp.ClientSession, domain: str
) -> dict[str, list[DNSRecord]]:
    """Resolve A, AAAA, MX, NS, TXT, CNAME for *domain*."""
    types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    results: dict[str, list[DNSRecord]] = {}
    tasks = [dns_resolve(session, domain, record_type=t) for t in types]
    resolved = await asyncio.gather(*tasks, return_exceptions=True)
    for t, recs in zip(types, resolved):
        if isinstance(recs, Exception):
            results[t] = []
        else:
            results[t] = recs
    return results


# ========================================================================
# 4. Subdomain enumeration
# ========================================================================

async def subdomains_from_ct(
    session: aiohttp.ClientSession, domain: str
) -> list[Subdomain]:
    """Find subdomains via Certificate Transparency logs."""
    records = await ct_search(session, f"%.{domain}")
    subs: set[str] = set()
    for r in records:
        for name in r.domain.split("\n"):
            name = name.strip().lower()
            if name.endswith(domain) and name != domain:
                subs.add(name.removeprefix("*."))
    return [Subdomain(name=s, source="crt.sh") for s in sorted(subs)]


async def subdomains_from_hackertarget(
    session: aiohttp.ClientSession, domain: str
) -> list[Subdomain]:
    """Find subdomains via HackerTarget API (free, rate-limited)."""
    url = f"{HACKERTARGET}/hostsearch/?q={domain}"
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                return []
            text = await resp.text()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return []

    subs: list[Subdomain] = []
    for line in text.strip().split("\n"):
        parts = line.split(",")
        if len(parts) >= 2:
            subs.append(Subdomain(name=parts[0], ip=parts[1], source="hackertarget", resolved=True))
    return subs


async def enumerate_subdomains(
    session: aiohttp.ClientSession, domain: str
) -> list[Subdomain]:
    """Enumerate subdomains from multiple sources."""
    ct_task = subdomains_from_ct(session, domain)
    ht_task = subdomains_from_hackertarget(session, domain)
    ct_subs, ht_subs = await asyncio.gather(ct_task, ht_task, return_exceptions=True)

    if isinstance(ct_subs, Exception):
        ct_subs = []
    if isinstance(ht_subs, Exception):
        ht_subs = []

    # Merge, deduplicate
    seen: set[str] = set()
    merged: list[Subdomain] = []
    for s in ct_subs + ht_subs:
        if s.name not in seen:
            seen.add(s.name)
            merged.append(s)
    return merged


# ========================================================================
# 5. WHOIS (via hackertarget)
# ========================================================================

async def whois_lookup(
    session: aiohttp.ClientSession, domain: str
) -> WHOISInfo:
    """Look up WHOIS info for *domain*."""
    url = f"{HACKERTARGET}/whois/?q={domain}"
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            if resp.status != 200:
                return WHOISInfo(domain=domain)
            text = await resp.text()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return WHOISInfo(domain=domain)

    info = WHOISInfo(domain=domain, raw=text)
    # Parse common WHOIS fields
    for line in text.split("\n"):
        line = line.strip()
        low = line.lower()
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip().lower()
        val = val.strip()
        if not val:
            continue
        if "registrar" in key and not info.registrar:
            info.registrar = val
        elif "creation" in key or "created" in key:
            if not info.created:
                info.created = val
        elif "updated" in key or "changed" in key:
            if not info.updated:
                info.updated = val
        elif "expiry" in key or "expires" in key or "registry expiry" in key:
            if not info.expires:
                info.expires = val
        elif "name server" in key:
            info.name_servers.append(val)
        elif "registrant" in key and "name" in key:
            if not info.registrant:
                info.registrant = val
        elif "@" in val:
            info.emails.append(val)

    return info


# ========================================================================
# 6. IP geolocation
# ========================================================================

async def ip_geolocate(
    session: aiohttp.ClientSession, ip: str
) -> IPGeoInfo:
    """Geolocate an IP via ipinfo.io (free tier: 50k req/month)."""
    url = f"{IPINFO}/{ip}/json"
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status != 200:
                return IPGeoInfo(ip=ip)
            data = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return IPGeoInfo(ip=ip)

    loc = data.get("loc", "0,0").split(",")
    lat = float(loc[0]) if len(loc) == 2 else 0.0
    lon = float(loc[1]) if len(loc) == 2 else 0.0

    return IPGeoInfo(
        ip=ip,
        city=data.get("city", ""),
        region=data.get("region", ""),
        country=data.get("country", ""),
        org=data.get("org", ""),
        hostname=data.get("hostname", ""),
        latitude=lat,
        longitude=lon,
        timezone=data.get("timezone", ""),
    )


async def ip_geolocate_batch(
    session: aiohttp.ClientSession,
    ips: list[str],
    *,
    max_concurrent: int = 5,
) -> dict[str, IPGeoInfo]:
    """Geolocate multiple IPs with concurrency limit."""
    sem = asyncio.Semaphore(max_concurrent)

    async def _one(ip: str) -> tuple[str, IPGeoInfo]:
        async with sem:
            return ip, await ip_geolocate(session, ip)

    results = await asyncio.gather(*[_one(ip) for ip in ips])
    return dict(results)


# ========================================================================
# 7. Combined infrastructure scan
# ========================================================================

async def infra_scan(
    session: aiohttp.ClientSession,
    domain: str,
    *,
    shodan_key: str | None = None,
) -> dict[str, Any]:
    """Run a full infrastructure scan on *domain*.

    Returns CT records, DNS records, subdomains, WHOIS, and IP geo.
    """
    ct_task = ct_search(session, f"%.{domain}")
    dns_task = dns_all_records(session, domain)
    sub_task = enumerate_subdomains(session, domain)
    whois_task = whois_lookup(session, domain)

    ct_records, dns_records, subdomains, whois_info = await asyncio.gather(
        ct_task, dns_task, sub_task, whois_task,
        return_exceptions=True,
    )

    # Resolve domain to IP and geolocate
    try:
        ip = socket.gethostbyname(domain)
        geo = await ip_geolocate(session, ip)
    except (socket.gaierror, Exception):
        ip = ""
        geo = None

    # Shodan lookup if we have an IP
    shodan = None
    if ip:
        shodan = await shodan_lookup(session, ip, api_key=shodan_key)

    return {
        "domain": domain,
        "ct_records": ct_records if not isinstance(ct_records, Exception) else [],
        "dns": dns_records if not isinstance(dns_records, Exception) else {},
        "subdomains": subdomains if not isinstance(subdomains, Exception) else [],
        "whois": whois_info if not isinstance(whois_info, Exception) else WHOISInfo(domain=domain),
        "ip": ip,
        "geo": geo,
        "shodan": shodan,
    }


# ---- helpers ------------------------------------------------------------

def is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_valid_domain(s: str) -> bool:
    return bool(re.match(
        r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
        s.lower(),
    ))
