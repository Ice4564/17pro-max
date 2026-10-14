"""Threat intelligence export: STIX 2.1, MISP, Maltego graph XML,
IOC extraction, and OpenCTI bundle.

All exports are pure-Python JSON/XML generators — no external deps.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from xml.sax.saxutils import escape as xml_escape

# ========================================================================
# 1. IOC (Indicator of Compromise) Extraction
# ========================================================================

# Patterns for extracting IOCs from text
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
IPV6_RE = re.compile(r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b", re.I)
URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+\.[A-Za-z]{2,}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
ETH_ADDR_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
BTC_ADDR_RE = re.compile(r"\b[bc1][a-z0-9]{25,39}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I)


@dataclass
class IOC:
    """An extracted Indicator of Compromise."""

    type: str
    value: str
    context: str = ""


def extract_iocs(text: str) -> list[dict[str, str]]:
    """Extract all IOCs from a text string.

    Returns a list of ``{"type": str, "value": str}`` dicts.
    """
    iocs: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    patterns = [
        ("ipv4", IPV4_RE),
        ("ipv6", IPV6_RE),
        ("url", URL_RE),
        ("email", EMAIL_RE),
        ("md5", MD5_RE),
        ("sha1", SHA1_RE),
        ("sha256", SHA256_RE),
        ("cve", CVE_RE),
        ("ethereum", ETH_ADDR_RE),
        ("bitcoin", BTC_ADDR_RE),
        ("domain", DOMAIN_RE),
    ]

    for ioc_type, pattern in patterns:
        for match in pattern.finditer(text):
            value = match.group(0)
            key = (ioc_type, value.lower())
            if key not in seen:
                seen.add(key)
                # Get surrounding context (50 chars each side)
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end].replace("\n", " ").strip()
                iocs.append({"type": ioc_type, "value": value, "context": context})

    return iocs


def extract_iocs_from_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract IOCs from all profile data in search results."""
    all_iocs: list[dict[str, Any]] = []
    for r in results:
        if r.get("status") != "found":
            continue
        info = r.get("info") or {}
        text = " ".join(str(v) for v in info.values())
        iocs = extract_iocs(text)
        for ioc in iocs:
            ioc["source"] = f"{r['site']} @{r['username']}"
            ioc["url"] = r.get("url", "")
            all_iocs.append(ioc)
    return all_iocs


# ========================================================================
# 2. STIX 2.1 Export
# ========================================================================

def _stix_id(type_: str, value: str) -> str:
    """Generate a deterministic STIX ID."""
    h = hashlib.sha256(f"{type_}--{value}".encode()).hexdigest()[:36]
    return f"{type_}--{h}"


def to_stix(
    results: list[dict[str, Any]],
    *,
    identity_name: str = "Sleuth",
) -> dict[str, Any]:
    """Export search results as a STIX 2.1 bundle.

    Returns a dict that can be json.dumps'd to a valid STIX bundle.
    """
    now = datetime.now(timezone.utc).isoformat()
    objects: list[dict[str, Any]] = []

    # Identity (the tool)
    identity_id = _stix_id("identity", identity_name)
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "name": identity_name,
        "identity_class": "system",
        "created": now,
        "modified": now,
    })

    for r in results:
        if r.get("status") != "found":
            continue
        site = r.get("site", "")
        username = r.get("username", "")
        url = r.get("url", "")
        info = r.get("info") or {}

        # Account as a Threat Actor / Identity
        acct_id = _stix_id("identity", f"{site}/{username}")
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": acct_id,
            "name": info.get("name", username),
            "identity_class": "individual",
            "created": now,
            "modified": now,
            "external_references": [{
                "source_name": site,
                "url": url,
                "external_id": username,
            }],
        })

        # Extract IOCs and add as indicators
        text = " ".join(str(v) for v in info.values())
        for ioc in extract_iocs(text):
            ind_id = _stix_id("indicator", ioc["value"])
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "pattern": f"[{ioc['type']}:value = '{ioc['value']}']",
                "pattern_type": "stix",
                "valid_from": now,
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
            })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


# ========================================================================
# 3. MISP Event Export
# ========================================================================

MISP_TYPE_MAP = {
    "ipv4": "ip-src",
    "ipv6": "ip-src",
    "url": "url",
    "email": "email-src",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "cve": "vulnerability",
    "domain": "domain",
    "bitcoin": "btc",
    "ethereum": "other",
}


def to_misp(
    results: list[dict[str, Any]],
    *,
    event_name: str = "Sleuth OSINT Investigation",
) -> dict[str, Any]:
    """Export search results as a MISP event JSON."""
    now = datetime.now(timezone.utc).isoformat()
    attributes: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for r in results:
        if r.get("status") != "found":
            continue
        site = r.get("site", "")
        username = r.get("username", "")
        url = r.get("url", "")
        info = r.get("info") or {}

        # Add the account URL as a link attribute
        key = ("url", url.lower())
        if key not in seen:
            seen.add(key)
            attributes.append({
                "category": "External analysis",
                "type": "link",
                "value": url,
                "comment": f"{site} @{username}",
                "to_ids": False,
            })

        # Add extracted IOCs
        text = " ".join(str(v) for v in info.values())
        for ioc in extract_iocs(text):
            misp_type = MISP_TYPE_MAP.get(ioc["type"], "other")
            key = (misp_type, ioc["value"].lower())
            if key not in seen:
                seen.add(key)
                attributes.append({
                    "category": "Network activity" if misp_type in ("ip-src", "url", "domain") else "Payload delivery",
                    "type": misp_type,
                    "value": ioc["value"],
                    "comment": f"from {site} @{username}",
                    "to_ids": True,
                })

    return {
        "Event": {
            "info": event_name,
            "date": now[:10],
            "threat_level_id": "3",
            "analysis": "1",
            "timestamp": str(int(datetime.now(timezone.utc).timestamp())),
            "Attribute": attributes,
            "Tag": [
                {"name": "osint", "colour": "#004646"},
                {"name": "sleuth", "colour": "#2f6fed"},
            ],
        }
    }


# ========================================================================
# 4. Maltego Graph XML
# ========================================================================

MALTEGO_ENTITY_MAP = {
    "person": "maltego.Person",
    "email": "maltego.EmailAddress",
    "website": "maltego.Website",
    "domain": "maltego.Domain",
    "ip": "maltego.IPv4Address",
    "url": "maltego.URL",
    "alias": "maltego.Alias",
    "phone": "maltego.PhoneNumber",
    "social": "maltego.NSAlias",
}


def to_maltego(
    results: list[dict[str, Any]],
    connections: list[dict[str, Any]] | None = None,
) -> str:
    """Export results as a Maltego .graph XML file.

    Returns XML string that can be imported into Maltego.
    """
    entities: list[str] = []
    edges: list[str] = []
    entity_ids: dict[str, str] = {}

    for r in results:
        if r.get("status") != "found":
            continue
        site = r.get("site", "")
        username = r.get("username", "")
        url = r.get("url", "")
        info = r.get("info") or {}

        entity_id = f"ent_{hashlib.md5(f'{site}/{username}'.encode()).hexdigest()[:12]}"
        entity_ids[f"{site}/{username}"] = entity_id

        entity_type = MALTEGO_ENTITY_MAP.get("social", "maltego.NSAlias")
        label = f"{site} @{username}"
        entities.append(f'''    <Entity ID="{entity_id}" Type="{entity_type}">
      <Value>{xml_escape(label)}</Value>
      <Weight>100</Weight>
      <Fields>
        <Field Name="url">{xml_escape(url)}</Field>
        <Field Name="username">{xml_escape(username)}</Field>
        <Field Name="platform">{xml_escape(site)}</Field>
      </Fields>
    </Entity>''')

        # Add name as a Person entity if available
        name = info.get("name", "")
        if name:
            name_id = f"ent_{hashlib.md5(f'name:{name}'.encode()).hexdigest()[:12]}"
            if name_id not in entity_ids.values():
                entity_ids[f"name:{name}"] = name_id
                entities.append(f'''    <Entity ID="{name_id}" Type="maltego.Person">
      <Value>{xml_escape(name)}</Value>
      <Weight>100</Weight>
    </Entity>''')
                edges.append(f'''    <Edge fromID="{entity_id}" toID="{name_id}" Label="has name" />''')

        # Add email if available
        email = info.get("email", "")
        if email:
            email_id = f"ent_{hashlib.md5(f'email:{email}'.encode()).hexdigest()[:12]}"
            if email_id not in entity_ids.values():
                entity_ids[f"email:{email}"] = email_id
                entities.append(f'''    <Entity ID="{email_id}" Type="maltego.EmailAddress">
      <Value>{xml_escape(email)}</Value>
      <Weight>100</Weight>
    </Entity>''')
                edges.append(f'''    <Edge fromID="{entity_id}" toID="{email_id}" Label="has email" />''')

    # Add connection edges
    if connections:
        for conn in connections:
            a = conn.get("a", "")
            b = conn.get("b", "")
            score = conn.get("score", 0)
            a_id = entity_ids.get(a, "")
            b_id = entity_ids.get(b, "")
            if a_id and b_id:
                edges.append(f'''    <Edge fromID="{a_id}" toID="{b_id}" Label="linked ({score}%)" />''')

    return f'''<?xml version="1.0" encoding="UTF-8"?>
<MaltegoMessage>
  <MaltegoTransformResponseMessage>
    <Entities>
{chr(10).join(entities)}
    </Entities>
    <Edges>
{chr(10).join(edges)}
    </Edges>
  </MaltegoTransformResponseMessage>
</MaltegoMessage>'''


# ========================================================================
# 5. OpenCTI Export (STIX bundle with SRO relationships)
# ========================================================================

def to_opencti(
    results: list[dict[str, Any]],
    connections: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Export as an OpenCTI-compatible STIX bundle with relationships.

    Similar to STIX but includes SRO (relationship) objects for
    account-to-account connections.
    """
    bundle = to_stix(results)
    objects = bundle["objects"]

    # Add relationship objects for connections
    if connections:
        now = datetime.now(timezone.utc).isoformat()
        for conn in connections:
            a = conn.get("a", "")
            b = conn.get("b", "")
            score = conn.get("score", 0)
            a_id = _stix_id("identity", a.replace("/", ":"))
            b_id = _stix_id("identity", b.replace("/", ":"))
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _stix_id("relationship", f"{a}-{b}"),
                "relationship_type": "related-to",
                "source_ref": a_id,
                "target_ref": b_id,
                "confidence": score,
                "created": now,
                "modified": now,
            })

    bundle["objects"] = objects
    return bundle


# ========================================================================
# 6. Write exports to files
# ========================================================================

def write_stix(results: list[dict[str, Any]], path: str) -> str:
    """Write STIX bundle to a JSON file."""
    data = to_stix(results)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return path


def write_misp(results: list[dict[str, Any]], path: str) -> str:
    """Write MISP event to a JSON file."""
    data = to_misp(results)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return path


def write_maltego(results: list[dict[str, Any]], path: str,
                  connections: list[dict[str, Any]] | None = None) -> str:
    """Write Maltego graph XML to a file."""
    xml = to_maltego(results, connections)
    with open(path, "w", encoding="utf-8") as f:
        f.write(xml)
    return path


# Fix: use a proper class instead of the fake decorator
