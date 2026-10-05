"""Correlation rules: turn raw scan events into human-readable findings."""

from __future__ import annotations

from datetime import date
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .core import Event, Scanner

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MS SQL", 3306: "MySQL", 3389: "Remote Desktop",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 2375: "Docker API",
}


def _finding(rule: str, severity: str, title: str, detail: str, events: list["Event"]) -> dict[str, Any]:
    return {"rule": rule, "severity": severity, "title": title, "detail": detail,
            "events": [e.id for e in events][:50]}


def correlate(scan: "Scanner") -> list[dict[str, Any]]:
    by_type: dict[str, list[Event]] = {}
    for e in scan.events:
        by_type.setdefault(e.type, []).append(e)
    get = lambda t: by_type.get(t, [])  # noqa: E731
    out: list[dict[str, Any]] = []
    domain_events = [e for e in get("DOMAIN_NAME")]

    # --- email security -------------------------------------------------
    if domain_events and "emailsec" in scan.modules_run:
        if not get("SPF_RECORD"):
            out.append(_finding("no_spf", "medium", "ไม่มี SPF record",
                                "ใครก็ส่งอีเมลปลอมในนามโดเมนนี้ได้ง่ายขึ้น ควรเพิ่ม TXT record แบบ v=spf1", domain_events))
        for e in get("SPF_RECORD"):
            if e.extra.get("all") == "+":
                out.append(_finding("spf_plus_all", "high", "SPF อนุญาตทุกเซิร์ฟเวอร์ (+all)",
                                    "SPF แบบ +all แปลว่าเซิร์ฟเวอร์ไหนก็ส่งอีเมลในนามโดเมนนี้ได้", [e]))
        if not get("DMARC_RECORD"):
            out.append(_finding("no_dmarc", "medium", "ไม่มี DMARC record",
                                "ไม่มีนโยบายจัดการอีเมลปลอม ควรเพิ่ม _dmarc TXT record", domain_events))
        for e in get("DMARC_RECORD"):
            if e.extra.get("policy") == "none":
                out.append(_finding("dmarc_none", "low", "DMARC ตั้งเป็น p=none",
                                    "DMARC แค่รายงานผล แต่ไม่บล็อกอีเมลปลอม", [e]))

    # --- certificates and domain expiry -----------------------------------
    for e in get("SSL_CERT_INVALID"):
        out.append(_finding("ssl_invalid", "high", "SSL certificate ไม่ถูกต้อง", e.data, [e]))
    for e in get("SSL_CERT"):
        days = e.extra.get("days_left")
        if isinstance(days, int) and days < 0:
            out.append(_finding("ssl_expired", "high", "SSL certificate หมดอายุแล้ว", e.data, [e]))
        elif isinstance(days, int) and days <= 14:
            out.append(_finding("ssl_expiring", "medium", f"SSL certificate จะหมดอายุใน {days} วัน", e.data, [e]))
    for e in get("DOMAIN_EXPIRES"):
        try:
            days = (date.fromisoformat(e.data) - date.today()).days
        except ValueError:
            continue
        if days <= 30:
            out.append(_finding("domain_expiring", "medium" if days >= 0 else "high",
                                f"โดเมนจะหมดอายุใน {days} วัน", f"หมดอายุ {e.data}", [e]))

    # --- exposure ----------------------------------------------------------
    vulns = get("VULNERABILITY")
    if vulns:
        ids = sorted({v.data for v in vulns})
        out.append(_finding("cves", "high", f"พบช่องโหว่ที่รู้จัก {len(ids)} รายการ (CVE)",
                            "Shodan รายงานว่าซอฟต์แวร์บนเซิร์ฟเวอร์มีช่องโหว่: " + ", ".join(ids[:15])
                            + (" ..." if len(ids) > 15 else "") + " (ควรตรวจสอบเวอร์ชันจริงอีกครั้ง)", vulns))
    risky = [e for e in get("OPEN_PORT") if e.extra.get("port") in RISKY_PORTS]
    if risky:
        desc = ", ".join(f"{e.data} ({RISKY_PORTS[e.extra['port']]})" for e in risky[:15])
        out.append(_finding("risky_ports", "medium", "เปิดพอร์ตบริการที่ไม่ควรเปิดสู่อินเทอร์เน็ต", desc, risky))
    missing = get("WEB_HEADERS_MISSING")
    if missing:
        out.append(_finding("missing_headers", "low", "เว็บขาด security header บางตัว",
                            "; ".join(e.data for e in missing[:5]) + (f" และอีก {len(missing) - 5} โฮสต์" if len(missing) > 5 else ""), missing))
    emails = [e for e in get("EMAIL") if e.module != "root"]
    if emails:
        out.append(_finding("emails_exposed", "info", f"พบอีเมล {len(emails)} รายการบนเว็บไซต์",
                            "อีเมลที่เปิดเผยอาจถูกใช้ส่งสแปมหรือ phishing: " + ", ".join(e.data for e in emails[:10]),
                            emails))
    if domain_events and "webpage" in scan.modules_run and not get("SECURITY_TXT") and get("WEB_TITLE"):
        out.append(_finding("no_security_txt", "info", "ไม่มีไฟล์ security.txt",
                            "ควรมี /.well-known/security.txt เพื่อให้คนแจ้งช่องโหว่ได้", domain_events))

    # --- identity ----------------------------------------------------------
    accounts = get("ACCOUNT")
    if accounts:
        per_user: dict[str, list[Event]] = {}
        for a in accounts:
            per_user.setdefault(a.extra.get("username", ""), []).append(a)
        for user, accs in per_user.items():
            out.append(_finding("accounts", "info", f"username \"{user}\" มีบัญชีบน {len(accs)} เว็บ",
                                ", ".join(a.extra.get("site", "") for a in accs[:30])
                                + " (username เดียวกันไม่จำเป็นต้องเป็นคนเดียวกัน)", accs))
    subs = get("INTERNET_NAME")
    if len(subs) >= 1:
        out.append(_finding("subdomains", "info", f"พบซับโดเมน {len(subs)} รายการ",
                            ", ".join(e.data for e in subs[:20]) + (" ..." if len(subs) > 20 else ""), subs))

    out.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return out
