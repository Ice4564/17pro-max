"""Website analysis: page title, server, technologies, emails, social links,
security headers, security.txt and Wayback Machine history."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from html import unescape
from urllib.parse import quote, urljoin, urlparse

from ...linker import match_social as _match_big_platform
from ...sites import load_sites
from ..core import Context, Event, Module

EMAIL_IN_TEXT = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}(?![\w-])")
HREF_RE = re.compile(r"""href\s*=\s*["']([^"'#\s]+)""", re.I)
CFEMAIL_RE = re.compile(r'data-cfemail="([0-9a-fA-F]+)"')
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)

TECH_HEADERS = {
    "cf-ray": "Cloudflare", "x-vercel-id": "Vercel", "x-amz-cf-id": "Amazon CloudFront",
    "x-github-request-id": "GitHub Pages", "x-shopify-stage": "Shopify", "x-wix-request-id": "Wix",
    "x-nf-request-id": "Netlify", "x-fastly-request-id": "Fastly", "x-akamai-transformed": "Akamai",
    "x-drupal-cache": "Drupal", "x-litespeed-cache": "LiteSpeed Cache", "x-served-by": None,
}
TECH_BODY = {
    "/wp-content/": "WordPress", "/_next/": "Next.js", "__NUXT__": "Nuxt", "ng-version=": "Angular",
    "data-reactroot": "React", "cdn.shopify.com": "Shopify", "googletagmanager.com": "Google Tag Manager",
    "google-analytics.com": "Google Analytics", "gtag(": "Google Analytics", "jquery": "jQuery",
    "bootstrap.min": "Bootstrap", "static.wixstatic.com": "Wix", "squarespace.com": "Squarespace",
    "Drupal.settings": "Drupal", "/media/jui/": "Joomla", "___gatsby": "Gatsby", "static.hotjar.com": "Hotjar",
    "connect.facebook.net": "Facebook Pixel", "recaptcha": "reCAPTCHA", "cloudflare-static": "Cloudflare",
    "tailwind": "Tailwind CSS", "vue.": "Vue.js", "cdn.jsdelivr.net": "jsDelivr", "elementor": "Elementor",
    "woocommerce": "WooCommerce", "line.me/R/ti/p": "LINE Official Account",
}
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options")

JUNK_EMAIL = re.compile(r"(\.(png|jpe?g|gif|svg|webp|css|js)$)|example\.(com|org)|sentry|wixpress|@\d+x\.", re.I)

_SITES = None


def _sites():
    global _SITES
    if _SITES is None:
        _SITES = load_sites()
    return _SITES


def decode_cfemail(hexstr: str) -> str:
    """Decode Cloudflare's e-mail obfuscation."""
    data = bytes.fromhex(hexstr)
    return "".join(chr(b ^ data[0]) for b in data[1:])


def match_social(url: str) -> tuple[str, str] | None:
    hit = _match_big_platform(url)
    if hit:
        return hit
    for site in _sites():
        name = site.match_link(url)
        if name:
            return site.name, name
    return None


class WebPage(Module):
    name = "webpage"
    title = "วิเคราะห์หน้าเว็บ"
    description = "ชื่อเว็บ, web server, เทคโนโลยี, อีเมล, ลิงก์โซเชียล, security header และ security.txt"
    category = "web"
    watches = ("DOMAIN_NAME", "INTERNET_NAME")

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        host = event.data.lower()
        if not ctx.take("web", host):
            return
        page = None
        for scheme in ("https", "http"):
            try:
                status, body, headers = await ctx.get(f"{scheme}://{host}/", timeout=15)
            except Exception:
                continue
            page = (status, body, {k.lower(): v for k, v in headers.items()}, scheme)
            break
        if page is None:
            return
        status, body, headers, scheme = page
        base = f"{scheme}://{host}/"

        m = TITLE_RE.search(body)
        if m:
            title = " ".join(unescape(m.group(1)).split())[:200]
            if title:
                yield event.child("WEB_TITLE", f"{host}: {title}", self.name, host=host, status=status)
        if headers.get("server"):
            yield event.child("WEB_SERVER", headers["server"][:100], self.name, host=host)

        techs = set()
        for h, tech in TECH_HEADERS.items():
            if tech and h in headers:
                techs.add(tech)
        if headers.get("x-powered-by"):
            techs.add(headers["x-powered-by"][:60])
        gen = GENERATOR_RE.search(body)
        if gen:
            techs.add(gen.group(1)[:60])
        low = body[:600_000].lower()
        for needle, tech in TECH_BODY.items():
            if needle.lower() in low:
                techs.add(tech)
        for tech in sorted(techs):
            yield event.child("WEB_TECH", tech, self.name, host=host)

        if scheme == "https" or event.type == "DOMAIN_NAME":
            missing = [h for h in SECURITY_HEADERS if h not in headers]
            if missing:
                yield event.child("WEB_HEADERS_MISSING", f"{host}: {', '.join(missing)}", self.name,
                                  host=host, missing=missing)

        emails = set(EMAIL_IN_TEXT.findall(body))
        emails.update(decode_cfemail(x) for x in CFEMAIL_RE.findall(body))
        for href in HREF_RE.findall(body):
            if href.lower().startswith("mailto:"):
                emails.add(href[7:].split("?")[0])
        for email in sorted({e.strip().lower() for e in emails}):
            if EMAIL_IN_TEXT.fullmatch(email) and not JUNK_EMAIL.search(email):
                yield event.child("EMAIL", email, self.name, source=base)

        linked: set[str] = set()
        for href in HREF_RE.findall(body):
            url = urljoin(base, unescape(href))
            if not url.startswith("http"):
                continue
            social = match_social(url.split("?")[0])
            if social:
                platform, handle = social
                yield event.child("SOCIAL_PROFILE", url.split("?")[0], self.name, platform=platform,
                                  handle=handle, source=base)
                yield event.child("USERNAME", handle, self.name, source=f"{platform} link on {host}")
                continue
            other = urlparse(url).netloc.lower().split(":")[0].removeprefix("www.")
            if other and not ctx.in_scope(other) and other != host:
                linked.add(other)
            elif other and ctx.in_scope(other) and other != host:
                yield event.child("INTERNET_NAME", other, self.name)
        for d in sorted(linked)[:40]:
            yield event.child("LINKED_DOMAIN", d, self.name, source=base)

        if event.type == "DOMAIN_NAME":
            try:
                st, txt, _ = await ctx.get(f"{scheme}://{host}/.well-known/security.txt", timeout=10)
                if st == 200 and "contact:" in txt.lower() and "<html" not in txt.lower()[:500]:
                    contacts = re.findall(r"(?im)^contact:\s*(\S+)", txt)
                    yield event.child("SECURITY_TXT", ", ".join(contacts) or "present", self.name, host=host)
            except Exception:
                pass


class Wayback(Module):
    name = "wayback"
    title = "Wayback Machine"
    description = "เว็บนี้ถูกเก็บใน archive.org ตั้งแต่เมื่อไหร่ และครั้งล่าสุดเมื่อไหร่"
    category = "web"
    watches = ("DOMAIN_NAME",)

    async def handle(self, event: Event, ctx: Context) -> AsyncIterator[Event]:
        url = "https://web.archive.org/cdx/search/cdx?output=json&fl=timestamp&url=" + quote(event.data)
        _, first, _ = await ctx.get(url + "&limit=1", json=True, timeout=30)
        _, last, _ = await ctx.get(url + "&limit=-1", json=True, timeout=30)
        if not first or len(first) < 2:
            return
        fmt = lambda ts: f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"  # noqa: E731
        f_ts = first[1][0]
        l_ts = last[1][0] if last and len(last) > 1 else f_ts
        yield event.child("WAYBACK", f"เก็บครั้งแรก {fmt(f_ts)} · ล่าสุด {fmt(l_ts)}", self.name,
                          first=fmt(f_ts), last=fmt(l_ts),
                          url=f"https://web.archive.org/web/*/{event.data}")
