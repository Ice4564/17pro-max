"""Real-time & automation: WebSocket alerts, RSS/Atom feed monitor,
AI-driven auto-investigation, and scheduled scan with email delivery.
"""

from __future__ import annotations

import asyncio
import json
import re
import smtplib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any
from urllib.parse import urlparse

import aiohttp

# ========================================================================
# 1. WebSocket Alert Manager
# ========================================================================

class AlertManager:
    """Manages WebSocket connections and pushes real-time alerts.

    Designed to be used with aiohttp's WebSocket support.
    """

    def __init__(self) -> None:
        self._clients: set[Any] = set()  # aiohttp WebSocketResponse objects
        self._alert_history: list[dict[str, Any]] = []

    async def add_client(self, ws: Any) -> None:
        """Register a new WebSocket client."""
        self._clients.add(ws)
        # Send any recent alerts
        for alert in self._alert_history[-10:]:
            await ws.send_json(alert)

    def remove_client(self, ws: Any) -> None:
        """Remove a disconnected WebSocket client."""
        self._clients.discard(ws)

    async def broadcast(self, alert_type: str, data: dict[str, Any]) -> None:
        """Broadcast an alert to all connected clients."""
        alert = {
            "type": alert_type,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._alert_history.append(alert)
        # Keep last 100 alerts
        if len(self._alert_history) > 100:
            self._alert_history = self._alert_history[-100:]

        # Broadcast to all clients
        dead: list[Any] = []
        for ws in self._clients:
            try:
                await ws.send_json(alert)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._clients.discard(ws)

    async def alert_new_account(self, site: str, username: str, url: str) -> None:
        """Alert when a new account is found during a scan."""
        await self.broadcast("new_account", {
            "site": site, "username": username, "url": url,
        })

    async def alert_profile_change(self, site: str, username: str, changes: list[dict]) -> None:
        """Alert when a watched profile changes."""
        await self.broadcast("profile_change", {
            "site": site, "username": username, "changes": changes,
        })

    async def alert_scan_complete(self, target: str, found_count: int) -> None:
        """Alert when a scan completes."""
        await self.broadcast("scan_complete", {
            "target": target, "found": found_count,
        })

    @property
    def client_count(self) -> int:
        return len(self._clients)


# Global alert manager instance
alert_manager = AlertManager()


# ========================================================================
# 2. RSS/Atom Feed Monitor
# ========================================================================

@dataclass
class FeedItem:
    """A single item from an RSS/Atom feed."""

    title: str
    link: str
    description: str = ""
    published: str = ""
    author: str = ""


@dataclass
class FeedMonitor:
    """Monitors RSS/Atom feeds for mentions of a target."""

    feed_url: str
    target: str
    last_checked: datetime | None = None
    seen_items: set[str] = field(default_factory=set)

    async def check(self, session: aiohttp.ClientSession) -> list[FeedItem]:
        """Check the feed for new items mentioning the target."""
        try:
            async with session.get(
                self.feed_url,
                timeout=aiohttp.ClientTimeout(total=20),
            ) as resp:
                if resp.status != 200:
                    return []
                content = await resp.text()
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return []

        items = self._parse_feed(content)
        new_mentions: list[FeedItem] = []

        for item in items:
            # Check if this item mentions the target
            text = f"{item.title} {item.description}".lower()
            if self.target.lower() in text:
                item_id = item.link or item.title
                if item_id not in self.seen_items:
                    self.seen_items.add(item_id)
                    new_mentions.append(item)

        self.last_checked = datetime.now(timezone.utc)
        return new_mentions

    def _parse_feed(self, content: str) -> list[FeedItem]:
        """Parse RSS or Atom feed XML (simple regex parser)."""
        items: list[FeedItem] = []

        # RSS <item> tags
        rss_items = re.findall(
            r"<item>(.*?)</item>", content, re.DOTALL | re.IGNORECASE
        )
        for item_xml in rss_items:
            title = self._extract_tag(item_xml, "title")
            link = self._extract_tag(item_xml, "link")
            desc = self._extract_tag(item_xml, "description")
            pub = self._extract_tag(item_xml, "pubDate")
            author = self._extract_tag(item_xml, "author") or self._extract_tag(item_xml, "dc:creator")
            items.append(FeedItem(title=title, link=link, description=desc, published=pub, author=author))

        # Atom <entry> tags
        atom_entries = re.findall(
            r"<entry>(.*?)</entry>", content, re.DOTALL | re.IGNORECASE
        )
        for entry_xml in atom_entries:
            title = self._extract_tag(entry_xml, "title")
            link = self._extract_tag(entry_xml, "link") or self._extract_attr(entry_xml, "link", "href")
            desc = self._extract_tag(entry_xml, "summary") or self._extract_tag(entry_xml, "content")
            pub = self._extract_tag(entry_xml, "published") or self._extract_tag(entry_xml, "updated")
            author = ""
            author_match = re.search(r"<author>.*?<name>(.*?)</name>", entry_xml, re.DOTALL)
            if author_match:
                author = author_match.group(1).strip()
            items.append(FeedItem(title=title, link=link, description=desc, published=pub, author=author))

        return items

    @staticmethod
    def _extract_tag(xml: str, tag: str) -> str:
        match = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", xml, re.DOTALL | re.IGNORECASE)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _extract_attr(xml: str, tag: str, attr: str) -> str:
        match = re.search(rf'<{tag}[^>]*{attr}="([^"]*)"', xml, re.IGNORECASE)
        return match.group(1).strip() if match else ""


# Common RSS feeds for monitoring
DEFAULT_FEEDS = [
    "https://feeds.bbci.co.uk/news/rss.xml",
    "https://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml",
    "https://www.thaipbsworld.com/feed/",
    "https://www.bangkokpost.com/rss/data/topstories.xml",
]


async def monitor_feeds(
    session: aiohttp.ClientSession,
    target: str,
    feed_urls: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Monitor multiple RSS feeds for mentions of *target*."""
    feeds = feed_urls or DEFAULT_FEEDS
    monitors = [FeedMonitor(url, target) for url in feeds]

    results = await asyncio.gather(
        *[m.check(session) for m in monitors],
        return_exceptions=True,
    )

    mentions: list[dict[str, Any]] = []
    for monitor, items in zip(monitors, results):
        if isinstance(items, Exception):
            continue
        for item in items:
            mentions.append({
                "title": item.title,
                "link": item.link,
                "description": item.description[:200],
                "published": item.published,
                "author": item.author,
                "feed": monitor.feed_url,
            })

    return mentions


# ========================================================================
# 3. Auto-Investigation Mode (AI-driven search planning)
# ========================================================================

@dataclass
class InvestigationStep:
    """A single step in an auto-investigation plan."""

    action: str
    target: str
    reason: str
    priority: int  # 1-10
    status: str = "pending"  # pending, running, done, failed
    results: dict[str, Any] = field(default_factory=dict)


class AutoInvestigator:
    """AI-driven automatic investigation planner.

    Analyzes search results and automatically plans next steps:
    - Follow discovered links
    - Search for username mutations
    - Check archives for deleted profiles
    - Cross-reference with web search
    - Extract IOCs from found profiles
    """

    def __init__(self) -> None:
        self.steps: list[InvestigationStep] = []
        self.completed: list[InvestigationStep] = []
        self.findings: dict[str, Any] = {}

    def plan(self, results: list[dict[str, Any]]) -> list[InvestigationStep]:
        """Generate an investigation plan from initial search results."""
        found = [r for r in results if r.get("status") == "found"]
        steps: list[InvestigationStep] = []

        # Step 1: Check archives for all found accounts
        for r in found[:10]:  # limit to first 10
            steps.append(InvestigationStep(
                action="check_archive",
                target=r.get("url", ""),
                reason=f"Check if {r['site']} @{r['username']} has archived history",
                priority=8,
            ))

        # Step 2: Search for username mutations
        usernames = list(set(r["username"] for r in found))
        for username in usernames[:3]:
            steps.append(InvestigationStep(
                action="search_mutations",
                target=username,
                reason=f"Search for username variants of '{username}'",
                priority=7,
            ))

        # Step 3: Extract IOCs from found profiles
        steps.append(InvestigationStep(
            action="extract_iocs",
            target="all",
            reason="Extract IOCs (IPs, emails, hashes, URLs) from all found profiles",
            priority=9,
        ))

        # Step 4: Deep search (Google dorking, Reddit, GitHub)
        for username in usernames[:3]:
            steps.append(InvestigationStep(
                action="deep_search",
                target=username,
                reason=f"Deep search for '{username}' on Google, Reddit, GitHub",
                priority=6,
            ))

        # Step 5: Infrastructure scan for any domains found
        for r in found:
            info = r.get("info") or {}
            website = info.get("website", "")
            if website.startswith("http"):
                domain = urlparse(website).hostname
                if domain:
                    steps.append(InvestigationStep(
                        action="infra_scan",
                        target=domain,
                        reason=f"Infrastructure scan of {domain} (linked from {r['site']})",
                        priority=5,
                    ))

        # Step 6: Behavioral analysis
        if any((r.get("info") or {}).get("bio") for r in found):
            steps.append(InvestigationStep(
                action="behavior_analysis",
                target="all",
                reason="Analyze writing style, emoji patterns, and interests",
                priority=4,
            ))

        # Step 7: Counter-OSINT assessment
        steps.append(InvestigationStep(
            action="privacy_assessment",
            target="all",
            reason="Generate privacy risk assessment and remediation plan",
            priority=3,
        ))

        # Sort by priority
        steps.sort(key=lambda s: -s.priority)
        self.steps = steps
        return steps

    def mark_done(self, step: InvestigationStep, results: dict[str, Any]) -> None:
        """Mark a step as completed and store its results."""
        step.status = "done"
        step.results = results
        self.completed.append(step)
        self.findings[step.action] = results

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of the investigation."""
        return {
            "total_steps": len(self.steps),
            "completed": len(self.completed),
            "pending": len(self.steps) - len(self.completed),
            "findings": list(self.findings.keys()),
            "steps": [
                {
                    "action": s.action,
                    "target": s.target,
                    "reason": s.reason,
                    "priority": s.priority,
                    "status": s.status,
                }
                for s in self.steps
            ],
        }


# ========================================================================
# 4. Scheduled Scan with Email Delivery
# ========================================================================

@dataclass
class ScheduledScan:
    """A scheduled scan configuration."""

    target: str
    interval_hours: int
    email: str | None = None
    last_run: datetime | None = None
    last_results: list[dict[str, Any]] = field(default_factory=list)
    active: bool = True


class ScanScheduler:
    """Manages scheduled scans and email delivery of results."""

    def __init__(self) -> None:
        self._schedules: list[ScheduledScan] = []

    def add(self, target: str, interval_hours: int, email: str | None = None) -> None:
        """Add a new scheduled scan."""
        self._schedules.append(ScheduledScan(
            target=target,
            interval_hours=interval_hours,
            email=email,
        ))

    def remove(self, target: str) -> None:
        """Remove a scheduled scan."""
        self._schedules = [s for s in self._schedules if s.target != target]

    def list_schedules(self) -> list[dict[str, Any]]:
        """List all scheduled scans."""
        return [
            {
                "target": s.target,
                "interval_hours": s.interval_hours,
                "email": s.email,
                "last_run": s.last_run.isoformat() if s.last_run else None,
                "active": s.active,
            }
            for s in self._schedules
        ]

    def get_due(self) -> list[ScheduledScan]:
        """Get all schedules that are due to run."""
        now = datetime.now(timezone.utc)
        due: list[ScheduledScan] = []
        for s in self._schedules:
            if not s.active:
                continue
            if s.last_run is None:
                due.append(s)
            elif (now - s.last_run).total_seconds() / 3600 >= s.interval_hours:
                due.append(s)
        return due

    @staticmethod
    def send_email_report(
        target: str,
        results: list[dict[str, Any]],
        email: str,
        *,
        smtp_host: str = "localhost",
        smtp_port: int = 25,
        smtp_user: str | None = None,
        smtp_pass: str | None = None,
    ) -> bool:
        """Send a scan report via email.

        Returns True if sent successfully.
        """
        found = [r for r in results if r.get("status") == "found"]

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"Sleuth Report: {target} — {len(found)} accounts found"
        msg["From"] = smtp_user or "sleuth@localhost"
        msg["To"] = email

        # Plain text version
        text = f"Sleuth Scan Report\n{'='*40}\n\n"
        text += f"Target: {target}\n"
        text += f"Date: {datetime.now().isoformat()}\n"
        text += f"Accounts found: {len(found)}\n\n"
        for r in found:
            text += f"  {r['site']} @{r['username']}\n"
            text += f"    URL: {r.get('url', '')}\n"
            info = r.get("info") or {}
            if info.get("name"):
                text += f"    Name: {info['name']}\n"
            if info.get("bio"):
                text += f"    Bio: {info['bio'][:100]}\n"
            text += "\n"

        # HTML version
        html = f"""<html><body style="font-family: sans-serif;">
<h2>Sleuth Scan Report</h2>
<p><strong>Target:</strong> {target}<br>
<strong>Date:</strong> {datetime.now().isoformat()}<br>
<strong>Accounts found:</strong> {len(found)}</p>
<table border="1" cellpadding="6" style="border-collapse: collapse;">
<tr><th>Platform</th><th>Username</th><th>URL</th><th>Name</th></tr>
"""
        for r in found:
            info = r.get("info") or {}
            html += f"<tr><td>{r['site']}</td><td>{r['username']}</td>"
            html += f"<td><a href='{r.get('url', '')}'>{r.get('url', '')}</a></td>"
            html += f"<td>{info.get('name', '')}</td></tr>"
        html += "</table></body></html>"

        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        try:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                if smtp_user and smtp_pass:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                server.sendmail(msg["From"], [email], msg.as_string())
            return True
        except Exception:
            return False


# Global scheduler instance
scan_scheduler = ScanScheduler()
