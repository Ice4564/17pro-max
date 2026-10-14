"""Counter-OSINT: self-footprint checker, privacy risk score,
remediation guide, and exposure timeline.

Helps users understand their own digital footprint and what others
can find about them, with actionable remediation steps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ========================================================================
# 1. Privacy Risk Score
# ========================================================================

@dataclass
class PrivacyRiskFactor:
    """A single factor contributing to privacy risk."""

    category: str
    severity: str  # "high", "medium", "low"
    description: str
    remediation: str
    points: int  # contribution to total score


@dataclass
class PrivacyRiskAssessment:
    """Complete privacy risk assessment."""

    score: int  # 0-100, higher = more exposed
    level: str  # "Critical", "High", "Moderate", "Low", "Minimal"
    factors: list[PrivacyRiskFactor] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    exposed_data_types: list[str] = field(default_factory=list)


def assess_privacy_risk(results: list[dict[str, Any]]) -> PrivacyRiskAssessment:
    """Assess privacy risk from search results.

    Analyzes what personal information is publicly exposed across
    found accounts and generates a risk score with recommendations.
    """
    factors: list[PrivacyRiskFactor] = []
    found = [r for r in results if r.get("status") == "found"]

    if not found:
        return PrivacyRiskAssessment(
            score=0, level="Minimal",
            factors=[], recommendations=["No public accounts found — excellent privacy posture."],
        )

    # Count exposed data types
    exposed_types: set[str] = set()
    total_accounts = len(found)

    # Check for real name exposure
    names_exposed = sum(1 for r in found if (r.get("info") or {}).get("name"))
    if names_exposed > 0:
        severity = "high" if names_exposed >= 3 else "medium"
        factors.append(PrivacyRiskFactor(
            category="Real Name", severity=severity,
            description=f"Real name visible on {names_exposed} account(s)",
            remediation="Set profiles to private or remove real name from public profiles",
            points=15 if severity == "high" else 8,
        ))
        exposed_types.add("real_name")

    # Check for email exposure
    emails_exposed = sum(1 for r in found if (r.get("info") or {}).get("email"))
    if emails_exposed > 0:
        factors.append(PrivacyRiskFactor(
            category="Email", severity="high",
            description=f"Email address visible on {emails_exposed} account(s)",
            remediation="Use a separate email for public profiles, enable email privacy settings",
            points=12,
        ))
        exposed_types.add("email")

    # Check for phone exposure
    phones_exposed = sum(1 for r in found if any(
        "phone" in k.lower() or "tel" in k.lower()
        for k in (r.get("info") or {})
    ))
    if phones_exposed > 0:
        factors.append(PrivacyRiskFactor(
            category="Phone", severity="high",
            description=f"Phone number visible on {phones_exposed} account(s)",
            remediation="Remove phone numbers from public profiles immediately",
            points=15,
        ))
        exposed_types.add("phone")

    # Check for location exposure
    locations_exposed = sum(1 for r in found if (r.get("info") or {}).get("location"))
    if locations_exposed > 0:
        severity = "high" if locations_exposed >= 3 else "medium"
        factors.append(PrivacyRiskFactor(
            category="Location", severity=severity,
            description=f"Location/city visible on {locations_exposed} account(s)",
            remediation="Remove or generalize location info (e.g., just country instead of city)",
            points=10 if severity == "high" else 5,
        ))
        exposed_types.add("location")

    # Check for avatar exposure (can be used for face matching)
    avatars_exposed = sum(1 for r in found if (r.get("info") or {}).get("avatar", "").startswith("http"))
    if avatars_exposed >= 3:
        factors.append(PrivacyRiskFactor(
            category="Avatar/Face", severity="medium",
            description=f"Profile photos on {avatars_exposed} account(s) — enables reverse image search",
            remediation="Use different avatars on different platforms, or use abstract images",
            points=8,
        ))
        exposed_types.add("avatar")

    # Check for bio exposure
    bios_exposed = sum(1 for r in found if (r.get("info") or {}).get("bio", "").strip())
    if bios_exposed > 0:
        factors.append(PrivacyRiskFactor(
            category="Bio", severity="low",
            description=f"Personal bio visible on {bios_exposed} account(s)",
            remediation="Review bios for personal details (work, school, relationships)",
            points=4,
        ))
        exposed_types.add("bio")

    # Check for website/link exposure
    websites_exposed = sum(1 for r in found if (r.get("info") or {}).get("website", "").strip())
    if websites_exposed > 0:
        factors.append(PrivacyRiskFactor(
            category="Website Links", severity="medium",
            description=f"Personal website/blog linked on {websites_exposed} account(s)",
            remediation="Review linked sites for additional personal info",
            points=6,
        ))
        exposed_types.add("website")

    # Account count factor
    if total_accounts >= 10:
        factors.append(PrivacyRiskFactor(
            category="Account Count", severity="high",
            description=f"{total_accounts} public accounts found — large attack surface",
            remediation="Delete or deactivate unused accounts, consolidate to fewer platforms",
            points=15,
        ))
    elif total_accounts >= 5:
        factors.append(PrivacyRiskFactor(
            category="Account Count", severity="medium",
            description=f"{total_accounts} public accounts found",
            remediation="Consider reducing the number of active public accounts",
            points=8,
        ))

    # Cross-platform linking risk
    same_username = len(set(r["username"].lower() for r in found)) < total_accounts
    if same_username:
        factors.append(PrivacyRiskFactor(
            category="Username Reuse", severity="high",
            description="Same username used across multiple platforms — easily correlated",
            remediation="Use different usernames on different platforms to prevent correlation",
            points=12,
        ))
        exposed_types.add("username_correlation")

    # Calculate total score
    score = min(100, sum(f.points for f in factors))

    # Determine level
    if score >= 70:
        level = "Critical"
    elif score >= 50:
        level = "High"
    elif score >= 30:
        level = "Moderate"
    elif score >= 15:
        level = "Low"
    else:
        level = "Minimal"

    # Generate recommendations
    recommendations: list[str] = []
    for f in sorted(factors, key=lambda x: -x.points):
        if f.remediation not in recommendations:
            recommendations.append(f"[{f.severity.upper()}] {f.category}: {f.remediation}")

    recommendations.extend([
        "Enable two-factor authentication on all accounts",
        "Review privacy settings on each platform regularly",
        "Use a password manager with unique passwords per account",
        "Consider using a VPN to mask your IP address",
        "Regularly search for your own username to monitor exposure",
    ])

    return PrivacyRiskAssessment(
        score=score,
        level=level,
        factors=factors,
        recommendations=recommendations,
        exposed_data_types=sorted(exposed_types),
    )


# ========================================================================
# 2. Self-Footprint Checker
# ========================================================================

@dataclass
class FootprintReport:
    """Report of what someone can find about you."""

    accounts_found: int
    platforms: list[str]
    data_exposed: dict[str, int]  # type -> count
    risk_assessment: PrivacyRiskAssessment
    summary: str


def check_footprint(results: list[dict[str, Any]]) -> FootprintReport:
    """Generate a self-footprint report from search results.

    Run a search on your own username to see what others can find.
    """
    found = [r for r in results if r.get("status") == "found"]
    platforms = [r["site"] for r in found]

    data_exposed: dict[str, int] = {}
    for r in found:
        info = r.get("info") or {}
        for key in ("name", "email", "location", "bio", "website", "avatar", "phone"):
            if info.get(key):
                data_exposed[key] = data_exposed.get(key, 0) + 1

    risk = assess_privacy_risk(results)

    summary = (
        f"Found {len(found)} public account(s) across {len(set(platforms))} platform(s). "
        f"Privacy risk level: {risk.level} ({risk.score}/100). "
        f"Exposed data types: {', '.join(risk.exposed_data_types) or 'none'}."
    )

    return FootprintReport(
        accounts_found=len(found),
        platforms=platforms,
        data_exposed=data_exposed,
        risk_assessment=risk,
        summary=summary,
    )


# ========================================================================
# 3. Remediation Guide
# ========================================================================

REMEDIATION_GUIDES: dict[str, dict[str, str]] = {
    "instagram": {
        "private": "Settings > Privacy > Private Account",
        "remove_phone": "Settings > Privacy > Phone number > Remove",
        "hide_activity": "Settings > Privacy > Activity status > Off",
    },
    "twitter": {
        "private": "Settings > Privacy > Audience > Protect your Tweets",
        "remove_phone": "Settings > Privacy > Phone > Remove",
        "hide_location": "Settings > Privacy > Location > Off",
    },
    "facebook": {
        "private": "Settings > Privacy > Who can see > Friends only",
        "remove_phone": "Settings > Mobile > Remove",
        "hide_friends": "Settings > Privacy > Who can see friend list > Only me",
    },
    "tiktok": {
        "private": "Settings > Privacy > Private account",
        "remove_phone": "Settings > Account > Phone > Remove",
        "hide_location": "Settings > Privacy > Location services > Off",
    },
    "github": {
        "hide_email": "Settings > Emails > Keep email address private",
        "private_commits": "Settings > Emails > Block command line pushes that expose my email",
    },
    "reddit": {
        "private": "No native private profile — delete sensitive posts manually",
        "hide_history": "Settings > Privacy > Clear history",
    },
    "linkedin": {
        "private": "Settings > Visibility > Profile visibility > Connections only",
        "hide_photo": "Settings > Visibility > Profile photo > Connections only",
    },
    "youtube": {
        "private": "Settings > Privacy > Private channel",
        "hide_subscriptions": "Settings > Privacy > Keep subscriptions private",
    },
}


def get_remediation_guide(platform: str) -> dict[str, str]:
    """Get step-by-step remediation instructions for a platform."""
    return REMEDIATION_GUIDES.get(platform.lower(), {
        "general": "Check the platform's privacy settings page and set everything to private/friends-only"
    })


def generate_remediation_plan(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate a prioritized remediation plan based on found accounts."""
    found = [r for r in results if r.get("status") == "found"]
    risk = assess_privacy_risk(results)

    plan: list[dict[str, Any]] = []
    for f in sorted(risk.factors, key=lambda x: -x.points):
        plan.append({
            "priority": "HIGH" if f.severity == "high" else "MEDIUM" if f.severity == "medium" else "LOW",
            "category": f.category,
            "issue": f.description,
            "action": f.remediation,
        })

    # Add platform-specific guides
    for r in found:
        platform = r["site"].lower()
        guide = get_remediation_guide(platform)
        if guide:
            plan.append({
                "priority": "INFO",
                "category": f"{r['site']} Settings",
                "issue": f"Configure privacy on {r['site']} (@{r['username']})",
                "action": "; ".join(f"{k}: {v}" for k, v in guide.items()),
            })

    return plan


# ========================================================================
# 4. Exposure Timeline
# ========================================================================

@dataclass
class ExposureEvent:
    """A single exposure event in the timeline."""

    date: str
    event_type: str  # "account_created", "data_leaked", "profile_changed", "account_found"
    platform: str
    description: str
    severity: str = "info"
    url: str = ""


def build_exposure_timeline(
    results: list[dict[str, Any]],
    history_data: list[dict[str, Any]] | None = None,
) -> list[ExposureEvent]:
    """Build a timeline of exposure events.

    Combines account creation dates, profile changes, and scan history
    into a chronological timeline.
    """
    events: list[ExposureEvent] = []

    for r in results:
        if r.get("status") != "found":
            continue
        info = r.get("info") or {}
        site = r.get("site", "")
        username = r.get("username", "")
        url = r.get("url", "")

        # Account creation date
        created = info.get("created", "")
        if created:
            events.append(ExposureEvent(
                date=str(created),
                event_type="account_created",
                platform=site,
                description=f"Account created on {site} (@{username})",
                severity="info",
                url=url,
            ))

        # Data exposure events
        for field_name in ("email", "phone", "location"):
            if info.get(field_name):
                events.append(ExposureEvent(
                    date=str(created or "unknown"),
                    event_type=f"{field_name}_exposed",
                    platform=site,
                    description=f"{field_name.title()} exposed on {site} (@{username})",
                    severity="warning",
                    url=url,
                ))

        # Avatar exposure
        if info.get("avatar", "").startswith("http"):
            events.append(ExposureEvent(
                date=str(created or "unknown"),
                event_type="avatar_exposed",
                platform=site,
                description=f"Profile photo on {site} (@{username}) — enables reverse image search",
                severity="warning",
                url=url,
            ))

    # Add history events if available
    if history_data:
        for h in history_data:
            events.append(ExposureEvent(
                date=h.get("date", ""),
                event_type=h.get("type", "scan"),
                platform=h.get("platform", ""),
                description=h.get("description", ""),
                severity=h.get("severity", "info"),
            ))

    # Sort by date (unknown dates go last)
    events.sort(key=lambda e: e.date if e.date and e.date != "unknown" else "9999")
    return events
