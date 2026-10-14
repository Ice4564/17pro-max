"""Deep search: Google Dorking automation, forum deep search, code search,
academic search, paste site monitoring, and social geosearch.

All URL builders work offline. Live search functions use aiohttp.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlencode

import aiohttp

# ========================================================================
# 1. Google Dorking Automation
# ========================================================================

@dataclass
class DorkQuery:
    """A single Google dork query."""

    query: str
    url: str
    category: str
    description: str


def build_dorks(target: str) -> list[DorkQuery]:
    """Generate a comprehensive set of Google dork queries for *target*.

    *target* can be a username, email, phone, or domain.
    """
    dorks: list[DorkQuery] = []
    t = target.strip().strip("@")

    # Username / name dorks
    dorks.extend([
        DorkQuery(
            f'"{t}"',
            f"https://www.google.com/search?q={quote(f'\"{t}\"')}",
            "exact", f'Exact match for "{t}"',
        ),
        DorkQuery(
            f'intext:"{t}"',
            f"https://www.google.com/search?q={quote(f'intext:\"{t}\"')}",
            "intext", f'Pages containing "{t}" in text',
        ),
        DorkQuery(
            f'inurl:"{t}"',
            f"https://www.google.com/search?q={quote(f'inurl:\"{t}\"')}",
            "inurl", f'URLs containing "{t}"',
        ),
        DorkQuery(
            f'intitle:"{t}"',
            f"https://www.google.com/search?q={quote(f'intitle:\"{t}\"')}",
            "intitle", f'Page titles containing "{t}"',
        ),
        DorkQuery(
            f'"{t}" site:social media',
            f"https://www.google.com/search?q={quote(f'\"{t}\" (site:instagram.com OR site:twitter.com OR site:facebook.com OR site:tiktok.com OR site:youtube.com)')}",
            "social", f'"{t}" on social media sites',
        ),
        DorkQuery(
            f'"{t}" site:forum',
            f"https://www.google.com/search?q={quote(f'\"{t}\" (site:reddit.com OR site:forum.* OR site:board.*)')}",
            "forum", f'"{t}" on forums',
        ),
        DorkQuery(
            f'"{t}" filetype:pdf',
            f"https://www.google.com/search?q={quote(f'\"{t}\" filetype:pdf')}",
            "document", f'PDF documents mentioning "{t}"',
        ),
        DorkQuery(
            f'"{t}" filetype:doc OR filetype:docx',
            f"https://www.google.com/search?q={quote(f'\"{t}\" (filetype:doc OR filetype:docx)')}",
            "document", f'Word documents mentioning "{t}"',
        ),
        DorkQuery(
            f'"{t}" filetype:xls OR filetype:xlsx',
            f"https://www.google.com/search?q={quote(f'\"{t}\" (filetype:xls OR filetype:xlsx)')}",
            "document", f'Excel files mentioning "{t}"',
        ),
        DorkQuery(
            f'"{t}" (filetype:jpg OR filetype:png OR filetype:gif)',
            f"https://www.google.com/search?q={quote(f'\"{t}\" (filetype:jpg OR filetype:png OR filetype:gif)')}",
            "image", f'Images tagged with "{t}"',
        ),
    ])

    # Email-specific dorks
    if "@" in t:
        user, domain = t.split("@", 1)
        dorks.extend([
            DorkQuery(
                f'"{t}"',
                f"https://www.google.com/search?q={quote(f'\"{t}\"')}",
                "email", f'Exact email search',
            ),
            DorkQuery(
                f'"{user}" "@{domain}"',
                f"https://www.google.com/search?q={quote(f'\"{user}\" \"@{domain}\"')}",
                "email", f'Username + domain parts',
            ),
            DorkQuery(
                f'"{t}" (site:pastebin.com OR site:ghostbin.com OR site:gist.github.com)',
                f"https://www.google.com/search?q={quote(f'\"{t}\" (site:pastebin.com OR site:ghostbin.com OR site:gist.github.com)')}",
                "paste", f'Email in paste sites',
            ),
        ])

    # Domain-specific dorks
    if "." in t and "@" not in t and "/" not in t:
        dorks.extend([
            DorkQuery(
                f'site:{t}',
                f"https://www.google.com/search?q={quote(f'site:{t}')}",
                "domain", f'All pages on {t}',
            ),
            DorkQuery(
                f'site:*.{t}',
                f"https://www.google.com/search?q={quote(f'site:*.{t}')}",
                "domain", f'All subdomains of {t}',
            ),
            DorkQuery(
                f'site:{t} (inurl:admin OR inurl:login OR inurl:dashboard)',
                f"https://www.google.com/search?q={quote(f'site:{t} (inurl:admin OR inurl:login OR inurl:dashboard)')}",
                "domain", f'Admin/login pages on {t}',
            ),
            DorkQuery(
                f'site:{t} (inurl:api OR inurl:json OR inurl:graphql)',
                f"https://www.google.com/search?q={quote(f'site:{t} (inurl:api OR inurl:json OR inurl:graphql)')}",
                "domain", f'API endpoints on {t}',
            ),
            DorkQuery(
                f'site:{t} filetype:pdf',
                f"https://www.google.com/search?q={quote(f'site:{t} filetype:pdf')}",
                "domain", f'PDF files on {t}',
            ),
        ])

    # Phone-specific dorks (Thai format)
    phone_clean = re.sub(r"[\s\-()]", "", t)
    if phone_clean.isdigit() and len(phone_clean) >= 9:
        dorks.extend([
            DorkQuery(
                f'"{phone_clean}"',
                f"https://www.google.com/search?q={quote(f'\"{phone_clean}\"')}",
                "phone", f'Phone number search',
            ),
            DorkQuery(
                f'"{phone_clean[:3]}-{phone_clean[3:6]}-{phone_clean[6:]}"',
                f"https://www.google.com/search?q={quote(f'\"{phone_clean[:3]}-{phone_clean[3:6]}-{phone_clean[6:]}\"')}",
                "phone", f'Formatted phone search',
            ),
        ])

    return dorks


# ========================================================================
# 2. Forum Deep Search
# ========================================================================

@dataclass
class ForumResult:
    """A single forum search result."""

    platform: str
    title: str
    url: str
    snippet: str = ""
    author: str = ""
    date: str = ""
    score: int = 0


async def search_reddit(
    session: aiohttp.ClientSession,
    query: str,
    *,
    limit: int = 25,
) -> list[ForumResult]:
    """Search Reddit via the public JSON API."""
    params = {"q": query, "limit": str(limit), "sort": "relevance", "type": "link"}
    url = "https://www.reddit.com/search.json"
    try:
        async with session.get(
            url, params=params,
            timeout=aiohttp.ClientTimeout(total=15),
            headers={"User-Agent": "Sleuth/3.0 OSINT Tool"},
        ) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return []

    results: list[ForumResult] = []
    for child in data.get("data", {}).get("children", []):
        d = child.get("data", {})
        results.append(ForumResult(
            platform="Reddit",
            title=d.get("title", ""),
            url=f"https://reddit.com{d.get('permalink', '')}",
            snippet=d.get("selftext", "")[:200],
            author=d.get("author", ""),
            date=str(d.get("created_utc", "")),
            score=d.get("score", 0),
        ))
    return results


async def search_reddit_user(
    session: aiohttp.ClientSession,
    username: str,
) -> dict[str, Any]:
    """Look up a Reddit user profile."""
    url = f"https://www.reddit.com/user/{username}/about.json"
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=15),
            headers={"User-Agent": "Sleuth/3.0 OSINT Tool"},
        ) as resp:
            if resp.status != 200:
                return {"found": False}
            data = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return {"found": False}

    d = data.get("data", {})
    return {
        "found": True,
        "username": d.get("name", ""),
        "id": d.get("id", ""),
        "karma": d.get("total_karma", 0),
        "comment_karma": d.get("comment_karma", 0),
        "link_karma": d.get("link_karma", 0),
        "created": d.get("created_utc", ""),
        "is_verified": d.get("verified", False),
        "has_verified_email": d.get("has_verified_email", False),
        "icon_img": d.get("icon_img", ""),
        "url": f"https://reddit.com/user/{username}",
    }


async def search_4chan(
    session: aiohttp.ClientSession,
    query: str,
    *,
    board: str = "all",
) -> list[ForumResult]:
    """Search 4chan archives via the 4chen API."""
    # Use the searchable archive API
    url = "https://archive.4plebs.org/_/api/search/"
    params = {"q": query}
    if board != "all":
        params["board"] = board
    try:
        async with session.get(
            url, params=params,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return []

    results: list[ForumResult] = []
    for post in data.get("results", [])[:25]:
        results.append(ForumResult(
            platform="4chan",
            title=post.get("thread_subject", "Untitled"),
            url=post.get("url", ""),
            snippet=post.get("comment", "")[:200],
            author=post.get("name", "Anonymous"),
            date=str(post.get("timestamp", "")),
        ))
    return results


def discord_server_search_url(query: str) -> str:
    """Build a Discord server search URL (via disboard.org)."""
    return f"https://disboard.org/search?keyword={quote(query)}"


def discord_user_lookup_url(username: str) -> str:
    """Build a Discord user lookup URL."""
    return f"https://discord.id/?prefill={quote(username)}"


# ========================================================================
# 3. Code Search
# ========================================================================

async def search_github_code(
    session: aiohttp.ClientSession,
    query: str,
    *,
    token: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Search GitHub code for *query* (username, email, etc.).

    Requires a GitHub token for code search API.
    """
    url = "https://api.github.com/search/code"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    params = {"q": query, "per_page": str(limit)}

    try:
        async with session.get(
            url, params=params, headers=headers,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return []

    results: list[dict[str, Any]] = []
    for item in data.get("items", []):
        results.append({
            "file": item.get("name", ""),
            "repo": item.get("repository", {}).get("full_name", ""),
            "path": item.get("path", ""),
            "url": item.get("html_url", ""),
            "score": item.get("score", 0),
        })
    return results


async def search_github_users(
    session: aiohttp.ClientSession,
    query: str,
    *,
    token: str | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Search GitHub users."""
    url = "https://api.github.com/search/users"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    params = {"q": query, "per_page": str(limit)}

    try:
        async with session.get(
            url, params=params, headers=headers,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return []

    return [
        {
            "username": u.get("login", ""),
            "url": u.get("html_url", ""),
            "avatar": u.get("avatar_url", ""),
            "type": u.get("type", ""),
            "score": u.get("score", 0),
        }
        for u in data.get("items", [])
    ]


async def search_gitlab(
    session: aiohttp.ClientSession,
    query: str,
    *,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Search GitLab projects and users."""
    url = "https://gitlab.com/api/v4/search"
    params = {"scope": "projects", "search": query, "per_page": str(limit)}
    try:
        async with session.get(
            url, params=params,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return []

    return [
        {
            "name": p.get("name", ""),
            "url": p.get("web_url", ""),
            "description": p.get("description", ""),
            "owner": p.get("namespace", {}).get("name", ""),
        }
        for p in data
    ]


def gist_search_url(query: str) -> str:
    """Build a GitHub Gist search URL."""
    return f"https://gist.github.com/search?q={quote(query)}"


# ========================================================================
# 4. Academic Search
# ========================================================================

def google_scholar_url(query: str) -> str:
    """Build a Google Scholar search URL."""
    return f"https://scholar.google.com/scholar?q={quote(query)}"


def orcid_search_url(name: str) -> str:
    """Build an ORCID search URL."""
    return f"https://orcid.org/orcid-search/search?searchQuery={quote(name)}"


def researchgate_search_url(query: str) -> str:
    """Build a ResearchGate search URL."""
    return f"https://www.researchgate.net/search/publication?q={quote(query)}"


async def search_orcid(
    session: aiohttp.ClientSession,
    query: str,
    *,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Search ORCID public API for researchers."""
    url = "https://pub.orcid.org/v3.0/search/"
    headers = {"Accept": "application/json"}
    params = {"q": query, "rows": str(limit)}
    try:
        async with session.get(
            url, params=params, headers=headers,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return []

    results: list[dict[str, Any]] = []
    for r in data.get("result", []):
        orcid_id = r.get("orcid-identifier", {}).get("path", "")
        given = r.get("orcid-identifier", {}).get("given-names", {}).get("value", "")
        family = r.get("orcid-identifier", {}).get("family-names", {}).get("value", "")
        results.append({
            "orcid": orcid_id,
            "name": f"{given} {family}".strip(),
            "url": f"https://orcid.org/{orcid_id}",
        })
    return results


# ========================================================================
# 5. Paste Site Monitor
# ========================================================================

PASTE_SITES = {
    "pastebin": "https://pastebin.com",
    "ghostbin": "https://ghostbin.com",
    "paste.debian": "https://paste.debian.net",
    "hastebin": "https://hastebin.com",
}


async def search_pastebin(
    session: aiohttp.ClientSession,
    query: str,
) -> list[dict[str, Any]]:
    """Search Pastebin for pastes mentioning *query*.

    Uses Google site: search since Pastebin doesn't have a public search API.
    """
    # Pastebin has a scraping API but requires PRO
    # Fall back to Google site: search URL
    google_url = f"https://www.google.com/search?q={quote(f'site:pastebin.com \"{query}\"')}"
    return [{
        "platform": "Pastebin",
        "query": query,
        "search_url": google_url,
        "note": "Open this URL to see pastes mentioning the query",
    }]


async def monitor_paste_sites(
    session: aiohttp.ClientSession,
    queries: list[str],
) -> dict[str, list[dict[str, Any]]]:
    """Monitor multiple paste sites for multiple queries."""
    results: dict[str, list[dict[str, Any]]] = {}
    for q in queries:
        results[q] = await search_pastebin(session, q)
    return results


# ========================================================================
# 6. Social Geosearch
# ========================================================================

def geosearch_urls(lat: float, lon: float, radius_km: int = 5) -> dict[str, str]:
    """Build social media geosearch URLs for a location.

    Returns URLs for Twitter, Instagram, Flickr, and YouTube
    that search for content posted near the given coordinates.
    """
    # Twitter geosearch (via search API format)
    twitter_url = (
        f"https://twitter.com/search?q=&geocode={lat},{lon},{radius_km}km"
    )
    # Instagram doesn't have a public geosearch, but we can link to location pages
    instagram_url = f"https://www.instagram.com/explore/locations/"
    # Flickr geosearch
    flickr_url = (
        f"https://www.flickr.com/search/?lat={lat}&lon={lon}&radius={radius_km}"
    )
    # YouTube geosearch (via Google)
    youtube_url = (
        f"https://www.youtube.com/results?search_query=&sp=CAI%253D"
    )

    return {
        "twitter": twitter_url,
        "instagram": instagram_url,
        "flickr": flickr_url,
        "youtube": youtube_url,
    }


# ========================================================================
# 7. Combined deep search
# ========================================================================

async def deep_search(
    session: aiohttp.ClientSession,
    target: str,
    *,
    github_token: str | None = None,
) -> dict[str, Any]:
    """Run all deep search queries for *target* in parallel."""
    dorks = build_dorks(target)

    reddit_task = search_reddit(session, target)
    github_code_task = search_github_code(session, target, token=github_token)
    github_users_task = search_github_users(session, target, token=github_token)
    gitlab_task = search_gitlab(session, target)
    orcid_task = search_orcid(session, target)

    reddit, gh_code, gh_users, gitlab, orcid = await asyncio.gather(
        reddit_task, github_code_task, github_users_task,
        gitlab_task, orcid_task,
        return_exceptions=True,
    )

    return {
        "target": target,
        "dorks": dorks,
        "reddit": reddit if not isinstance(reddit, Exception) else [],
        "github_code": gh_code if not isinstance(gh_code, Exception) else [],
        "github_users": gh_users if not isinstance(gh_users, Exception) else [],
        "gitlab": gitlab if not isinstance(gitlab, Exception) else [],
        "orcid": orcid if not isinstance(orcid, Exception) else [],
        "academic_urls": {
            "google_scholar": google_scholar_url(target),
            "researchgate": researchgate_search_url(target),
        },
        "paste_search_url": gist_search_url(target),
        "discord_search": discord_server_search_url(target),
    }
