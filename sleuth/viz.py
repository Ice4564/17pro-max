"""Visualization: D3.js network graph data, timeline data,
geographic heatmap data, and activity calendar data.

Generates JSON data structures that the web UI renders with D3.js.
All data is computed from search results — no external rendering deps.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# ========================================================================
# 1. Network Graph (D3.js force-directed)
# ========================================================================

@dataclass
class GraphNode:
    """A node in the network graph."""

    id: str
    label: str
    type: str  # "account", "identity", "domain", "email", "phone", "crypto"
    url: str = ""
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """An edge in the network graph."""

    source: str
    target: str
    label: str = ""
    weight: int = 1


def build_network_graph(
    results: list[dict[str, Any]],
    connections: list[dict[str, Any]] | None = None,
    intel: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a D3.js-compatible force-directed graph from results.

    Returns ``{"nodes": [...], "links": [...]}`` suitable for
    ``JSON.stringify`` and feeding to a D3 force simulation.
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_ids: set[str] = set()

    def add_node(node_id: str, label: str, ntype: str, url: str = "", **props) -> None:
        if node_id not in node_ids:
            node_ids.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "type": ntype,
                "url": url,
                "properties": props,
            })

    # Add account nodes
    for r in results:
        if r.get("status") != "found":
            continue
        site = r.get("site", "")
        username = r.get("username", "")
        url = r.get("url", "")
        info = r.get("info") or {}
        node_id = f"acct:{site}/{username}"

        add_node(node_id, f"{site} @{username}", "account", url,
                 platform=site, username=username,
                 avatar=info.get("avatar", ""),
                 followers=info.get("followers", ""))

        # Add linked identity nodes
        name = info.get("name", "")
        if name:
            name_id = f"name:{name.lower()}"
            add_node(name_id, name, "identity")
            edges.append({"source": node_id, "target": name_id, "label": "has name", "weight": 2})

        email = info.get("email", "")
        if email:
            email_id = f"email:{email.lower()}"
            add_node(email_id, email, "email")
            edges.append({"source": node_id, "target": email_id, "label": "has email", "weight": 3})

        location = info.get("location", "")
        if location:
            loc_id = f"loc:{location.lower()}"
            add_node(loc_id, location, "location")
            edges.append({"source": node_id, "target": loc_id, "label": "located in", "weight": 1})

        website = info.get("website", "")
        if website and website.startswith("http"):
            web_id = f"web:{website.lower()}"
            add_node(web_id, website, "domain")
            edges.append({"source": node_id, "target": web_id, "label": "links to", "weight": 1})

    # Add connection edges (identity correlation)
    if connections:
        for conn in connections:
            a = conn.get("a", "")
            b = conn.get("b", "")
            score = conn.get("score", 0)
            # Try to match connection format to node IDs
            a_id = f"acct:{a}" if "/" in a else a
            b_id = f"acct:{b}" if "/" in b else b
            if a_id in node_ids and b_id in node_ids:
                edges.append({
                    "source": a_id, "target": b_id,
                    "label": f"linked ({score}%)",
                    "weight": max(1, score // 20),
                })

    # Add intel nodes (crypto, phones, images)
    if intel:
        for crypto_item in intel.get("crypto", []):
            cval = crypto_item.get("value", "")
            ctype = crypto_item.get("type", "")
            cid = f"crypto:{cval.lower()}"
            add_node(cid, cval, "crypto", crypto_type=ctype)
            for src in crypto_item.get("sources", []):
                src_id = f"acct:{src.replace('@', '').replace(' ', '/')}"
                # Try to find matching node
                for n in nodes:
                    if src.lower() in n["label"].lower():
                        edges.append({"source": n["id"], "target": cid, "label": "mentions", "weight": 1})
                        break

        for phone_item in intel.get("phones", []):
            pnum = phone_item.get("number", "")
            pid = f"phone:{pnum}"
            add_node(pid, pnum, "phone")
            for src in phone_item.get("sources", []):
                for n in nodes:
                    if src.lower() in n["label"].lower():
                        edges.append({"source": n["id"], "target": pid, "label": "has phone", "weight": 2})
                        break

    return {"nodes": nodes, "links": edges}


# ========================================================================
# 2. Timeline Visualization
# ========================================================================

@dataclass
class TimelineEvent:
    """A single event in the timeline."""

    date: str
    title: str
    description: str
    category: str  # "account", "identity", "infrastructure", "search", "alert"
    url: str = ""
    importance: int = 5  # 1-10


def build_timeline(
    results: list[dict[str, Any]],
    connections: list[dict[str, Any]] | None = None,
    history_data: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Build a timeline of all events for visualization.

    Returns a list of events sorted chronologically.
    """
    events: list[dict[str, Any]] = []

    for r in results:
        if r.get("status") != "found":
            continue
        info = r.get("info") or {}
        site = r.get("site", "")
        username = r.get("username", "")
        url = r.get("url", "")

        # Account creation
        created = info.get("created", "")
        if created:
            events.append({
                "date": str(created),
                "title": f"Account created on {site}",
                "description": f"@{username} joined {site}",
                "category": "account",
                "url": url,
                "importance": 7,
            })

        # Profile changes from history
        if history_data:
            for h in history_data:
                if h.get("platform", "").lower() == site.lower():
                    events.append({
                        "date": h.get("date", ""),
                        "title": f"Profile changed on {site}",
                        "description": h.get("description", ""),
                        "category": "alert",
                        "url": url,
                        "importance": 5,
                    })

        # First seen (from search)
        events.append({
            "date": datetime.now().isoformat()[:10],
            "title": f"Found on {site}",
            "description": f"@{username} discovered during search",
            "category": "search",
            "url": url,
            "importance": 6,
        })

    # Sort by date
    events.sort(key=lambda e: e.get("date", ""))
    return events


# ========================================================================
# 3. Geographic Heatmap
# ========================================================================

@dataclass
class GeoPoint:
    """A geographic point for the heatmap."""

    lat: float
    lon: float
    label: str
    weight: int = 1
    url: str = ""
    category: str = "account"


def build_geo_data(
    results: list[dict[str, Any]],
    geo_info: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build geographic data for heatmap visualization.

    Combines location names from profiles with IP geolocation data.
    """
    points: list[dict[str, Any]] = []

    # Known city coordinates (simplified — in production would use a geocoder)
    CITY_COORDS: dict[str, tuple[float, float]] = {
        "bangkok": (13.7563, 100.5018),
        "thailand": (15.8700, 100.9925),
        "tokyo": (35.6762, 139.6503),
        "japan": (36.2048, 138.2529),
        "seoul": (37.5665, 126.9780),
        "korea": (35.9078, 127.7669),
        "beijing": (39.9042, 116.4074),
        "china": (35.8617, 104.1954),
        "singapore": (1.3521, 103.8198),
        "london": (51.5074, -0.1278),
        "uk": (55.3781, -3.4360),
        "new york": (40.7128, -74.0060),
        "usa": (37.0902, -95.7129),
        "paris": (48.8566, 2.3522),
        "france": (46.2276, 2.2137),
        "berlin": (52.5200, 13.4050),
        "germany": (51.1657, 10.4515),
        "sydney": (-33.8688, 151.2093),
        "australia": (-25.2744, 133.7751),
    }

    for r in results:
        if r.get("status") != "found":
            continue
        info = r.get("info") or {}
        location = (info.get("location") or "").lower().strip()

        if location:
            # Try to match city/country
            for key, (lat, lon) in CITY_COORDS.items():
                if key in location:
                    points.append({
                        "lat": lat, "lon": lon,
                        "label": f"{r['site']} @{r['username']}",
                        "weight": 1,
                        "url": r.get("url", ""),
                        "category": "account",
                        "location": location,
                    })
                    break

    # Add IP geolocation points
    if geo_info:
        for ip, info in geo_info.items():
            if hasattr(info, "latitude") and info.latitude:
                points.append({
                    "lat": info.latitude,
                    "lon": info.longitude,
                    "label": f"{ip} ({info.city}, {info.country})",
                    "weight": 2,
                    "url": "",
                    "category": "infrastructure",
                    "location": f"{info.city}, {info.country}",
                })

    return points


# ========================================================================
# 4. Activity Calendar (GitHub-style contribution graph)
# ========================================================================

def build_activity_calendar(
    timestamps: list[datetime | str],
    *,
    weeks: int = 52,
) -> dict[str, Any]:
    """Build a GitHub-style contribution graph data structure.

    Returns ``{"days": [...], "max": int, "total": int}`` where each day
    is ``{"date": "YYYY-MM-DD", "count": int, "level": 0-4}``.
    """
    # Count activity per day
    day_counts: dict[str, int] = defaultdict(int)

    for ts in timestamps:
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                continue
        elif isinstance(ts, datetime):
            dt = ts
        else:
            continue
        date_str = dt.strftime("%Y-%m-%d")
        day_counts[date_str] += 1

    # Build the calendar grid (last N weeks)
    today = datetime.now()
    days: list[dict[str, Any]] = []
    total_days = weeks * 7

    for i in range(total_days - 1, -1, -1):
        day = today - __import__("datetime").timedelta(days=i)
        date_str = day.strftime("%Y-%m-%d")
        count = day_counts.get(date_str, 0)
        # Level: 0 (none), 1 (low), 2 (medium), 3 (high), 4 (very high)
        if count == 0:
            level = 0
        elif count <= 2:
            level = 1
        elif count <= 5:
            level = 2
        elif count <= 10:
            level = 3
        else:
            level = 4

        days.append({
            "date": date_str,
            "count": count,
            "level": level,
            "day_of_week": day.weekday(),
        })

    max_count = max((d["count"] for d in days), default=0)
    total = sum(d["count"] for d in days)

    return {
        "days": days,
        "max": max_count,
        "total": total,
        "weeks": weeks,
    }


# ========================================================================
# 5. Summary dashboard data
# ========================================================================

def build_dashboard_data(
    results: list[dict[str, Any]],
    connections: list[dict[str, Any]] | None = None,
    intel: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a complete dashboard data structure for the web UI.

    Combines graph, timeline, geo, and summary stats.
    """
    found = [r for r in results if r.get("status") == "found"]

    # Platform distribution
    platform_counts = Counter(r["site"] for r in found)

    # Data type exposure
    data_types: dict[str, int] = defaultdict(int)
    for r in found:
        info = r.get("info") or {}
        for key in ("name", "email", "location", "bio", "website", "avatar", "phone", "created"):
            if info.get(key):
                data_types[key] += 1

    return {
        "summary": {
            "total_accounts": len(found),
            "platforms": len(platform_counts),
            "connections": len(connections or []),
            "top_platforms": platform_counts.most_common(10),
            "data_types": dict(data_types),
        },
        "graph": build_network_graph(results, connections, intel),
        "timeline": build_timeline(results, connections),
        "geo": build_geo_data(results),
    }
