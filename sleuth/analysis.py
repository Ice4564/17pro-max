"""Analysis modules: bot detection, sentiment, graph centrality, temporal patterns.

Pure-Python implementations that don't require heavy ML dependencies.
Uses heuristic methods that work offline and are suitable for OSINT analysis.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any


# ========================================================================
# 1. Bot Detection
# ========================================================================

@dataclass
class BotScore:
    """Heuristic bot/automation detection score."""

    score: int  # 0-100, higher = more likely bot
    signals: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.score >= 70:
            return "Likely Bot"
        if self.score >= 40:
            return "Suspicious"
        return "Likely Human"


def detect_bot(account: dict[str, Any]) -> BotScore:
    """Score an account for bot-like characteristics.

    Uses heuristics derived from public research on social media bots:
    - Default profile picture
    - No bio / very short bio
    - Very high or very low follower/following ratio
    - Username with many numbers or repetitive patterns
    - Very recent account creation
    - Extreme posting frequency
    """
    score = 0
    signals = []

    # Default avatar
    avatar = account.get("avatar", "")
    if not avatar or "default" in avatar.lower() or "placeholder" in avatar.lower():
        score += 15
        signals.append("Default/missing profile picture")

    # No bio or very short bio
    bio = account.get("bio", "")
    if not bio:
        score += 15
        signals.append("No bio/description")
    elif len(bio) < 20:
        score += 8
        signals.append("Very short bio")

    # Username pattern analysis
    username = account.get("username", "")
    if username:
        digits = sum(c.isdigit() for c in username)
        if digits > 4 and len(username) > 4:
            score += 15
            signals.append(f"Username has many numbers ({digits} digits)")
        # Repetitive patterns like "aaaa1234"
        if re.match(r"^(.)\1{3,}", username):
            score += 10
            signals.append("Repetitive username pattern")
        # All caps + numbers
        if username.isupper() and digits > 2:
            score += 5
            signals.append("All-caps username with numbers")

    # Follower ratio
    followers = account.get("followers", 0) or 0
    following = account.get("following", 0) or 0
    if following > 0:
        ratio = followers / following
        if ratio < 0.05 and following > 500:
            score += 20
            signals.append(f"Very low follower ratio ({ratio:.3f}) with high following ({following})")
        elif ratio > 100 and followers > 10000 and following < 50:
            score += 10
            signals.append(f"Extremely high follower ratio ({ratio:.0f}:1)")

    # Account age
    created = account.get("created", "")
    if created:
        try:
            if isinstance(created, str):
                # Try ISO format
                dt = datetime.fromisoformat(created.replace("Z", "+00:00").replace("+00:00", ""))
            elif isinstance(created, (int, float)):
                dt = datetime.fromtimestamp(created)
            else:
                dt = None
            if dt:
                age_days = (datetime.now(dt.tzinfo) - dt).days if dt.tzinfo else (datetime.now() - dt).days
                if age_days < 30:
                    score += 15
                    signals.append(f"Very new account ({age_days} days old)")
                elif age_days < 7:
                    score += 25
                    signals.append(f"Extremely new account ({age_days} days old)")
        except (ValueError, TypeError):
            pass

    # Verified badge absent + high follower count
    verified = account.get("verified", False)
    if not verified and followers > 50000:
        score += 5
        signals.append("High followers without verification badge")

    return BotScore(score=min(100, score), signals=signals)


# ========================================================================
# 2. Sentiment & Language Detection
# ========================================================================

# Simple positive/negative word lists (English + Thai)
_POSITIVE = {
    "good", "great", "awesome", "excellent", "amazing", "love", "happy",
    "best", "wonderful", "fantastic", "beautiful", "perfect", "nice",
    "cool", "fun", "enjoy", "thankful", "grateful", "blessed", "excited",
    "ดี", "เยี่ยม", "สุดยอด", "รัก", "มีความสุข", "ดีใจ", "ขอบคุณ",
}

_NEGATIVE = {
    "bad", "terrible", "awful", "hate", "horrible", "worst", "sad",
    "angry", "stupid", "ugly", "disgusting", "annoying", "disappointed",
    "fail", "broken", "sucks", "trash", "garbage", "pathetic", "boring",
    "แย่", "เกลียด", "เศร้า", "โกรธ", "ผิดหวัง", "น่ารำคาญ",
}

# Common language detection by character ranges
_LANG_RANGES = {
    "thai": (0x0E00, 0x0E7F),
    "chinese": (0x4E00, 0x9FFF),
    "japanese_hira": (0x3040, 0x309F),
    "japanese_kata": (0x30A0, 0x30FF),
    "korean": (0xAC00, 0xD7AF),
    "arabic": (0x0600, 0x06FF),
    "cyrillic": (0x0400, 0x04FF),
    "hebrew": (0x0590, 0x05FF),
}


@dataclass
class SentimentResult:
    """Simple sentiment analysis result."""

    sentiment: str  # positive, negative, neutral
    score: int  # -100 to +100
    positive_words: list[str] = field(default_factory=list)
    negative_words: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)


def detect_languages(text: str) -> list[str]:
    """Detect languages present in text by character range analysis."""
    if not text:
        return []
    langs = set()
    has_latin = False
    for ch in text:
        cp = ord(ch)
        matched = False
        for lang, (lo, hi) in _LANG_RANGES.items():
            if lo <= cp <= hi:
                langs.add(lang)
                matched = True
                break
        if not matched and ch.isalpha() and ch.isascii():
            has_latin = True
    if has_latin:
        langs.add("latin/english")
    return sorted(langs) if langs else ["unknown"]


def analyze_sentiment(text: str) -> SentimentResult:
    """Simple dictionary-based sentiment analysis.

    Works for English and Thai text. Returns a sentiment score from
    -100 (very negative) to +100 (very positive).
    """
    if not text:
        return SentimentResult(sentiment="neutral", score=0)

    # Lowercase for matching
    lower = text.lower()

    # Tokenize (split on non-word, keeping Thai characters)
    tokens = re.findall(r"[\w]+", lower, re.UNICODE)

    positive_found = [w for w in tokens if w in _POSITIVE]
    negative_found = [w for w in tokens if w in _NEGATIVE]

    pos_count = len(positive_found)
    neg_count = len(negative_found)
    total = pos_count + neg_count

    if total == 0:
        score = 0
    else:
        score = int(100 * (pos_count - neg_count) / total)

    if score > 15:
        sentiment = "positive"
    elif score < -15:
        sentiment = "negative"
    else:
        sentiment = "neutral"

    languages = detect_languages(text)

    return SentimentResult(
        sentiment=sentiment,
        score=score,
        positive_words=positive_found,
        negative_words=negative_found,
        languages=languages,
    )


# ========================================================================
# 3. Graph Centrality (pure Python)
# ========================================================================

@dataclass
class CentralityResult:
    """Graph centrality analysis for identity clusters."""

    degree_centrality: dict[str, float] = field(default_factory=dict)
    betweenness_centrality: dict[str, float] = field(default_factory=dict)
    most_central: str | None = None
    hub_score: float = 0.0


def compute_centrality(nodes: list[str], edges: list[tuple[str, str]]) -> CentralityResult:
    """Compute degree and betweenness centrality for a graph.

    Pure Python implementation (no networkx dependency).
    """
    if not nodes:
        return CentralityResult()

    # Adjacency list
    adj: dict[str, set[str]] = {n: set() for n in nodes}
    for a, b in edges:
        if a in adj and b in adj:
            adj[a].add(b)
            adj[b].add(a)

    # Degree centrality = degree / (n-1)
    n = len(nodes)
    max_deg = n - 1 if n > 1 else 1
    degree: dict[str, float] = {node: len(adj[node]) / max_deg for node in nodes}

    # Betweenness centrality (Brandes' algorithm)
    betweenness: dict[str, float] = {n: 0.0 for n in nodes}
    for s in nodes:
        # BFS
        stack: list[str] = []
        pred: dict[str, list[str]] = {n: [] for n in nodes}
        sigma: dict[str, float] = {n: 0.0 for n in nodes}
        sigma[s] = 1.0
        dist: dict[str, int] = {n: -1 for n in nodes}
        dist[s] = 0
        queue: list[str] = [s]
        while queue:
            v = queue.pop(0)
            stack.append(v)
            for w in adj[v]:
                if dist[w] < 0:
                    queue.append(w)
                    dist[w] = dist[v] + 1
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)
        # Accumulation
        delta: dict[str, float] = {n: 0.0 for n in nodes}
        while stack:
            w = stack.pop()
            for v in pred[w]:
                delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
            if w != s:
                betweenness[w] += delta[w]

    # Normalize betweenness
    norm = max(1.0, (n - 1) * (n - 2) / 2.0)
    betweenness = {k: v / norm for k, v in betweenness.items()}

    # Find most central node
    combined = {n: degree[n] + betweenness[n] for n in nodes}
    most_central = max(combined, key=combined.get) if combined else None
    hub_score = combined.get(most_central, 0.0) if most_central else 0.0

    return CentralityResult(
        degree_centrality=degree,
        betweenness_centrality=betweenness,
        most_central=most_central,
        hub_score=hub_score,
    )


# ========================================================================
# 4. Temporal Pattern Analysis
# ========================================================================

@dataclass
class TemporalPattern:
    """Analysis of posting/activity patterns over time."""

    peak_hour: int | None = None
    peak_day: str | None = None  # day of week
    timezone_guess: str | None = None
    activity_consistency: float = 0.0  # 0-1, higher = more consistent
    burst_periods: list[tuple[str, str]] = field(default_factory=list)  # date ranges
    night_ratio: float = 0.0  # fraction of activity at night
    weekend_ratio: float = 0.0  # fraction on Sat/Sun


def analyze_temporal_patterns(
    timestamps: list[str | int | datetime],
    assume_utc: bool = True,
) -> TemporalPattern:
    """Analyze temporal patterns from a list of timestamps.

    Detects likely timezone, peak activity times, burst periods, and
    activity consistency from posting timestamps.

    Args:
        timestamps: List of ISO strings, Unix timestamps, or datetime objects.
        assume_utc: If True, timestamps are treated as UTC.
    """
    if not timestamps:
        return TemporalPattern()

    dts: list[datetime] = []
    for ts in timestamps:
        try:
            if isinstance(ts, datetime):
                dt = ts
            elif isinstance(ts, (int, float)):
                dt = datetime.fromtimestamp(ts)
            elif isinstance(ts, str):
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.tzinfo:
                    dt = dt.replace(tzinfo=None)  # normalize to naive
            else:
                continue
            dts.append(dt)
        except (ValueError, TypeError):
            continue

    if len(dts) < 3:
        return TemporalPattern()

    # Hour distribution
    hour_counts = Counter(dt.hour for dt in dts)
    peak_hour = hour_counts.most_common(1)[0][0] if hour_counts else None

    # Day of week distribution
    day_counts = Counter(dt.strftime("%A") for dt in dts)
    peak_day = day_counts.most_common(1)[0][0] if day_counts else None

    # Night activity (22:00-05:00 local)
    night_count = sum(c for h, c in hour_counts.items() if h >= 22 or h < 5)
    night_ratio = night_count / len(dts)

    # Weekend ratio
    weekend_count = sum(c for d, c in day_counts.items() if d in ("Saturday", "Sunday"))
    weekend_ratio = weekend_count / len(dts) if len(dts) > 0 else 0

    # Timezone guess: the offset where peak hour becomes "reasonable" (9-21)
    # If peak hour is already in range, tz offset = 0
    # Otherwise, find offset that puts peak into range
    if peak_hour is not None and (peak_hour < 9 or peak_hour > 21):
        # Try to find a timezone that shifts peak to daytime
        best_offset = 0
        for offset in range(-12, 13):
            shifted = (peak_hour + offset) % 24
            if 9 <= shifted <= 21:
                best_offset = offset
                break
        if best_offset:
            tz_guess = f"UTC{'+' if best_offset > 0 else ''}{best_offset}"
        else:
            tz_guess = None
    elif peak_hour is not None:
        tz_guess = "UTC+0 (or local)"
    else:
        tz_guess = None

    # Activity consistency: how evenly spread are the timestamps?
    dts_sorted = sorted(dts)
    total_span = (dts_sorted[-1] - dts_sorted[0]).total_seconds()
    if total_span > 0 and len(dts_sorted) > 1:
        expected_interval = total_span / (len(dts_sorted) - 1)
        intervals = [
            (dts_sorted[i + 1] - dts_sorted[i]).total_seconds()
            for i in range(len(dts_sorted) - 1)
        ]
        if intervals:
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval > 0:
                variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
                cv = math.sqrt(variance) / mean_interval if mean_interval > 0 else 1
                activity_consistency = max(0.0, min(1.0, 1.0 / (1.0 + cv)))
            else:
                activity_consistency = 0.0
        else:
            activity_consistency = 0.0
    else:
        activity_consistency = 0.0

    # Burst detection: find periods with unusually high activity
    bursts = []
    if len(dts_sorted) >= 5:
        # Group by day
        day_groups: dict[str, list[datetime]] = defaultdict(list)
        for dt in dts_sorted:
            day_groups[dt.strftime("%Y-%m-%d")].append(dt)

        avg_per_day = len(dts_sorted) / max(1, len(day_groups))
        threshold = avg_per_day * 3 if avg_per_day > 0 else 5

        current_burst: list[str] = []
        for day_str in sorted(day_groups.keys()):
            if len(day_groups[day_str]) >= threshold:
                current_burst.append(day_str)
            else:
                if len(current_burst) >= 2:
                    bursts.append((current_burst[0], current_burst[-1]))
                current_burst = []
        if len(current_burst) >= 2:
            bursts.append((current_burst[0], current_burst[-1]))

    return TemporalPattern(
        peak_hour=peak_hour,
        peak_day=peak_day,
        timezone_guess=tz_guess,
        activity_consistency=activity_consistency,
        burst_periods=bursts,
        night_ratio=night_ratio,
        weekend_ratio=weekend_ratio,
    )
