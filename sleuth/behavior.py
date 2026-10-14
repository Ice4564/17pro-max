"""Behavioral profiling: timezone inference, activity heatmap, stylometry,
emoji fingerprint, and hashtag/interest analysis.

All pure-Python, no ML dependencies. Uses statistical heuristics.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

# ========================================================================
# 1. Timezone Inference
# ========================================================================

@dataclass
class TimezoneGuess:
    """Inferred timezone from activity patterns."""

    utc_offset: int  # hours, e.g. +7 for ICT
    confidence: int  # 0-100
    likely_zones: list[str] = field(default_factory=list)
    active_hours_utc: list[int] = field(default_factory=list)
    details: str = ""


def infer_timezone(
    timestamps: list[datetime | str],
) -> TimezoneGuess:
    """Infer the target's timezone from posting timestamps.

    *timestamps* can be datetime objects or ISO strings (assumed UTC).
    Returns the most likely UTC offset.
    """
    hours: list[int] = []  # UTC hours 0-23

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
        hours.append(dt.hour)

    if len(hours) < 3:
        return TimezoneGuess(0, 0, details="insufficient data (need >=3 timestamps)")

    # Find the peak activity hours (UTC)
    hour_counts = Counter(hours)
    # Smooth with a 3-hour window
    smoothed: dict[int, int] = {}
    for h in range(24):
        smoothed[h] = sum(hour_counts.get((h + d) % 24, 0) for d in range(-1, 2))

    # Peak hour (UTC) — assume this is ~14:00-16:00 local time (afternoon peak)
    peak_utc = max(smoothed, key=smoothed.get)
    # Assume peak local time is ~15:00 (typical social media peak)
    assumed_peak_local = 15
    offset = (peak_utc - assumed_peak_local) % 24
    if offset > 12:
        offset -= 24

    # Confidence based on how concentrated the activity is
    total = sum(hour_counts.values())
    peak_concentration = smoothed[peak_utc] / total if total > 0 else 0
    confidence = min(100, int(peak_concentration * 200))

    # Map offset to likely timezone names
    tz_map = {
        -8: ["America/Los_Angeles", "America/Tijuana"],
        -7: ["America/Denver", "America/Phoenix"],
        -6: ["America/Chicago", "America/Mexico_City"],
        -5: ["America/New_York", "America/Toronto"],
        -4: ["America/Halifax", "America/Caracas"],
        -3: ["America/Sao_Paulo", "America/Buenos_Aires"],
        0: ["Europe/London", "Europe/Lisbon", "Africa/Lagos"],
        1: ["Europe/Paris", "Europe/Berlin", "Europe/Rome"],
        2: ["Europe/Athens", "Africa/Cairo", "EET"],
        3: ["Europe/Moscow", "Africa/Nairobi", "Asia/Baghdad"],
        4: ["Asia/Dubai", "Asia/Baku"],
        5: ["Asia/Karachi", "Asia/Tashkent"],
        5.5: ["Asia/Kolkata", "Asia/Colombo"],
        7: ["Asia/Bangkok", "Asia/Jakarta", "Asia/Ho_Chi_Minh"],
        8: ["Asia/Singapore", "Asia/Hong_Kong", "Asia/Manila"],
        9: ["Asia/Tokyo", "Asia/Seoul"],
        10: ["Australia/Sydney", "Australia/Melbourne"],
    }
    likely_zones = tz_map.get(offset, [])

    return TimezoneGuess(
        utc_offset=offset,
        confidence=confidence,
        likely_zones=likely_zones,
        active_hours_utc=sorted(hour_counts.keys()),
        details=f"peak_utc={peak_utc}:00, concentration={peak_concentration:.2f}",
    )


# ========================================================================
# 2. Activity Heatmap
# ========================================================================

@dataclass
class ActivityHeatmap:
    """Activity heatmap data for visualization."""

    grid: list[list[int]]  # 7x24: [day_of_week][hour]
    peak_day: str
    peak_hour: int
    total_activity: int
    most_active_period: str


def build_activity_heatmap(
    timestamps: list[datetime | str],
) -> ActivityHeatmap:
    """Build a 7x24 activity grid (days x hours).

    Returns data suitable for rendering a GitHub-style contribution heatmap.
    """
    # 7 days x 24 hours
    grid = [[0] * 24 for _ in range(7)]
    day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

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
        # Monday=0, Sunday=6
        dow = dt.weekday()
        hour = dt.hour
        grid[dow][hour] += 1

    total = sum(sum(row) for row in grid)
    # Find peak
    peak_val = 0
    peak_day_idx = 0
    peak_hour = 0
    for d in range(7):
        for h in range(24):
            if grid[d][h] > peak_val:
                peak_val = grid[d][h]
                peak_day_idx = d
                peak_hour = h

    # Determine most active period
    morning = sum(grid[d][h] for d in range(7) for h in range(6, 12))
    afternoon = sum(grid[d][h] for d in range(7) for h in range(12, 18))
    evening = sum(grid[d][h] for d in range(7) for h in range(18, 24))
    night = sum(grid[d][h] for d in range(7) for h in range(0, 6))

    periods = {"morning": morning, "afternoon": afternoon, "evening": evening, "night": night}
    most_active = max(periods, key=periods.get)

    return ActivityHeatmap(
        grid=grid,
        peak_day=day_names[peak_day_idx],
        peak_hour=peak_hour,
        total_activity=total,
        most_active_period=most_active,
    )


# ========================================================================
# 3. Stylometry (Writing Style Fingerprint)
# ========================================================================

@dataclass
class WritingStyle:
    """Writing style fingerprint."""

    avg_sentence_length: float
    avg_word_length: float
    punctuation_density: float
    capitalization_ratio: float
    emoji_density: float
    hashtag_density: float
    vocabulary_richness: float  # type-token ratio
    signature: str  # compact fingerprint string
    top_punctuation: list[tuple[str, int]] = field(default_factory=list)
    top_words: list[tuple[str, int]] = field(default_factory=list)


def analyze_writing_style(texts: list[str]) -> WritingStyle:
    """Analyze writing style across multiple texts.

    Produces a fingerprint that can be compared across platforms
    to determine if two accounts belong to the same person.
    """
    all_text = " ".join(texts)
    if not all_text.strip():
        return WritingStyle(0, 0, 0, 0, 0, 0, 0, "empty")

    # Sentence analysis
    sentences = re.split(r"[.!?]+", all_text)
    sentences = [s.strip() for s in sentences if s.strip()]
    total_sentences = max(len(sentences), 1)

    # Word analysis
    words = re.findall(r"\b\w+\b", all_text.lower())
    total_words = max(len(words), 1)

    # Average sentence length (in words)
    avg_sent_len = total_words / total_sentences

    # Average word length
    total_chars = sum(len(w) for w in words)
    avg_word_len = total_chars / total_words

    # Punctuation density
    punct_count = sum(1 for c in all_text if c in ".,!?;:()[]{}\"'`-—")
    punct_density = punct_count / max(len(all_text), 1)

    # Capitalization ratio
    upper_count = sum(1 for c in all_text if c.isupper())
    alpha_count = sum(1 for c in all_text if c.isalpha())
    cap_ratio = upper_count / max(alpha_count, 1)

    # Emoji density
    emoji_re = re.compile(
        "[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF"
        "\U0001F1E0-\U0001F1FF\U00002600-\U000027BF\U0001F900-\U0001F9FF"
        "\U0001FA00-\U0001FA6F\U0001FA70-\U0001FAFF]"
    )
    emoji_count = len(emoji_re.findall(all_text))
    emoji_density = emoji_count / max(total_words, 1)

    # Hashtag density
    hashtag_count = len(re.findall(r"#\w+", all_text))
    hashtag_density = hashtag_count / max(total_words, 1)

    # Vocabulary richness (type-token ratio)
    unique_words = set(words)
    vocab_richness = len(unique_words) / total_words

    # Top punctuation
    punct_counter = Counter(c for c in all_text if c in ".,!?;:()[]{}\"'`-—")
    top_punct = punct_counter.most_common(5)

    # Top words (excluding common stop words)
    stop_words = {"the", "a", "an", "and", "or", "but", "in", "on", "at",
                  "to", "of", "is", "are", "was", "were", "be", "been",
                  "have", "has", "had", "do", "does", "did", "will", "would",
                  "could", "should", "may", "might", "can", "this", "that",
                  "these", "those", "i", "you", "he", "she", "it", "we", "they",
                  "my", "your", "his", "her", "its", "our", "their", "me",
                  "him", "us", "them", "for", "with", "from", "by", "as",
                  "so", "if", "then", "than", "but", "not", "no"}
    content_words = [w for w in words if w not in stop_words and len(w) > 2]
    word_counter = Counter(content_words)
    top_words = word_counter.most_common(10)

    # Compact signature: rounded metrics joined
    sig = f"S{avg_sent_len:.0f}W{avg_word_len:.1f}P{punct_density:.3f}C{cap_ratio:.2f}E{emoji_density:.3f}V{vocab_richness:.2f}"

    return WritingStyle(
        avg_sentence_length=round(avg_sent_len, 1),
        avg_word_length=round(avg_word_len, 1),
        punctuation_density=round(punct_density, 4),
        capitalization_ratio=round(cap_ratio, 3),
        emoji_density=round(emoji_density, 4),
        hashtag_density=round(hashtag_density, 4),
        vocabulary_richness=round(vocab_richness, 3),
        signature=sig,
        top_punctuation=top_punct,
        top_words=top_words,
    )


def compare_writing_styles(a: WritingStyle, b: WritingStyle) -> float:
    """Compare two writing styles and return similarity 0-100.

    Higher = more likely same author.
    """
    if a.signature == "empty" or b.signature == "empty":
        return 0.0

    # Weighted difference
    diffs = [
        abs(a.avg_sentence_length - b.avg_sentence_length) / max(a.avg_sentence_length, 1) * 0.15,
        abs(a.avg_word_length - b.avg_word_length) / max(a.avg_word_length, 1) * 0.15,
        abs(a.punctuation_density - b.punctuation_density) / max(a.punctuation_density, 0.01) * 0.20,
        abs(a.capitalization_ratio - b.capitalization_ratio) / max(a.capitalization_ratio, 0.01) * 0.10,
        abs(a.emoji_density - b.emoji_density) / max(a.emoji_density, 0.001) * 0.15,
        abs(a.vocabulary_richness - b.vocabulary_richness) / max(a.vocabulary_richness, 0.01) * 0.25,
    ]
    total_diff = sum(diffs)
    similarity = max(0.0, 100.0 - total_diff * 100)
    return round(similarity, 1)


# ========================================================================
# 4. Emoji Fingerprint
# ========================================================================

@dataclass
class EmojiFingerprint:
    """Emoji usage pattern unique to a user."""

    total_emojis: int
    unique_emojis: int
    top_emojis: list[tuple[str, int]] = field(default_factory=list)
    emoji_set: set[str] = field(default_factory=set)
    density: float = 0.0  # emojis per 100 words
    signature: str = ""  # top-5 emojis as a string


def analyze_emoji_usage(texts: list[str]) -> EmojiFingerprint:
    """Analyze emoji usage patterns across texts."""
    emoji_re = re.compile(
        "[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF"
        "\U0001F1E0-\U0001F1FF\U00002600-\U000027BF\U0001F900-\U0001F9FF"
        "\U0001FA00-\U0001FA6F\U0001FA70-\U0001FAFF]"
    )
    all_emojis: list[str] = []
    total_words = 0

    for text in texts:
        all_emojis.extend(emoji_re.findall(text))
        total_words += len(re.findall(r"\b\w+\b", text))

    counter = Counter(all_emojis)
    emoji_set = set(all_emojis)
    top5 = counter.most_common(5)
    sig = "".join(e for e, _ in top5)

    return EmojiFingerprint(
        total_emojis=len(all_emojis),
        unique_emojis=len(emoji_set),
        top_emojis=counter.most_common(20),
        emoji_set=emoji_set,
        density=round(len(all_emojis) / max(total_words, 1) * 100, 2),
        signature=sig,
    )


def compare_emoji_fingerprints(a: EmojiFingerprint, b: EmojiFingerprint) -> float:
    """Compare two emoji fingerprints. Returns similarity 0-100."""
    if not a.emoji_set or not b.emoji_set:
        return 0.0
    # Jaccard similarity
    intersection = len(a.emoji_set & b.emoji_set)
    union = len(a.emoji_set | b.emoji_set)
    jaccard = intersection / union if union > 0 else 0
    # Also compare density
    density_diff = abs(a.density - b.density) / max(a.density, b.density, 0.01)
    density_score = max(0, 1 - density_diff)
    return round((jaccard * 0.6 + density_score * 0.4) * 100, 1)


# ========================================================================
# 5. Hashtag / Interest Analysis
# ========================================================================

@dataclass
class InterestProfile:
    """Profile of a user's interests based on hashtags and keywords."""

    hashtags: list[tuple[str, int]] = field(default_factory=list)
    categories: dict[str, list[str]] = field(default_factory=dict)
    top_interests: list[str] = field(default_factory=list)
    diversity_score: float = 0.0  # 0-1, higher = more diverse interests


# Interest categories with keywords
INTEREST_CATEGORIES: dict[str, set[str]] = {
    "tech": {"coding", "programming", "python", "javascript", "ai", "ml",
             "devops", "cybersecurity", "hacking", "linux", "opensource",
             "webdev", "react", "gamedev", "blockchain", "crypto"},
    "gaming": {"gaming", "gamer", "esports", "twitch", "xbox", "playstation",
               "nintendo", "steam", "valorant", "lol", "dota", "minecraft",
               "fortnite", "genshin"},
    "music": {"music", "spotify", "band", "guitar", "piano", "rap", "hiphop",
              "rock", "jazz", "edm", "producer", "singer", "songwriter"},
    "art": {"art", "design", "illustration", "digitalart", "photography",
            "drawing", "painting", "creative", "artist", "sketch"},
    "finance": {"stocks", "investing", "trading", "forex", "crypto", "bitcoin",
                "ethereum", "defi", "nft", "finance", "money", "passive"},
    "fitness": {"fitness", "gym", "workout", "bodybuilding", "yoga", "running",
                "health", "diet", "nutrition", "weightloss"},
    "travel": {"travel", "wanderlust", "backpacking", "adventure", "explore",
               "vacation", "trip", "journey", "nomad", "digitalnomad"},
    "food": {"food", "foodie", "cooking", "recipe", "chef", "restaurant",
             "baking", "foodporn", "instafood"},
    "fashion": {"fashion", "style", "ootd", "outfit", "streetwear",
                "sneakers", "luxury", "brand", "model"},
    "politics": {"politics", "news", "election", "democracy", "activism",
                 "protest", "government", "policy"},
}


def analyze_interests(texts: list[str]) -> InterestProfile:
    """Analyze hashtags and keywords to build an interest profile."""
    all_text = " ".join(texts).lower()

    # Extract hashtags
    hashtags = re.findall(r"#(\w+)", all_text)
    hashtag_counter = Counter(hashtags)

    # Categorize
    words = set(re.findall(r"\b\w+\b", all_text))
    categories: dict[str, list[str]] = {}
    for cat, keywords in INTEREST_CATEGORIES.items():
        matched = sorted(keywords & words)
        if matched:
            categories[cat] = matched

    # Top interests (categories with most matches)
    cat_scores = {cat: len(matches) for cat, matches in categories.items()}
    top_interests = sorted(cat_scores, key=cat_scores.get, reverse=True)[:5]

    # Diversity: how many categories are represented
    diversity = len(categories) / len(INTEREST_CATEGORIES) if INTEREST_CATEGORIES else 0

    return InterestProfile(
        hashtags=hashtag_counter.most_common(20),
        categories=categories,
        top_interests=top_interests,
        diversity_score=round(diversity, 2),
    )


# ========================================================================
# 6. Combined behavioral profile
# ========================================================================

def build_behavioral_profile(
    texts: list[str],
    timestamps: list[datetime | str] | None = None,
) -> dict[str, Any]:
    """Build a complete behavioral profile from texts and timestamps."""
    profile: dict[str, Any] = {
        "writing_style": analyze_writing_style(texts),
        "emoji": analyze_emoji_usage(texts),
        "interests": analyze_interests(texts),
    }
    if timestamps:
        profile["timezone"] = infer_timezone(timestamps)
        profile["activity"] = build_activity_heatmap(timestamps)
    return profile


def compare_profiles(
    a: dict[str, Any], b: dict[str, Any]
) -> dict[str, float]:
    """Compare two behavioral profiles. Returns per-signal similarity scores."""
    scores: dict[str, float] = {}

    if "writing_style" in a and "writing_style" in b:
        scores["writing_style"] = compare_writing_styles(
            a["writing_style"], b["writing_style"])

    if "emoji" in a and "emoji" in b:
        scores["emoji"] = compare_emoji_fingerprints(
            a["emoji"], b["emoji"])

    if "timezone" in a and "timezone" in b:
        tz_diff = abs(a["timezone"].utc_offset - b["timezone"].utc_offset)
        scores["timezone"] = round(max(0, 100 - tz_diff * 8), 1)

    if "interests" in a and "interests" in b:
        a_cats = set(a["interests"].categories.keys())
        b_cats = set(b["interests"].categories.keys())
        if a_cats or b_cats:
            jaccard = len(a_cats & b_cats) / len(a_cats | b_cats)
            scores["interests"] = round(jaccard * 100, 1)

    if scores:
        scores["overall"] = round(sum(scores.values()) / len(scores), 1)

    return scores
