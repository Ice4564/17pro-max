"""Image forensics: steganography detection, ELA, face detection,
image hash clustering, and deepfake indicators.

Pure-Python implementations using Pillow (already a dependency).
No external ML libraries required.
"""

from __future__ import annotations

import hashlib
import io
import math
import struct
from dataclasses import dataclass, field
from typing import Any

from PIL import Image, ImageChops, ImageStat

# ========================================================================
# 1. LSB Steganography Detection
# ========================================================================

@dataclass
class StegoResult:
    """Result of steganography detection."""

    has_hidden_data: bool
    confidence: int  # 0-100
    lsb_ratio: float  # fraction of pixels with unusual LSB patterns
    channels_checked: list[str] = field(default_factory=list)
    details: str = ""


def detect_lsb_steganography(image: Image.Image) -> StegoResult:
    """Detect potential LSB (Least Significant Bit) steganography.

    Analyzes the LSB plane for statistical anomalies that suggest
    hidden data embedding. Uses chi-square and sample-pair analysis.
    """
    img = image.convert("RGB")
    width, height = img.size
    total_pixels = width * height

    if total_pixels < 100:
        return StegoResult(False, 0, 0.0, ["R", "G", "B"], "image too small")

    pixels = list(img.getdata())
    channels = ["R", "G", "B"]
    lsb_ratios: list[float] = []
    chi_squares: list[float] = []

    for ch_idx in range(3):
        # Extract LSBs for this channel
        lsbs = [p[ch_idx] & 1 for p in pixels]

        # Count pairs (0,0), (0,1), (1,0), (1,1)
        pairs = {"00": 0, "01": 0, "10": 0, "11": 0}
        for i in range(0, len(lsbs) - 1, 2):
            key = f"{lsbs[i]}{lsbs[i + 1]}"
            pairs[key] = pairs.get(key, 0) + 1

        # Chi-square test: in natural images, (0,1) and (1,0) pairs
        # are roughly equal. In stego images, they diverge.
        total_pairs = sum(pairs.values())
        if total_pairs == 0:
            continue

        expected = total_pairs / 4
        chi_sq = sum((pairs[k] - expected) ** 2 / expected for k in pairs)
        chi_squares.append(chi_sq)

        # LSB ratio: fraction of pixels where LSB differs from neighbor
        lsb_diff = sum(1 for i in range(len(lsbs) - 1) if lsbs[i] != lsbs[i + 1])
        lsb_ratios.append(lsb_diff / (len(lsbs) - 1))

    avg_chi = sum(chi_squares) / len(chi_squares) if chi_squares else 0
    avg_lsb = sum(lsb_ratios) / len(lsb_ratios) if lsb_ratios else 0

    # High chi-square = more likely stego (natural images have low chi-sq)
    # LSB ratio near 0.5 = random data (stego), near 0 = natural image
    confidence = min(100, int(avg_chi * 10))
    has_hidden = avg_lsb > 0.45 or confidence > 50

    return StegoResult(
        has_hidden_data=has_hidden,
        confidence=confidence,
        lsb_ratio=avg_lsb,
        channels_checked=channels,
        details=f"chi_square={avg_chi:.2f}, lsb_ratio={avg_lsb:.4f}",
    )


# ========================================================================
# 2. Error Level Analysis (ELA)
# ========================================================================

@dataclass
class ELAResult:
    """Result of Error Level Analysis."""

    is_manipulated: bool
    manipulation_score: int  # 0-100
    error_levels: list[float] = field(default_factory=list)
    details: str = ""


def error_level_analysis(image: Image.Image, quality: int = 90) -> ELAResult:
    """Perform Error Level Analysis on an image.

    Re-saves the image at a known JPEG quality, then compares the
    difference. Areas with high difference may have been edited.
    """
    # Save as JPEG at specified quality
    original = image.convert("RGB")
    buf = io.BytesIO()
    original.save(buf, format="JPEG", quality=quality)
    buf.seek(0)
    reencoded = Image.open(buf).convert("RGB")

    # Compute pixel difference
    diff = ImageChops.difference(original, reencoded)
    stat = ImageStat.Stat(diff)

    # Average per-channel difference
    channel_diffs = stat.mean  # [R, G, B]
    avg_diff = sum(channel_diffs) / len(channel_diffs)

    # Also compute max difference regions
    extrema = diff.getextrema()
    max_diff = max(e[1] for e in extrema)

    # Score: higher difference = more likely manipulated
    score = min(100, int(avg_diff * 5))
    is_manipulated = avg_diff > 5 or max_diff > 30

    return ELAResult(
        is_manipulated=is_manipulated,
        manipulation_score=score,
        error_levels=channel_diffs,
        details=f"avg_diff={avg_diff:.2f}, max_diff={max_diff}",
    )


# ========================================================================
# 3. Face Detection (pure Python — skin-tone heuristic)
# ========================================================================

@dataclass
class FaceRegion:
    """A detected face region."""

    x: int
    y: int
    width: int
    height: int
    confidence: int  # 0-100


@dataclass
class FaceDetectionResult:
    """Result of face detection."""

    faces: list[FaceRegion] = field(default_factory=list)
    face_count: int = 0
    has_face: bool = False
    skin_ratio: float = 0.0  # fraction of image that is skin-tone


def detect_faces(image: Image.Image) -> FaceDetectionResult:
    """Detect faces using skin-tone heuristic (no ML required).

    Uses YCbCr color space skin detection + region analysis.
    Not as accurate as a CNN, but works for avatar-sized images.
    """
    img = image.convert("YCbCr")
    width, height = img.size
    pixels = list(img.getdata())

    # Skin detection in YCbCr
    # Typical skin: Y > 80, 77 <= Cb <= 127, 133 <= Cr <= 173
    skin_map: list[bool] = []
    for y_val, cb, cr in pixels:
        is_skin = (
            y_val > 80
            and 77 <= cb <= 127
            and 133 <= cr <= 173
        )
        skin_map.append(is_skin)

    skin_count = sum(skin_map)
    total = len(skin_map)
    skin_ratio = skin_count / total if total > 0 else 0

    # Find connected skin regions (simple bounding-box approach)
    # Downsample for speed on large images
    grid_w = min(width, 64)
    grid_h = min(height, 64)
    cell_w = width / grid_w
    cell_h = height / grid_h

    grid: list[list[bool]] = [[False] * grid_w for _ in range(grid_h)]
    for gy in range(grid_h):
        for gx in range(grid_w):
            px = int(gx * cell_w)
            py = int(gy * cell_h)
            idx = py * width + px
            if idx < len(skin_map):
                grid[gy][gx] = skin_map[idx]

    # Find connected components (flood fill)
    visited: set[tuple[int, int]] = set()
    regions: list[tuple[int, int, int, int]] = []  # min_x, min_y, max_x, max_y

    for gy in range(grid_h):
        for gx in range(grid_w):
            if not grid[gy][gx] or (gx, gy) in visited:
                continue
            # Flood fill
            stack = [(gx, gy)]
            min_x = max_x = gx
            min_y = max_y = gy
            while stack:
                cx, cy = stack.pop()
                if (cx, cy) in visited or cx < 0 or cx >= grid_w or cy < 0 or cy >= grid_h:
                    continue
                if not grid[cy][cx]:
                    continue
                visited.add((cx, cy))
                min_x = min(min_x, cx)
                max_x = max(max_x, cx)
                min_y = min(min_y, cy)
                max_y = max(max_y, cy)
                stack.extend([(cx + 1, cy), (cx - 1, cy), (cx, cy + 1), (cx, cy - 1)])

            # Filter: face-like regions are roughly square and not too small
            w = max_x - min_x + 1
            h = max_y - min_y + 1
            if w >= 4 and h >= 4 and 0.5 < w / h < 2.0:
                regions.append((min_x, min_y, max_x, max_y))

    faces: list[FaceRegion] = []
    for rx, ry, rmx, rmy in regions[:5]:  # top 5 faces
        fx = int(rx * cell_w)
        fy = int(ry * cell_h)
        fw = int((rmx - rx + 1) * cell_w)
        fh = int((rmy - ry + 1) * cell_h)
        confidence = min(100, int((fw * fh / (width * height)) * 500))
        faces.append(FaceRegion(x=fx, y=fy, width=fw, height=fh, confidence=confidence))

    return FaceDetectionResult(
        faces=faces,
        face_count=len(faces),
        has_face=len(faces) > 0,
        skin_ratio=skin_ratio,
    )


# ========================================================================
# 4. Image Hash Clustering (pHash + dHash + color histogram)
# ========================================================================

def phash(image: Image.Image, hash_size: int = 8) -> int:
    """Compute a perceptual hash (pHash) using DCT.

    More robust than dHash for images that have been resized or
    slightly modified.
    """
    img = image.convert("L").resize((hash_size * 4, hash_size * 4), Image.LANCZOS)
    pixels = list(img.getdata())
    w = hash_size * 4

    # Simple DCT (we only need the top-left hash_size x hash_size block)
    # For speed, use a simplified version
    dct_block: list[float] = []
    for i in range(hash_size):
        for j in range(hash_size):
            s = 0.0
            for x in range(hash_size * 4):
                for y in range(hash_size * 4):
                    s += pixels[x * w + y] * math.cos(
                        math.pi * (2 * x + 1) * i / (2 * hash_size * 4)
                    ) * math.cos(
                        math.pi * (2 * y + 1) * j / (2 * hash_size * 4)
                    )
            dct_block.append(s)

    # Median threshold
    median = sorted(dct_block)[len(dct_block) // 2]
    result = 0
    for v in dct_block:
        result = (result << 1) | (1 if v > median else 0)
    return result


def color_histogram(image: Image.Image, bins: int = 8) -> list[int]:
    """Compute a color histogram for an image.

    Returns a flat list of ``bins*3`` values (R, G, B histograms).
    """
    img = image.convert("RGB").resize((64, 64), Image.LANCZOS)
    hist_r = [0] * bins
    hist_g = [0] * bins
    hist_b = [0] * bins
    for r, g, b in img.getdata():
        hist_r[r * bins // 256] += 1
        hist_g[g * bins // 256] += 1
        hist_b[b * bins // 256] += 1
    return hist_r + hist_g + hist_b


def histogram_distance(h1: list[int], h2: list[int]) -> float:
    """Compute the chi-square distance between two histograms."""
    total = 0
    for a, b in zip(h1, h2):
        denom = a + b
        if denom > 0:
            total += (a - b) ** 2 / denom
    return total / 2


@dataclass
class ImageCluster:
    """A cluster of similar images."""

    representative_url: str
    member_urls: list[str]
    similarity: float  # 0-1, higher = more similar


def cluster_images(
    images: list[dict[str, Any]],
    *,
    phash_threshold: int = 12,
    hist_threshold: float = 0.3,
) -> list[ImageCluster]:
    """Cluster images by visual similarity.

    *images* is a list of ``{"url": str, "pil": Image.Image}``.
    Uses pHash + color histogram for robust matching.
    """
    if len(images) < 2:
        return []

    # Compute hashes
    hashes: list[tuple[int, list[int], str]] = []
    for img_info in images:
        pil = img_info.get("pil")
        url = img_info.get("url", "")
        if pil is None:
            continue
        ph = phash(pil)
        hist = color_histogram(pil)
        hashes.append((ph, hist, url))

    if len(hashes) < 2:
        return []

    # Union-Find for clustering
    parent = list(range(len(hashes)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        px, py = find(x), find(y)
        if px != py:
            parent[px] = py

    for i in range(len(hashes)):
        for j in range(i + 1, len(hashes)):
            # Hamming distance between pHashes
            ph_dist = bin(hashes[i][0] ^ hashes[j][0]).count("1")
            # Histogram distance
            h_dist = histogram_distance(hashes[i][1], hashes[j][1])
            if ph_dist <= phash_threshold or h_dist < hist_threshold:
                union(i, j)

    # Group by cluster
    clusters: dict[int, list[int]] = {}
    for i in range(len(hashes)):
        root = find(i)
        clusters.setdefault(root, []).append(i)

    result: list[ImageCluster] = []
    for members in clusters.values():
        if len(members) < 2:
            continue
        urls = [hashes[m][2] for m in members]
        result.append(ImageCluster(
            representative_url=urls[0],
            member_urls=urls,
            similarity=1.0 - phash_threshold / 64,
        ))

    return result


# ========================================================================
# 5. Deepfake Indicators (frequency-domain analysis)
# ========================================================================

@dataclass
class DeepfakeResult:
    """Result of deepfake detection."""

    is_likely_deepfake: bool
    confidence: int  # 0-100
    indicators: list[str] = field(default_factory=list)
    details: str = ""


def detect_deepfake_indicators(image: Image.Image) -> DeepfakeResult:
    """Detect potential AI-generated image indicators.

    Uses frequency-domain analysis (DCT) and noise pattern analysis.
    AI-generated images often have distinct frequency signatures.
    """
    img = image.convert("L").resize((64, 64), Image.LANCZOS)
    pixels = list(img.getdata())
    w = 64

    # Compute 2D DCT energy distribution
    # Natural images have more energy in low frequencies
    # AI images may have unusual high-frequency patterns
    low_freq_energy = 0.0
    high_freq_energy = 0.0

    for i in range(64):
        for j in range(64):
            s = 0.0
            for x in range(64):
                for y in range(64):
                    s += pixels[x * w + y] * math.cos(
                        math.pi * (2 * x + 1) * i / 128
                    ) * math.cos(
                        math.pi * (2 * y + 1) * j / 128
                    )
            if i < 8 and j < 8:
                low_freq_energy += abs(s)
            elif i > 32 or j > 32:
                high_freq_energy += abs(s)

    total = low_freq_energy + high_freq_energy
    if total == 0:
        return DeepfakeResult(False, 0, ["unable to analyze"])

    high_ratio = high_freq_energy / total
    # Natural images: high-freq ratio typically < 0.1
    # AI images: often > 0.15 due to GAN artifacts

    indicators: list[str] = []
    confidence = 0

    if high_ratio > 0.15:
        indicators.append(f"unusual high-frequency energy ({high_ratio:.3f})")
        confidence += 30

    # Check for unnatural smoothness (AI images are often too smooth)
    # Compute pixel variance
    mean = sum(pixels) / len(pixels)
    variance = sum((p - mean) ** 2 for p in pixels) / len(pixels)
    if variance < 100:  # very low variance = suspiciously smooth
        indicators.append(f"unnaturally smooth (variance={variance:.1f})")
        confidence += 25

    # Check for repeating patterns (GAN artifacts)
    # Simple autocorrelation check
    autocorr = 0
    for i in range(0, len(pixels) - 1, 2):
        autocorr += abs(pixels[i] - pixels[i + 1])
    avg_diff = autocorr / (len(pixels) // 2)
    if avg_diff < 5:  # very low local difference = possible artifact
        indicators.append(f"low local variation (avg_diff={avg_diff:.1f})")
        confidence += 20

    is_deepfake = confidence >= 50

    return DeepfakeResult(
        is_likely_deepfake=is_deepfake,
        confidence=min(100, confidence),
        indicators=indicators,
        details=f"high_freq_ratio={high_ratio:.4f}, variance={variance:.1f}",
    )


# ========================================================================
# 6. Full forensic analysis
# ========================================================================

def full_forensic_analysis(image: Image.Image) -> dict[str, Any]:
    """Run all forensic checks on an image and return combined result."""
    return {
        "steganography": detect_lsb_steganography(image),
        "ela": error_level_analysis(image),
        "faces": detect_faces(image),
        "deepfake": detect_deepfake_indicators(image),
        "phash": phash(image),
        "histogram": color_histogram(image),
    }


async def analyze_avatar(
    session: Any, url: str
) -> dict[str, Any]:
    """Download and forensically analyze an avatar image."""
    from .avatars import dhash  # reuse existing dhash

    try:
        async with session.get(url, timeout=__import__("aiohttp").ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                return {"url": url, "error": f"HTTP {resp.status}"}
            data = await resp.read()
    except Exception as e:
        return {"url": url, "error": str(e)}

    try:
        img = Image.open(io.BytesIO(data))
    except Exception as e:
        return {"url": url, "error": f"cannot open image: {e}"}

    result = full_forensic_analysis(img)
    result["url"] = url
    result["dhash"] = dhash(img)
    return result
