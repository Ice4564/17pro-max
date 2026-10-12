"""Reverse image search URL builders and EXIF metadata extraction.

Provides URL generators for Google, TinEye, and Yandex reverse image
search, and extracts EXIF metadata (GPS, camera, timestamp) from
downloaded images using Pillow.
"""

from __future__ import annotations

import asyncio
import io
import math
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlencode

import aiohttp

try:
    from PIL import Image, ExifTags
    from PIL.ExifTags import TAGS, GPSTAGS
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False


# ---- reverse image search URL builders -----------------------------------


def google_reverse_image_url(image_url: str) -> str:
    """Build a Google Lens / Google Images reverse search URL."""
    return (
        "https://lens.google.com/uploadbyurl?"
        + urlencode({"url": image_url})
    )


def google_reverse_image_url_old(image_url: str) -> str:
    """Legacy Google Images reverse search (still works in some regions)."""
    return (
        "https://www.google.com/searchbyimage?"
        + urlencode({"image_url": image_url})
    )


def tineye_reverse_image_url(image_url: str) -> str:
    """Build a TinEye reverse image search URL."""
    return f"https://www.tineye.com/search?url={quote(image_url, safe='')}"


def yandex_reverse_image_url(image_url: str) -> str:
    """Build a Yandex reverse image search URL."""
    return f"https://yandex.com/images/search?url={quote(image_url, safe='')}&rpt=imageview"


def bing_reverse_image_url(image_url: str) -> str:
    """Build a Bing visual search URL."""
    return f"https://www.bing.com/images/search?q=&view=detailv2&iss=SBI&form=BISFPS&sbisrc={quote(image_url, safe='')}"


def reverse_search_urls(image_url: str) -> dict[str, str]:
    """Generate all reverse image search URLs for an image."""
    return {
        "google": google_reverse_image_url(image_url),
        "tineye": tineye_reverse_image_url(image_url),
        "yandex": yandex_reverse_image_url(image_url),
        "bing": bing_reverse_image_url(image_url),
    }


# ---- EXIF extraction -----------------------------------------------------


@dataclass
class EXIFData:
    """Extracted EXIF metadata from an image."""

    camera_make: str | None = None
    camera_model: str | None = None
    lens: str | None = None
    software: str | None = None
    date_taken: str | None = None
    iso: int | None = None
    f_number: float | None = None
    exposure_time: str | None = None
    focal_length: float | None = None
    gps_latitude: float | None = None
    gps_longitude: float | None = None
    gps_altitude: float | None = None
    orientation: int | None = None
    width: int | None = None
    height: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def has_gps(self) -> bool:
        return self.gps_latitude is not None and self.gps_longitude is not None

    @property
    def google_maps_url(self) -> str | None:
        if not self.has_gps:
            return None
        return f"https://www.google.com/maps?q={self.gps_latitude},{self.gps_longitude}"

    @property
    def osm_url(self) -> str | None:
        if not self.has_gps:
            return None
        return f"https://www.openstreetmap.org/?mlat={self.gps_latitude}&mlon={self.gps_longitude}#map=15/{self.gps_latitude}/{self.gps_longitude}"


def _convert_gps(value: tuple) -> float | None:
    """Convert GPS coordinates from EXIF rational format to decimal degrees."""
    if not value or not isinstance(value, (tuple, list)) or len(value) != 3:
        return None
    try:
        d, m, s = value
        if isinstance(d, tuple):
            d = d[0] / d[1] if d[1] else 0
        if isinstance(m, tuple):
            m = m[0] / m[1] if m[1] else 0
        if isinstance(s, tuple):
            s = s[0] / s[1] if s[1] else 0
        return float(d) + float(m) / 60 + float(s) / 3600
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def extract_exif(image_bytes: bytes) -> EXIFData:
    """Extract EXIF metadata from raw image bytes.

    Requires Pillow to be installed. If not available, returns an empty
    EXIFData object.
    """
    if not _PIL_AVAILABLE:
        return EXIFData()

    data = EXIFData()
    try:
        img = Image.open(io.BytesIO(image_bytes))
        data.width = img.width
        data.height = img.height

        exif_data = img._getexif()
        if not exif_data:
            return data

        raw: dict[str, Any] = {}
        gps_info = {}

        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)
            raw[str(tag_name)] = value
            if tag_name == "Make":
                data.camera_make = str(value).strip()
            elif tag_name == "Model":
                data.camera_model = str(value).strip()
            elif tag_name == "LensModel":
                data.lens = str(value).strip()
            elif tag_name == "Software":
                data.software = str(value).strip()
            elif tag_name == "DateTimeOriginal":
                data.date_taken = str(value)
            elif tag_name == "ISOSpeedRatings":
                data.iso = int(value) if isinstance(value, (int, tuple)) else None
            elif tag_name == "FNumber":
                data.f_number = float(value[0] / value[1]) if isinstance(value, tuple) and value[1] else None
            elif tag_name == "ExposureTime":
                if isinstance(value, tuple) and value[1]:
                    data.exposure_time = f"{value[0]}/{value[1]}"
                elif isinstance(value, int):
                    data.exposure_time = f"1/{value}"
            elif tag_name == "FocalLength":
                data.focal_length = float(value[0] / value[1]) if isinstance(value, tuple) and value[1] else None
            elif tag_name == "Orientation":
                data.orientation = int(value) if isinstance(value, int) else None
            elif tag_name == "GPSInfo":
                gps_info = value

        # Parse GPS
        if gps_info:
            for gps_tag, gps_value in gps_info.items():
                gps_name = GPSTAGS.get(gps_tag, gps_tag)
                if gps_name == "GPSLatitude":
                    data.gps_latitude = _convert_gps(gps_value)
                elif gps_name == "GPSLongitude":
                    data.gps_longitude = _convert_gps(gps_value)
                elif gps_name == "GPSAltitude":
                    if isinstance(gps_value, tuple) and gps_value[1]:
                        data.gps_altitude = float(gps_value[0] / gps_value[1])
                    elif isinstance(gps_value, (int, float)):
                        data.gps_altitude = float(gps_value)

            # Apply N/S, E/W
            for gps_tag, gps_value in gps_info.items():
                gps_name = GPSTAGS.get(gps_tag, gps_tag)
                if gps_name == "GPSLatitudeRef" and gps_value == "S" and data.gps_latitude:
                    data.gps_latitude = -data.gps_latitude
                elif gps_name == "GPSLongitudeRef" and gps_value == "W" and data.gps_longitude:
                    data.gps_longitude = -data.gps_longitude

        data.raw = raw
    except Exception:
        pass

    return data


async def fetch_and_extract_exif(
    image_url: str, session: aiohttp.ClientSession
) -> EXIFData:
    """Download an image and extract its EXIF metadata."""
    try:
        async with session.get(
            image_url,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as r:
            if r.status != 200:
                return EXIFData()
            data = await r.read()
            return extract_exif(data)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return EXIFData()


async def batch_exif(
    image_urls: list[str], session: aiohttp.ClientSession
) -> dict[str, EXIFData]:
    """Fetch and extract EXIF from multiple images concurrently."""
    results = {}
    tasks = {url: fetch_and_extract_exif(url, session) for url in image_urls}
    done = await asyncio.gather(*tasks.values(), return_exceptions=True)
    for url, result in zip(tasks.keys(), done):
        if isinstance(result, EXIFData):
            results[url] = result
        else:
            results[url] = EXIFData()
    return results
