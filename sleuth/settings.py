"""Optional API keys for the features that need them.

Most of Sleuth works with no accounts at all. A few data sources become
richer with a key (Shodan for exposed-service data, a GitHub token to raise
code-search limits, HIBP for breach lookups). Keys are read from, in order:

1. environment variables — ``SLEUTH_SHODAN_KEY`` etc. (good for servers/CI)
2. ``~/.sleuth/keys.json`` — written by the Settings panel

Values are never sent anywhere except the matching provider, and the API
never returns stored key values — only which ones are set.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

# name -> (environment variable, human label, what it unlocks)
KEYS: dict[str, tuple[str, str, str]] = {
    "shodan": ("SLEUTH_SHODAN_KEY", "Shodan", "พอร์ต/เซอร์วิส/ช่องโหว่ของ IP"),
    "github": ("SLEUTH_GITHUB_TOKEN", "GitHub token", "เพิ่มลิมิตการค้นโค้ด/gist"),
    "hibp": ("SLEUTH_HIBP_KEY", "Have I Been Pwned", "ตรวจอีเมลในข้อมูลรั่ว (ของตัวเอง)"),
    "ipinfo": ("SLEUTH_IPINFO_TOKEN", "ipinfo.io", "geolocation IP ที่แม่นขึ้น"),
}

KEYS_FILE = Path(os.environ.get("SLEUTH_KEYS", Path.home() / ".sleuth" / "keys.json"))


def _load_file() -> dict[str, str]:
    try:
        data = json.loads(KEYS_FILE.read_text(encoding="utf-8"))
        return {k: str(v) for k, v in data.items() if isinstance(v, str) and v.strip()}
    except (OSError, ValueError):
        return {}


def load_keys() -> dict[str, str]:
    """All known keys that are set (env wins over the file)."""
    out = _load_file()
    for name, (env, _, _) in KEYS.items():
        v = os.environ.get(env)
        if v and v.strip():
            out[name] = v.strip()
    return {k: v for k, v in out.items() if k in KEYS and v}


def get_key(name: str) -> str | None:
    return load_keys().get(name)


def save_keys(updates: dict[str, Any]) -> dict[str, bool]:
    """Merge ``updates`` into the keys file (empty string removes a key)."""
    data = _load_file()
    for name, value in updates.items():
        if name not in KEYS:
            continue
        value = str(value or "").strip()
        if value:
            data[name] = value
        else:
            data.pop(name, None)
    try:
        KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
        KEYS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            os.chmod(KEYS_FILE, 0o600)  # keys are secrets: owner-only where supported
        except OSError:
            pass
    except OSError:
        pass
    return status()


def status() -> dict[str, dict[str, Any]]:
    """Which keys are set and where — never the values themselves."""
    have = load_keys()
    file_keys = _load_file()
    out = {}
    for name, (env, label, unlocks) in KEYS.items():
        src = "env" if os.environ.get(env) else ("file" if name in file_keys else None)
        out[name] = {"label": label, "unlocks": unlocks, "env": env, "set": name in have, "source": src}
    return out
