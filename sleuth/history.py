"""Username-search history in SQLite (``~/.sleuth/history.db`` by default).

Three jobs share one small database:

* **snapshots**  every run stores what each profile looked like, so the next
                 run can say "bio changed", "avatar changed",
                 "followers 1,240 -> 1,391" (profile change tracker);
* **accounts**   first time an account was seen and when it was last
                 checked, for the evidence list;
* **cache**      definitive answers (found / not found) are reused for a
                 few hours instead of asking the same site again.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DB = Path(os.environ.get("SLEUTH_HISTORY", Path.home() / ".sleuth" / "history.db"))
DEFAULT_TTL = 6 * 3600  # seconds a cached answer stays valid

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usernames TEXT NOT NULL,
    started TEXT NOT NULL,
    finished TEXT,
    stats TEXT,
    options TEXT
);
CREATE TABLE IF NOT EXISTS snapshots (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    site_key TEXT NOT NULL, user_key TEXT NOT NULL,
    site TEXT NOT NULL, username TEXT NOT NULL, url TEXT NOT NULL,
    status TEXT NOT NULL, info TEXT NOT NULL, avatar_hash TEXT, checked_at TEXT NOT NULL,
    PRIMARY KEY (run_id, site_key, user_key)
);
CREATE TABLE IF NOT EXISTS accounts (
    site_key TEXT NOT NULL, user_key TEXT NOT NULL,
    site TEXT NOT NULL, username TEXT NOT NULL, url TEXT NOT NULL,
    first_seen TEXT, last_found TEXT, last_checked TEXT NOT NULL,
    last_status TEXT NOT NULL, last_info TEXT NOT NULL, last_hash TEXT, last_run INTEGER,
    PRIMARY KEY (site_key, user_key)
);
CREATE TABLE IF NOT EXISTS changes (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    site TEXT NOT NULL, username TEXT NOT NULL, url TEXT NOT NULL,
    field TEXT NOT NULL, kind TEXT NOT NULL, old TEXT, new TEXT, old_seen TEXT, detected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cache (
    site_key TEXT NOT NULL, user_key TEXT NOT NULL, sig TEXT NOT NULL,
    ts REAL NOT NULL, data TEXT NOT NULL,
    PRIMARY KEY (site_key, user_key)
);
CREATE INDEX IF NOT EXISTS snapshots_user ON snapshots(user_key);
CREATE INDEX IF NOT EXISTS changes_user ON changes(username);
"""

# Profile fields worth tracking, with Thai labels for reports.
TRACKED = {
    "name": "ชื่อที่แสดง",
    "bio": "Bio",
    "location": "ที่อยู่",
    "website": "เว็บไซต์",
    "followers": "ผู้ติดตาม",
    "following": "กำลังติดตาม",
    "avatar": "รูปโปรไฟล์",
}
STATUS_LABEL = {"status": "สถานะบัญชี"}
AVATAR_CHANGED = 10  # bits out of 64 between two dHashes that count as a different picture


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_count(value: str | None) -> int | None:
    """'1,240' -> 1240, '1.2K' -> 1200, '3M' -> 3000000, anything else -> None."""
    if not value:
        return None
    m = re.fullmatch(r"\s*([\d][\d,.\s]*)\s*([kKmMbB]?)\s*", str(value))
    if not m:
        return None
    num, unit = m.group(1).replace(" ", ""), m.group(2).lower()
    if unit:
        try:
            return int(float(num.replace(",", ".") if num.count(",") == 1 and "." not in num else num.replace(",", ""))
                       * {"k": 1e3, "m": 1e6, "b": 1e9}[unit])
        except ValueError:
            return None
    digits = re.sub(r"[,.]", "", num)
    return int(digits) if digits.isdigit() else None


def _avatar_path(url: str) -> str:
    # CDNs add signatures/size parameters that change on every request
    return re.sub(r"[?#].*$", "", url or "")


def diff_profile(old_status: str, old_info: dict[str, str], old_hash: int | None,
                 new_status: str, new_info: dict[str, str], new_hash: int | None) -> list[dict[str, Any]]:
    """What changed between two snapshots of the same account."""
    out: list[dict[str, Any]] = []
    if old_status != new_status:
        if old_status == "found" and new_status == "not_found":
            out.append({"field": "status", "kind": "removed", "old": "พบบัญชี", "new": "ไม่พบแล้ว",
                        "note": "บัญชีถูกลบ ปิด หรือเปลี่ยนชื่อ"})
        elif old_status == "not_found" and new_status == "found":
            out.append({"field": "status", "kind": "added", "old": "ไม่พบ", "new": "พบบัญชี",
                        "note": "บัญชีเพิ่งถูกสร้างหรือเปิดกลับมา"})
        return out
    if new_status != "found":
        return out
    for f in ("name", "bio", "location", "website"):
        a, b = (old_info.get(f) or "").strip(), (new_info.get(f) or "").strip()
        if a == b:
            continue
        kind = "added" if not a else "removed" if not b else "changed"
        out.append({"field": f, "kind": kind, "old": a, "new": b})
    for f in ("followers", "following"):
        a, b = parse_count(old_info.get(f)), parse_count(new_info.get(f))
        if a is not None and b is not None and a != b:
            out.append({"field": f, "kind": "changed", "old": f"{a:,}", "new": f"{b:,}", "delta": b - a})
    if old_hash is not None and new_hash is not None:
        if bin(old_hash ^ new_hash).count("1") > AVATAR_CHANGED:
            out.append({"field": "avatar", "kind": "changed", "old": old_info.get("avatar", ""),
                        "new": new_info.get("avatar", ""), "note": "เทียบจากภาพจริง (dHash)"})
    else:
        a, b = _avatar_path(old_info.get("avatar", "")), _avatar_path(new_info.get("avatar", ""))
        if a and b and a != b:
            out.append({"field": "avatar", "kind": "changed", "old": old_info.get("avatar", ""),
                        "new": new_info.get("avatar", ""), "note": "ลิงก์รูปเปลี่ยน (ยังไม่ได้เทียบภาพจริง)"})
        elif bool(a) != bool(b):
            out.append({"field": "avatar", "kind": "added" if b else "removed",
                        "old": old_info.get("avatar", ""), "new": new_info.get("avatar", "")})
    return out


def _hash_str(h: int | None) -> str | None:
    return None if h is None else format(h, "x")


def _hash_int(s: str | None) -> int | None:
    try:
        return int(s, 16) if s else None
    except ValueError:
        return None


class History:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_DB
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path))
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    # ---- cache -------------------------------------------------------------
    def cached(self, site: str, username: str, sig: str, ttl: float = DEFAULT_TTL) -> dict[str, Any] | None:
        row = self.db.execute("SELECT sig, ts, data FROM cache WHERE site_key=? AND user_key=?",
                              (site.lower(), username.lower())).fetchone()
        if not row or row["sig"] != sig or time.time() - row["ts"] > ttl:
            return None
        try:
            return json.loads(row["data"])
        except ValueError:
            return None

    def put_cache(self, site: str, username: str, sig: str, data: dict[str, Any]) -> None:
        self.db.execute("INSERT OR REPLACE INTO cache VALUES (?,?,?,?,?)",
                        (site.lower(), username.lower(), sig, time.time(), json.dumps(data, ensure_ascii=False)))

    def clear_cache(self) -> int:
        n = self.db.execute("DELETE FROM cache").rowcount
        self.db.commit()
        return n

    # ---- runs ----------------------------------------------------------------
    def known(self, keys: list[tuple[str, str]]) -> dict[tuple[str, str], dict[str, Any]]:
        """first_seen / last_found / last_checked for accounts seen in earlier runs."""
        out: dict[tuple[str, str], dict[str, Any]] = {}
        for site, user in keys:
            row = self.db.execute("SELECT first_seen, last_found, last_checked, last_run FROM accounts "
                                  "WHERE site_key=? AND user_key=?", (site.lower(), user.lower())).fetchone()
            if row:
                out[(site.lower(), user.lower())] = dict(row)
        return out

    def record_run(self, usernames: list[str], results: list[dict[str, Any]],
                   hashes: dict[tuple[str, str], int] | None = None, stats: dict[str, Any] | None = None,
                   options: dict[str, Any] | None = None, started: str | None = None) -> dict[str, Any]:
        """Save a finished search; return ``{"run_id", "changes", "seen"}``.

        ``seen`` maps ``(site, username)`` (lower case) to first_seen /
        last_checked after this run. Results answered from the cache are not
        new observations: they don't create snapshots or changes.
        """
        hashes = hashes or {}
        when = now_iso()
        cur = self.db.execute("INSERT INTO runs (usernames, started, finished, stats, options) VALUES (?,?,?,?,?)",
                              (json.dumps(usernames, ensure_ascii=False), started or when, when,
                               json.dumps(stats or {}), json.dumps(options or {})))
        run_id = cur.lastrowid
        changes: list[dict[str, Any]] = []
        seen: dict[tuple[str, str], dict[str, Any]] = {}
        for r in results:
            if r.get("status") not in ("found", "not_found") or r.get("linked"):
                continue  # unknown/manual answers and owner-linked placeholders say nothing new
            sk, uk = r["site"].lower(), r["username"].lower()
            checked = r.get("checked_at") or when
            info = {k: v for k, v in (r.get("info") or {}).items() if k in TRACKED or k == "avatar"}
            h = hashes.get((sk, uk))
            prev = self.db.execute("SELECT * FROM accounts WHERE site_key=? AND user_key=?", (sk, uk)).fetchone()
            if r.get("cached"):
                if prev:
                    seen[(sk, uk)] = {"first_seen": prev["first_seen"], "last_checked": prev["last_checked"],
                                      "last_found": prev["last_found"]}
                continue
            self.db.execute("INSERT OR REPLACE INTO snapshots VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (run_id, sk, uk, r["site"], r["username"], r["url"], r["status"],
                             json.dumps(info, ensure_ascii=False), _hash_str(h), checked))
            if prev:
                old_info = json.loads(prev["last_info"] or "{}")
                old_hash = _hash_int(prev["last_hash"])
                for c in diff_profile(prev["last_status"], old_info, old_hash, r["status"], info, h):
                    c.update(site=r["site"], username=r["username"], url=r["url"], old_seen=prev["last_checked"],
                             detected_at=checked, label=TRACKED.get(c["field"]) or STATUS_LABEL.get(c["field"], c["field"]))
                    changes.append(c)
                    self.db.execute("INSERT INTO changes VALUES (?,?,?,?,?,?,?,?,?,?)",
                                    (run_id, r["site"], r["username"], r["url"], c["field"], c["kind"],
                                     c.get("old"), c.get("new"), prev["last_checked"], checked))
                # keep the old hash when this run had none (avatars off / download failed)
                keep_hash = _hash_str(h) if h is not None else (prev["last_hash"] if r["status"] == "found" else None)
                first = prev["first_seen"] or (checked if r["status"] == "found" else None)
                last_found = checked if r["status"] == "found" else prev["last_found"]
                self.db.execute("UPDATE accounts SET site=?, username=?, url=?, first_seen=?, last_found=?, "
                                "last_checked=?, last_status=?, last_info=?, last_hash=?, last_run=? "
                                "WHERE site_key=? AND user_key=?",
                                (r["site"], r["username"], r["url"], first, last_found, checked, r["status"],
                                 json.dumps(info, ensure_ascii=False), keep_hash, run_id, sk, uk))
            else:
                first = checked if r["status"] == "found" else None
                last_found = first
                self.db.execute("INSERT INTO accounts VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                                (sk, uk, r["site"], r["username"], r["url"], first, last_found, checked,
                                 r["status"], json.dumps(info, ensure_ascii=False), _hash_str(h), run_id))
            seen[(sk, uk)] = {"first_seen": first, "last_checked": checked, "last_found": last_found}
        self.db.commit()
        return {"run_id": run_id, "changes": changes, "seen": seen}

    def list_runs(self, username: str | None = None, limit: int = 30) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit * 5 if username else limit,))
        out = []
        for row in rows:
            names = json.loads(row["usernames"])
            if username and username.lower() not in {n.lower() for n in names}:
                continue
            n_changes = self.db.execute("SELECT COUNT(*) FROM changes WHERE run_id=?", (row["id"],)).fetchone()[0]
            out.append({"id": row["id"], "usernames": names, "started": row["started"], "finished": row["finished"],
                        "stats": json.loads(row["stats"] or "{}"), "changes": n_changes})
            if len(out) >= limit:
                break
        return out

    def changes_for(self, usernames: list[str] | None = None, limit: int = 200) -> list[dict[str, Any]]:
        """Recorded changes, newest first (optionally only for these usernames)."""
        if usernames:
            marks = ",".join("?" * len(usernames))
            rows = self.db.execute(f"SELECT * FROM changes WHERE lower(username) IN ({marks}) "
                                   "ORDER BY detected_at DESC LIMIT ?", (*[u.lower() for u in usernames], limit))
        else:
            rows = self.db.execute("SELECT * FROM changes ORDER BY detected_at DESC LIMIT ?", (limit,))
        return [dict(r, label=TRACKED.get(r["field"]) or STATUS_LABEL.get(r["field"], r["field"])) for r in rows]

    def account_history(self, site: str, username: str) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT run_id, status, info, checked_at FROM snapshots "
                               "WHERE site_key=? AND user_key=? ORDER BY checked_at",
                               (site.lower(), username.lower()))
        return [{"run_id": r["run_id"], "status": r["status"], "info": json.loads(r["info"]),
                 "checked_at": r["checked_at"]} for r in rows]

    def delete_run(self, run_id: int) -> bool:
        n = self.db.execute("DELETE FROM runs WHERE id=?", (run_id,)).rowcount
        self.db.commit()
        return bool(n)
