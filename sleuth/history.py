"""Local intelligence database in SQLite (``~/.sleuth/history.db`` by default).

One small database remembers everything Sleuth has seen, so the next search
starts from what is already known instead of from zero:

* **runs**          every search, with its full result (``payload``) and the
                    investigation replay, so it can be reopened later
* **snapshots**     what each profile looked like in each run -> change tracker
                    ("bio changed", "followers 1,240 -> 1,391", "new external link")
* **accounts**      first seen / last checked per account
* **usernames, domains, emails, urls, relationships**
                    the entities and evidence-backed edges between them,
                    de-duplicated across runs (a URL found by 15 queries is one row)
* **cases**         investigation workspaces grouping targets, runs and notes
* **watchlist / alerts**
                    targets re-checked on a schedule; only changes are reported
* **cache**         definitive answers (found / not found) reused for a few hours
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import zlib
from datetime import datetime, timedelta, timezone
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
CREATE TABLE IF NOT EXISTS usernames (
    user_key TEXT PRIMARY KEY, username TEXT NOT NULL, first_seen TEXT, last_seen TEXT,
    accounts INTEGER NOT NULL DEFAULT 0, searched INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS domains (
    domain TEXT PRIMARY KEY, url TEXT, title TEXT, personal INTEGER, emails TEXT, sources TEXT,
    first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS emails (
    email TEXT PRIMARY KEY, sources TEXT, first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS urls (
    url_key TEXT PRIMARY KEY, url TEXT NOT NULL, title TEXT, snippet TEXT, platform TEXT, handle TEXT,
    mentions TEXT, found_by TEXT, first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS relationships (
    src TEXT NOT NULL, dst TEXT NOT NULL, kind TEXT NOT NULL, label TEXT, evidence TEXT,
    first_seen TEXT, last_seen TEXT, PRIMARY KEY (src, dst, kind)
);
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, created TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS case_targets (
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE, target TEXT NOT NULL,
    PRIMARY KEY (case_id, target)
);
CREATE TABLE IF NOT EXISTS case_runs (
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    PRIMARY KEY (case_id, run_id)
);
CREATE TABLE IF NOT EXISTS watchlist (
    target TEXT PRIMARY KEY, added TEXT NOT NULL, interval_hours REAL NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
    options TEXT, last_run TEXT, next_run TEXT, last_run_id INTEGER, last_error TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, created TEXT NOT NULL, run_id INTEGER,
    changes TEXT NOT NULL, seen INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS snapshots_user ON snapshots(user_key);
CREATE INDEX IF NOT EXISTS changes_user ON changes(username);
"""
MIGRATIONS = [("runs", "payload", "BLOB")]

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
OTHER_LABELS = {"status": "สถานะบัญชี", "account": "บัญชีใหม่", "links": "ลิงก์ภายนอก", "username": "username"}
AVATAR_CHANGED = 10  # bits out of 64 between two dHashes that count as a different picture


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def label_of(field: str) -> str:
    return TRACKED.get(field) or OTHER_LABELS.get(field, field)


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


def _platform_handles(links: list[str]) -> dict[str, set[str]]:
    """["Instagram: ice", "GitHub: ice4564"] -> {"instagram": {"ice"}, "github": {"ice4564"}}"""
    out: dict[str, set[str]] = {}
    for x in links or []:
        platform, _, handle = x.partition(": ")
        if handle:
            out.setdefault(platform.lower(), set()).add(handle)
        else:
            out.setdefault("", set()).add(platform)
    return out


def diff_profile(old_status: str, old_info: dict[str, Any], old_hash: int | None,
                 new_status: str, new_info: dict[str, Any], new_hash: int | None) -> list[dict[str, Any]]:
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
    # accounts the owner links to: a new platform, or the same platform under a new handle
    if "links" in old_info or "links" in new_info:
        old_l, new_l = _platform_handles(old_info.get("links", [])), _platform_handles(new_info.get("links", []))
        for platform, handles in new_l.items():
            before = old_l.get(platform, set())
            if not before and platform:
                out.append({"field": "links", "kind": "added", "old": "",
                            "new": ", ".join(f"{platform}: {h}" for h in sorted(handles)), "note": "ลิงก์ภายนอกใหม่"})
            elif handles != before and platform and len(before) == 1 and len(handles) == 1:
                out.append({"field": "username", "kind": "changed", "old": f"{platform}: {next(iter(before))}",
                            "new": f"{platform}: {next(iter(handles))}", "note": "ลิงก์ไปบัญชีเดิมแต่ username เปลี่ยน"})
            elif handles - before:
                out.append({"field": "links", "kind": "added", "old": ", ".join(sorted(before)),
                            "new": ", ".join(sorted(handles - before)), "note": "ลิงก์ภายนอกใหม่"})
    return out


def _hash_str(h: int | None) -> str | None:
    return None if h is None else format(h, "x")


def _hash_int(s: str | None) -> int | None:
    try:
        return int(s, 16) if s else None
    except ValueError:
        return None


def _pack(obj: Any) -> bytes:
    return zlib.compress(json.dumps(obj, ensure_ascii=False).encode("utf-8"), 6)


def _unpack(blob: bytes | None) -> Any:
    if not blob:
        return None
    try:
        return json.loads(zlib.decompress(blob).decode("utf-8"))
    except (zlib.error, ValueError):
        return None


def _merge_json_list(old: str | None, new: list[Any], limit: int = 50) -> str:
    items = json.loads(old) if old else []
    for x in new:
        if x not in items:
            items.append(x)
    return json.dumps(items[-limit:], ensure_ascii=False)


class History:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_DB
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        # timeout: wait for another Sleuth (web server + CLI) instead of failing with "database is locked"
        self.db = sqlite3.connect(str(self.path), timeout=30)
        self.db.row_factory = sqlite3.Row
        if str(self.path) != ":memory:":
            self.db.execute("PRAGMA journal_mode=WAL")  # readers don't block the writer and vice versa
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(SCHEMA)
        for table, column, ctype in MIGRATIONS:  # databases created by older versions
            cols = {r["name"] for r in self.db.execute(f"PRAGMA table_info({table})")}
            if column not in cols:
                self.db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ctype}")
        self.db.commit()

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

    def commit(self) -> None:
        self.db.commit()

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
                   options: dict[str, Any] | None = None, started: str | None = None, *,
                   domains: list[dict[str, Any]] | None = None, hits: list[dict[str, Any]] | None = None,
                   graph: dict[str, Any] | None = None) -> dict[str, Any]:
        """Save a finished search; return ``{"run_id", "changes", "seen"}``.

        ``seen`` maps ``(site, username)`` (lower case) to first_seen /
        last_checked after this run. Results answered from the cache are not
        new observations: they don't create snapshots or changes. Domains,
        search hits and graph edges go into the intelligence tables.
        """
        hashes = hashes or {}
        when = now_iso()
        cur = self.db.execute("INSERT INTO runs (usernames, started, finished, stats, options) VALUES (?,?,?,?,?)",
                              (json.dumps(usernames, ensure_ascii=False), started or when, when,
                               json.dumps(stats or {}), json.dumps(options or {})))
        run_id = cur.lastrowid
        changes: list[dict[str, Any]] = []
        seen: dict[tuple[str, str], dict[str, Any]] = {}
        # usernames observed before this run: a newly found account for one of them is news
        watched = {u.lower() for u in usernames}
        seen_before = {r["user_key"] for r in self.db.execute(
            "SELECT DISTINCT user_key FROM snapshots WHERE run_id <> ?", (run_id,))} & watched
        for r in results:
            if r.get("status") not in ("found", "not_found") or r.get("linked"):
                continue  # unknown/manual answers and owner-linked placeholders say nothing new
            sk, uk = r["site"].lower(), r["username"].lower()
            checked = r.get("checked_at") or when
            info: dict[str, Any] = {k: v for k, v in (r.get("info") or {}).items() if k in TRACKED or k == "avatar"}
            if r.get("discovered"):
                info["links"] = sorted(r["discovered"])
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
            found_changes: list[dict[str, Any]] = []
            if prev:
                old_info = json.loads(prev["last_info"] or "{}")
                found_changes = diff_profile(prev["last_status"], old_info, _hash_int(prev["last_hash"]),
                                             r["status"], info, h)
                for c in found_changes:
                    c["old_seen"] = prev["last_checked"]
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
                if r["status"] == "found" and uk in seen_before:
                    found_changes = [{"field": "account", "kind": "added", "old": "", "new": r["url"],
                                      "note": f"พบบัญชีใหม่บน {r['site']}", "old_seen": None}]
            for c in found_changes:
                c.update(site=r["site"], username=r["username"], url=r["url"], detected_at=checked,
                         label=label_of(c["field"]))
                changes.append(c)
                self.db.execute("INSERT INTO changes VALUES (?,?,?,?,?,?,?,?,?,?)",
                                (run_id, r["site"], r["username"], r["url"], c["field"], c["kind"],
                                 c.get("old"), c.get("new"), c.get("old_seen"), checked))
            seen[(sk, uk)] = {"first_seen": first, "last_checked": checked, "last_found": last_found}
        self._record_intel(usernames, results, domains or [], hits or [], graph or {}, when)
        self.db.commit()
        return {"run_id": run_id, "changes": changes, "seen": seen}

    def _record_intel(self, usernames: list[str], results: list[dict[str, Any]], domains: list[dict[str, Any]],
                      hits: list[dict[str, Any]], graph: dict[str, Any], when: str) -> None:
        """Upsert entities and evidence-backed relationships (de-duplicated across runs)."""
        from .similarity import emails_of  # late: keeps history importable without the scoring stack
        counts: dict[str, tuple[str, int]] = {}
        for r in results:
            if r.get("status") == "found":
                k = r["username"].lower()
                counts[k] = (r["username"], counts.get(k, (r["username"], 0))[1] + 1)
        for u in usernames:
            counts.setdefault(u.lower(), (u, 0))
        typed = {u.lower() for u in usernames}
        for k, (name, n) in counts.items():
            self.db.execute(
                "INSERT INTO usernames VALUES (?,?,?,?,?,?) ON CONFLICT(user_key) DO UPDATE SET "
                "last_seen=excluded.last_seen, accounts=MAX(usernames.accounts, excluded.accounts), "
                "first_seen=COALESCE(usernames.first_seen, excluded.first_seen), searched=usernames.searched+excluded.searched",
                (k, name, when if n else None, when if n else None, n, 1 if k in typed else 0))
        for d in domains:
            self.db.execute(
                "INSERT INTO domains VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(domain) DO UPDATE SET "
                "url=excluded.url, title=excluded.title, personal=MAX(domains.personal, excluded.personal), "
                "emails=excluded.emails, sources=excluded.sources, last_seen=excluded.last_seen",
                (d["domain"], d.get("url"), d.get("title"), int(bool(d.get("personal"))),
                 json.dumps(d.get("emails", [])), json.dumps(d.get("via", [])), when, when))
        emails: dict[str, list[str]] = {}
        for r in results:
            if r.get("status") == "found":
                for e in emails_of(r):
                    emails.setdefault(e, []).append(f"{r['site']} @{r['username']}")
        for d in domains:
            for e in d.get("emails", []):
                emails.setdefault(e, []).append(f"เว็บไซต์ {d['domain']}")
        for e, sources in emails.items():
            old = self.db.execute("SELECT sources FROM emails WHERE email=?", (e,)).fetchone()
            self.db.execute("INSERT OR REPLACE INTO emails VALUES (?,?,COALESCE((SELECT first_seen FROM emails WHERE email=?), ?),?)",
                            (e, _merge_json_list(old["sources"] if old else None, sources), e, when, when))
        from .websearch import url_key
        for h in hits:
            k = url_key(h["url"])
            old = self.db.execute("SELECT found_by FROM urls WHERE url_key=?", (k,)).fetchone()
            found_by = h.get("found_by") or [{"engine": h["engine"], "query": h["query"], "rank": h["rank"]}]
            self.db.execute(
                "INSERT OR REPLACE INTO urls VALUES (?,?,?,?,?,?,?,?,COALESCE((SELECT first_seen FROM urls WHERE url_key=?), ?),?)",
                (k, h["url"], h.get("title"), h.get("snippet"), h.get("platform"), h.get("handle"),
                 h["username"] if h.get("mentions") else None,
                 _merge_json_list(old["found_by"] if old else None, [{k2: v for k2, v in x.items() if k2 != "query_n"}
                                                                     for x in found_by], 100),
                 k, when, when))
        for e in graph.get("edges", []):
            if e["kind"] == "candidate":
                continue  # a guess is not a relationship
            self.db.execute(
                "INSERT INTO relationships VALUES (?,?,?,?,?,?,?) ON CONFLICT(src, dst, kind) DO UPDATE SET "
                "label=excluded.label, evidence=excluded.evidence, last_seen=excluded.last_seen",
                (e["source"], e["target"], e["kind"], e.get("label"),
                 json.dumps(e.get("evidence", []), ensure_ascii=False), when, when))

    def save_payload(self, run_id: int, payload: dict[str, Any]) -> None:
        """The run's full result (results, findings, graph, replay ...) for reopening later."""
        self.db.execute("UPDATE runs SET payload=? WHERE id=?", (_pack(payload), run_id))
        self.db.commit()

    def get_run(self, run_id: int) -> dict[str, Any] | None:
        row = self.db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            return None
        return {"id": row["id"], "usernames": json.loads(row["usernames"]), "started": row["started"],
                "finished": row["finished"], "stats": json.loads(row["stats"] or "{}"),
                "options": json.loads(row["options"] or "{}"), "payload": _unpack(row["payload"])}

    def list_runs(self, username: str | None = None, limit: int = 30) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT id, usernames, started, finished, stats, payload IS NOT NULL AS has_payload "
                               "FROM runs ORDER BY id DESC LIMIT ?", (limit * 5 if username else limit,))
        out = []
        for row in rows:
            names = json.loads(row["usernames"])
            if username and username.lower() not in {n.lower() for n in names}:
                continue
            n_changes = self.db.execute("SELECT COUNT(*) FROM changes WHERE run_id=?", (row["id"],)).fetchone()[0]
            out.append({"id": row["id"], "usernames": names, "started": row["started"], "finished": row["finished"],
                        "stats": json.loads(row["stats"] or "{}"), "changes": n_changes,
                        "has_payload": bool(row["has_payload"])})
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
        return [dict(r, label=label_of(r["field"])) for r in rows]

    def account_history(self, site: str, username: str) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT run_id, status, info, checked_at FROM snapshots "
                               "WHERE site_key=? AND user_key=? ORDER BY checked_at",
                               (site.lower(), username.lower()))
        return [{"run_id": r["run_id"], "status": r["status"], "info": json.loads(r["info"]),
                 "checked_at": r["checked_at"]} for r in rows]

    def username_history(self, cores: set[str], core_of: Any) -> list[dict[str, Any]]:
        """Every spelling seen for these handle cores, with first/last seen (historical evidence)."""
        rows = self.db.execute("SELECT * FROM usernames WHERE first_seen IS NOT NULL ORDER BY first_seen")
        return [dict(r) for r in rows if core_of(r["username"]) in cores]

    def delete_run(self, run_id: int) -> bool:
        n = self.db.execute("DELETE FROM runs WHERE id=?", (run_id,)).rowcount
        self.db.commit()
        return bool(n)

    # ---- intelligence search ------------------------------------------------------
    def intel_search(self, q: str, limit: int = 50) -> dict[str, list[dict[str, Any]]]:
        """Everything the database knows that matches ``q`` (username, site, domain, email, URL, text)."""
        like = f"%{q.strip().lower()}%"
        acc = self.db.execute("SELECT site, username, url, first_seen, last_found, last_checked, last_status, last_info "
                              "FROM accounts WHERE last_status='found' AND (lower(username) LIKE ? OR lower(site) LIKE ? "
                              "OR lower(url) LIKE ? OR lower(last_info) LIKE ?) ORDER BY last_checked DESC LIMIT ?",
                              (like, like, like, like, limit))
        out = {"accounts": [dict(r, last_info=json.loads(r["last_info"] or "{}")) for r in acc]}
        out["usernames"] = [dict(r) for r in self.db.execute(
            "SELECT * FROM usernames WHERE user_key LIKE ? ORDER BY last_seen DESC LIMIT ?", (like, limit))]
        out["domains"] = [dict(r, emails=json.loads(r["emails"] or "[]"), sources=json.loads(r["sources"] or "[]"))
                          for r in self.db.execute("SELECT * FROM domains WHERE lower(domain) LIKE ? OR lower(title) LIKE ? "
                                                   "LIMIT ?", (like, like, limit))]
        out["emails"] = [dict(r, sources=json.loads(r["sources"] or "[]")) for r in self.db.execute(
            "SELECT * FROM emails WHERE email LIKE ? LIMIT ?", (like, limit))]
        out["urls"] = [dict(r, found_by=json.loads(r["found_by"] or "[]")) for r in self.db.execute(
            "SELECT * FROM urls WHERE url_key LIKE ? OR lower(title) LIKE ? OR lower(snippet) LIKE ? "
            "OR lower(mentions) LIKE ? ORDER BY last_seen DESC LIMIT ?", (like, like, like, like, limit))]
        out["relationships"] = [dict(r, evidence=json.loads(r["evidence"] or "[]")) for r in self.db.execute(
            "SELECT * FROM relationships WHERE src LIKE ? OR dst LIKE ? ORDER BY last_seen DESC LIMIT ?",
            (like, like, limit))]
        return out

    def intel_stats(self) -> dict[str, int]:
        tables = ("runs", "accounts", "usernames", "domains", "emails", "urls", "relationships", "snapshots",
                  "changes", "cases", "watchlist")
        out = {t: self.db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}
        out["accounts"] = self.db.execute("SELECT COUNT(*) FROM accounts WHERE last_status='found'").fetchone()[0]
        return out

    # ---- cases (investigation workspace) --------------------------------------------
    def create_case(self, name: str, targets: list[str] | None = None, notes: str = "") -> int:
        cid = self.db.execute("INSERT INTO cases (name, created, notes) VALUES (?,?,?)",
                              (name.strip() or "Case", now_iso(), notes)).lastrowid
        for t in targets or []:
            self.db.execute("INSERT OR IGNORE INTO case_targets VALUES (?,?)", (cid, t.strip().lstrip("@")))
        self.db.commit()
        return cid

    def list_cases(self) -> list[dict[str, Any]]:
        out = []
        for c in self.db.execute("SELECT * FROM cases ORDER BY id DESC"):
            targets = [r["target"] for r in self.db.execute("SELECT target FROM case_targets WHERE case_id=?", (c["id"],))]
            runs = self.db.execute("SELECT COUNT(*) FROM case_runs WHERE case_id=?", (c["id"],)).fetchone()[0]
            out.append({**dict(c), "targets": targets, "runs": runs})
        return out

    def get_case(self, case_id: int) -> dict[str, Any] | None:
        c = self.db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not c:
            return None
        targets = [r["target"] for r in self.db.execute("SELECT target FROM case_targets WHERE case_id=?", (case_id,))]
        runs = []
        for r in self.db.execute("SELECT r.id, r.usernames, r.started, r.stats, r.payload FROM case_runs cr "
                                 "JOIN runs r ON r.id = cr.run_id WHERE cr.case_id=? ORDER BY r.id DESC", (case_id,)):
            payload = _unpack(r["payload"]) or {}
            done = payload.get("done", {})
            runs.append({"id": r["id"], "usernames": json.loads(r["usernames"]), "started": r["started"],
                         "stats": json.loads(r["stats"] or "{}"), "summary": done.get("summary", {}),
                         "entities": done.get("entities", [])[:5], "contradictions": done.get("contradictions", []),
                         "findings": len(done.get("findings", [])), "timeline": done.get("timeline", [])})
        names = [t.lower() for t in targets] or None
        return {**dict(c), "targets": targets, "runs": runs,
                "changes": self.changes_for(names, 100) if names else [],
                "watching": [w["target"] for w in self.watch_list() if w["target"].lower() in (names or [])]}

    def update_case(self, case_id: int, *, name: str | None = None, notes: str | None = None,
                    status: str | None = None, add_targets: list[str] | None = None,
                    remove_targets: list[str] | None = None, add_run: int | None = None) -> bool:
        if not self.db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
            return False
        for col, val in (("name", name), ("notes", notes), ("status", status)):
            if val is not None:
                self.db.execute(f"UPDATE cases SET {col}=? WHERE id=?", (val, case_id))
        for t in add_targets or []:
            self.db.execute("INSERT OR IGNORE INTO case_targets VALUES (?,?)", (case_id, t.strip().lstrip("@")))
        for t in remove_targets or []:
            self.db.execute("DELETE FROM case_targets WHERE case_id=? AND target=?", (case_id, t))
        if add_run is not None and self.db.execute("SELECT 1 FROM runs WHERE id=?", (add_run,)).fetchone():
            self.db.execute("INSERT OR IGNORE INTO case_runs VALUES (?,?)", (case_id, add_run))
            for u in json.loads(self.db.execute("SELECT usernames FROM runs WHERE id=?", (add_run,)).fetchone()[0]):
                self.db.execute("INSERT OR IGNORE INTO case_targets VALUES (?,?)", (case_id, u))
        self.db.commit()
        return True

    def delete_case(self, case_id: int) -> bool:
        n = self.db.execute("DELETE FROM cases WHERE id=?", (case_id,)).rowcount
        self.db.commit()
        return bool(n)

    # ---- watchlist ------------------------------------------------------------------
    def watch_add(self, target: str, interval_hours: float = 24, options: dict[str, Any] | None = None) -> None:
        t = target.strip().lstrip("@")
        self.db.execute("INSERT INTO watchlist (target, added, interval_hours, options, next_run) VALUES (?,?,?,?,?) "
                        "ON CONFLICT(target) DO UPDATE SET interval_hours=excluded.interval_hours, "
                        "options=excluded.options, enabled=1",
                        (t, now_iso(), max(0.25, float(interval_hours)), json.dumps(options or {}), now_iso()))
        self.db.commit()

    def watch_remove(self, target: str) -> bool:
        n = self.db.execute("DELETE FROM watchlist WHERE lower(target)=lower(?)", (target.strip().lstrip("@"),)).rowcount
        self.db.commit()
        return bool(n)

    def watch_list(self) -> list[dict[str, Any]]:
        out = []
        for r in self.db.execute("SELECT * FROM watchlist ORDER BY target"):
            unseen = self.db.execute("SELECT COUNT(*) FROM alerts WHERE lower(target)=lower(?) AND seen=0",
                                     (r["target"],)).fetchone()[0]
            out.append({**dict(r), "options": json.loads(r["options"] or "{}"), "unseen": unseen})
        return out

    def watch_due(self, now: str | None = None) -> list[dict[str, Any]]:
        now = now or now_iso()
        return [w for w in self.watch_list() if w["enabled"] and (not w["next_run"] or w["next_run"] <= now)]

    def watch_done(self, target: str, run_id: int | None, changes: list[dict[str, Any]], error: str | None = None) -> None:
        w = self.db.execute("SELECT interval_hours FROM watchlist WHERE target=?", (target,)).fetchone()
        hours = w["interval_hours"] if w else 24
        nxt = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(timespec="seconds")
        self.db.execute("UPDATE watchlist SET last_run=?, next_run=?, last_run_id=?, last_error=? WHERE target=?",
                        (now_iso(), nxt, run_id, error, target))
        if changes:
            self.db.execute("INSERT INTO alerts (target, created, run_id, changes) VALUES (?,?,?,?)",
                            (target, now_iso(), run_id, json.dumps(changes, ensure_ascii=False)))
        self.db.commit()

    def alerts(self, unseen_only: bool = False, limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM alerts" + (" WHERE seen=0" if unseen_only else "") + " ORDER BY id DESC LIMIT ?"
        return [dict(r, changes=json.loads(r["changes"])) for r in self.db.execute(sql, (limit,))]

    def mark_alerts_seen(self, ids: list[int] | None = None) -> int:
        if ids:
            marks = ",".join("?" * len(ids))
            n = self.db.execute(f"UPDATE alerts SET seen=1 WHERE id IN ({marks})", ids).rowcount
        else:
            n = self.db.execute("UPDATE alerts SET seen=1 WHERE seen=0").rowcount
        self.db.commit()
        return n
