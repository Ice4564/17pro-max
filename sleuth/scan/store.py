"""Scan history in SQLite (``~/.sleuth/scans.db`` by default)."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

DEFAULT_DB = Path(os.environ.get("SLEUTH_DB", Path.home() / ".sleuth" / "scans.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    modules TEXT NOT NULL,
    started REAL NOT NULL,
    finished REAL,
    status TEXT NOT NULL DEFAULT 'running',
    counts TEXT
);
CREATE TABLE IF NOT EXISTS events (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    type TEXT NOT NULL,
    data TEXT NOT NULL,
    module TEXT NOT NULL,
    parent TEXT,
    depth INTEGER NOT NULL,
    extra TEXT,
    ts REAL NOT NULL,
    PRIMARY KEY (scan_id, id)
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule TEXT, severity TEXT, title TEXT, detail TEXT, events TEXT
);
CREATE INDEX IF NOT EXISTS events_scan ON events(scan_id);
"""


class Store:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_DB
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    def new_scan(self, target: str, target_type: str, modules: list[str]) -> int:
        cur = self.db.execute("INSERT INTO scans (target, target_type, modules, started) VALUES (?,?,?,?)",
                              (target, target_type, ",".join(modules), time.time()))
        self.db.commit()
        return int(cur.lastrowid)

    def add_event(self, scan_id: int, ev: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?)",
            (scan_id, ev["id"], ev["type"], ev["data"], ev["module"], ev.get("parent"), ev.get("depth", 0),
             json.dumps(ev.get("extra", {}), ensure_ascii=False), ev.get("ts", time.time())),
        )

    def add_finding(self, scan_id: int, f: dict[str, Any]) -> None:
        self.db.execute("INSERT INTO findings VALUES (?,?,?,?,?,?)",
                        (scan_id, f["rule"], f["severity"], f["title"], f["detail"], json.dumps(f["events"])))

    def finish(self, scan_id: int, status: str, counts: dict[str, int]) -> None:
        self.db.execute("UPDATE scans SET finished=?, status=?, counts=? WHERE id=?",
                        (time.time(), status, json.dumps(counts), scan_id))
        self.db.commit()

    def commit(self) -> None:
        self.db.commit()

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["counts"] = json.loads(d["counts"]) if d["counts"] else {}
            d["findings"] = self.db.execute("SELECT severity, COUNT(*) c FROM findings WHERE scan_id=? GROUP BY severity",
                                            (r["id"],)).fetchall()
            d["findings"] = {x["severity"]: x["c"] for x in d["findings"]}
            out.append(d)
        return out

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        row = self.db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            return None
        scan = dict(row)
        scan["counts"] = json.loads(scan["counts"]) if scan["counts"] else {}
        scan["events"] = [
            {**dict(e), "extra": json.loads(e["extra"] or "{}")}
            for e in self.db.execute("SELECT * FROM events WHERE scan_id=? ORDER BY ts", (scan_id,))
        ]
        for e in scan["events"]:
            e.pop("scan_id", None)
        scan["findings"] = [
            {**dict(f), "events": json.loads(f["events"] or "[]")}
            for f in self.db.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,))
        ]
        for f in scan["findings"]:
            f.pop("scan_id", None)
        return scan

    def delete_scan(self, scan_id: int) -> bool:
        cur = self.db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        self.db.commit()
        return cur.rowcount > 0
