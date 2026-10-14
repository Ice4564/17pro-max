"""Case management: investigation playbooks, evidence chain of custody,
multi-investigator notes, and tagging/annotation system.

Uses SQLite for persistence (shared with history.py).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ========================================================================
# 1. Investigation Playbooks
# ========================================================================

@dataclass
class PlaybookStep:
    """A single step in an investigation playbook."""

    step: int
    title: str
    description: str
    tools: list[str] = field(default_factory=list)
    expected_output: str = ""


@dataclass
class Playbook:
    """An investigation playbook template."""

    name: str
    category: str  # "missing_person", "fraud", "identity_theft", "threat_assessment", "due_diligence"
    description: str
    steps: list[PlaybookStep] = field(default_factory=list)
    legal_notes: str = ""


# Pre-built playbooks
PLAYBOOKS: dict[str, Playbook] = {
    "missing_person": Playbook(
        name="Missing Person Investigation",
        category="missing_person",
        description="Systematic approach to finding a missing person through OSINT",
        steps=[
            PlaybookStep(1, "Initial Search", "Search for the person's username across all platforms", ["sleuth search"], "List of found accounts"),
            PlaybookStep(2, "Archive Check", "Check Wayback Machine for deleted or changed profiles", ["sleuth archive"], "Archived snapshots"),
            PlaybookStep(3, "Social Circle", "Search for family/friends accounts, look for mentions", ["sleuth deep-search"], "Social connections"),
            PlaybookStep(4, "Location Analysis", "Check location tags, geotags, and check-ins", ["sleuth geo"], "Last known locations"),
            PlaybookStep(5, "Activity Timeline", "Build timeline of last known activity", ["sleuth timeline"], "Activity timeline"),
            PlaybookStep(6, "Phone/Email", "Search for phone numbers and emails in profiles", ["sleuth enrich"], "Contact info"),
            PlaybookStep(7, "Behavioral Analysis", "Analyze writing style for distress signals", ["sleuth behavior"], "Behavioral profile"),
            PlaybookStep(8, "Report", "Generate comprehensive report for authorities", ["sleuth report --format pdf"], "Final report"),
        ],
        legal_notes="Coordinate with law enforcement. Do not contact suspects directly. Preserve all evidence.",
    ),
    "fraud": Playbook(
        name="Fraud Investigation",
        category="fraud",
        description="Investigate suspected fraud or scam accounts",
        steps=[
            PlaybookStep(1, "Account Discovery", "Search for the suspected fraudster's username", ["sleuth search"], "Found accounts"),
            PlaybookStep(2, "Identity Verification", "Cross-reference names, photos, and details across platforms", ["sleuth identity"], "Identity confidence"),
            PlaybookStep(3, "Contradiction Check", "Look for contradictions in location, name, or details", ["sleuth contradictions"], "Contradictions found"),
            PlaybookStep(4, "Bot Detection", "Check if accounts are automated/bot-controlled", ["sleuth behavior"], "Bot scores"),
            PlaybookStep(5, "Financial Links", "Search for crypto addresses, payment links in profiles", ["sleuth crypto"], "Financial traces"),
            PlaybookStep(6, "Infrastructure", "Scan linked domains/websites for infrastructure info", ["sleuth infra"], "Infrastructure data"),
            PlaybookStep(7, "IOC Extraction", "Extract IPs, emails, URLs from profiles", ["sleuth ioc"], "IOC list"),
            PlaybookStep(8, "Threat Intel Export", "Export findings as STIX/MISP for sharing", ["sleuth export --stix"], "STIX/MISP files"),
            PlaybookStep(9, "Report", "Generate fraud investigation report", ["sleuth report --format pdf"], "Final report"),
        ],
        legal_notes="Document everything. Do not confront the suspect. Report to relevant authorities.",
    ),
    "identity_theft": Playbook(
        name="Identity Theft Investigation",
        category="identity_theft",
        description="Investigate suspected identity theft or impersonation",
        steps=[
            PlaybookStep(1, "Account Search", "Search for the victim's username and real name", ["sleuth search"], "Found accounts"),
            PlaybookStep(2, "Avatar Analysis", "Compare avatars across platforms — look for photo theft", ["sleuth forensics"], "Avatar comparison"),
            PlaybookStep(3, "Timeline Analysis", "Determine which accounts are genuine vs fake", ["sleuth timeline"], "Account authenticity"),
            PlaybookStep(4, "Writing Style", "Compare writing styles to identify the impersonator", ["sleuth behavior"], "Style comparison"),
            PlaybookStep(5, "Archive Check", "Check if genuine profiles were scraped for info", ["sleuth archive"], "Archive evidence"),
            PlaybookStep(6, "Counter-OSINT", "Assess victim's privacy exposure", ["sleuth counter"], "Privacy assessment"),
            PlaybookStep(7, "Report", "Generate identity theft report for authorities", ["sleuth report --format pdf"], "Final report"),
        ],
        legal_notes="Report to platform abuse teams. File police report. Document all evidence with timestamps.",
    ),
    "threat_assessment": Playbook(
        name="Threat Assessment",
        category="threat_assessment",
        description="Assess potential threats from an individual's online presence",
        steps=[
            PlaybookStep(1, "Account Discovery", "Find all accounts associated with the subject", ["sleuth search"], "Account list"),
            PlaybookStep(2, "Behavioral Analysis", "Analyze for aggressive patterns, bot indicators", ["sleuth behavior"], "Behavioral profile"),
            PlaybookStep(3, "Interest Analysis", "Analyze hashtags/keywords for concerning interests", ["sleuth behavior"], "Interest profile"),
            PlaybookStep(4, "Network Analysis", "Map social connections and affiliations", ["sleuth graph"], "Network graph"),
            PlaybookStep(5, "Weapon Indicators", "Search for weapons, violence-related content", ["sleuth deep-search"], "Concerning content"),
            PlaybookStep(6, "Location", "Determine subject's location and movement patterns", ["sleuth geo"], "Location data"),
            PlaybookStep(7, "Timeline", "Build activity timeline for pattern analysis", ["sleuth timeline"], "Activity timeline"),
            PlaybookStep(8, "Report", "Generate threat assessment report", ["sleuth report --format pdf"], "Final report"),
        ],
        legal_notes="Follow organizational threat assessment protocols. Involve security team. Maintain confidentiality.",
    ),
    "due_diligence": Playbook(
        name="Due Diligence (Background Check)",
        category="due_diligence",
        description="Background investigation for business or personal due diligence",
        steps=[
            PlaybookStep(1, "Initial Search", "Search for the subject's name and known usernames", ["sleuth search"], "Found accounts"),
            PlaybookStep(2, "Professional Profile", "Check LinkedIn, ResearchGate, academic profiles", ["sleuth search --tag professional"], "Professional history"),
            PlaybookStep(3, "Public Records", "Search for domain registrations, business affiliations", ["sleuth infra"], "Business affiliations"),
            PlaybookStep(4, "Social Media", "Review social media for red flags", ["sleuth search --tag social"], "Social media review"),
            PlaybookStep(5, "Contradiction Check", "Verify consistency of claimed information", ["sleuth contradictions"], "Contradictions"),
            PlaybookStep(6, "Archive Check", "Check for deleted content or changed profiles", ["sleuth archive"], "Archive findings"),
            PlaybookStep(7, "Report", "Generate due diligence report", ["sleuth report --format pdf"], "Final report"),
        ],
        legal_notes="Comply with local privacy laws (GDPR, PDPA, etc.). Only use publicly available information.",
    ),
}


def get_playbook(category: str) -> Playbook | None:
    """Get a playbook by category name."""
    return PLAYBOOKS.get(category)


def list_playbooks() -> list[dict[str, str]]:
    """List all available playbooks."""
    return [
        {"name": p.name, "category": p.category, "description": p.description}
        for p in PLAYBOOKS.values()
    ]


# ========================================================================
# 2. Evidence Chain of Custody
# ========================================================================

@dataclass
class CustodyEntry:
    """A single entry in the chain of custody."""

    timestamp: str
    action: str  # "collected", "viewed", "analyzed", "exported", "shared"
    actor: str  # investigator name/ID
    evidence_id: str
    description: str
    hash: str = ""  # SHA-256 of evidence at this point


class ChainOfCustody:
    """Tracks the handling of evidence throughout an investigation.

    Every access, analysis, or transfer of evidence is logged
    with a timestamp, actor, and description.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self._db = db_path or str(Path.home() / ".sleuth" / "custody.db")
        self._init_db()

    def _init_db(self) -> None:
        Path(self._db).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._db) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS custody (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    description TEXT,
                    hash TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_custody_case
                ON custody(case_id)
            """)

    def log(
        self,
        case_id: str,
        action: str,
        actor: str,
        evidence_id: str,
        description: str = "",
        evidence_data: bytes | None = None,
    ) -> None:
        """Log a custody event."""
        import hashlib
        h = ""
        if evidence_data:
            h = hashlib.sha256(evidence_data).hexdigest()

        with sqlite3.connect(self._db) as conn:
            conn.execute(
                "INSERT INTO custody (case_id, timestamp, action, actor, evidence_id, description, hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (case_id, datetime.now(timezone.utc).isoformat(),
                 action, actor, evidence_id, description, h),
            )

    def get_chain(self, case_id: str) -> list[dict[str, Any]]:
        """Get the full chain of custody for a case."""
        with sqlite3.connect(self._db) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM custody WHERE case_id = ? ORDER BY timestamp",
                (case_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def verify_chain(self, case_id: str) -> dict[str, Any]:
        """Verify the integrity of the chain of custody."""
        chain = self.get_chain(case_id)
        if not chain:
            return {"valid": True, "entries": 0, "note": "no entries"}

        # Check for gaps or modifications
        issues: list[str] = []
        for i, entry in enumerate(chain):
            if not entry.get("timestamp"):
                issues.append(f"entry {i}: missing timestamp")
            if not entry.get("actor"):
                issues.append(f"entry {i}: missing actor")

        return {
            "valid": len(issues) == 0,
            "entries": len(chain),
            "issues": issues,
            "first_entry": chain[0]["timestamp"] if chain else None,
            "last_entry": chain[-1]["timestamp"] if chain else None,
        }


# ========================================================================
# 3. Multi-Investigator Notes
# ========================================================================

@dataclass
class Note:
    """A single investigation note."""

    id: int
    case_id: str
    author: str
    timestamp: str
    content: str
    tags: list[str] = field(default_factory=list)
    pinned: bool = False


class CaseNotes:
    """Manages investigation notes for a case.

    Supports multiple investigators adding notes, tagging,
    and pinning important notes.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self._db = db_path or str(Path.home() / ".sleuth" / "notes.db")
        self._init_db()

    def _init_db(self) -> None:
        Path(self._db).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._db) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    author TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    content TEXT NOT NULL,
                    tags TEXT,
                    pinned INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_notes_case
                ON notes(case_id)
            """)

    def add(
        self,
        case_id: str,
        author: str,
        content: str,
        tags: list[str] | None = None,
        pinned: bool = False,
    ) -> int:
        """Add a new note to a case."""
        with sqlite3.connect(self._db) as conn:
            cursor = conn.execute(
                "INSERT INTO notes (case_id, author, timestamp, content, tags, pinned) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (case_id, author, datetime.now(timezone.utc).isoformat(),
                 content, json.dumps(tags or []), int(pinned)),
            )
            return cursor.lastrowid

    def get_notes(self, case_id: str) -> list[dict[str, Any]]:
        """Get all notes for a case, pinned first."""
        with sqlite3.connect(self._db) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM notes WHERE case_id = ? ORDER BY pinned DESC, timestamp DESC",
                (case_id,),
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d.get("tags", "[]"))
            result.append(d)
        return result

    def search(self, case_id: str, query: str) -> list[dict[str, Any]]:
        """Search notes within a case."""
        with sqlite3.connect(self._db) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM notes WHERE case_id = ? AND content LIKE ? "
                "ORDER BY pinned DESC, timestamp DESC",
                (case_id, f"%{query}%"),
            ).fetchall()
        return [dict(r) for r in rows]

    def pin(self, note_id: int, pinned: bool = True) -> None:
        """Pin or unpin a note."""
        with sqlite3.connect(self._db) as conn:
            conn.execute(
                "UPDATE notes SET pinned = ? WHERE id = ?",
                (int(pinned), note_id),
            )

    def delete(self, note_id: int) -> None:
        """Delete a note."""
        with sqlite3.connect(self._db) as conn:
            conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))


# ========================================================================
# 4. Tagging & Annotation System
# ========================================================================

@dataclass
class Tag:
    """A tag for a search result or finding."""

    name: str
    color: str = "#2f6fed"
    description: str = ""


@dataclass
class Annotation:
    """An annotation on a search result."""

    result_key: str  # "site/username"
    author: str
    timestamp: str
    note: str
    tags: list[str] = field(default_factory=list)
    confidence: int = 0  # 0-100, investigator's confidence in this finding


class ResultAnnotations:
    """Manages tags and annotations on search results.

    Allows investigators to mark findings as confirmed, suspicious,
    false positive, etc., and add notes.
    """

    # Predefined tags
    PREDEFINED_TAGS: dict[str, Tag] = {
        "confirmed": Tag("confirmed", "#14804a", "Verified as the target"),
        "suspicious": Tag("suspicious", "#b45309", "Needs further verification"),
        "false_positive": Tag("false_positive", "#c2410c", "Not the target"),
        "high_value": Tag("high_value", "#c0262d", "High-value finding"),
        "monitor": Tag("monitor", "#7a3fd1", "Watch for changes"),
        "deleted": Tag("deleted", "#6b7280", "Account appears deleted"),
        "bot": Tag("bot", "#dc2626", "Likely automated account"),
        "impersonation": Tag("impersonation", "#be185d", "Possible impersonation"),
    }

    def __init__(self, db_path: str | None = None) -> None:
        self._db = db_path or str(Path.home() / ".sleuth" / "annotations.db")
        self._init_db()

    def _init_db(self) -> None:
        Path(self._db).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._db) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS annotations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT,
                    result_key TEXT NOT NULL,
                    author TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    note TEXT,
                    tags TEXT,
                    confidence INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_anno_result
                ON annotations(result_key)
            """)

    def annotate(
        self,
        result_key: str,
        author: str,
        note: str,
        tags: list[str] | None = None,
        confidence: int = 0,
        case_id: str = "default",
    ) -> int:
        """Add an annotation to a search result."""
        with sqlite3.connect(self._db) as conn:
            cursor = conn.execute(
                "INSERT INTO annotations (case_id, result_key, author, timestamp, note, tags, confidence) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (case_id, result_key, author,
                 datetime.now(timezone.utc).isoformat(),
                 note, json.dumps(tags or []), confidence),
            )
            return cursor.lastrowid

    def get_annotations(self, result_key: str) -> list[dict[str, Any]]:
        """Get all annotations for a result."""
        with sqlite3.connect(self._db) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM annotations WHERE result_key = ? ORDER BY timestamp",
                (result_key,),
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d.get("tags", "[]"))
            result.append(d)
        return result

    def get_tagged_results(self, case_id: str = "default") -> dict[str, list[str]]:
        """Get all results grouped by tag."""
        with sqlite3.connect(self._db) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT result_key, tags FROM annotations WHERE case_id = ?",
                (case_id,),
            ).fetchall()

        tagged: dict[str, list[str]] = {}
        for r in rows:
            tags = json.loads(r["tags"])
            for tag in tags:
                tagged.setdefault(tag, []).append(r["result_key"])
        return tagged

    @classmethod
    def available_tags(cls) -> list[dict[str, str]]:
        """List all predefined tags."""
        return [
            {"name": t.name, "color": t.color, "description": t.description}
            for t in cls.PREDEFINED_TAGS.values()
        ]
