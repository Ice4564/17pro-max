"""Username mutation generator.

People rarely get the same handle everywhere, so when ``ice4564`` is taken
they register ``ice_4564``, ``ice4564x`` or ``real.ice4564``. This module
lists those spellings, most plausible first, so the engine can check them
all in the same pass as the typed username.

It starts with :func:`linker.candidates` (separators, digit tricks) and adds
the padding people use when a handle is taken. Every mutation is a guess:
results for it are labelled "candidate" and start at low confidence.
"""

from __future__ import annotations

import re

from .linker import Candidate, candidates

# (template, reason) in rough order of how often people use them.
# {u} = the username as typed.
_PADDING: list[tuple[str, str]] = [
    ("{u}_", "เติม _ ท้ายชื่อ (ชื่อเดิมถูกใช้แล้ว)"),
    ("_{u}", "เติม _ หน้าชื่อ"),
    ("{u}x", "เติม x ท้ายชื่อ"),
    ("{u}th", "เติม th (ประเทศไทย) ท้ายชื่อ"),
    ("{u}_th", "เติม _th ท้ายชื่อ"),
    ("{u}.th", "เติม .th ท้ายชื่อ"),
    ("real{u}", "เติม real หน้าชื่อ"),
    ("real_{u}", "เติม real_ หน้าชื่อ"),
    ("the{u}", "เติม the หน้าชื่อ"),
    ("its{u}", "เติม its หน้าชื่อ"),
    ("im{u}", "เติม im หน้าชื่อ"),
    ("{u}official", "เติม official ท้ายชื่อ"),
    ("{u}_official", "เติม _official ท้ายชื่อ"),
    ("{u}1", "เติมเลข 1 ท้ายชื่อ"),
    ("{u}01", "เติมเลข 01 ท้ายชื่อ"),
    ("{u}__", "เติม __ ท้ายชื่อ"),
    ("x{u}x", "ครอบด้วย x"),
    ("{u}.official", "เติม .official ท้ายชื่อ"),
]

# Common look-alike swaps (only applied once, to the first match).
_LEET = [("o", "0"), ("i", "1"), ("e", "3"), ("a", "4"), ("s", "5")]

ALLOWED = re.compile(r"^[A-Za-z0-9._-]{3,40}$")


def mutations(username: str, limit: int = 12, padding: bool = True, leet: bool = True) -> list[Candidate]:
    """Alternative spellings of ``username``, most plausible first.

    ice4564 -> ice_4564, ice.4564, ice-4564, ice, 4564ice, ice4564_, _ice4564,
               ice4564x, ice4564th, ...
    """
    base = username.strip().lstrip("@")
    out: list[Candidate] = list(candidates(base, limit=limit))
    if padding:
        out += [Candidate(t.format(u=base), why) for t, why in _PADDING]
    if leet:
        low = base.lower()
        for a, b in _LEET:
            i = low.find(a)
            if i >= 0 and not low.isdigit():
                out.append(Candidate(base[:i] + b + base[i + 1:], f"เปลี่ยน {a} เป็น {b} (ตัวอักษรหน้าตาคล้ายกัน)"))
                break

    seen = {base.lower()}
    uniq: list[Candidate] = []
    for c in out:
        k = c.username.lower()
        if k not in seen and ALLOWED.match(c.username):
            seen.add(k)
            uniq.append(c)
    return uniq[:limit]


def mutation_names(username: str, limit: int = 12) -> list[str]:
    return [c.username for c in mutations(username, limit)]
