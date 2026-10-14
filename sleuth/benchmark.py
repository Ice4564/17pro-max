"""Accuracy benchmark for the core correlation logic.

The identity scoring (similarity.compare / linker.identity_summary) combines
signals with hand-set weights (+25 username, +40 full name, ...). Those
numbers were chosen by reasoning, never measured. This module checks them
against a labelled set of account pairs whose ground truth is known —
"same person" or "two different people" — and reports how well the score
separates the two:

    AUC                     probability a same-person pair outscores a
                            different-person pair (1.0 = perfect, .5 = coin)
    precision @ HIGH (>=70) of the pairs we call high-confidence, how many
                            really are the same person
    recall @ HIGH           of the real same-person pairs, how many reach
                            the high-confidence bar

The labelled pairs are synthetic but model real patterns (shared e-mail,
same full name, owner link, same avatar, common-handle collisions, fan
accounts, shared app-store links). Run it with ``python -m sleuth
--benchmark``; a regression test asserts the metrics stay healthy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .similarity import compare


def _acct(site: str, user: str, **info: Any) -> dict[str, Any]:
    links = info.pop("links", [])
    return {"site": site, "username": user, "url": f"https://{site.lower()}/{user}", "status": "found",
            "info": info, "links": links, "discovered": info.pop("discovered", []),
            "evidence": info.pop("evidence", []), "linked": info.pop("linked", False)}


@dataclass
class Pair:
    a: dict[str, Any]
    b: dict[str, Any]
    same: bool          # ground truth
    why: str            # what makes this pair hard/easy
    hashes: dict | None = None


# Hash helpers for the avatar signal (64-bit dHash space).
_SAME_PIC = {("github", "skydev"): 0, ("dribbble", "sky.makes"): 1}       # ~identical
_DIFF_PIC = {("a", "x"): 0, ("b", "y"): (1 << 40) - 1}                     # clearly different


def labelled_pairs() -> list[Pair]:
    """Pairs with known ground truth, spanning the signals the scorer uses."""
    P: list[Pair] = []

    # --- true positives: should score HIGH ---
    P.append(Pair(
        _acct("GitHub", "sky", bio="contact me at sky@skymail.dev", name="Sky Walker"),
        _acct("Dev.to", "sky_codes", bio="reach: sky@skymail.dev", name="Sky Walker"),
        True, "shared e-mail + same full name"))
    P.append(Pair(
        dict(_acct("Linktree", "sky", name="Sky Walker"), discovered=["Instagram: sky.pixels"]),
        dict(_acct("Instagram", "sky.pixels", name="Sky Walker"), linked=True,
             evidence=["ลิงก์จากโปรไฟล์ Linktree (@sky)"]),
        True, "owner linked the account directly"))
    P.append(Pair(
        _acct("GitHub", "skydev", name="Sky Walker", bio="building pixel art games in Bangkok",
              website="https://sky.dev"),
        _acct("Dribbble", "sky.makes", name="Sky Walker", bio="pixel art games, based in Bangkok",
              website="https://sky.dev"),
        True, "same name + website + similar bio + same avatar", hashes=_SAME_PIC))
    P.append(Pair(
        _acct("Mastodon", "artsky", name="Sky Walker", bio="illustrator · sky.dev · she/her"),
        _acct("Behance", "sky_art", name="Sky Walker", bio="illustrator, portfolio sky.dev"),
        True, "same full name + same personal website host"))
    P.append(Pair(
        _acct("Twitch", "skyplays", bio="streamer, business: sky@skymail.dev"),
        _acct("YouTube", "SkyPlaysTH", bio="contact sky@skymail.dev for business"),
        True, "shared business e-mail"))

    # --- true negatives: should score LOW ---
    P.append(Pair(
        _acct("GitHub", "sky", name="Somchai P."),
        _acct("Reddit", "sky", name="Jane Doe"),
        False, "same common handle, different real names"))
    P.append(Pair(
        _acct("Instagram", "selena", name="Selena"),
        _acct("TikTok", "selena", name="Selena"),
        False, "same first name only (fan/namesake collision)"))
    P.append(Pair(
        _acct("A", "coder123", links=["https://play.google.com/store/apps/details?id=x"]),
        _acct("B", "builder", links=["https://play.google.com/store/apps/details?id=x"]),
        False, "only a shared app-store link (junk)"))
    P.append(Pair(
        _acct("GitHub", "mike", name="Mike Johnson", bio="software engineer"),
        _acct("GitLab", "mike_dev", name="Michael Chen", bio="software engineer"),
        False, "generic bio, different full names"))
    P.append(Pair(
        _acct("X", "john", name="John Smith", website="https://company.com"),
        _acct("LinkedIn", "john-doe-2", name="John Doe", website="https://company.com"),
        False, "shared employer website, different people"))
    P.append(Pair(
        _acct("A", "alex", bio="support@bigcorp.com"),
        _acct("B", "alexb", bio="support@bigcorp.com"),
        False, "shared role/support e-mail (not personal)"))
    P.append(Pair(
        _acct("A", "gamer", name="Alex Lee"),
        _acct("B", "gamerx", name="Alex Lee", bio=""),
        False, "same name but both too common / thin profiles"))

    # --- harder positives: weaker but real ---
    P.append(Pair(
        _acct("GitHub", "skywalker", name="Sky Walker", bio="pixel art + tiny games, bkk"),
        _acct("Reddit", "sky_walker", name="Sky Walker", bio="i make pixel art and tiny games"),
        True, "similar handle + same full name + similar bio"))
    P.append(Pair(
        _acct("Keybase", "skycrypto", bio="eth: sky.eth, mail sky@skymail.dev"),
        _acct("GitHub", "sky", bio="my wallet sky.eth"),
        True, "shared e-mail + shared crypto id"))

    # --- harder negatives: superficially similar ---
    P.append(Pair(
        _acct("A", "photos", name="Nature Photos", bio="daily nature photography"),
        _acct("B", "photos", name="Travel Photos", bio="daily travel photography"),
        False, "same handle + parallel bios, different brands"))
    P.append(Pair(
        _acct("A", "dev", name="Dev Team", bio="official dev account"),
        _acct("B", "dev", name="Dev Team", bio="official dev account", links=["https://apple.com"]),
        False, "brand/role account, not a person"))
    return P


def score_pairs(pairs: list[Pair] | None = None) -> list[tuple[int, bool, str]]:
    """(confidence, same, why) for every labelled pair."""
    pairs = pairs or labelled_pairs()
    out = []
    for p in pairs:
        c = compare(p.a, p.b, p.hashes)
        out.append((c["confidence"], p.same, p.why))
    return out


def auc(scored: list[tuple[int, bool, str]]) -> float:
    """Probability a positive outscores a negative (Mann-Whitney U / ROC-AUC)."""
    pos = [s for s, same, _ in scored if same]
    neg = [s for s, same, _ in scored if not same]
    if not pos or not neg:
        return 0.0
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def at_threshold(scored: list[tuple[int, bool, str]], t: int) -> dict[str, float]:
    tp = sum(1 for s, same, _ in scored if same and s >= t)
    fp = sum(1 for s, same, _ in scored if not same and s >= t)
    fn = sum(1 for s, same, _ in scored if same and s < t)
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"threshold": t, "tp": tp, "fp": fp, "fn": fn, "precision": prec, "recall": rec, "f1": f1}


def run(pairs: list[Pair] | None = None) -> dict[str, Any]:
    scored = score_pairs(pairs)
    pos = [s for s, same, _ in scored if same]
    neg = [s for s, same, _ in scored if not same]
    thresholds = [at_threshold(scored, t) for t in (70, 45)]
    # the pairs the scorer got most wrong, for insight
    misses = sorted(((s, same, why) for s, same, why in scored
                     if (same and s < 45) or (not same and s >= 45)), key=lambda x: -abs(x[0] - 45))
    return {
        "pairs": len(scored),
        "positives": len(pos), "negatives": len(neg),
        "auc": round(auc(scored), 3),
        "mean_positive": round(sum(pos) / len(pos), 1) if pos else 0,
        "mean_negative": round(sum(neg) / len(neg), 1) if neg else 0,
        "thresholds": thresholds,
        "misranked": [{"score": s, "same": same, "why": why} for s, same, why in misses],
        "scored": [{"score": s, "same": same, "why": why} for s, same, why in scored],
    }


def format_report(result: dict[str, Any]) -> str:
    L = [f"Identity-scoring benchmark — {result['pairs']} labelled pairs "
         f"({result['positives']} same person, {result['negatives']} different)",
         "",
         f"  AUC (separation)      {result['auc']:.3f}   (1.0 perfect · 0.5 random)",
         f"  mean score  same     {result['mean_positive']}",
         f"  mean score  different {result['mean_negative']}",
         ""]
    for t in result["thresholds"]:
        label = "HIGH" if t["threshold"] >= 70 else "MEDIUM"
        L.append(f"  @{t['threshold']:>3} ({label:<6}) precision {t['precision']:.2f}  recall {t['recall']:.2f}  "
                 f"f1 {t['f1']:.2f}   (tp {t['tp']} fp {t['fp']} fn {t['fn']})")
    if result["misranked"]:
        L += ["", "  Misranked (worth a look):"]
        for m in result["misranked"]:
            tag = "should be SAME" if m["same"] else "should be DIFF"
            L.append(f"    {m['score']:>3}  {tag}  — {m['why']}")
    return "\n".join(L)
