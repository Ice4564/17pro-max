"""Accuracy benchmark: identity scoring must keep separating same vs different people."""

from sleuth.benchmark import at_threshold, auc, labelled_pairs, run, score_pairs
from sleuth.similarity import compare, crypto_ids_of


def test_benchmark_metrics_stay_healthy():
    r = run()
    # separation between same-person and different-person pairs
    assert r["auc"] >= 0.85, f"AUC regressed to {r['auc']}"
    # the key safety property: a HIGH-confidence call almost never merges two different people
    high = r["thresholds"][0]
    assert high["threshold"] == 70 and high["precision"] >= 0.95, f"high-confidence precision {high['precision']}"
    # same-person pairs clearly outscore different-person pairs on average
    assert r["mean_positive"] - r["mean_negative"] >= 25


def test_every_labelled_pair_is_scored():
    scored = score_pairs()
    assert len(scored) == len(labelled_pairs()) >= 12
    assert all(0 <= s <= 100 and isinstance(same, bool) for s, same, _ in scored)


def test_auc_and_threshold_helpers():
    scored = [(90, True, ""), (80, True, ""), (40, False, ""), (10, False, "")]
    assert auc(scored) == 1.0
    m = at_threshold(scored, 70)
    assert m["precision"] == 1.0 and m["recall"] == 1.0 and m["f1"] == 1.0


def test_shared_crypto_id_is_a_strong_signal():
    a = {"site": "GitHub", "username": "sky", "url": "u", "status": "found",
         "info": {"bio": "my wallet sky.eth"}, "links": []}
    b = {"site": "Keybase", "username": "skycrypto", "url": "u", "status": "found",
         "info": {"bio": "contact sky.eth"}, "links": []}
    assert crypto_ids_of(a) == {"sky.eth"}
    c = compare(a, b)
    assert any(s["name"] == "crypto" and s["ok"] for s in c["signals"]) and c["confidence"] >= 60
