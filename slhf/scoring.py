from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from slhf.investigation_validator import validate_investigation_steps

# ---------------------------------------------------------------------------
# Score weights
# ---------------------------------------------------------------------------
# The five categories sum to 100 points.  Investigation steps (category 5)
# are a *bonus* category worth up to 20 additional points, making the
# achievable maximum 120.  This is intentional: a learner who works through
# the full investigation chain earns recognition beyond the baseline 100.
#
#   Category                   Max pts   Notes
#   ─────────────────────────  ───────   ──────────────────────────────────
#   1. Host classification        35     Precision/recall F1 against GT hosts
#   2. Evidence (event IDs)       25     Intersection over GT event IDs
#   3a. Phase identification      15     Which phases occurred (unordered)
#   3b. Phase ordering            10     Correct relative ordering bonus
#   4. False-positive handling    15     Correct suspicious hosts (validated)
#   5. Investigation steps        20     Bonus; derived from playbook phases
#   ─────────────────────────  ───────
#   Baseline total               100     (categories 1–4)
#   Maximum total                120     (categories 1–5)

_WEIGHTS = {
    "classification":    35,
    "evidence":          25,
    "phase_id":          15,
    "phase_order":       10,
    "false_positives":   15,
    "investigation":     20,   # bonus
}


def score_submission(
    submission: Dict[str, Any],
    labels: List[Dict[str, Any]],
    playbooks: List[Dict[str, Any]] | None = None,
) -> Tuple[Dict[str, float], Dict[str, Any]]:
    """
    Score a learner's submission against ground-truth *labels*.

    Parameters
    ----------
    submission:
        Dict with optional keys:
          - ``malicious_hosts``   list[str]  – hostnames identified as malicious
          - ``suspicious_hosts``  list[str]  – hostnames flagged as suspicious FPs
          - ``event_ids``         list[str]  – Windows event IDs cited as evidence
          - ``timeline``          list[str]  – attack phase names in learner order
          - ``investigation_steps`` list[dict] – step evidence dicts

    labels:
        Ground-truth labels as produced by GroundTruth.build().

    playbooks:
        Loaded playbook dicts (optional).  When provided, investigation-step
        scoring uses dynamically derived steps instead of the static fallback.

    Returns
    -------
    (score_dict, investigation_detail)
        score_dict keys: ``classification``, ``evidence``, ``phase_id``,
        ``phase_order``, ``false_positives``, ``investigation``,
        ``baseline_total`` (100-pt scale), ``total`` (120-pt scale).
    """
    score: Dict[str, float] = {k: 0.0 for k in _WEIGHTS}

    # ── Ground-truth sets ────────────────────────────────────────────────
    gt_hosts: Set[str] = {l["host"] for l in labels if l.get("host")}
    gt_events: Set[str] = {str(l["event_id"]) for l in labels if l.get("event_id") is not None}

    # All host names that appear anywhere in the dataset (for FP validation)
    # Labels only cover malicious hosts; we approximate the full host set from
    # the union of all labelled hosts.  Callers may extend this if they pass
    # the full event list, but labels are sufficient for validation.
    all_labelled_hosts: Set[str] = gt_hosts.copy()

    # Phase order by first timestamp
    phase_first_ts: Dict[str, str] = {}
    for l in labels:
        if l.get("phase") and l.get("timestamp"):
            phase_first_ts.setdefault(l["phase"], l["timestamp"])
    gt_phase_order = [p for p, _ in sorted(phase_first_ts.items(), key=lambda kv: kv[1])]
    gt_phase_set: Set[str] = set(gt_phase_order)

    # ── 1. Host classification (35 pts) ──────────────────────────────────
    # F1-style: reward both recall (finding the right hosts) and precision
    # (not flooding the answer with every host in the network).
    sub_hosts: Set[str] = set(submission.get("malicious_hosts", []))
    tp = len(sub_hosts & gt_hosts)
    precision = tp / len(sub_hosts) if sub_hosts else 0.0
    recall    = tp / len(gt_hosts)  if gt_hosts  else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    score["classification"] = round(f1 * _WEIGHTS["classification"], 2)

    # ── 2. Evidence – event IDs (25 pts) ─────────────────────────────────
    sub_eids: Set[str] = set(submission.get("event_ids", []))
    score["evidence"] = round(
        (len(sub_eids & gt_events) / max(1, len(gt_events))) * _WEIGHTS["evidence"], 2
    )

    # ── 3a. Phase identification (15 pts) ────────────────────────────────
    # Credit for identifying which phases occurred, regardless of order.
    sub_tl = submission.get("timeline", [])
    sub_phase_set: Set[str] = set(sub_tl)
    phase_recall = len(sub_phase_set & gt_phase_set) / max(1, len(gt_phase_set))
    # Penalise invented phases (precision)
    phase_precision = (
        len(sub_phase_set & gt_phase_set) / len(sub_phase_set) if sub_phase_set else 0.0
    )
    phase_f1 = (
        (2 * phase_precision * phase_recall / (phase_precision + phase_recall))
        if (phase_precision + phase_recall) > 0 else 0.0
    )
    score["phase_id"] = round(phase_f1 * _WEIGHTS["phase_id"], 2)

    # ── 3b. Phase ordering bonus (10 pts) ────────────────────────────────
    # Only phases that are both submitted AND correct contribute.
    # We reward longest common subsequence alignment rather than exact
    # positional match, so partial ordering knowledge still earns credit.
    correct_phases_in_order = [p for p in sub_tl if p in gt_phase_set]
    lcs_len = _lcs_length(correct_phases_in_order, gt_phase_order)
    order_score = lcs_len / max(1, len(gt_phase_order))
    score["phase_order"] = round(order_score * _WEIGHTS["phase_order"], 2)

    # ── 4. False-positive handling (15 pts) ──────────────────────────────
    # The learner gets credit for naming hosts that:
    #   (a) appear in the dataset (not invented), AND
    #   (b) are NOT actually malicious (they really are benign/suspicious).
    # This validates that the learner found and correctly dismissed decoys.
    susp_submitted: List[str] = submission.get("suspicious_hosts", [])
    if susp_submitted and gt_hosts:
        # Valid FP calls: submitted as suspicious, exists in dataset, not malicious
        valid_fp = [h for h in susp_submitted if h not in gt_hosts and h in all_labelled_hosts]
        # Penalty for false FP calls (claiming a malicious host is benign)
        false_fp = [h for h in susp_submitted if h in gt_hosts]
        raw = len(valid_fp) - len(false_fp)
        # Normalise to max-3 valid FP hosts (as before) then clamp to [0, 1]
        fp_ratio = max(0.0, min(1.0, raw / 3.0))
        score["false_positives"] = round(fp_ratio * _WEIGHTS["false_positives"], 2)

    # ── 5. Investigation steps – bonus (20 pts) ──────────────────────────
    inv = validate_investigation_steps(submission, labels, playbooks=playbooks)
    score["investigation"] = round(
        (inv["steps_valid"] / max(1, inv["steps_required"])) * _WEIGHTS["investigation"], 2
    )

    # ── Totals ────────────────────────────────────────────────────────────
    baseline = round(
        score["classification"] + score["evidence"] +
        score["phase_id"] + score["phase_order"] + score["false_positives"],
        2,
    )
    total = round(baseline + score["investigation"], 2)
    score["baseline_total"] = baseline   # /100
    score["total"] = total               # /120 (with bonus)

    return score, inv


# ---------------------------------------------------------------------------
# Longest Common Subsequence length (O(n*m) DP, sufficient for short lists)
# ---------------------------------------------------------------------------

def _lcs_length(a: List[str], b: List[str]) -> int:
    m, n = len(a), len(b)
    if m == 0 or n == 0:
        return 0
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    return dp[m][n]
