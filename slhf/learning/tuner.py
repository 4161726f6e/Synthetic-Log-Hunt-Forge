from __future__ import annotations

from slhf.learning.learner import load_memory


# Minimum multiplier applied to min_time_gap_seconds when the failure
# threshold is reached.  Each additional crossing doubles it further.
_GAP_SCALE = 2.0
_GAP_MIN   = 120  # seconds – floor after the first correction kick-in


def apply_learned_defaults(cfg: dict) -> dict:
    """
    Pre-tune *cfg* based on accumulated failure history so repeat runs avoid
    known failure modes without waiting for adaptive retry to kick in.
    """
    mem  = load_memory()
    fails = mem.get("failure_patterns", {})

    # Correlation failures: inject extra 4624 events
    if fails.get("DCSYNC_NO_4624", {}).get("count", 0) >= 3:
        cfg.setdefault("force_logon_correlation", True)

    # Ambiguity: ensure benign anchors don't collide with malicious ones
    if fails.get("AMBIGUOUS_ANCHOR_MATCH", {}).get("count", 0) >= 2:
        cfg.setdefault("reduce_benign_anchor_overlap", True)

    # FIX: TIMELINE_TOO_SHORT was a no-op because it only enforced the
    # existing default (60 s) rather than *increasing* it.  Now we scale up
    # proportionally to how many times the failure has been seen.
    too_short_count = fails.get("TIMELINE_TOO_SHORT", {}).get("count", 0)
    if too_short_count >= 2:
        current = cfg.get("min_time_gap_seconds", 60)
        # Scale by 2^(occurrences // 2), capped at a sensible max (10 min).
        scale_steps = too_short_count // 2
        new_gap = min(current * (_GAP_SCALE ** scale_steps), 600)
        cfg["min_time_gap_seconds"] = max(_GAP_MIN, int(new_gap))

    # No false positives: ensure at least one benign decoy is injected
    if fails.get("NO_FALSE_POSITIVES", {}).get("count", 0) >= 2:
        cfg.setdefault("min_false_positive_hosts", 2)

    return cfg
