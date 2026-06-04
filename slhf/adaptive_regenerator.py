from __future__ import annotations

# Maximum gap the adaptive regenerator will push min_time_gap_seconds to.
_MAX_GAP_SECONDS = 600  # 10 minutes


def adapt_config(cfg: dict, failure: dict) -> dict:
    """
    Apply one-step self-correcting adjustments to *cfg* based on the
    root-cause code of the most recent validation failure.

    Design constraint: this function is called *after* the injector has
    already tried to use ``cfg["min_time_gap_seconds"]`` to spread phases.
    We add a fixed increment (not multiply) to avoid compounding on top of
    the tuner's already-applied historical scaling.
    """
    rc = failure.get("root_cause")

    if rc == "DCSYNC_NO_4624":
        cfg["force_logon_correlation"] = True
        cfg["min_4624_per_4662"] = 1

    elif rc == "TIMELINE_TOO_SHORT":
        current = cfg.get("min_time_gap_seconds", 60)
        cfg["min_time_gap_seconds"] = min(current + 60, _MAX_GAP_SECONDS)
        cfg["spread_attack_over_time"] = True

    elif rc in ("AMBIGUOUS_ANCHOR_MATCH", "NO_DISCRIMINATOR"):
        cfg["reduce_benign_anchor_overlap"] = True
        cfg["require_unique_anchor"] = True

    elif rc == "TOO_MANY_FALSE_POSITIVES":
        cfg["max_false_positive_hosts"] = max(1, cfg.get("max_false_positive_hosts", 5) - 1)

    elif rc == "NO_FALSE_POSITIVES":
        cfg["min_false_positive_hosts"] = max(1, cfg.get("min_false_positive_hosts", 2))

    # PROC_MISSING_LINEAGE: this was a deterministic injector bug (process-only
    # playbook phases not getting a default parent_process.name).  It is fixed
    # in injector.py and should never fire again.  If it somehow did, bumping
    # the seed would not help — the fix must be in the playbook or injector.
    # We intentionally leave it unhandled here so that if it resurfaces it
    # fails visibly rather than looping fruitlessly through seed increments.

    return cfg
