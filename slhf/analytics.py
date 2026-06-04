from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from slhf.learning.metrics import metrics_summary


def write_analytics_report(
    out_dir: str,
    attempt_history: List[Dict[str, Any]],
    final_config: Dict[str, Any],
    *,
    # Optional richer context supplied by the engine after a successful run
    selected_attacks: List[str] | None = None,
    selected_anomalies: List[str] | None = None,
    total_events: int | None = None,
    label_count: int | None = None,
) -> str:
    """
    Write an analytics report to ``<out_dir>/analytics/analytics_report.json``.

    Parameters
    ----------
    out_dir:
        Root output directory.
    attempt_history:
        List of per-attempt dicts from the regenerator.
    final_config:
        The config dict used on the successful attempt.
    selected_attacks:
        playbook_id strings of the attack playbooks that were injected.
    selected_anomalies:
        playbook_id strings of the benign/suspicious playbooks that were injected.
    total_events:
        Total number of events in the generated dataset.
    label_count:
        Number of ground-truth labels (malicious events).
    """
    os.makedirs(os.path.join(out_dir, "analytics"), exist_ok=True)

    dataset_summary: Dict[str, Any] = {}
    if selected_attacks is not None:
        dataset_summary["attack_playbooks"] = selected_attacks
    if selected_anomalies is not None:
        dataset_summary["benign_playbooks"] = selected_anomalies
    if total_events is not None:
        dataset_summary["total_events"] = total_events
    if label_count is not None:
        dataset_summary["malicious_label_count"] = label_count

    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "run_summary": {
            "attempts":         len(attempt_history),
            "failure_sequence": [x.get("root_cause") for x in attempt_history],
            "final_config":     final_config,
        },
        "dataset_summary": dataset_summary,
        "global_metrics":  metrics_summary(),
    }

    fp = os.path.join(out_dir, "analytics", "analytics_report.json")
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return fp
