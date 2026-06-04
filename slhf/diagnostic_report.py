from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class ValidationIssue:
    code: str
    severity: str
    message: str
    attack_id: Optional[str] = None
    host: Optional[str] = None
    event_id: Optional[int] = None
    phase: Optional[str] = None
    logon_id: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_default(o):
    if isinstance(o, set):
        return list(o)
    return str(o)


# Fix catalog kept in sync with every code raised by ProvabilityValidator.
# Each entry maps an issue code to a human-readable fix suggestion shown
# in the validation report so an operator knows exactly what to address.
_FIX_CATALOG: Dict[str, str] = {
    # Host / label presence
    "GT_HOST_MISSING":        "Emitter must write per-host logs for all ground-truth hosts.",
    # DCSync correlation chain
    "DCSYNC_NO_4662":         "No 4662 event found on the expected host — check injector phase mapping.",
    "DCSYNC_NO_LOGON_ID":     "Ensure event 4662 includes logon.logon_id for pivot correlation.",
    "DCSYNC_NO_4624":         "Ensure a correlated event 4624 exists for the same logon_id.",
    # Process lineage
    "PROC_MISSING_LINEAGE":   (
        "Event 4688 is missing process.name or parent_process.name. "
        "Add a process_chain to the playbook phase, or ensure the injector "
        "supplies a default parent for process-only phases."
    ),
    # Timeline
    "TIMELINE_NO_TS":         "Ensure all ground-truth labels have a valid ISO 8601 timestamp.",
    "TIMELINE_TOO_SHORT":     (
        "Attack phase spread is < 30 s. Increase min_time_gap_seconds in config, "
        "add more phases to the playbook, or widen the --days window."
    ),
    # Ambiguity / discriminability
    "NO_DISCRIMINATOR":       (
        "No anchor signature appears exclusively on malicious hosts. "
        "Ensure at least one attack playbook produces a distinctive event "
        "(DCSync 4662, LOLBIN chain, POST /cgi-bin/) not replicated by benign playbooks."
    ),
    "NO_FALSE_POSITIVES":     (
        "No benign host produced an anchor-like event. "
        "Ensure at least one benign playbook generates events that look suspicious "
        "(e.g. backup_activity with replication properties, admin_powershell via wscript)."
    ),
    "TOO_MANY_FALSE_POSITIVES": (
        "Too many hosts look like false positives. "
        "Reduce benign anchor-like injections or lower --anomalies."
    ),
    # Catch-all for any new codes not yet catalogued
}


def write_validation_report(
    *,
    output_dir: str,
    name: str,
    stage: str,
    passed: bool,
    issues: List[ValidationIssue],
    context: Optional[Dict[str, Any]] = None,
) -> str:

    full_path = os.path.join(output_dir, "validation", name)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)

    report = {
        "schema_version": "1.0",
        "generated_utc":  _utc_now(),
        "stage":          stage,
        "passed":         passed,
        "issue_count":    len(issues),
        "issues":         [asdict(i) for i in issues],
        "fix_suggestions": {
            i.code: _FIX_CATALOG.get(i.code, "Review generator settings and playbook definitions.")
            for i in issues
        },
        "context": context or {},
    }

    with open(full_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=_json_default)

    return full_path
