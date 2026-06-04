from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

REQUIRED_TOP_LEVEL = {"playbook_id", "classification", "phases"}
VALID_CLASSIFICATIONS = {"malicious", "suspicious", "benign"}
VALID_SOURCES = {"windows", "syslog"}


class PlaybookValidationError(ValueError):
    """Raised when a playbook YAML does not satisfy the expected schema."""


def _validate_playbook(pb: Dict[str, Any], path: str) -> None:
    """Raise PlaybookValidationError with a helpful message if the playbook is malformed."""
    missing = REQUIRED_TOP_LEVEL - set(pb.keys())
    if missing:
        raise PlaybookValidationError(
            f"[{path}] Missing required fields: {sorted(missing)}"
        )

    classification = pb.get("classification", "")
    if classification not in VALID_CLASSIFICATIONS:
        raise PlaybookValidationError(
            f"[{path}] Invalid classification {classification!r}. "
            f"Must be one of {sorted(VALID_CLASSIFICATIONS)}."
        )

    phases = pb.get("phases", [])
    if not isinstance(phases, list) or len(phases) == 0:
        raise PlaybookValidationError(
            f"[{path}] 'phases' must be a non-empty list."
        )

    for i, phase in enumerate(phases):
        if not isinstance(phase, dict):
            raise PlaybookValidationError(
                f"[{path}] phases[{i}] must be a mapping, got {type(phase).__name__}."
            )
        if "id" not in phase:
            raise PlaybookValidationError(
                f"[{path}] phases[{i}] is missing required 'id' field."
            )
        source = phase.get("source", "windows")
        if source not in VALID_SOURCES:
            raise PlaybookValidationError(
                f"[{path}] phases[{i}] has invalid source {source!r}. "
                f"Must be one of {sorted(VALID_SOURCES)}."
            )
        if source == "windows" and "event_id" not in phase:
            raise PlaybookValidationError(
                f"[{path}] phases[{i}] (source=windows) is missing required 'event_id'."
            )
        if source == "syslog" and "app" not in phase:
            raise PlaybookValidationError(
                f"[{path}] phases[{i}] (source=syslog) is missing required 'app'."
            )

    # Validate anchors reference real phase event_ids
    phase_event_ids = {p.get("event_id") for p in phases if p.get("event_id") is not None}
    for anchor in pb.get("anchors", []):
        if not isinstance(anchor, dict):
            raise PlaybookValidationError(
                f"[{path}] Each entry in 'anchors' must be a mapping."
            )
        aid = anchor.get("event_id")
        if aid is not None and aid not in phase_event_ids:
            raise PlaybookValidationError(
                f"[{path}] Anchor references event_id {aid} which does not appear in any phase."
            )


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_playbooks(base_dir: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Load and validate all playbooks under *base_dir*.

    Raises PlaybookValidationError (a subclass of ValueError) for the first
    malformed YAML encountered so problems are surfaced immediately rather
    than causing mysterious failures downstream.
    """
    base = Path(base_dir)
    attacks: List[Dict[str, Any]] = []
    benign: List[Dict[str, Any]] = []

    for directory, bucket in [("attack", attacks), ("benign", benign)]:
        pb_dir = base / directory
        if not pb_dir.exists():
            continue
        for p in sorted(pb_dir.glob("*.yaml")):
            try:
                pb = yaml.safe_load(p.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                raise PlaybookValidationError(
                    f"[{p}] YAML parse error: {exc}"
                ) from exc

            if not isinstance(pb, dict):
                raise PlaybookValidationError(
                    f"[{p}] Playbook root must be a YAML mapping."
                )

            _validate_playbook(pb, str(p))
            bucket.append(pb)

    return attacks, benign
