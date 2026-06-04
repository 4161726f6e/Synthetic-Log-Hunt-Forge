from __future__ import annotations

import json
import os
from typing import Any, Dict, List


class GroundTruth:
    """
    Accumulates ground-truth labels from a list of generated events and
    serialises them to JSONL.

    Labels are only emitted for events that carry a non-None ``attack_id``
    in their metadata — i.e. events injected from a malicious playbook.
    Benign/noise events are not labelled.

    Note: the previous implementation used ``@dataclass`` but then manually
    overrode ``__init__``, which discarded the generated initialiser and left
    the field annotation as dead code.  The class is now a plain class with a
    clean ``__init__``.
    """

    def __init__(self) -> None:
        self.labels: List[Dict[str, Any]] = []

    def build(self, events: List[Dict[str, Any]]) -> None:
        """Scan *events* and append a label dict for each malicious event."""
        for e in events:
            md = e.get("metadata", {})
            if not md.get("attack_id"):
                continue
            self.labels.append({
                "timestamp":      e.get("timestamp"),
                "host":           e.get("hostname"),
                "event_id":       e.get("event_id"),
                "classification": "malicious",
                "attack_id":      md.get("attack_id"),
                "phase":          md.get("phase"),
                "technique":      md.get("technique"),
                "anchor":         bool(md.get("anchor", False)),
            })

    def save(self, out_dir: str) -> str:
        """Write labels to ``<out_dir>/ground_truth/labels.jsonl``."""
        path = os.path.join(out_dir, "ground_truth")
        os.makedirs(path, exist_ok=True)
        fp = os.path.join(path, "labels.jsonl")
        with open(fp, "w", encoding="utf-8") as f:
            for label in self.labels:
                f.write(json.dumps(label) + "\n")
        return fp

    def __len__(self) -> int:
        return len(self.labels)

    def __repr__(self) -> str:
        return f"GroundTruth(labels={len(self.labels)})"
