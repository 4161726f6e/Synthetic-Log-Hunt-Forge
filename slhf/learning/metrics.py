from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from slhf.learning._filelock import lock_shared, lock_exclusive, unlock
from slhf.learning.learner import _default_data_dir


def _metrics_path() -> Path:
    d = _default_data_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / "metrics_store.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load(path: Path) -> dict:
    if not path.exists():
        return {"runs": []}
    with open(path, "r", encoding="utf-8") as f:
        lock_shared(f)
        try:
            return json.load(f)
        finally:
            unlock(f)


def _save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        lock_exclusive(f)
        try:
            json.dump(data, f, indent=2)
        finally:
            unlock(f)
    tmp.replace(path)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_metrics() -> dict:
    return _load(_metrics_path())


def save_metrics(m: dict) -> None:
    _save(_metrics_path(), m)


def record_run(success: bool, attempts: int, final_seed, failure_chain) -> None:
    path = _metrics_path()
    m = _load(path)
    m["runs"].append({
        "timestamp": _now(),
        "success": success,
        "attempts": attempts,
        "final_seed": final_seed,
        "failures": [x.get("root_cause") for x in failure_chain],
    })
    m["runs"] = m["runs"][-200:]
    _save(path, m)


def metrics_summary() -> dict:
    m = load_metrics()
    runs = m.get("runs", [])
    if not runs:
        return {"total_runs": 0, "success_rate": 0.0, "avg_attempts": 0.0, "top_failures": []}

    total = len(runs)
    successes = sum(1 for r in runs if r.get("success"))
    avg_attempts = sum(r.get("attempts", 0) for r in runs) / max(1, total)

    c: Counter = Counter()
    for r in runs:
        c.update([f for f in r.get("failures", []) if f])

    return {
        "total_runs": total,
        "success_rate": round(successes / total, 3),
        "avg_attempts": round(avg_attempts, 2),
        "top_failures": c.most_common(10),
    }
