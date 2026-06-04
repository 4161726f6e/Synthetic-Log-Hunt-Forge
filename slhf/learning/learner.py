from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from slhf.learning._filelock import lock_shared, lock_exclusive, unlock


# ---------------------------------------------------------------------------
# Store location
# ---------------------------------------------------------------------------
# Precedence: SLHF_DATA_DIR env var → XDG_DATA_HOME/slhf → ~/.local/share/slhf
# This keeps accumulated history outside the package tree so reinstalls and
# read-only install locations (e.g. site-packages) don't cause problems.

def _default_data_dir() -> Path:
    env = os.environ.get("SLHF_DATA_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "slhf"
    return Path.home() / ".local" / "share" / "slhf"


def _mem_path() -> Path:
    d = _default_data_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / "memory_store.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_locked(path: Path) -> dict:
    """Read JSON from *path*, returning an empty skeleton if missing."""
    if not path.exists():
        return {"failure_patterns": {}, "successful_configs": []}
    with open(path, "r", encoding="utf-8") as f:
        lock_shared(f)
        try:
            return json.load(f)
        finally:
            unlock(f)


def _save_locked(path: Path, data: dict) -> None:
    """Write *data* as JSON to *path* under an exclusive lock.

    Uses a write-to-temp-then-atomic-rename strategy so a crash during the
    write never leaves a partial file.  The lock is belt-and-suspenders for
    concurrent CLI invocations on the same machine.
    """
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

def load_memory() -> dict:
    return _load_locked(_mem_path())


def save_memory(mem: dict) -> None:
    _save_locked(_mem_path(), mem)


def record_failure(code: str) -> None:
    path = _mem_path()
    mem = _load_locked(path)
    p = mem["failure_patterns"].setdefault(code, {"count": 0, "last_seen": None})
    p["count"] += 1
    p["last_seen"] = _now()
    _save_locked(path, mem)


def record_success(config: dict) -> None:
    path = _mem_path()
    mem = _load_locked(path)
    mem["successful_configs"].append({"timestamp": _now(), "config": config})
    mem["successful_configs"] = mem["successful_configs"][-50:]
    _save_locked(path, mem)
