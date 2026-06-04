from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Any, Dict, List


def write_windows_jsonl(events: List[Dict[str, Any]], out_dir: str) -> None:
    base = os.path.join(out_dir, "logs", "windows")
    os.makedirs(base, exist_ok=True)

    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e.get("channel") == "Security":
            grouped[e["hostname"]].append(e)

    for host, evs in grouped.items():
        fp = os.path.join(base, f"{host}.jsonl")
        with open(fp, "w", encoding="utf-8") as f:
            for e in evs:
                f.write(json.dumps(e) + "\n")


def write_syslog(events: List[Dict[str, Any]], out_dir: str) -> None:
    base = os.path.join(out_dir, "logs", "syslog")
    os.makedirs(base, exist_ok=True)

    # FIX: group all syslog events by host first, then open each file once.
    # The previous implementation opened and closed the file handle on every
    # single event, which was O(n) file-open syscalls for the syslog stream.
    grouped: Dict[str, List[str]] = defaultdict(list)
    for e in events:
        if e.get("source") != "syslog":
            continue
        host = e["hostname"]
        # RFC5424-ish: <PRI>1 TIMESTAMP HOST APP - - - MSG
        line = (
            f"<{e.get('pri', 134)}>1 {e['timestamp']} {host} "
            f"{e.get('app', 'app')} - - - {e.get('message', '')}\n"
        )
        grouped[host].append(line)

    for host, lines in grouped.items():
        fp = os.path.join(base, f"{host}.log")
        with open(fp, "w", encoding="utf-8") as f:
            f.writelines(lines)
