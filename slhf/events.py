from __future__ import annotations

from typing import Any, Dict


def base_windows_event(ts: str, host: str) -> Dict[str, Any]:
    return {
        "timestamp": ts,
        "hostname":  host,
        "channel":   "Security",
        "provider":  "Microsoft-Windows-Security-Auditing",
        "event_id":   None,
        "event_type": None,
        "user":           {"name": None, "domain": "CORP", "sid": None, "is_admin": False},
        "logon":          {"logon_id": None, "logon_type": None, "source_ip": None, "source_host": None},
        "process":        {"pid": None, "name": None, "path": None, "command_line": None},
        "parent_process": {"pid": None, "name": None, "path": None},
        "object":         {"type": None, "name": None, "access_mask": None, "properties": []},
        "network":        {"src_ip": None, "src_port": None, "dst_ip": None, "dst_port": None, "protocol": None},
        "metadata":       {"severity": "informational", "noise": True, "attack_id": None,
                           "phase": None, "technique": None, "anchor": False},
    }


def syslog_event(ts: str, host: str, app: str, msg: str, pri: int = 134) -> Dict[str, Any]:
    return {
        "timestamp": ts,
        "hostname":  host,
        "source":    "syslog",
        "pri":       pri,
        "app":       app,
        "message":   msg,
        "metadata":  {"noise": True, "attack_id": None, "phase": None, "technique": None, "anchor": False},
    }
