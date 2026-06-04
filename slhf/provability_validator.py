from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from slhf.diagnostic_report import ValidationIssue


class ValidationFailed(Exception):
    def __init__(self, issues: List[ValidationIssue]):
        super().__init__("; ".join([f"{i.code}: {i.message}" for i in issues]))
        self.issues = issues
        self.code = issues[0].code if issues else "UNKNOWN"


def _parse_ts(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _get(d: Dict[str, Any], path: str, default=None):
    cur: Any = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


@dataclass(frozen=True)
class LabelView:
    timestamp: str
    host: str
    event_id: Optional[int]
    attack_id: Optional[str]
    phase: Optional[str]
    technique: Optional[str]
    anchor: bool


# ---------------------------------------------------------------------------
# Anchor detection helpers
# ---------------------------------------------------------------------------
# These functions are intentionally broader than the old hardcoded strings so
# that benign decoy playbooks don't need to use exact production phrasing to
# register as false-positive anchors.

def _is_dcsync_like(e: Dict[str, Any]) -> bool:
    """Any 4662 that touches AD replication properties looks DCSync-like."""
    if e.get("event_id") != 4662:
        return False
    props = _get(e, "object.properties", [])
    if not isinstance(props, list):
        return False
    # Match "Replicating Directory Changes" with or without "All"
    return any("Replicating Directory Changes" in str(p) for p in props)


def _is_lolbin_like(e: Dict[str, Any]) -> bool:
    """Any powershell.exe launched from a script host looks LOLBIN-like."""
    if e.get("event_id") != 4688:
        return False
    proc   = (_get(e, "process.name") or "").lower()
    parent = (_get(e, "parent_process.name") or "").lower()
    _SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "mshta.exe", "hh.exe"}
    return proc == "powershell.exe" and parent in _SCRIPT_HOSTS


def _is_cgi_like(e: Dict[str, Any]) -> bool:
    """Any syslog line with a POST to /cgi-bin/ looks like a web exploit."""
    return (
        e.get("source") == "syslog"
        and "POST /cgi-bin/" in (e.get("message") or "")
    )


def _is_cred_tool_like(e: Dict[str, Any]) -> bool:
    """Any 4688 launching a known credential-dumping tool."""
    if e.get("event_id") != 4688:
        return False
    proc = (_get(e, "process.name") or "").lower()
    _CRED_TOOLS = {"mimikatz.exe", "wce.exe", "gsecdump.exe", "pwdump.exe",
                   "fgdump.exe", "cachedump.exe", "procdump.exe"}
    return proc in _CRED_TOOLS


def _is_pth_like(e: Dict[str, Any]) -> bool:
    """Any explicit-credential logon (4648) looks like Pass-the-Hash."""
    return e.get("event_id") == 4648


def _is_spray_like(e: Dict[str, Any]) -> bool:
    """
    A failed logon (4625) looks like brute force / spray only when it carries
    a failure reason — injected events set object.name to the reason string.
    Plain noise does not generate 4625 events, but this guards against future changes.
    """
    if e.get("event_id") != 4625:
        return False
    return bool(_get(e, "object.name"))


def _is_scheduled_task_like(e: Dict[str, Any]) -> bool:
    """
    A scheduled task creation (4698) looks like persistence only when it
    carries a task name — injected events set object.name, noise does not
    generate 4698 events, but this keeps the pattern consistent.
    """
    if e.get("event_id") != 4698:
        return False
    return bool(_get(e, "object.name"))


def _is_shadow_delete_like(e: Dict[str, Any]) -> bool:
    """vssadmin.exe or wmic shadowcopy launched from cmd — ransomware precursor."""
    if e.get("event_id") != 4688:
        return False
    proc = (_get(e, "process.name") or "").lower()
    cmd  = (_get(e, "process.command_line") or "").lower()
    return proc in ("vssadmin.exe", "wmic.exe") and (
        "shadow" in cmd or "delete" in cmd
    )


def _is_service_install_like(e: Dict[str, Any]) -> bool:
    """
    A service install (7045) looks suspicious only when it carries a named
    service — noise-generated 7045 events have object.name=None and are
    excluded to prevent the entire host pool from being flagged as FP-like.
    """
    if e.get("event_id") != 7045:
        return False
    # Noise events have no service name; injected events always set object.name
    return bool(_get(e, "object.name"))


def _is_kerberoast_like(e: Dict[str, Any]) -> bool:
    """4769 with RC4 encryption type (0x17) — Kerberoasting indicator."""
    if e.get("event_id") != 4769:
        return False
    enc = (_get(e, "object.access_mask") or "").lower()
    return "0x17" in enc or "23" in enc


def _is_exfil_like(e: Dict[str, Any]) -> bool:
    """Syslog firewall event with large byte count — exfiltration indicator."""
    if e.get("source") != "syslog":
        return False
    msg = e.get("message") or ""
    if "bytes=" not in msg:
        return False
    try:
        raw = msg.split("bytes=")[1].split()[0].replace(",", "")
        return int(raw) > 10_000_000
    except (IndexError, ValueError):
        return False


def _is_staging_like(e: Dict[str, Any]) -> bool:
    """Data staging tools (robocopy, compact) used for exfiltration preparation."""
    if e.get("event_id") != 4688:
        return False
    proc = (_get(e, "process.name") or "").lower()
    return proc in ("robocopy.exe", "compact.exe", "xcopy.exe", "7z.exe", "rar.exe")


def _anchor_tag(e: Dict[str, Any]) -> Optional[str]:
    """Return a tag string if the event matches any suspicious anchor pattern."""
    if _is_dcsync_like(e):          return "ANCHOR_DCSYNC"
    if _is_lolbin_like(e):          return "ANCHOR_LOLBIN"
    if _is_cgi_like(e):             return "ANCHOR_CGI"
    if _is_cred_tool_like(e):       return "ANCHOR_CREDTOOL"
    if _is_pth_like(e):             return "ANCHOR_PTH"
    if _is_spray_like(e):           return "ANCHOR_SPRAY"
    if _is_scheduled_task_like(e):  return "ANCHOR_TASK"
    if _is_shadow_delete_like(e):   return "ANCHOR_SHADOW"
    if _is_service_install_like(e): return "ANCHOR_SERVICE"
    if _is_kerberoast_like(e):      return "ANCHOR_KERBEROAST"
    if _is_exfil_like(e):           return "ANCHOR_EXFIL"
    if _is_staging_like(e):         return "ANCHOR_STAGING"
    return None


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class ProvabilityValidator:
    def __init__(self, events: List[Dict[str, Any]], labels: List[Dict[str, Any]]):
        self.events = events
        self.labels_raw = labels
        self.labels: List[LabelView] = []

        self.by_host: Dict[str, List[Dict]] = defaultdict(list)
        self.by_logon: Dict[str, List[Dict]] = defaultdict(list)

        for e in events:
            h = e.get("hostname")
            if h:
                self.by_host[h].append(e)
            lid = _get(e, "logon.logon_id")
            if lid:
                self.by_logon[lid].append(e)

        for l in labels:
            self.labels.append(LabelView(
                timestamp=l.get("timestamp", ""),
                host=l.get("host", ""),
                event_id=l.get("event_id"),
                attack_id=l.get("attack_id"),
                phase=l.get("phase"),
                technique=l.get("technique"),
                anchor=bool(l.get("anchor", False)),
            ))

    def _malicious_attack_ids(self) -> Set[str]:
        return {lv.attack_id for lv in self.labels if lv.attack_id}

    def validate(self, fail_fast: bool = True, max_issues: int = 50) -> None:
        issues: List[ValidationIssue] = []

        def add(issue: ValidationIssue):
            issues.append(issue)
            if fail_fast or len(issues) >= max_issues:
                raise ValidationFailed(issues)

        # 1) Every ground-truth host must appear in the emitted logs
        hosts_in_logs = set(self.by_host.keys())
        for lv in self.labels:
            if lv.host and lv.host not in hosts_in_logs:
                add(ValidationIssue(
                    "GT_HOST_MISSING", "error",
                    f"Ground truth host {lv.host} not present in logs",
                    host=lv.host, attack_id=lv.attack_id,
                    event_id=lv.event_id, phase=lv.phase,
                ))

        # 2) DCSync-style: any attack using 4662 must have a correlated 4624
        for lv in self.labels:
            if lv.event_id != 4662 or not lv.attack_id:
                continue
            evs_4662 = [
                e for e in self.by_host.get(lv.host, [])
                if e.get("event_id") == 4662
                and _get(e, "metadata.attack_id") == lv.attack_id
            ]
            if not evs_4662:
                add(ValidationIssue(
                    "DCSYNC_NO_4662", "error",
                    f"No 4662 events found on host {lv.host} for attack {lv.attack_id}",
                    host=lv.host, attack_id=lv.attack_id, event_id=4662, phase=lv.phase,
                ))
            for e in evs_4662:
                lid = _get(e, "logon.logon_id")
                if not lid:
                    add(ValidationIssue(
                        "DCSYNC_NO_LOGON_ID", "error",
                        "4662 missing logon_id pivot",
                        host=lv.host, attack_id=lv.attack_id, event_id=4662, phase=lv.phase,
                    ))
                    continue
                rel = self.by_logon.get(lid, [])
                if not any(x.get("event_id") == 4624 for x in rel):
                    add(ValidationIssue(
                        "DCSYNC_NO_4624", "error",
                        f"No 4624 for logon_id {lid}",
                        host=lv.host, attack_id=lv.attack_id,
                        event_id=4662, phase=lv.phase, logon_id=lid,
                    ))

        # 3) Process lineage for malicious 4688 labels
        for lv in self.labels:
            if lv.event_id != 4688 or not lv.attack_id:
                continue
            evs = [
                e for e in self.by_host.get(lv.host, [])
                if e.get("event_id") == 4688
                and _get(e, "metadata.attack_id") == lv.attack_id
            ]
            for e in evs:
                if not _get(e, "process.name") or not _get(e, "parent_process.name"):
                    add(ValidationIssue(
                        "PROC_MISSING_LINEAGE", "error",
                        "4688 missing process/parent names",
                        host=lv.host, attack_id=lv.attack_id, event_id=4688, phase=lv.phase,
                    ))

        # 4) Timeline coherence — derived from labels, no hardcoded attack IDs
        malicious_ids = self._malicious_attack_ids()
        attacks: Dict[str, List[LabelView]] = defaultdict(list)
        for lv in self.labels:
            if lv.attack_id in malicious_ids:
                attacks[lv.attack_id].append(lv)

        for aid, items in attacks.items():
            parsed: List[Tuple[datetime, LabelView]] = []
            for lv in items:
                if not lv.timestamp:
                    add(ValidationIssue(
                        "TIMELINE_NO_TS", "error",
                        f"Missing timestamp in label for attack {aid}",
                        attack_id=aid, host=lv.host, event_id=lv.event_id, phase=lv.phase,
                    ))
                    continue
                try:
                    parsed.append((_parse_ts(lv.timestamp), lv))
                except Exception:
                    add(ValidationIssue(
                        "TIMELINE_NO_TS", "error",
                        f"Unparseable timestamp {lv.timestamp}",
                        attack_id=aid, host=lv.host, event_id=lv.event_id, phase=lv.phase,
                    ))
            if not parsed:
                continue
            parsed.sort(key=lambda x: x[0])
            duration = (parsed[-1][0] - parsed[0][0]).total_seconds()
            if duration < 30:
                add(ValidationIssue(
                    "TIMELINE_TOO_SHORT", "error",
                    f"Attack {aid} duration {duration:.1f}s too short",
                    attack_id=aid,
                ))

        # 5) Ambiguity / discriminability checks
        malicious_hosts: Set[str] = set(lv.host for lv in self.labels if lv.attack_id)

        # Collect anchor-like signatures per host using the broadened helpers
        anchor_hits: Dict[str, Set[str]] = defaultdict(set)
        for host, evs in self.by_host.items():
            for e in evs:
                tag = _anchor_tag(e)
                if tag:
                    anchor_hits[host].add(tag)
        # Also check syslog events (stored separately from by_host for syslog-only hosts)
        for e in self.events:
            if e.get("source") == "syslog":
                host = e.get("hostname")
                if host and _is_cgi_like(e):
                    anchor_hits[host].add("ANCHOR_CGI")

        # At least one anchor must appear exclusively on malicious hosts
        anchor_to_hosts: Dict[str, Set[str]] = defaultdict(set)
        for h, anchors in anchor_hits.items():
            for a in anchors:
                anchor_to_hosts[a].add(h)

        if not any(
            hosts.issubset(malicious_hosts) and hosts
            for hosts in anchor_to_hosts.values()
        ):
            add(ValidationIssue(
                "NO_DISCRIMINATOR", "error",
                "No discriminating anchor signature unique to malicious hosts",
            ))

        # False positives: suspicious-looking benign hosts must exist
        fp_like = [
            h for h in anchor_hits.keys()
            if h not in malicious_hosts and anchor_hits[h]
        ]
        if len(fp_like) == 0:
            add(ValidationIssue(
                "NO_FALSE_POSITIVES", "error",
                "No false-positive-like hosts detected",
            ))
        if len(fp_like) > max(5, len(malicious_hosts) * 3):
            add(ValidationIssue(
                "TOO_MANY_FALSE_POSITIVES", "error",
                f"Too many false-positive-like hosts ({len(fp_like)})",
            ))
