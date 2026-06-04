from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, FrozenSet, List

from slhf.events import base_windows_event, syslog_event
from slhf.timing import iso_z


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Credential-dumping tools are almost always launched from a command shell,
# not directly from explorer.  Used to supply a realistic default parent
# when a playbook phase specifies a process name but no process_chain.
_CRED_TOOLS = frozenset({
    "mimikatz.exe", "wce.exe", "gsecdump.exe", "pwdump.exe",
    "fgdump.exe", "cachedump.exe", "procdump.exe",
})

# Processes that should get cmd.exe as default parent (recon / staging tools)
_RECON_TOOLS = frozenset({
    "net.exe", "net1.exe", "nltest.exe", "whoami.exe",
    "ipconfig.exe", "systeminfo.exe", "vssadmin.exe",
    "wmic.exe", "robocopy.exe", "compact.exe",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pick_host(rng, topo: Dict, preferred_role: str = "windows",
               excluded: frozenset = frozenset()) -> Any:
    """
    Return a host appropriate for the given role hint.

    If *excluded* is provided (a frozenset of host names), prefer hosts
    not in that set.  Falls back to any available host if all candidates
    are excluded, so generation never deadlocks.
    """
    candidates = topo.get(preferred_role) or topo.get("windows") or topo["all"]
    preferred  = [h for h in candidates if h.name not in excluded]
    pool       = preferred if preferred else candidates
    return rng.choice(pool)


def _build_windows_event(ts: str, host_name: str, phase: Dict[str, Any],
                         attack_id: str, logon_id: str, user: str,
                         is_anchor: bool) -> Dict[str, Any]:
    """Translate a windows-typed playbook phase into a log event dict."""
    eid = phase.get("event_id")
    e = base_windows_event(ts, host_name)
    e["event_id"] = eid
    e["user"]["name"] = phase.get("user", user)
    e["logon"]["logon_id"] = logon_id
    e["metadata"]["attack_id"] = attack_id
    e["metadata"]["phase"] = phase.get("id")
    e["metadata"]["technique"] = phase.get("technique")
    e["metadata"]["noise"] = False
    e["metadata"]["anchor"] = is_anchor

    # Per-event-ID enrichment driven by playbook fields
    if eid == 4624:
        conds = phase.get("conditions", {})
        e["event_type"] = "logon_success"
        e["logon"]["logon_type"] = conds.get("logon_type", 3)
        if "user_contains" in conds:
            e["user"]["name"] = conds["user_contains"]

    elif eid == 4688:
        e["event_type"] = "process_creation"
        proc          = phase.get("process", {})
        process_chain = phase.get("process_chain", {})
        cmd_contains  = phase.get("command_line_contains", [])

        # Resolve process name and parent from whichever field is present.
        if process_chain:
            # Explicit chain definition takes precedence.
            e["process"]["name"]        = process_chain.get("child", "")
            e["parent_process"]["name"] = process_chain.get("parent", "cmd.exe")
        elif proc:
            child_name = proc.get("name", "")
            e["process"]["name"] = child_name
            # No process_chain supplied — synthesise a realistic default parent
            # so the validator's lineage check never fails on a None value.
            # Credential-dump tools are typically launched from a command shell;
            # everything else defaults to explorer.exe (interactive desktop launch).
            child_lower = child_name.lower()
            if child_lower in _CRED_TOOLS or child_lower in _RECON_TOOLS:
                e["parent_process"]["name"] = "cmd.exe"
            elif child_lower == "powershell.exe":
                e["parent_process"]["name"] = "explorer.exe"
            else:
                e["parent_process"]["name"] = "explorer.exe"

        if cmd_contains:
            e["process"]["command_line"] = " ".join(cmd_contains)

    elif eid == 4662:
        e["event_type"] = "directory_object_access"
        obj = phase.get("object", {})
        e["object"]["type"] = obj.get("type", "domainDNS")
        e["object"]["access_mask"] = obj.get("access_mask", "0x100")
        props = obj.get("properties", [])
        e["object"]["properties"] = props if isinstance(props, list) else [props]

    elif eid == 4769:
        e["event_type"] = "kerberos_service_ticket"
        conds = phase.get("conditions", {})
        if "service_contains" in conds:
            e["object"]["name"] = conds["service_contains"]
        if "ticket_encryption_type" in conds:
            e["object"]["access_mask"] = conds["ticket_encryption_type"]

    elif eid == 4625:
        # Logon failure
        e["event_type"] = "logon_failure"
        conds = phase.get("conditions", {})
        e["logon"]["logon_type"] = conds.get("logon_type", 3)
        if "failure_reason" in conds:
            e["object"]["name"] = conds["failure_reason"]

    elif eid == 4648:
        # Explicit credential logon (Pass-the-Hash indicator)
        e["event_type"] = "explicit_credential_logon"
        conds = phase.get("conditions", {})
        if "target_contains" in conds:
            e["network"]["dst_ip"] = conds["target_contains"]
            e["object"]["name"]    = conds["target_contains"]

    elif eid == 4698:
        # Scheduled task created
        e["event_type"] = "scheduled_task_created"
        conds = phase.get("conditions", {})
        if "task_name_contains" in conds:
            e["object"]["name"] = conds["task_name_contains"]
        if "task_action_contains" in conds:
            e["object"]["properties"] = [conds["task_action_contains"]]

    elif eid == 4663:
        # Object access (shadow copies, file access)
        e["event_type"] = "object_access"
        obj = phase.get("object", {})
        e["object"]["type"]        = obj.get("type", "File")
        e["object"]["name"]        = obj.get("name", "")
        e["object"]["access_mask"] = obj.get("access_mask", "0x1")

    elif eid == 7045:
        # Service installed
        e["event_type"] = "service_install"
        conds = phase.get("conditions", {})
        if "service_name_contains" in conds:
            e["object"]["name"] = conds["service_name_contains"]
        if "service_path_contains" in conds:
            e["object"]["properties"] = [conds["service_path_contains"]]

    return e


def _build_syslog_event(ts: str, host_name: str, phase: Dict[str, Any],
                        attack_id: str, is_anchor: bool) -> Dict[str, Any]:
    """Translate a syslog-typed playbook phase into a log event dict."""
    app = phase.get("app", "apache")
    msg = phase.get("message_contains", "")
    e = syslog_event(ts, host_name, app, msg)
    e["metadata"]["attack_id"] = attack_id
    e["metadata"]["phase"] = phase.get("id")
    e["metadata"]["technique"] = phase.get("technique")
    e["metadata"]["noise"] = False
    e["metadata"]["anchor"] = is_anchor
    return e


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def inject_playbook(
    rng,
    pb: Dict[str, Any],
    topo: Dict,
    start,
    end,
    config: Dict,
    excluded_hosts: FrozenSet[str] = frozenset(),
) -> List[Dict]:
    """
    Generate synthetic log events for a single playbook.

    For *malicious* playbooks the phases defined in the YAML are iterated and
    translated into concrete events.  For *benign/suspicious* playbooks the
    same mechanism is used, but ``attack_id`` is left None so ground-truth
    labelling does not flag them as malicious.

    *excluded_hosts* is a set of host names already used by malicious playbooks.
    Benign playbooks will prefer hosts not in this set, ensuring the false-positive
    hosts are distinct from the confirmed-malicious hosts the validator checks for.
    """

    events: List[Dict] = []

    attack_id      = pb.get("playbook_id")
    classification = pb.get("classification", "malicious")
    is_malicious   = classification == "malicious"

    phases  = pb.get("phases", [])
    anchors = {a.get("event_id") for a in pb.get("anchors", [])}

    # Shared correlation fields
    logon_id = hex(rng.randint(0x1000, 0xFFFFF))
    user     = "itadmin" if is_malicious else pb.get("user", "svc_user")

    # Spread phases evenly across the middle portion of the time window so the
    # gap between first and last phase always exceeds the minimum required
    # by the validator (30 s by default, configurable via config).
    min_gap   = config.get("min_time_gap_seconds", 60)
    window    = (end - start).total_seconds()
    spread    = max(min_gap * max(1, len(phases) - 1), window * 0.10)
    t0_offset = (window - spread) / 2
    t0        = start + timedelta(seconds=t0_offset)
    step      = spread / max(1, len(phases) - 1) if len(phases) > 1 else 0

    for i, phase in enumerate(phases):
        ts     = iso_z(t0 + timedelta(seconds=i * step))
        source = phase.get("source", "windows")

        # Pick host: DCs for directory-object phases, linux for syslog phases.
        # For benign playbooks, steer toward hosts not used by attacks so the
        # validator can find genuinely distinct false-positive-like hosts.
        excl = excluded_hosts if not is_malicious else frozenset()
        if source == "syslog":
            host = _pick_host(rng, topo, "linux", excl)
        elif phase.get("event_id") in (4662, 4769):
            host = _pick_host(rng, topo, "dcs", excl)
        else:
            host = _pick_host(rng, topo, "workstations", excl)

        is_anchor = phase.get("event_id") in anchors

        if source == "syslog":
            e = _build_syslog_event(ts, host.name, phase,
                                    attack_id if is_malicious else None,
                                    is_anchor)
        else:
            e = _build_windows_event(ts, host.name, phase,
                                     attack_id if is_malicious else None,
                                     logon_id, user, is_anchor)

        # Benign events: wipe attack_id so they are not labelled malicious
        if not is_malicious:
            e["metadata"]["attack_id"] = None
            e["metadata"]["noise"] = True

        events.append(e)

    return events
