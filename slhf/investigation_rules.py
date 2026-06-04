from __future__ import annotations

from typing import Any, Dict, List


def required_steps_for_attack(attack_id: str, playbook: Dict[str, Any] | None = None) -> List[str]:
    """
    Return the list of investigation step IDs required to fully solve the
    given attack scenario.

    When a *playbook* dict is provided the steps are derived directly from the
    playbook's phase/event structure so new playbooks work automatically.
    The fallback dict is kept for backwards-compatibility when no playbook is
    available.
    """
    if playbook:
        return _derive_steps(playbook)

    # Fallback: static registry for the three built-in attack playbooks.
    # This is intentionally limited; callers should pass a playbook where
    # possible to support custom scenarios.
    return {
        "windows_dcsync_chain": [
            "identify_4662",
            "pivot_logon_id",
            "find_4624",
            "attribute_source_host",
        ],
        "windows_lolbin_chain": [
            "identify_powershell",
            "trace_parent_chain",
            "confirm_lolbin_sequence",
        ],
        "cloud_to_ad": [
            "identify_web_exploit",
            "identify_shell",
            "link_to_ad_activity",
            "detect_credential_tool",
        ],
    }.get(attack_id, [])


# ---------------------------------------------------------------------------
# Derive steps from playbook metadata
# ---------------------------------------------------------------------------

def _derive_steps(pb: Dict[str, Any]) -> List[str]:
    """Infer required investigation steps from a playbook dict."""
    steps: List[str] = []
    phases = pb.get("phases", [])
    anchors = pb.get("anchors", [])
    correlation = pb.get("correlation", [])

    for phase in phases:
        eid = phase.get("event_id")
        source = phase.get("source", "windows")

        if source == "syslog":
            if "POST /cgi-bin/" in phase.get("message_contains", ""):
                steps.append("identify_web_exploit")
            if "reverse shell" in phase.get("message_contains", ""):
                steps.append("identify_shell")

        elif eid == 4688:
            proc_chain = phase.get("process_chain", {})
            proc = phase.get("process", {})
            proc_name = proc_chain.get("child", "") or (proc.get("name", "") if proc else "")
            parent_name = proc_chain.get("parent", "")

            if "powershell.exe" in proc_name.lower():
                steps.append("identify_powershell")
            if parent_name:
                steps.append("trace_parent_chain")
            if proc_chain:
                steps.append("confirm_lolbin_sequence")
            cred_tools = {"mimikatz.exe", "wce.exe", "gsecdump.exe"}
            if proc_name.lower() in cred_tools:
                steps.append("detect_credential_tool")

        elif eid == 4662:
            steps.append("identify_4662")
            obj = phase.get("object", {})
            props = obj.get("properties", [])
            if any("Replicating Directory Changes" in str(p) for p in props):
                steps.append("link_to_ad_activity")

        elif eid == 4624:
            steps.append("find_4624")

        elif eid == 4769:
            steps.append("link_to_ad_activity")

    # Correlation fields imply additional steps
    if "logon_id" in correlation:
        if "pivot_logon_id" not in steps:
            steps.append("pivot_logon_id")
        if "attribute_source_host" not in steps:
            steps.append("attribute_source_host")

    # Deduplicate while preserving order
    seen: set = set()
    result: List[str] = []
    for s in steps:
        if s not in seen:
            seen.add(s)
            result.append(s)
    return result
