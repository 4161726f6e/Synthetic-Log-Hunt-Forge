from __future__ import annotations

from typing import Any, Dict, List, Optional

from slhf.investigation_rules import required_steps_for_attack


def validate_investigation_steps(
    submission: Dict[str, Any],
    labels: List[Dict[str, Any]],
    playbooks: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Validate the investigation steps provided in a learner's submission.

    Parameters
    ----------
    submission:
        Must contain ``investigation_steps``: a list of dicts, each
        representing one piece of evidence the learner documented.  Each
        dict may have any combination of:
          ``event_id`` (str), ``logon_id`` (str), ``host`` (str),
          ``process`` (str), ``parent_process`` (str),
          ``process_chain`` (dict/str), ``step`` (str).

    labels:
        Ground-truth labels produced by GroundTruth.build().

    playbooks:
        Loaded playbook dicts.  When provided, investigation steps are
        derived dynamically from playbook structure.  Falls back to the
        static registry when None.

    Returns
    -------
    dict with keys:
        ``steps_valid``   – count of required steps that are satisfied
        ``steps_required``– total required steps across all attacks
        ``details``       – list of per-step result dicts
    """
    results: Dict[str, Any] = {"steps_valid": 0, "steps_required": 0, "details": []}

    # Build a lookup from attack_id → playbook so dynamic derivation works
    pb_by_id: Dict[str, Dict[str, Any]] = {}
    if playbooks:
        for pb in playbooks:
            pid = pb.get("playbook_id")
            if pid:
                pb_by_id[pid] = pb

    attack_ids = sorted({l.get("attack_id") for l in labels if l.get("attack_id")})
    provided: List[Dict[str, Any]] = submission.get("investigation_steps", [])

    # Pre-build lookup sets for O(1) membership tests across all steps
    provided_event_ids = {str(s.get("event_id")) for s in provided if s.get("event_id")}
    provided_has_logon_id = any("logon_id" in s for s in provided)
    provided_has_host = any("host" in s for s in provided)
    provided_processes = {str(s.get("process", "")).lower() for s in provided}
    provided_has_parent = any("parent_process" in s for s in provided)
    provided_has_chain = any("process_chain" in s for s in provided)
    provided_step_names = {str(s.get("step", "")).lower() for s in provided}

    for aid in attack_ids:
        # FIX: pass the playbook so dynamic derivation fires instead of
        # always falling back to the static hardcoded registry.
        pb = pb_by_id.get(aid)
        req = required_steps_for_attack(aid, playbook=pb)
        results["steps_required"] += len(req)

        for step in req:
            ok = _check_step(
                step,
                provided_event_ids=provided_event_ids,
                provided_has_logon_id=provided_has_logon_id,
                provided_has_host=provided_has_host,
                provided_processes=provided_processes,
                provided_has_parent=provided_has_parent,
                provided_has_chain=provided_has_chain,
                provided_step_names=provided_step_names,
            )
            results["steps_valid"] += 1 if ok else 0
            results["details"].append({
                "attack_id": aid,
                "step": step,
                "status": "valid" if ok else "missing",
            })

    return results


# ---------------------------------------------------------------------------
# Per-step satisfaction logic
# ---------------------------------------------------------------------------

def _check_step(
    step: str,
    *,
    provided_event_ids: set,
    provided_has_logon_id: bool,
    provided_has_host: bool,
    provided_processes: set,
    provided_has_parent: bool,
    provided_has_chain: bool,
    provided_step_names: set,
) -> bool:
    """Return True if the submitted evidence satisfies *step*."""
    if step == "identify_4662":
        return "4662" in provided_event_ids
    if step == "find_4624":
        return "4624" in provided_event_ids
    if step == "pivot_logon_id":
        return provided_has_logon_id
    if step == "attribute_source_host":
        return provided_has_host
    if step == "identify_powershell":
        return "powershell.exe" in provided_processes
    if step == "trace_parent_chain":
        return provided_has_parent
    if step == "confirm_lolbin_sequence":
        return provided_has_chain
    if step == "identify_web_exploit":
        return step in provided_step_names or "4688" in provided_event_ids
    if step == "identify_shell":
        return step in provided_step_names
    if step == "link_to_ad_activity":
        return "4662" in provided_event_ids or "4769" in provided_event_ids
    if step == "detect_credential_tool":
        return step in provided_step_names or any(
            t in provided_processes for t in ("mimikatz.exe", "wce.exe", "gsecdump.exe")
        )
    # Generic fallback: look for exact step name in submitted step dicts
    return step.lower() in provided_step_names
