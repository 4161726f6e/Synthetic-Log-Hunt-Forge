from __future__ import annotations

"""
scenario_brief.py
-----------------
Generates two documents alongside every dataset:

``reports/scenario_brief.md``
    The *learner-facing* document.  It provides context, investigation
    prompts, and log-file navigation guidance.  It deliberately contains
    NO answers: no hostnames, no event-ID lists, no phase names.

``reports/instructor_notes.md``
    The *instructor-facing* supplement.  Summarises what was injected,
    lists anchor events and MITRE mappings, and notes any adaptive config
    tweaks that were applied.  Keep this out of learner hands.
"""

import os
from datetime import datetime, timezone
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def write_scenario_documents(
    events: List[Dict[str, Any]],
    labels: List[Dict[str, Any]],
    config: Dict[str, Any],
    out_dir: str,
) -> None:
    """Write scenario_brief.md and instructor_notes.md into <out_dir>/reports/."""
    os.makedirs(os.path.join(out_dir, "reports"), exist_ok=True)

    _write_brief(events, labels, config, out_dir)
    _write_instructor_notes(events, labels, config, out_dir)


# ---------------------------------------------------------------------------
# Learner brief (no answers)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Tactic hint derivation
# ---------------------------------------------------------------------------

# Maps the first four characters of a MITRE technique ID to a plain-English
# tactic category description shown in the learner brief.
# Broad enough to be helpful without revealing specific techniques.
_TACTIC_MAP = {
    "T107": "Defense evasion (covering tracks, disabling protections)",
    "T108": "Defense evasion (masquerading, obfuscation)",
    "T109": "Discovery (network, host, or account enumeration)",
    "T110": "Credential access (brute force or password guessing)",
    "T105": "Persistence (maintaining access across reboots)",
    "T106": "Privilege escalation",
    "T104": "Execution (running attacker-controlled code)",
    "T103": "Credential access (dumping or stealing credentials)",
    "T155": "Credential access (Kerberos ticket abuse)",
    "T154": "Lateral movement (remote service or pass-the-hash)",
    "T156": "Lateral movement (alternate authentication material)",
    "T157": "Lateral movement (remote services)",
    "T105": "Persistence (scheduled tasks, services, or startup items)",
    "T119": "Initial access (exploit public-facing application)",
    "T120": "Initial access (phishing or user execution)",
    "T149": "Impact (data destruction or ransomware staging)",
    "T074": "Collection (data staged for exfiltration)",
    "T048": "Exfiltration (data leaving the network)",
    "T078": "Valid accounts (use of legitimate credentials)",
    "T059": "Execution (scripting or command-line interpreter)",
    "T056": "Credential access (input capture)",
    "T053": "Persistence / scheduled task creation",
    "T058": "Lateral movement (remote execution via services)",
}


def _tactic_hints_from_techniques(techniques: list) -> list:
    """
    Return a deduplicated, sorted list of tactic-category hint strings
    derived from the MITRE technique IDs present in the dataset.
    """
    seen = set()
    hints = []
    for t in techniques:
        # Use first 4 chars of technique ID as lookup key (e.g. "T105" from "T1053.005")
        key = t[:4] if len(t) >= 4 else t
        desc = _TACTIC_MAP.get(key)
        if desc and desc not in seen:
            seen.add(desc)
            hints.append(desc)
    return sorted(hints) if hints else ["(technique categories redacted — discover them yourself)"]


def _write_brief(
    events: List[Dict[str, Any]],
    labels: List[Dict[str, Any]],
    config: Dict[str, Any],
    out_dir: str,
) -> None:
    # Derive statistics without revealing answers
    total_events      = len(events)
    windows_events    = sum(1 for e in events if e.get("channel") == "Security")
    syslog_events     = sum(1 for e in events if e.get("source") == "syslog")
    unique_hosts      = len({e.get("hostname") for e in events if e.get("hostname")})
    windows_hosts     = len({e.get("hostname") for e in events if e.get("channel") == "Security"})
    linux_hosts       = len({e.get("hostname") for e in events if e.get("source") == "syslog"})
    attack_count      = len({l.get("attack_id") for l in labels if l.get("attack_id")})
    days              = config.get("days", "?")
    noise_level       = config.get("noise_level", "?")
    generated_utc     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Unique event IDs present in the dataset (observable fact, not answer)
    observable_eids = sorted({str(e.get("event_id")) for e in events if e.get("event_id")})

    # Derive tactic categories from technique IDs in labels for the brief hint
    techniques_in_data = sorted({l["technique"] for l in labels if l.get("technique")})
    tactic_hints = _tactic_hints_from_techniques(techniques_in_data)

    lines = [
        "# Threat Hunt Scenario Brief",
        "",
        f"*Generated: {generated_utc}*  |  "
        f"Seed: `{config.get('seed', '?')}`  |  "
        f"Noise: {noise_level}  |  "
        f"Window: {days} day(s)",
        "",
        "---",
        "",
        "## Situation",
        "",
        "Your SOC has received an alert indicating potential adversarial activity across",
        "the corporate network.  You have been provided with a snapshot of Windows Security",
        "Event Logs and RFC 5424 Syslog data covering the past observation window.",
        "",
        f"The dataset contains **{total_events:,} events** across **{unique_hosts} hosts**",
        f"({windows_hosts} Windows, {linux_hosts} Linux) over **{days} day(s)**.",
        f"A background of realistic noise ({noise_level} level) has been included to",
        "simulate a production environment.",
        "",
        f"There {'is' if attack_count == 1 else 'are'} **{attack_count}** injected attack",
        f"scenario{'s' if attack_count != 1 else ''} embedded in the data,",
        "along with one or more benign-but-suspicious decoy patterns.",
        "Part of your task is to distinguish real attacks from false positives.",
        "",
        "**Tactic categories observed in this dataset** *(broad hints only — techniques",
        "are yours to discover)*:",
        "",
    ] + [f"- {hint}" for hint in tactic_hints] + [
        "",
        "---",
        "",
        "## Log File Structure",
        "",
        "```",
        "logs/",
        "├─ windows/          # One JSONL file per Windows host",
        "│  └─ <HOST>.jsonl   # Each line is one Security event (JSON)",
        "└─ syslog/           # One text file per Linux host",
        "   └─ <HOST>.log     # RFC 5424 formatted syslog lines",
        "```",
        "",
        "### Key Windows Event IDs present in this dataset",
        "",
        "| Event ID | Meaning |",
        "|----------|---------|",
    ]

    # Describe observable event IDs (these are facts about the data, not answers)
    eid_descriptions = {
        "4624": "Logon success — includes logon_type and logon_id",
        "4662": "Directory object access — Active Directory operations",
        "4688": "Process creation — includes process name, parent, and command line",
        "4769": "Kerberos service ticket request",
        "7045": "New service installed",
    }
    for eid in observable_eids:
        desc = eid_descriptions.get(eid, "Other security event")
        lines.append(f"| {eid} | {desc} |")

    lines += [
        "",
        "### Key JSONL fields for Windows events",
        "",
        "```",
        "timestamp          ISO 8601 UTC",
        "hostname           Source host",
        "event_id           Windows Security Event ID",
        "user.name          Account name",
        "logon.logon_id     Session token — pivot between logon and subsequent events",
        "logon.logon_type   2=Interactive, 3=Network, 10=RemoteInteractive",
        "process.name       New process executable name",
        "parent_process.name  Parent process executable name",
        "object.properties  AD object properties accessed (for event 4662)",
        "```",
        "",
        "### Key fields for syslog events",
        "",
        "```",
        "timestamp   ISO 8601 UTC",
        "hostname    Source host",
        "app         Application (sshd, apache, sudo, ...)",
        "message     Log message text",
        "```",
        "",
        "---",
        "",
        "## Investigation Objectives",
        "",
        "Work through these questions in order.  Document your evidence as you go —",
        "the scoring system rewards showing your work, not just the final answers.",
        "",
        "1. **Host Identification**",
        "   Which hosts show confirmed malicious activity?  What is your evidence?",
        "",
        "2. **Evidence Collection**",
        "   Which Windows Event IDs are most significant to the attack chain?",
        "   Why do they matter — and why are they insufficient in isolation?",
        "",
        "3. **Attack Timeline**",
        "   What are the distinct phases of the attack(s)?  Reconstruct them",
        "   in chronological order, citing specific events as anchors.",
        "",
        "4. **Threat Intelligence**",
        "   Map the observed techniques to MITRE ATT&CK.  Are there sub-technique",
        "   distinctions you can support with evidence?",
        "",
        "5. **False Positive Triage**",
        "   Identify any hosts or events that look suspicious but are benign.",
        "   Explain *why* you ruled them out — what evidence exonerates them?",
        "",
        "6. **Investigation Steps** *(bonus)*",
        "   Document the pivot chain you used: which correlation fields led you",
        "   from the initial indicator to confirmed compromise?",
        "",
        "---",
        "",
        "## Pivot Technique Primer",
        "",
        "If you are unfamiliar with Windows log pivoting, here is the core technique",
        "used in most investigations in this dataset:",
        "",
        "```",
        "  Anchor event (e.g. EventID 4662 — unusual AD object access)",
        "       │",
        "       │  Extract:  logon.logon_id  from this event",
        "       │",
        "       ▼",
        "  Search all events WHERE logon.logon_id == <extracted value>",
        "       │",
        "       │  Find:  EventID 4624 — the logon that created this session",
        "       │         EventID 4688 — processes launched in this session",
        "       │",
        "       ▼",
        "  From EventID 4624:  extract  logon.source_host",
        "                      →  this is the origin host of the activity",
        "```",
        "",
        "Apply the same pattern with `process.name` → `parent_process.name` chains",
        "to reconstruct execution lineage.",
        "",
        "---",
        "",
        "## Submission",
        "",
        "Each investigation objective above corresponds to a challenge in CTFd.",
        "Once you have your answer, format it as a flag and submit it on the challenge page:",
        "",
        "```",
        "flag{value1,value2,...}",
        "```",
        "",
        "Values should be sorted alphabetically — except the **Attack Phases** challenge,",
        "where the order must be chronological.",
        "",
        "The **False Positives** challenge is free-text and manually graded —",
        "write your reasoning directly into the CTFd answer box.",
        "",
        "Good luck.",
        "",
    ]

    fp = os.path.join(out_dir, "reports", "scenario_brief.md")
    with open(fp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ---------------------------------------------------------------------------
# Instructor notes (with answers)
# ---------------------------------------------------------------------------

def _write_instructor_notes(
    events: List[Dict[str, Any]],
    labels: List[Dict[str, Any]],
    config: Dict[str, Any],
    out_dir: str,
) -> None:
    attack_ids = sorted({l.get("attack_id") for l in labels if l.get("attack_id")})

    # Per-attack summary
    attack_summaries: List[str] = []
    for aid in attack_ids:
        al = [l for l in labels if l.get("attack_id") == aid]
        hosts     = sorted({l["host"] for l in al if l.get("host")})
        phases    = []
        phase_ts: Dict[str, str] = {}
        for l in al:
            if l.get("phase") and l.get("timestamp"):
                phase_ts.setdefault(l["phase"], l["timestamp"])
        phases = [p for p, _ in sorted(phase_ts.items(), key=lambda kv: kv[1])]
        techniques = sorted({l["technique"] for l in al if l.get("technique")})
        anchors   = [l for l in al if l.get("anchor")]

        block = [
            f"### Attack: `{aid}`",
            "",
            f"**Hosts involved:** {', '.join(hosts)}",
            f"**Phase order:**    {' → '.join(phases)}",
            f"**MITRE:**          {', '.join(techniques) or '(none tagged)'}",
            "",
            "**Anchor events:**",
        ]
        for a in anchors:
            block.append(
                f"  - `{a['timestamp']}` | `{a['host']}` | "
                f"EventID {a['event_id']} | phase: {a.get('phase')}"
            )
        attack_summaries.append("\n".join(block))

    adaptive_notes: List[str] = []
    for key in ("force_logon_correlation", "spread_attack_over_time",
                "reduce_benign_anchor_overlap", "min_time_gap_seconds",
                "min_false_positive_hosts"):
        if key in config:
            adaptive_notes.append(f"  - `{key}` = `{config[key]}`")

    lines = [
        "# Instructor Notes — KEEP PRIVATE",
        "",
        "> Do not distribute this file to learners.",
        "",
        f"Seed: `{config.get('seed', '?')}`  |  "
        f"Attacks: {len(attack_ids)}  |  "
        f"Noise: {config.get('noise_level', '?')}  |  "
        f"Days: {config.get('days', '?')}",
        "",
        "---",
        "",
        "## Injected Attacks",
        "",
        "\n\n".join(attack_summaries) if attack_summaries else "*(none)*",
        "",
        "---",
        "",
        "## Adaptive Config Applied",
        "",
    ]
    if adaptive_notes:
        lines += adaptive_notes
    else:
        lines.append("  *(no adaptive adjustments were needed)*")

    lines += [
        "",
        "---",
        "",
        "## Scoring Notes",
        "",
        "- **Host classification** is F1-scored — both recall AND precision matter.",
        "  Learners who dump every host score poorly on precision.",
        "- **Timeline** awards partial credit via LCS — getting phases right but",
        "  slightly misordered is better than missing phases entirely.",
        "- **False positives** deduct points for incorrectly flagging a malicious",
        "  host as benign, so learners must justify their FP calls.",
        "- **Investigation steps** are a 20-pt bonus.  Full `baseline_total` is /100.",
        "",
        "Full answer key: `ctfd/instructor/answer_key.json`",
        "Full labels:     `ctfd/instructor/full_labels.jsonl`",
        "",
    ]

    fp = os.path.join(out_dir, "reports", "instructor_notes.md")
    with open(fp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
