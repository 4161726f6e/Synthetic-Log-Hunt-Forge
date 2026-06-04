from __future__ import annotations

import json
import os
import zipfile
from typing import Any, Dict, List, Optional

import yaml


# ---------------------------------------------------------------------------
# Flag formatting
# ---------------------------------------------------------------------------

def _make_flag(values: List[str]) -> str:
    """
    Format a sorted list of values into the canonical submission flag.

    Examples
    --------
    >>> _make_flag(["DC01", "WS-1142"])
    'flag{DC01,WS-1142}'
    >>> _make_flag(["T1003.006", "T1059.001"])
    'flag{T1003.006,T1059.001}'
    """
    return "flag{" + ",".join(sorted(values)) + "}"


# ---------------------------------------------------------------------------
# False-positive host derivation
# ---------------------------------------------------------------------------

def _derive_fp_hosts(
    events: List[Dict[str, Any]],
    labels: List[Dict[str, Any]],
) -> List[str]:
    """
    Return the sorted list of false-positive hosts: hosts that produced at
    least one anchor-tagged event but are NOT in the malicious host set.
    Guaranteed non-empty after a successful validation pass.
    """
    from slhf.provability_validator import _anchor_tag

    malicious_hosts = {l["host"] for l in labels if l.get("host")}
    fp_hosts = {
        e.get("hostname")
        for e in events
        if e.get("hostname")
        and e["hostname"] not in malicious_hosts
        and _anchor_tag(e)
    }
    return sorted(fp_hosts)


# ---------------------------------------------------------------------------
# ctfcli challenge.yml schema
# ---------------------------------------------------------------------------

def _challenge_yml(
    *,
    name: str,
    category: str,
    description: str,
    value: int,
    flag: str,
    hints: List[Dict[str, Any]],
    tags: List[str],
    files: Optional[List[str]] = None,
    flag_case_sensitive: bool = True,
    requirements: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Return a dict that serialises to a valid ctfcli challenge.yml.

    The schema matches ctfcli v0.1 (the version field) which is the format
    accepted by ``ctf challenge install`` and ``ctf challenge sync``.

    *requirements* is a list of challenge *names* (not IDs) that must be
    solved before this challenge becomes visible in CTFd.  This enforces
    the intended investigation sequence: hosts → event IDs → timeline →
    MITRE → false positives.
    """
    doc: Dict[str, Any] = {
        "name":        name,
        "author":      "SLHF",
        "category":    category,
        "description": description,
        "value":       value,
        "type":        "standard",
        "flags": [
            {
                "type":    "static",
                "content": flag,
                "data":    "" if flag_case_sensitive else "case_insensitive",
            }
        ],
        "hints":  hints,
        "files":  files or [],
        "tags":   tags + ["blue-team", "threat-hunting"],
        "state":  "hidden",
        "version": "0.1",
    }
    if requirements:
        doc["requirements"] = requirements
    return doc


# ---------------------------------------------------------------------------
# Per-challenge definitions
# ---------------------------------------------------------------------------

def _challenges(
    malicious_hosts: List[str],
    malicious_event_ids: List[str],
    phase_order: List[str],
    techniques: List[str],
    fp_hosts: List[str],
) -> List[Dict[str, Any]]:
    """
    Return the five challenge specs as dicts containing both the
    ctfcli-compatible ``yml`` field and metadata used by the rest of
    the export (answer key, directory name, etc.).
    """

    flag_hosts    = _make_flag(malicious_hosts)
    flag_events   = _make_flag(malicious_event_ids)
    flag_timeline = _make_flag(phase_order)           # ordered — exact match
    flag_mitre    = _make_flag(techniques)
    flag_fp       = _make_flag(fp_hosts) if fp_hosts else "flag{NONE_DETECTED}"

    return [
        {
            "dir":      "investigation__identify-malicious-hosts",
            "id":       "ch_hosts",
            "flag":     flag_hosts,
            "answers":  malicious_hosts,
            "match":    "flag",
            "yml": _challenge_yml(
                name="Identify Malicious Hosts",
                category="Investigation",
                description=(
                    "Examine the Windows event logs (`logs/windows/*.jsonl`) and "
                    "syslog files (`logs/syslog/*.log`).\n\n"
                    "Identify **all** hostnames that show confirmed malicious activity "
                    "and submit them in alphabetical order using the flag format:\n\n"
                    "```\nflag{HOSTNAME1,HOSTNAME2,...}\n```\n\n"
                    "Example: `flag{DC01,WS-1042}`"
                ),
                value=200,
                flag=flag_hosts,
                hints=[
                    {"content": "Start from anchor events in the logs and pivot outward using correlation fields.", "cost": 25},
                    {"content": "Cross-reference logon_id values between event 4662 and event 4624 to confirm which host initiated the session.", "cost": 50},
                ],
                tags=["investigation", "windows-logs", "host-identification"],
                files=["dist/logs.zip", "dist/scenario_brief.md"],
            ),
        },
        {
            "dir":      "detection__critical-event-ids",
            "id":       "ch_events",
            "flag":     flag_events,
            "answers":  malicious_event_ids,
            "match":    "flag",
            "yml": _challenge_yml(
                name="Critical Event IDs",
                category="Detection",
                requirements=["Identify Malicious Hosts"],
                description=(
                    "Which Windows Security Event IDs provide the strongest "
                    "evidence of compromise in this dataset?\n\n"
                    "**How to approach this:**\n"
                    "1. Open the Windows JSONL logs in `logs/windows/`\n"
                    "2. Identify which event IDs appear in the attack chain "
                    "(not just as background noise)\n"
                    "3. Ask: does this event ID directly evidence malicious "
                    "behaviour, or is it only meaningful when correlated with another?\n\n"
                    "The `event_id` field in each JSONL line tells you the event type. "
                    "The `metadata.noise` field is `false` on injected events if you "
                    "want to verify your findings.\n\n"
                    "Submit event IDs in numerical order using the flag format:\n\n"
                    "```\nflag{EVENTID1,EVENTID2,...}\n```\n\n"
                    "Example: `flag{4624,4662,4688}`"
                ),
                value=150,
                flag=flag_events,
                hints=[
                    {"content": "Focus on credential access and process execution event categories.", "cost": 20},
                    {"content": "Some event IDs only carry investigative weight when correlated with others via a shared logon_id.", "cost": 40},
                ],
                tags=["detection", "windows-events"],
                files=["dist/logs.zip", "dist/scenario_brief.md"],
            ),
        },
        {
            "dir":      "timeline__attack-phases-ordered",
            "id":       "ch_timeline",
            "flag":     flag_timeline,
            "answers":  phase_order,
            "match":    "flag",
            "note":     "Phases must be submitted in correct chronological order.",
            "yml": _challenge_yml(
                name="Attack Phases (Ordered)",
                category="Timeline",
                requirements=["Critical Event IDs"],
                description=(
                    "Reconstruct the attack chain by identifying the distinct phases "
                    "of the intrusion **in chronological order**.\n\n"
                    "**How to approach this:**\n"
                    "1. Start from the anchor events — the most distinctive indicators "
                    "(e.g. a DCSync-like 4662, a LOLBIN execution chain, a web exploit "
                    "in syslog)\n"
                    "2. Work outward using `logon_id` and `parent_process` pivots to "
                    "find the events that preceded each anchor\n"
                    "3. Group related events into named phases based on their behaviour\n"
                    "4. Sort the phases by the earliest timestamp in each group\n\n"
                    "Phase names are snake_case strings found in the `metadata.phase` "
                    "field of each event. The order matters — this flag is "
                    "chronological, not alphabetical.\n\n"
                    "```\nflag{phase_one,phase_two,...}\n```"
                ),
                value=250,
                flag=flag_timeline,
                hints=[
                    {"content": "Group events by behavioural pattern first, then sort the groups by their earliest timestamp.", "cost": 30},
                    {"content": "The pivot fields (logon_id, parent_process) help you establish the boundary between phases.", "cost": 60},
                ],
                tags=["timeline", "attack-chain"],
                files=["dist/logs.zip", "dist/scenario_brief.md"],
            ),
        },
        {
            "dir":      "threat-intel__mitre-attack-techniques",
            "id":       "ch_mitre",
            "flag":     flag_mitre,
            "answers":  techniques,
            "match":    "flag",
            "yml": _challenge_yml(
                name="MITRE ATT&CK Techniques",
                category="Threat Intelligence",
                requirements=["Attack Phases (Ordered)"],
                description=(
                    "Map the observed attacker behaviours to "
                    "[MITRE ATT&CK](https://attack.mitre.org/) technique IDs.\n\n"
                    "**How to approach this:**\n"
                    "1. Identify the attack chain events (those where `metadata.noise` "
                    "is `false` in the JSONL logs)\n"
                    "2. For each event, ask: what is the attacker doing? "
                    "Executing code? Accessing credentials? Moving laterally?\n"
                    "3. Map each behaviour to the most specific ATT&CK (sub-)technique "
                    "you can support with evidence\n\n"
                    "**Key mappings to consider:**\n"
                    "- Process creation chains (4688) → Execution techniques (T1059.x)\n"
                    "- AD directory object access (4662) with replication properties "
                    "→ Credential Access (T1003.x)\n"
                    "- Kerberos service tickets (4769) → Credential Access (T1558.x)\n"
                    "- Remote logon types in 4624 → Initial Access or Lateral Movement\n"
                    "- Web exploit patterns in syslog → Initial Access (T1190)\n\n"
                    "Submit technique IDs in alphabetical order:\n\n"
                    "```\nflag{T1003.006,T1059.001,...}\n```"
                ),
                value=150,
                flag=flag_mitre,
                hints=[
                    {"content": "Consider both the execution and credential-access tactic categories.", "cost": 25},
                    {"content": "Look at the process names and AD object properties — each maps to a distinct (sub-)technique.", "cost": 50},
                ],
                tags=["mitre", "threat-intel"],
                files=["dist/logs.zip", "dist/scenario_brief.md"],
            ),
        },
        {
            "dir":      "investigation__false-positives",
            "id":       "ch_fp",
            "flag":     flag_fp,
            "answers":  fp_hosts,
            "match":    "flag",
            "note":     (
                "Auto-graded. Flag is flag{HOST1,HOST2,...} — the sorted list of "
                "hosts that produced anchor-like events but are NOT in the malicious "
                "set. Derived from the event stream at generation time."
            ),
            "yml": _challenge_yml(
                name="False Positives",
                category="Investigation",
                requirements=["Identify Malicious Hosts"],
                description=(
                    "Not every suspicious-looking event is malicious. "
                    "Part of threat hunting is knowing when to stand down.\n\n"
                    "**How to approach this:**\n"
                    "1. Find hosts that produce the same *type* of events as the "
                    "confirmed malicious hosts (same event IDs, similar process names, "
                    "similar AD object access)\n"
                    "2. Attempt to build the same correlation chain you used for the "
                    "real attacks — does it hold up?\n"
                    "3. Look at the **user account** context. A `backup_service` "
                    "account accessing AD replication attributes is expected behaviour. "
                    "An `itadmin` account doing the same at 3 AM is not.\n"
                    "4. Check whether the full attack sequence is present, or just "
                    "a single suspicious-looking event in isolation\n\n"
                    "For each host you identify, explain:\n"
                    "- What made it look suspicious\n"
                    "- What specific evidence exonerates it\n\n"
                    "Submit all false-positive hostnames in alphabetical order:\\n\\n"
                    "```\\nflag{HOSTNAME1,HOSTNAME2,...}\\n```"
                ),
                value=100,
                flag=flag_fp,
                hints=[
                    {"content": "Look for hosts that share the same suspicious event IDs as the confirmed attacks but lack the full correlation chain (logon_id pivot, process lineage).", "cost": 30},
                    {"content": "The user account context is the key distinguishing factor. A backup_service or helpdesk_svc account doing something suspicious is almost always benign.", "cost": 50},
                ],
                tags=["investigation", "false-positives", "triage"],
                files=["dist/logs.zip", "dist/scenario_brief.md"],
            ),
        },
    ]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_ctfd_export(
    events: List[Dict[str, Any]],
    labels: List[Dict[str, Any]],
    out_dir: str,
) -> None:
    """
    Write a ctfcli-importable challenge tree under ``<out_dir>/ctfd/``.

    Output layout
    -------------
    ::

        ctfd/
        ├─ ctf.toml                          # ctfcli project file (fill in URL + token)
        ├─ challenges/
        │  ├─ investigation__identify-malicious-hosts/
        │  │  ├─ challenge.yml               # ctfcli spec — run: ctf challenge install
        │  │  └─ dist/
        │  │     ├─ logs.zip                 # all log files bundled for download
        │  │     └─ scenario_brief.md        # learner brief (no answers)
        │  ├─ detection__critical-event-ids/
        │  │  ├─ challenge.yml
        │  │  └─ dist/logs.zip
        │  ├─ timeline__attack-phases-ordered/
        │  │  ├─ challenge.yml
        │  │  └─ dist/logs.zip
        │  ├─ threat-intel__mitre-attack-techniques/
        │  │  ├─ challenge.yml
        │  │  └─ dist/logs.zip
        │  └─ investigation__false-positives/
        │     ├─ challenge.yml
        │     └─ dist/logs.zip
        └─ instructor/
           ├─ answer_key.json                # machine-readable answers + flags
           └─ full_labels.jsonl              # complete ground-truth labels

    Import workflow (one-time setup per CTFd instance)
    ---------------------------------------------------
    1. ``pip install ctfcli``
    2. Edit ``ctfd/ctf.toml`` — fill in ``url`` and ``access_token``
    3. ``cd ctfd && ctf challenge install challenges/*``
       or sync individual challenges: ``ctf challenge sync <dir>``

    Flag format
    -----------
    All auto-gradeable flags use ``flag{value1,value2,...}`` with values
    sorted alphabetically/numerically.  The False Positives challenge uses
    a placeholder flag and must be graded manually in the CTFd admin panel.
    """
    ctfd_dir      = os.path.join(out_dir, "ctfd")
    challenge_dir = os.path.join(ctfd_dir, "challenges")
    instructor_dir = os.path.join(ctfd_dir, "instructor")
    os.makedirs(challenge_dir, exist_ok=True)
    os.makedirs(instructor_dir, exist_ok=True)

    # ── Derive answer data from labels ────────────────────────────────────
    malicious_hosts      = sorted({l["host"] for l in labels if l.get("host")})
    malicious_event_ids  = sorted({str(l["event_id"]) for l in labels if l.get("event_id") is not None})
    techniques           = sorted({l["technique"] for l in labels if l.get("technique")})

    phase_first: Dict[str, str] = {}
    for l in labels:
        ph, ts = l.get("phase"), l.get("timestamp")
        if ph and ts:
            phase_first.setdefault(ph, ts)
    phase_order = [p for p, _ in sorted(phase_first.items(), key=lambda kv: kv[1])]

    # ── Build challenge specs ─────────────────────────────────────────────
    fp_hosts = _derive_fp_hosts(events, labels)
    specs = _challenges(malicious_hosts, malicious_event_ids, phase_order, techniques, fp_hosts)

    # ── Build the shared logs.zip (created once, referenced by all challenges) ─
    logs_zip_src = _build_logs_zip(out_dir)

    # ── Write per-challenge directories ──────────────────────────────────
    for spec in specs:
        ch_dir   = os.path.join(challenge_dir, spec["dir"])
        dist_dir = os.path.join(ch_dir, "dist")
        os.makedirs(dist_dir, exist_ok=True)

        # challenge.yml
        yml_path = os.path.join(ch_dir, "challenge.yml")
        with open(yml_path, "w", encoding="utf-8") as f:
            yaml.dump(spec["yml"], f, allow_unicode=True,
                      default_flow_style=False, sort_keys=False)

        # Copy logs.zip into dist/ for this challenge
        if logs_zip_src and os.path.exists(logs_zip_src):
            _copy_file(logs_zip_src, os.path.join(dist_dir, "logs.zip"))

        # Copy scenario_brief.md into every challenge so learners always
        # have the investigation primer regardless of which challenge they open.
        brief_src = os.path.join(out_dir, "reports", "scenario_brief.md")
        if os.path.exists(brief_src):
            _copy_file(brief_src, os.path.join(dist_dir, "scenario_brief.md"))

    # ── ctf.toml — ctfcli project file ───────────────────────────────────
    _write_text(os.path.join(ctfd_dir, "ctf.toml"), _ctf_toml())

    # ── Instructor answer key ─────────────────────────────────────────────
    answer_key = [
        {
            "challenge_id": s["id"],
            "challenge_name": s["yml"]["name"],
            "flag": s["flag"],
            "answers": s["answers"],
            "match": s["match"],
            **({ "note": s["note"] } if s.get("note") else {}),
        }
        for s in specs
    ]
    _write_json(os.path.join(instructor_dir, "answer_key.json"), answer_key)
    _write_json(os.path.join(instructor_dir, "full_labels.jsonl"), labels, jsonl=True)
    _write_text(os.path.join(instructor_dir, "README.txt"), _instructor_readme())

    # ── Top-level README ──────────────────────────────────────────────────
    _write_text(os.path.join(ctfd_dir, "README.txt"), _ctfd_readme())


# ---------------------------------------------------------------------------
# Log archive builder
# ---------------------------------------------------------------------------

def _build_logs_zip(out_dir: str) -> Optional[str]:
    """
    Bundle all log files into a single zip suitable for CTFd file attachment.

    Preserves the ``logs/windows/`` and ``logs/syslog/`` structure inside
    the archive so learners can extract and navigate them naturally.

    The zip is written directly to a temporary file and then moved into place,
    avoiding a separate staging directory that needs cleanup and avoids
    Windows file-locking issues with shutil.rmtree on the staging folder.

    Returns the path to the zip, or None if no log files exist yet.
    """
    import tempfile

    logs_root = os.path.join(out_dir, "logs")
    if not os.path.isdir(logs_root):
        return None

    # Final destination: ctfd/logs.zip (no intermediate _logs_dist dir needed)
    final_zip = os.path.join(out_dir, "ctfd", "logs.zip")
    os.makedirs(os.path.dirname(final_zip), exist_ok=True)

    # Write to a sibling temp file then atomically rename so a crash during
    # zip creation never leaves a partial file at the final path.
    tmp_fd, tmp_path = tempfile.mkstemp(
        suffix=".zip.tmp", dir=os.path.dirname(final_zip)
    )
    try:
        os.close(tmp_fd)
        with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for root, _dirs, files in os.walk(logs_root):
                for fname in sorted(files):
                    abs_path = os.path.join(root, fname)
                    arc_name = os.path.relpath(abs_path, out_dir)
                    zf.write(abs_path, arc_name)
        # Replace final destination (works cross-platform including Windows)
        if os.path.exists(final_zip):
            os.remove(final_zip)
        os.rename(tmp_path, final_zip)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise

    return final_zip


# ---------------------------------------------------------------------------
# Template text
# ---------------------------------------------------------------------------

def _ctf_toml() -> str:
    return """\
# SLHF CTFd export — reference notes
# ====================================
# NOTE: ctfcli does NOT read this file.
# ctfcli stores its config in .ctf/config, created when you run:
#
#   ctf init
#
# This file is a reminder of the values you entered during init.
# See README.txt in this directory for the full setup workflow.

[ctf]
url   = "https://YOUR-CTFD-INSTANCE.example.com"   # set during: ctf init
token = "YOUR-ADMIN-API-TOKEN"                      # set during: ctf init
"""


def _instructor_readme() -> str:
    return """\
INSTRUCTOR PACK — KEEP PRIVATE
================================

answer_key.json
  Machine-readable answer key.  Each entry contains:
    challenge_id    Internal identifier
    challenge_name  Display name as shown in CTFd
    flag            The exact flag string CTFd checks against
    answers         Human-readable list of correct values
    match           "flag" (auto) or "manual" (instructor grades)

  The False Positives challenge is now auto-graded (match="flag").
  Flag is flag{HOST1,HOST2,...} — sorted list of hosts that produced
  anchor-like events but are not in the malicious set.
  Derived from the event stream at generation time; no manual review needed.

full_labels.jsonl
  Complete ground-truth labels including anchor flags,
  MITRE technique IDs, phase boundaries, and exact timestamps.
  Do not distribute to learners.

Do NOT share this directory with participants.
"""


def _ctfd_readme() -> str:
    return """\
CTFD EXPORT — SETUP INSTRUCTIONS
==================================

IMPORTANT: ctfcli requires an initialised project before install works.
Without running "ctf init" first, ctf challenge install hangs silently.

Prerequisites
-------------
  pip install ctfcli

One-time setup (run once per CTFd instance)
--------------------------------------------
1. Open a terminal and cd into this directory:
     cd path/to/your/output/ctfd

2. Initialise the ctfcli project. This creates .ctf/config with your
   CTFd URL and admin token — it will prompt you interactively:
     ctf init

   When prompted:
     CTFd instance URL:        https://your-ctfd-instance.example.com
     CTFd Admin Access Token:  (Admin Panel → Config → Access Tokens)
     Continue? [Y/n]:          Y

3. Install each challenge (run from the ctfd/ directory):
     ctf challenge install challenges/investigation__identify-malicious-hosts
     ctf challenge install challenges/detection__critical-event-ids
     ctf challenge install challenges/timeline__attack-phases-ordered
     ctf challenge install challenges/threat-intel__mitre-attack-techniques
     ctf challenge install challenges/investigation__false-positives

   Each should print: Installing <name>... Success!

4. Go to CTFd admin panel → Challenges and set each to "Visible"
   when you are ready for learners to see them.
   (They install as Hidden by default.)

Re-generating the dataset (new seed)
--------------------------------------
After running SLHF again with a new seed, sync the updated flags and files:
  ctf challenge sync challenges/investigation__identify-malicious-hosts
  ctf challenge sync challenges/detection__critical-event-ids
  ctf challenge sync challenges/timeline__attack-phases-ordered
  ctf challenge sync challenges/threat-intel__mitre-attack-techniques
  ctf challenge sync challenges/investigation__false-positives

sync updates flags and re-uploads attachments without wiping solve history.

Flag format
-----------
All auto-graded flags use:   flag{value1,value2,...}
Values are sorted so submission order does not matter — EXCEPT the
attack-phase (timeline) challenge, where chronological order IS the answer.

All five challenges are now fully auto-graded.
The False Positives flag is flag{HOST1,HOST2,...} — the sorted list of
hostnames that look suspicious but are provably benign.

Files
-----
Each challenge's dist/logs.zip contains the complete log dataset.
All five challenges reference the same zip so learners download it once.

Instructor materials
--------------------
instructor/answer_key.json   — exact flags + human-readable answer lists
instructor/full_labels.jsonl — complete ground-truth labels (do not share)
"""


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _write_json(path: str, data: Any, jsonl: bool = False) -> None:
    with open(path, "w", encoding="utf-8") as f:
        if jsonl and isinstance(data, list):
            for item in data:
                f.write(json.dumps(item) + "\n")
        else:
            json.dump(data, f, indent=2)


def _write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _copy_file(src: str, dst: str) -> None:
    import shutil
    shutil.copy2(src, dst)
