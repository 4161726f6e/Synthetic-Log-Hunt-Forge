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
    the intended investigation sequence: hosts -> event IDs -> timeline ->
    MITRE -> false positives.
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
                    "- Process creation chains (4688) -> Execution techniques (T1059.x)\n"
                    "- AD directory object access (4662) with replication properties "
                    "-> Credential Access (T1003.x)\n"
                    "- Kerberos service tickets (4769) -> Credential Access (T1558.x)\n"
                    "- Remote logon types in 4624 -> Initial Access or Lateral Movement\n"
                    "- Web exploit patterns in syslog -> Initial Access (T1190)\n\n"
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
        +- ctf.toml                          # ctfcli project file (fill in URL + token)
        +- challenges/
        |  +- investigation__identify-malicious-hosts/
        |  |  +- challenge.yml               # ctfcli spec — run: ctf challenge install
        |  |  +- solution.md                 # step-by-step instructor walkthrough
        |  |  `- dist/
        |  |     +- logs.zip                 # all log files bundled for download
        |  |     `- scenario_brief.md        # learner brief (no answers)
        |  +- detection__critical-event-ids/
        |  |  +- challenge.yml
        |  |  +- solution.md
        |  |  `- dist/logs.zip
        |  +- timeline__attack-phases-ordered/
        |  |  +- challenge.yml
        |  |  +- solution.md
        |  |  `- dist/logs.zip
        |  +- threat-intel__mitre-attack-techniques/
        |  |  +- challenge.yml
        |  |  +- solution.md
        |  |  `- dist/logs.zip
        |  `- investigation__false-positives/
        |     +- challenge.yml
        |     +- solution.md
        |     `- dist/logs.zip
        `- instructor/
           +- answer_key.json                # machine-readable answers + flags
           +- full_labels.jsonl              # complete ground-truth labels
           `- solutions_bundle.md            # all five walkthroughs combined

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

    # -- Derive answer data from labels ------------------------------------
    malicious_hosts      = sorted({l["host"] for l in labels if l.get("host")})
    malicious_event_ids  = sorted({str(l["event_id"]) for l in labels if l.get("event_id") is not None})
    techniques           = sorted({l["technique"] for l in labels if l.get("technique")})

    phase_first: Dict[str, str] = {}
    for l in labels:
        ph, ts = l.get("phase"), l.get("timestamp")
        if ph and ts:
            phase_first.setdefault(ph, ts)
    phase_order = [p for p, _ in sorted(phase_first.items(), key=lambda kv: kv[1])]

    # -- Build challenge specs ---------------------------------------------
    fp_hosts = _derive_fp_hosts(events, labels)
    specs = _challenges(malicious_hosts, malicious_event_ids, phase_order, techniques, fp_hosts)

    # -- Build the shared logs.zip (created once, referenced by all challenges) -
    logs_zip_src = _build_logs_zip(out_dir)

    # -- Write per-challenge directories ----------------------------------
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

    # -- ctf.toml — ctfcli project file -----------------------------------
    _write_text(os.path.join(ctfd_dir, "ctf.toml"), _ctf_toml())

    # -- Per-challenge solution walkthroughs -------------------------------
    write_challenge_solutions(
        events=events,
        labels=labels,
        specs=specs,
        challenge_dir=challenge_dir,
        instructor_dir=instructor_dir,
    )

    # -- Instructor answer key ---------------------------------------------
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

    # -- Top-level README --------------------------------------------------
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

solutions_bundle.md
  All five challenge walkthroughs combined into one document.
  Each walkthrough explains the step-by-step pivot chain and reasoning
  needed to derive the correct answer from the log data.
  Individual solution.md files also live alongside each challenge.yml.
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
     CTFd Admin Access Token:  (Admin Panel -> Config -> Access Tokens)
     Continue? [Y/n]:          Y

3. Install each challenge (run from the ctfd/ directory):
     ctf challenge install challenges/investigation__identify-malicious-hosts
     ctf challenge install challenges/detection__critical-event-ids
     ctf challenge install challenges/timeline__attack-phases-ordered
     ctf challenge install challenges/threat-intel__mitre-attack-techniques
     ctf challenge install challenges/investigation__false-positives

   Each should print: Installing <name>... Success!

4. Go to CTFd admin panel -> Challenges and set each to "Visible"
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
instructor/answer_key.json      — exact flags + human-readable answer lists
instructor/full_labels.jsonl    — complete ground-truth labels (do not share)
instructor/solutions_bundle.md  — all five challenge walkthroughs (do not share)

Each challenge directory also contains a solution.md with the step-by-step
pivot chain for that specific challenge.  ctfcli uploads this to CTFd as the
solution field, visible only to admins.
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


# ---------------------------------------------------------------------------
# Solution generation
# ---------------------------------------------------------------------------

def _get(d: "Dict[str, Any]", path: str, default=None):
    """Dot-notation getter — mirrors provability_validator._get."""
    cur: Any = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def _anchor_summary(events: "List[Dict[str, Any]]", labels: "List[Dict[str, Any]]") -> "List[str]":
    """
    Return a list of markdown lines describing each injected anchor event
    (events where metadata.anchor == True).  Used in the hosts and timeline
    solution walkthroughs.
    """
    anchor_events = [
        e for e in events
        if e.get("metadata", {}).get("anchor")
    ]
    if not anchor_events:
        return ["*(no anchor events found in labels)*"]

    lines = []
    for e in sorted(anchor_events, key=lambda x: x.get("timestamp", "")):
        ts    = e.get("timestamp", "?")
        host  = e.get("hostname", "?")
        eid   = e.get("event_id", "?")
        phase = _get(e, "metadata.phase") or "?"
        tech  = _get(e, "metadata.technique") or "?"
        proc  = _get(e, "process.name") or ""
        par   = _get(e, "parent_process.name") or ""
        obj   = _get(e, "object.properties") or ""
        msg   = e.get("message") or ""

        detail_parts = []
        if proc:
            detail_parts.append(f"`{proc}`")
            if par:
                detail_parts.append(f"<- `{par}`")
        if obj and isinstance(obj, list):
            detail_parts.append(f"props: {', '.join(str(p) for p in obj[:2])}")
        if msg and e.get("source") == "syslog":
            detail_parts.append(f"`{msg[:80]}`")

        detail = " | ".join(detail_parts) if detail_parts else ""
        lines.append(
            f"- `{ts}` **{host}** EventID {eid} phase:`{phase}` technique:`{tech}`"
            + (f"\n  {detail}" if detail else "")
        )
    return lines


def _pivot_examples(events: "List[Dict[str, Any]]", labels: "List[Dict[str, Any]]") -> "List[str]":
    """
    Return markdown lines showing concrete logon_id pivot examples drawn
    from the actual generated data.  Finds a 4662 or 4688 injected event
    that has a logon_id, then shows the correlated 4624 on the same host.
    """
    by_logon: "Dict[str, List[Dict]]" = {}
    for e in events:
        lid = _get(e, "logon.logon_id")
        if lid:
            by_logon.setdefault(lid, []).append(e)

    # Find an injected 4662 with a logon_id
    for e in events:
        if (
            e.get("event_id") == 4662
            and _get(e, "metadata.attack_id")
            and _get(e, "logon.logon_id")
        ):
            lid   = _get(e, "logon.logon_id")
            host  = e.get("hostname", "?")
            peers = by_logon.get(lid, [])
            logon = next((p for p in peers if p.get("event_id") == 4624), None)
            lines = [
                "**Pivot example (logon_id):**",
                "",
                f"```",
                f"# Step 1 — Anchor event on {host}",
                f"EventID  : 4662",
                f"timestamp: {e.get('timestamp', '?')}",
                f"logon_id : {lid}",
                f"",
                f"# Step 2 — Find all events sharing that logon_id",
                f"jq 'select(.logon.logon_id == \"{lid}\")' logs/windows/{host}.jsonl",
            ]
            if logon:
                lines += [
                    f"",
                    f"# Step 3 — Correlated 4624 (the logon that opened this session)",
                    f"EventID  : 4624",
                    f"timestamp: {logon.get('timestamp', '?')}",
                    f"user     : {_get(logon, 'user.name', '?')}",
                    f"logon_type: {_get(logon, 'logon.logon_type', '?')}",
                ]
            lines.append("```")
            return lines

    # Fallback — no 4662 found; try 4688
    for e in events:
        if (
            e.get("event_id") == 4688
            and _get(e, "metadata.attack_id")
            and _get(e, "process.name")
            and _get(e, "parent_process.name")
        ):
            host = e.get("hostname", "?")
            return [
                "**Pivot example (process lineage):**",
                "",
                "```",
                f"# Process creation chain on {host}",
                f"EventID      : 4688",
                f"timestamp    : {e.get('timestamp', '?')}",
                f"process      : {_get(e, 'process.name', '?')}",
                f"parent       : {_get(e, 'parent_process.name', '?')}",
                f"command_line : {_get(e, 'process.command_line', '?')}",
                "```",
            ]

    return ["*(no pivot example available for this dataset)*"]


def _technique_rationale(technique: str) -> str:
    """Return a one-line plain-English rationale for a MITRE technique ID."""
    _RATIONALE: "Dict[str, str]" = {
        "T1003.006": "DCSync: EventID 4662 with 'Replicating Directory Changes' properties signals credential extraction via AD replication protocol.",
        "T1059.001": "PowerShell execution: EventID 4688 with powershell.exe launched from a script host (wscript/cscript) indicates attacker-controlled script execution.",
        "T1059.003": "Windows Command Shell: cmd.exe in the process creation chain is the attacker's primary execution vehicle.",
        "T1078":     "Valid Accounts: logon_type 3 (Network) or 10 (RemoteInteractive) with attacker-controlled credentials indicates use of stolen/forged account tokens.",
        "T1548.002": "Bypass UAC: process creation chain where a medium-integrity parent spawns a high-integrity child without a UAC prompt.",
        "T1190":     "Exploit Public-Facing Application: POST /cgi-bin/ in syslog with non-200 response or shell command in URL indicates web exploitation.",
        "T1558.003": "Kerberoasting: EventID 4769 with RC4 encryption type (0x17) for a service account ticket request — the hash is then cracked offline.",
        "T1021.002": "Remote Services (SMB/Windows Admin Shares): lateral movement via network logon (type 3) to ADMIN$ or C$.",
        "T1548":     "Abuse Elevation Control Mechanism: process lineage showing privilege escalation without standard UAC prompt.",
        "T1053.005": "Scheduled Task: EventID 4698 (task creation) with attacker-named task — persistence mechanism.",
        "T1489":     "Service Stop: sc.exe or net stop in process creation chain targeting AV or backup services.",
        "T1490":     "Inhibit System Recovery: vssadmin.exe or wmic shadowcopy delete in EventID 4688 — precedes ransomware encryption.",
        "T1486":     "Data Encrypted for Impact: combination of shadow copy deletion and file-extension-changing process chain.",
        "T1560":     "Archive Collected Data: compact.exe, 7z.exe, or rar.exe in EventID 4688 indicates staging before exfiltration.",
        "T1048":     "Exfiltration Over Alternative Protocol: firewall syslog showing outbound bytes > 10 MB to an external IP.",
        "T1110":     "Brute Force: EventID 4625 cluster from a single source with alternating account names.",
        "T1550.002": "Pass-the-Hash: EventID 4648 (explicit credentials logon) with NTLM from a process context — hash reuse without plaintext password.",
        "T1543.003": "Windows Service: EventID 7045 with attacker-named service binary path — persistence via new service installation.",
        "T1204":     "User Execution: initial execution vector triggered by user (e.g. macro, script) — look at the parent_process chain root.",
    }
    return _RATIONALE.get(technique, f"Review MITRE ATT&CK entry for {technique} and map the observed event fields to that technique's data sources.")


def write_challenge_solutions(
    events: "List[Dict[str, Any]]",
    labels: "List[Dict[str, Any]]",
    specs: "List[Dict[str, Any]]",
    challenge_dir: str,
    instructor_dir: str,
) -> None:
    """
    Generate per-challenge ``solution.md`` files and a combined
    ``instructor/solutions_bundle.md``.

    Each solution explains *how* to derive the answer from the log data —
    the pivot chain, the discriminating evidence, and the reasoning — not
    just what the answer is.

    Output
    ------
    ``ctfd/challenges/<dir>/solution.md``
        Step-by-step walkthrough for that challenge.  Referenced in
        ``challenge.yml`` via the ``solution`` field (ctfcli >= 0.1).

    ``ctfd/instructor/solutions_bundle.md``
        All five walkthroughs concatenated for printing or sharing with
        co-facilitators.  Do not distribute to learners.
    """
    from collections import defaultdict

    # -- Pre-compute shared data structures -------------------------------
    malicious_hosts   = sorted({l["host"] for l in labels if l.get("host")})
    malicious_eids    = sorted({str(l["event_id"]) for l in labels if l.get("event_id") is not None})
    techniques        = sorted({l["technique"] for l in labels if l.get("technique")})

    phase_first: "Dict[str, str]" = {}
    for l in labels:
        ph, ts = l.get("phase"), l.get("timestamp")
        if ph and ts:
            phase_first.setdefault(ph, ts)
    phase_order = [p for p, _ in sorted(phase_first.items(), key=lambda kv: kv[1])]

    anchor_lines  = _anchor_summary(events, labels)
    pivot_lines   = _pivot_examples(events, labels)

    # Per-attack phase breakdown for the timeline solution
    attack_phases: "Dict[str, List[str]]" = defaultdict(list)
    attack_phase_ts: "Dict[str, Dict[str, str]]" = defaultdict(dict)
    for l in labels:
        aid, ph, ts = l.get("attack_id"), l.get("phase"), l.get("timestamp")
        if aid and ph and ts:
            attack_phase_ts[aid].setdefault(ph, ts)
    for aid, pts in attack_phase_ts.items():
        attack_phases[aid] = [p for p, _ in sorted(pts.items(), key=lambda kv: kv[1])]

    # -- Per-challenge solution text ---------------------------------------
    solutions: "Dict[str, str]" = {}

    # --- CH1: Identify Malicious Hosts ---
    ch_hosts_lines = [
        "# Solution: Identify Malicious Hosts",
        "",
        "## Answer",
        "",
        f"`flag{{{','.join(malicious_hosts)}}}`",
        "",
        "---",
        "",
        "## Step-by-step walkthrough",
        "",
        "### Step 1 — Locate anchor events",
        "",
        "Anchor events are the highest-signal indicators in the dataset.",
        "The following injected anchor events are present:",
        "",
    ] + anchor_lines + [
        "",
        "### Step 2 — Pivot from anchor to logon session",
        "",
        "Extract the `logon.logon_id` from each anchor event, then search",
        "for all events sharing that ID to find the correlated logon (EventID 4624).",
        "",
    ] + pivot_lines + [
        "",
        "### Step 3 — Confirm host attribution",
        "",
        "A host is confirmed malicious when:",
        "- It has at least one anchor event, AND",
        "- The full correlation chain (logon_id pivot to 4624) holds up, AND",
        "- The user account context is not a known service account (those are false positives)",
        "",
        "**Confirmed malicious hosts:**",
        "",
    ] + [f"- `{h}`" for h in malicious_hosts] + [
        "",
        "### Step 4 — Eliminate false positives",
        "",
        "Some hosts produce anchor-like events but are NOT malicious.",
        "The distinguishing test: does the *complete* correlation chain exist,",
        "or is it just an isolated suspicious event with a service-account context?",
        "Hosts that fail this test should be excluded from this flag.",
        "",
        "---",
        "",
        "## Flag construction",
        "",
        "Sort the confirmed malicious hostnames alphabetically and wrap in `flag{}`:",
        "",
        f"```",
        f"flag{{{','.join(malicious_hosts)}}}",
        "```",
    ]
    solutions["investigation__identify-malicious-hosts"] = "\n".join(ch_hosts_lines)

    # --- CH2: Critical Event IDs ---
    eid_rationale = {
        "4624": "Logon success — establishes the session (logon_id) that ties all subsequent events to the attacker's authentication context.",
        "4625": "Logon failure — clusters of 4625 from a single source indicate brute force or password spray.",
        "4648": "Explicit-credential logon — used in Pass-the-Hash: the attacker replays an NTLM hash without knowing the plaintext.",
        "4662": "Directory object access — when properties include 'Replicating Directory Changes', this is the DCSync credential-dump signature.",
        "4688": "Process creation — captures execution chains; the `process.name` and `parent_process.name` fields reveal LOLBIN abuse and credential-tool launches.",
        "4698": "Scheduled task created — persistence mechanism; task name in `object.name` identifies attacker-controlled persistence.",
        "4769": "Kerberos service ticket — RC4 encryption type (0x17) is the Kerberoasting indicator; the ticket hash is cracked offline.",
        "7045": "New service installed — attacker-named service in `object.name` indicates persistence via service installation.",
    }
    ch_events_lines = [
        "# Solution: Critical Event IDs",
        "",
        "## Answer",
        "",
        f"`flag{{{','.join(malicious_eids)}}}`",
        "",
        "---",
        "",
        "## Step-by-step walkthrough",
        "",
        "### Step 1 — Identify event IDs present in the attack chain",
        "",
        "Filter the logs to events where `metadata.noise == false`.",
        "These are injected events; their event IDs are the answer set.",
        "",
        "```bash",
        "# For each host in the confirmed malicious set:",
        "jq 'select(.metadata.noise == false) | .event_id' \\",
        "    logs/windows/<HOST>.jsonl | sort -u",
        "```",
        "",
        "### Step 2 — Assess investigative weight",
        "",
        "Not all event IDs are equally significant.  The question asks for those",
        "that *directly evidence* malicious behaviour, or that are necessary anchors",
        "in the correlation chain.  Evaluate each:",
        "",
    ]
    for eid in malicious_eids:
        rationale = eid_rationale.get(eid, f"EventID {eid}: review its role in the injected attack chain on the malicious hosts.")
        ch_events_lines.append(f"- **{eid}** — {rationale}")

    ch_events_lines += [
        "",
        "### Step 3 — Exclude noise-only event IDs",
        "",
        "Event IDs that appear *only* in noise events (where `metadata.noise == true`)",
        "should be excluded.  They are background chatter, not evidence.",
        "",
        "---",
        "",
        "## Flag construction",
        "",
        "Sort the confirmed event IDs numerically and wrap in `flag{}`:",
        "",
        "```",
        f"flag{{{','.join(malicious_eids)}}}",
        "```",
    ]
    solutions["detection__critical-event-ids"] = "\n".join(ch_events_lines)

    # --- CH3: Attack Phases (Timeline) ---
    ch_timeline_lines = [
        "# Solution: Attack Phases (Ordered)",
        "",
        "## Answer",
        "",
        f"`flag{{{','.join(phase_order)}}}`",
        "",
        "---",
        "",
        "## Step-by-step walkthrough",
        "",
        "### Step 1 — Extract phase metadata from anchor events",
        "",
        "Each injected event carries a `metadata.phase` field.  Extract the",
        "distinct phase names and their earliest timestamps:",
        "",
        "```bash",
        "jq 'select(.metadata.noise == false) | {phase: .metadata.phase, ts: .timestamp}' \\",
        "    logs/windows/<HOST>.jsonl | sort",
        "```",
        "",
        "### Step 2 — Sort phases by earliest timestamp",
        "",
        "Group events by `metadata.phase` and record the earliest timestamp per group.",
        "The chronological order of those earliest timestamps gives the phase order.",
        "",
        "**Phase order for this dataset:**",
        "",
    ]
    for i, aid in enumerate(sorted(attack_phases.keys()), 1):
        phases = attack_phases[aid]
        if phases:
            ch_timeline_lines.append(f"**Attack {i}** (`{aid}`):")
            for j, ph in enumerate(phases, 1):
                ts = attack_phase_ts[aid].get(ph, "?")
                ch_timeline_lines.append(f"  {j}. `{ph}` — first seen at `{ts}`")
            ch_timeline_lines.append("")

    ch_timeline_lines += [
        "**Combined phase order (across all attacks):**",
        "",
    ] + [f"{i+1}. `{ph}`" for i, ph in enumerate(phase_order)] + [
        "",
        "### Step 3 — Verify with behavioural grouping",
        "",
        "Cross-check by grouping events behaviourally (what is the attacker *doing*",
        "in each phase?) and confirming the order makes tactical sense:",
        "- Initial access / web exploit phases precede lateral movement",
        "- Credential access precedes use of those credentials for lateral movement",
        "- Persistence and impact phases come last",
        "",
        "---",
        "",
        "## Flag construction",
        "",
        "Phases must be submitted in **chronological order** (not alphabetical):",
        "",
        "```",
        f"flag{{{','.join(phase_order)}}}",
        "```",
    ]
    solutions["timeline__attack-phases-ordered"] = "\n".join(ch_timeline_lines)

    # --- CH4: MITRE ATT&CK Techniques ---
    ch_mitre_lines = [
        "# Solution: MITRE ATT&CK Techniques",
        "",
        "## Answer",
        "",
        f"`flag{{{','.join(techniques)}}}`",
        "",
        "---",
        "",
        "## Step-by-step walkthrough",
        "",
        "### Step 1 — Enumerate injected techniques from labels",
        "",
        "The `metadata.technique` field on each non-noise event records the",
        "MITRE technique mapped at generation time.  Extract the unique set:",
        "",
        "```bash",
        "jq 'select(.metadata.noise == false) | .metadata.technique' \\",
        "    logs/windows/<HOST>.jsonl | sort -u",
        "```",
        "",
        "### Step 2 — Justify each mapping with evidence",
        "",
        "A complete answer requires evidence, not just the technique ID.",
        "For each technique present in this dataset:",
        "",
    ]
    for tech in techniques:
        rationale = _technique_rationale(tech)
        ch_mitre_lines += [
            f"#### `{tech}`",
            "",
            rationale,
            "",
        ]
    ch_mitre_lines += [
        "### Step 3 — Check for sub-technique specificity",
        "",
        "MITRE sub-techniques (e.g. T1059**.001** for PowerShell vs T1059**.003**",
        "for cmd.exe) are preferred when the evidence supports them.  Use the",
        "process name and command-line fields to distinguish.",
        "",
        "---",
        "",
        "## Flag construction",
        "",
        "Sort technique IDs alphabetically and wrap in `flag{}`:",
        "",
        "```",
        f"flag{{{','.join(techniques)}}}",
        "```",
    ]
    solutions["threat-intel__mitre-attack-techniques"] = "\n".join(ch_mitre_lines)

    # --- CH5: False Positives ---
    fp_hosts = _derive_fp_hosts(events, labels)
    fp_flag  = (
        "flag{" + ",".join(sorted(fp_hosts)) + "}" if fp_hosts else "flag{NONE_DETECTED}"
    )

    ch_fp_lines = [
        "# Solution: False Positives",
        "",
        "## Answer",
        "",
        f"`{fp_flag}`",
        "",
        "---",
        "",
        "## Step-by-step walkthrough",
        "",
        "### Step 1 — Find hosts with anchor-like events",
        "",
        "Repeat the anchor search from Challenge 1, but this time collect *all*",
        "hosts that produce anchor-like event patterns — not just confirmed malicious ones.",
        "",
        "```bash",
        "# Look for 4662 with replication properties on ALL hosts:",
        "jq 'select(.event_id == 4662) |",
        "    select(.object.properties[]? | contains(\"Replicating\")) |",
        "    .hostname' logs/windows/*.jsonl | sort -u",
        "",
        "# Look for powershell.exe from script hosts on ALL hosts:",
        "jq 'select(.event_id == 4688) |",
        "    select(.process.name == \"powershell.exe\") |",
        "    select([.parent_process.name] | inside([\"wscript.exe\",\"cscript.exe\"])) |",
        "    .hostname' logs/windows/*.jsonl | sort -u",
        "```",
        "",
        "### Step 2 — Attempt the correlation chain on suspicious-but-benign hosts",
        "",
        "For each host NOT in the confirmed malicious set that produced anchor-like events:",
        "",
        "1. Extract the `logon.logon_id` from the suspicious event",
        "2. Search for a correlated 4624 — does it exist?",
        "3. Check the user account: is it `backup_service`, `helpdesk_svc`,",
        "   or another service account performing scheduled maintenance?",
        "4. Is the full attack phase sequence present, or just this one event?",
        "",
        "**False positive hosts for this dataset:**",
        "",
    ]
    if fp_hosts:
        ch_fp_lines += [f"- `{h}` — anchor-like events present, but correlation chain or account context exonerates it" for h in fp_hosts]
    else:
        ch_fp_lines.append("*(no false-positive hosts detected in this dataset)*")

    ch_fp_lines += [
        "",
        "### Step 3 — Document the exoneration reasoning",
        "",
        "For each false-positive host, the answer should include:",
        "- **What made it suspicious:** the specific event ID and pattern",
        "- **What exonerates it:** broken chain, service-account context,",
        "  or absence of follow-on phases that would indicate real compromise",
        "",
        "---",
        "",
        "## Flag construction",
        "",
        "Sort confirmed false-positive hostnames alphabetically and wrap in `flag{}`:",
        "",
        "```",
        fp_flag,
        "```",
    ]
    solutions["investigation__false-positives"] = "\n".join(ch_fp_lines)

    # -- Write per-challenge solution.md files ----------------------------
    for spec in specs:
        ch_dir  = os.path.join(challenge_dir, spec["dir"])
        sol_key = spec["dir"]
        if sol_key in solutions:
            sol_path = os.path.join(ch_dir, "solution.md")
            _write_text(sol_path, solutions[sol_key])

            # Also reference it in challenge.yml so ctfcli picks it up
            yml_path = os.path.join(ch_dir, "challenge.yml")
            if os.path.exists(yml_path):
                with open(yml_path, "r", encoding="utf-8") as f:
                    doc = yaml.safe_load(f)
                doc["solution"] = "solution.md"
                with open(yml_path, "w", encoding="utf-8") as f:
                    yaml.dump(doc, f, allow_unicode=True,
                               default_flow_style=False, sort_keys=False)

    # -- Combined solutions bundle for the instructor pack -----------------
    separator = "\n\n---\n\n"
    bundle_order = [
        "investigation__identify-malicious-hosts",
        "detection__critical-event-ids",
        "timeline__attack-phases-ordered",
        "threat-intel__mitre-attack-techniques",
        "investigation__false-positives",
    ]
    bundle_parts = ["# SLHF Instructor Solutions Bundle", "",
                    "> Keep private — do not distribute to learners.", ""]
    for key in bundle_order:
        if key in solutions:
            bundle_parts.append(solutions[key])
    bundle_text = separator.join(bundle_parts)

    _write_text(os.path.join(instructor_dir, "solutions_bundle.md"), bundle_text)
    _write_text(os.path.join(instructor_dir, "README.txt"), _instructor_readme())
