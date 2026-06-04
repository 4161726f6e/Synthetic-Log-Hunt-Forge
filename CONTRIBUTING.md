# Contributing to SLHF

Thank you for your interest in contributing. This document covers the development workflow, how to add playbooks, and the standards the codebase follows.

---

## Development setup

```bash
git clone https://github.com/YOUR-ORG/slhf.git
cd slhf
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install pytest
```

Verify everything works:

```bash
pytest tests/test_slhf.py -v
python cli.py --list-playbooks
python cli.py --output ./test-out --seed 42 --attacks 1 --noise low --noise-multiplier 0.25
```

---

## Running the test suite

```bash
pytest tests/test_slhf.py -v
```

Tests cover: flag formatting, playbook schema validation, injector phase handling (all event ID types), provability validator failure codes, CLI argument validation, RNG determinism, and investigation rule derivation. All 49 tests must pass before opening a pull request.

---

## Adding a new attack playbook

1. Create `playbooks/attack/<your_playbook_id>.yaml` following the schema below.
2. Run `python cli.py --list-playbooks` — your playbook should appear.
3. Run `python cli.py --output ./test-out --seed 42 --attacks 9 --anomalies 5 --noise low` — generation should succeed.
4. Check `test-out/analytics/analytics_report.json` — your playbook ID should appear in `dataset_summary.attack_playbooks`.

### Playbook schema

```yaml
playbook_id: unique_snake_case_id   # must be unique across all playbooks
classification: malicious

description: >
  One or two sentences describing the attack scenario and what makes
  the anchor events distinctive.

phases:
  - id: phase_name                  # unique within this playbook
    event_id: 4688                  # Windows Security event ID
    process_chain:                  # for 4688 with explicit parent/child
      parent: parent.exe
      child: child.exe
    command_line_contains:          # optional: substrings in command line
      - "-flag"
    technique: T1059.001            # MITRE ATT&CK technique ID

  - id: another_phase
    source: syslog                  # use this for Linux log events
    app: apache                     # syslog application name
    message_contains: "POST /cgi-bin/"
    technique: T1190

anchors:
  - event_id: 4688
    condition: "brief description of what makes this event distinctive"

correlation:
  - logon_id    # fields that link phases together (logon_id and/or user)
  - user
```

**Supported event IDs and their required fields:**

| Event ID | Event type | Required playbook fields |
|---|---|---|
| 4624 | Logon success | `conditions.logon_type` |
| 4625 | Logon failure | `conditions.failure_reason` |
| 4648 | Explicit credential logon | `conditions.target_contains` |
| 4662 | Directory object access | `object.type`, `object.properties` |
| 4688 | Process creation | `process_chain` or `process.name` |
| 4698 | Scheduled task created | `conditions.task_name_contains`, `conditions.task_action_contains` |
| 4769 | Kerberos service ticket | `conditions.service_contains`, `conditions.ticket_encryption_type` |
| 7045 | Service installed | `conditions.service_name_contains`, `conditions.service_path_contains` |
| syslog | Syslog line | `app`, `message_contains` |

### Anchor design guidelines

A good anchor event is one that:
- Appears on malicious hosts but **not** on benign hosts under normal circumstances
- Is distinctive enough that a learner can identify it without the ground-truth labels
- Maps clearly to a MITRE ATT&CK (sub-)technique

The validator checks that at least one anchor type appears *exclusively* on malicious hosts. If your new attack shares an anchor type with an existing benign decoy, the engine will use a different decoy for that run — this is handled automatically.

---

## Adding a new benign decoy playbook

Benign decoys live in `playbooks/benign/`. Their purpose is to produce events that look identical to a real attack at the event-ID level but are provably benign based on context (user account, command-line verb, service path, etc.).

A good decoy:
1. Uses the **same event IDs** as the attack it mimics
2. Has a **clearly benign user account** (e.g. `backup_svc`, `helpdesk_svc`, `patch_svc`)
3. Has a **plausible benign explanation** that a real analyst would recognise

The engine automatically steers benign playbooks onto hosts that the attacks have not used, so you don't need to worry about host collision.

---

## Code style

- **Python 3.10+** — use `from __future__ import annotations` for type hint compatibility
- **Type annotations** on all public functions
- **No bare `except:`** clauses — always catch a specific exception type
- **No `print()` in library code** except in `regenerator.py` for progress output
- **Determinism** — all randomness must flow through `DeterministicRng.derive(label)`. Never call `random.random()` directly
- Line length is not strictly enforced but keep lines under 100 characters where practical

---

## Validation codes

When writing code that touches the generation pipeline, be aware of the validation codes the `ProvabilityValidator` can raise. Each represents a specific invariant the dataset must satisfy:

| Code | Meaning |
|---|---|
| `GT_HOST_MISSING` | A labelled host has no events in the log output |
| `DCSYNC_NO_4662` | Attack labelled with 4662 but no such event exists |
| `DCSYNC_NO_LOGON_ID` | 4662 event missing `logon.logon_id` pivot field |
| `DCSYNC_NO_4624` | No 4624 event found for the logon_id from a 4662 |
| `PROC_MISSING_LINEAGE` | Malicious 4688 event missing `process.name` or `parent_process.name` |
| `TIMELINE_NO_TS` | Ground-truth label has no parseable timestamp |
| `TIMELINE_TOO_SHORT` | Attack phase span is under 30 seconds |
| `NO_DISCRIMINATOR` | No anchor type appears exclusively on malicious hosts |
| `NO_FALSE_POSITIVES` | No benign host produced an anchor-like event |
| `TOO_MANY_FALSE_POSITIVES` | Too many non-malicious hosts look anchor-like |

---

## Pull request checklist

- [ ] `pytest tests/test_slhf.py -v` — all 49 tests pass
- [ ] `python cli.py --list-playbooks` — new playbooks appear correctly
- [ ] Full generation succeeds: `python cli.py --output ./test-out --seed 42 --attacks 9 --anomalies 5 --noise low`
- [ ] New playbooks have a `description` field and at least one `anchor`
- [ ] New code paths have at least one test in `tests/test_slhf.py`
- [ ] No hardcoded seeds, host names, or attack IDs in validator or engine code
