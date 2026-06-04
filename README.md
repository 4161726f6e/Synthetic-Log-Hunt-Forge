# Synthetic Log Hunt Forge (SLHF)

**SLHF** generates realistic synthetic Windows Event Log (JSONL) and Syslog datasets for blue-team training, threat hunting, and detection engineering — packaged as fully autonomous CTFd challenges.

> **Safety**: This project generates **offline synthetic logs only**. No malware, no exploits, no live network callbacks.

---

## What it does

Each run produces:

- **Per-host Windows JSONL logs** — Security channel events with realistic correlation fields (`logon_id`, process lineage, AD object properties)
- **Per-host Syslog** — RFC 5424-style text lines from Linux hosts
- **Ground truth labels** — attack windows, phases, MITRE ATT&CK IDs
- **CTFd challenge export** — five fully auto-graded challenges with correct flags, hints, prerequisite chain, and log file attachments
- **Learner scenario brief** — investigation objectives, pivot technique primer, tactic category hints (no answers)
- **Instructor notes** — complete answer key, anchor events, MITRE mappings
- **Validation chain reports** — per-attempt diagnostic JSON with fix suggestions
- **Analytics report** — selected playbooks, event counts, historical success rates

---

## Quick start

```bash
git clone https://github.com/YOUR-ORG/slhf.git
cd slhf

python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux / macOS:
source .venv/bin/activate

pip install -r requirements.txt

# Generate a dataset with all 9 attack scenarios
python cli.py --output ./out --seed 1337 --attacks 9 --anomalies 5 --days 8 --noise high
```

On success, outputs are written to `./out/`.

---

## Output structure

```
out/
├─ logs/
│  ├─ windows/<HOST>.jsonl       # One file per Windows host
│  └─ syslog/<HOST>.log          # One file per Linux host
├─ ground_truth/
│  └─ labels.jsonl               # Malicious event labels
├─ reports/
│  ├─ scenario_brief.md          # Learner-facing brief (no answers)
│  ├─ instructor_notes.md        # Instructor answer key
│  └─ timeline.md                # Ground-truth phase/anchor timeline
├─ ctfd/
│  ├─ ctf.toml                   # ctfcli reference file
│  ├─ README.txt                 # Setup instructions
│  ├─ logs.zip                   # Shared log archive
│  ├─ challenges/
│  │  ├─ investigation__identify-malicious-hosts/
│  │  │  ├─ challenge.yml
│  │  │  └─ dist/
│  │  │     ├─ logs.zip
│  │  │     └─ scenario_brief.md
│  │  ├─ detection__critical-event-ids/
│  │  ├─ timeline__attack-phases-ordered/
│  │  ├─ threat-intel__mitre-attack-techniques/
│  │  └─ investigation__false-positives/
│  └─ instructor/
│     ├─ answer_key.json
│     └─ full_labels.jsonl
├─ validation_chain/
│  ├─ attempt_001_validation_report.json
│  └─ summary.json
└─ analytics/
   └─ analytics_report.json
```

---

## CLI reference

```
python cli.py [OPTIONS]

Options:
  --output DIR          Output directory (required)
  --seed INT            Random seed (default: 1337)
  --attacks INT         Attack playbooks to inject, min 1 (default: 2)
  --anomalies INT       Benign decoy playbooks to inject, min 0 (default: 3)
  --days INT            Observation window in days, min 1 (default: 3)
  --noise LEVEL         Background noise level: low | medium | high (default: high)
  --noise-multiplier N  Scale factor on top of noise preset (default: 1.0)
                        Use 0.25 for fast test runs, 2.0 for denser noise
  --max-attempts INT    Validation retry limit (default: 10)
  --list-playbooks      Print available playbooks and exit
  --reset-metrics       Clear accumulated run history and exit
```

### Example invocations

```bash
# All 9 attacks, all 5 decoys, 8-day window
python cli.py --output ./out --seed 1337 --attacks 9 --anomalies 5 --days 8

# Quick smoke-test with minimal noise
python cli.py --output ./test-out --seed 42 --attacks 1 --noise low --noise-multiplier 0.25

# List available playbooks
python cli.py --list-playbooks

# Reset historical metrics after fixing bugs
python cli.py --reset-metrics
```

---

## Attack playbooks

| Playbook | Phases | Key event IDs | MITRE |
|---|---|---|---|
| `windows_dcsync_chain` | initial_access → privileged_context → credential_access | 4624, 4662 | T1078, T1003.006 |
| `windows_lolbin_chain` | initial_access → script_execution → payload_execution | 4688 chain | T1204.002, T1059.005, T1059.001 |
| `cloud_to_ad` | web_exploit → shell → ad_activity → credential_tool_execution | syslog + 4769 + 4688 | T1190, T1059, T1558, T1003 |
| `lateral_movement_pth` | initial_compromise → explicit_credential_use → lateral_logon → remote_execution | 4624, 4648, 4688 | T1078, T1550.002, T1569.002 |
| `persistence_scheduled_task` | initial_access → task_creation → payload_execution | 4624, 4698, 4688 | T1078, T1053.005, T1059.001 |
| `ransomware_precursor` | initial_access → shadow_copy_deletion → volume_enumeration → service_install | 4624, 4688, 7045 | T1078, T1490, T1082, T1543.003 |
| `brute_force_spray` | spray_attempt × 3 → successful_logon → discovery | 4625, 4624, 4688 | T1110.003, T1078, T1087.002 |
| `kerberoasting` | initial_access → spn_ticket_request × 3 | 4624, 4769 (etype 0x17) | T1078, T1558.003 |
| `data_exfiltration` | initial_access → data_staging → archive_creation → exfiltration_http | 4624, 4688, syslog | T1078, T1074.001, T1560.001, T1048.002 |

## Benign decoy playbooks

| Playbook | Mimics | Distinguishing factor |
|---|---|---|
| `backup_activity` | DCSync (4662 with replication properties) | `backup_service` account |
| `admin_powershell` | LOLBIN chain (wscript → powershell) | `admin` account, business hours |
| `helpdesk_remote_logon` | Pass-the-Hash (4624 type 3 + 4648) | `helpdesk_svc` account |
| `legitimate_scheduled_task` | Persistence task (4698) | `patch_svc` account, signed binary path |
| `backup_shadow_copy` | Ransomware precursor (vssadmin + 7045) | `backup_svc` account, `list` not `delete` |

---

## CTFd integration

The five generated challenges are fully auto-graded with a prerequisite chain:

```
Identify Malicious Hosts  (200 pts)  ─┬─▶ Critical Event IDs  (150 pts)
                                       │        ▶ Attack Phases  (250 pts)
                                       │              ▶ MITRE ATT&CK  (150 pts)
                                       └─▶ False Positives  (100 pts)
                                                          Total: 850 pts
```

### Setup (one-time per CTFd instance)

```bash
pip install ctfcli
cd out/ctfd
ctf init          # enter your CTFd URL and admin API token when prompted
ctf challenge install challenges/investigation__identify-malicious-hosts
ctf challenge install challenges/detection__critical-event-ids
ctf challenge install challenges/timeline__attack-phases-ordered
ctf challenge install challenges/threat-intel__mitre-attack-techniques
ctf challenge install challenges/investigation__false-positives
```

Then in the CTFd admin panel, set each challenge to **Visible** when ready.

### Regenerating (new seed)

```bash
python cli.py --output ./out --seed 9999 --attacks 9 --anomalies 5 --days 8
cd out/ctfd
ctf challenge sync challenges/*
```

`sync` updates flags and re-uploads log attachments without losing solve history.

---

## Writing new playbooks

Place attack playbooks in `playbooks/attack/*.yaml` and benign decoys in `playbooks/benign/*.yaml`. The schema is validated on load.

**Minimum required fields:**

```yaml
playbook_id: my_new_attack
classification: malicious          # malicious | suspicious
description: "Brief description"

phases:
  - id: phase_name                 # snake_case, unique within playbook
    event_id: 4688                 # Windows event ID, OR use source: syslog
    process_chain:                 # for 4688: explicit parent/child
      parent: cmd.exe
      child: powershell.exe
    command_line_contains:
      - "-enc"
    technique: T1059.001           # MITRE ATT&CK technique ID

anchors:
  - event_id: 4688
    condition: "description of what makes this distinctive"

correlation:
  - logon_id                       # fields used to link phases together
```

**Supported event IDs:** 4624, 4625, 4648, 4662, 4663, 4688, 4698, 4769, 7045, plus `source: syslog` for Linux log phases.

Run `python cli.py --list-playbooks` to verify your new playbook loads correctly before generating a dataset.

---

## Architecture

```
cli.py
└── slhf/regenerator.py          Adaptive retry loop with seed bumping
    └── slhf/engine.py           Dataset orchestration
        ├── slhf/topology.py     Seed-variable network topology
        ├── slhf/playbook_loader.py  YAML loading + schema validation
        ├── slhf/noise.py        Background event generation
        ├── slhf/injector.py     Playbook-driven event injection
        ├── slhf/ground_truth.py Label collection
        ├── slhf/emitters.py     JSONL / syslog file writers
        ├── slhf/ctfd.py         CTFd challenge export
        └── slhf/scenario_brief.py  Learner + instructor documents

slhf/provability_validator.py    Post-generation validation (8 check types)
slhf/adaptive_regenerator.py     Config adjustment on validation failure
slhf/learning/
    ├── learner.py               Failure pattern memory (cross-run persistence)
    ├── metrics.py               Run success/failure metrics
    └── tuner.py                 Pre-run config tuning from history
```

---

## Running tests

```bash
pip install pytest
pytest tests/test_slhf.py -v
```

49 tests covering flag formatting, playbook schema validation, injector phase handling, provability validator failure codes, CLI argument validation, RNG determinism, and investigation rule derivation.

---

## Requirements

- Python 3.10+
- `pyyaml` — playbook loading and CTFd challenge export
- `ctfcli` — for uploading challenges to CTFd (optional, install separately: `pip install ctfcli`)
- `git` — required by ctfcli for `ctf init`

---

## License

MIT
