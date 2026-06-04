# Changelog

All notable changes to SLHF are documented here.

---

## [1.0.0] — Initial release

### Attack playbooks (9 total)
- `windows_dcsync_chain` — Active Directory replication abuse (DCSync)
- `windows_lolbin_chain` — LOLBIN-based execution chain (hh.exe → wscript.exe → powershell.exe)
- `cloud_to_ad` — Web exploit to shell to AD credential tool execution
- `lateral_movement_pth` — Pass-the-Hash lateral movement (4648 + 4624 type 3)
- `persistence_scheduled_task` — Malicious scheduled task creation (4698)
- `ransomware_precursor` — Shadow copy deletion + rogue service install
- `brute_force_spray` — Password spray (4625 × 3) followed by successful logon
- `kerberoasting` — RC4 Kerberos ticket requests across multiple SPNs (4769 etype 0x17)
- `data_exfiltration` — Data staging with robocopy/compact + large outbound syslog transfer

### Benign decoy playbooks (5 total)
- `backup_activity` — AD replication attribute access by backup service (mimics DCSync)
- `admin_powershell` — Admin PowerShell via wscript (mimics LOLBIN chain)
- `helpdesk_remote_logon` — Helpdesk remote logon with explicit credentials (mimics PtH)
- `legitimate_scheduled_task` — Patch management task creation (mimics persistence)
- `backup_shadow_copy` — Backup VSS access and provider install (mimics ransomware precursor)

### CTFd integration
- Five fully auto-graded challenges with `flag{...}` format for all challenges including False Positives
- Prerequisite chain enforced via ctfcli `requirements` field
- `ctf challenge install` / `ctf challenge sync` workflow documented
- Participant and instructor packs separated (`ctfd/challenges/` vs `ctfd/instructor/`)

### Validation and reliability
- Provability validator with 10 distinct failure codes and actionable fix suggestions
- Adaptive retry with seed bumping and config adjustment per failure type
- Persistent learning store (`~/.local/share/slhf/`) for cross-run failure pattern memory
- Anchor-type filtering prevents `NO_DISCRIMINATOR` when benign decoys share anchor types with attacks
- `excluded_hosts` ensures benign events always land on distinct hosts from attacks
- Fallback to overlapping benign pool when all attack anchor types are saturated (`--attacks 9`)

### Performance
- Single dataset generation per successful run (dry-run validated events written directly via `write_outputs_from_cache`)
- Probe injection (~0.1ms per benign playbook) replaces expensive re-generation for anchor-type filtering
- Batched syslog file writes (one file-open per host, not per event)
- Conditional rejection sampling in noise generation (no unconditional double-draw)

### Developer experience
- `--list-playbooks` — print available playbooks without generating
- `--noise-multiplier FLOAT` — fine-grained noise density control
- `--reset-metrics` — clear historical failure data after fixes
- 49-test suite covering all critical paths
- Unexpected exceptions printed immediately with full traceback and written to validation chain
- Cross-platform file locking (`fcntl` on POSIX, `msvcrt` on Windows)
- Windows `PermissionError` on CTFd zip cleanup fixed (atomic rename, no staging directory)
