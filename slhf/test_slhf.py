"""
SLHF test suite
===============
Run with:  pytest tests/test_slhf.py -v
"""
from __future__ import annotations

import json
import os
import random
import sys
import tempfile
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup — allow imports from the project root
# ---------------------------------------------------------------------------
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Minimal stubs so modules that import slhf.* can be loaded in isolation
# ---------------------------------------------------------------------------

def _stub_slhf_modules():
    """Ensure slhf.events and slhf.timing are loaded from the real source files."""
    import importlib.util as _ilu

    def _load(mod_name, rel_path):
        if mod_name in sys.modules:
            return sys.modules[mod_name]
        spec = _ilu.spec_from_file_location(mod_name, str(ROOT / rel_path))
        mod  = _ilu.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)
        return mod

    # Ensure parent package exists
    if "slhf" not in sys.modules:
        sys.modules["slhf"] = types.ModuleType("slhf")

    _load("slhf.events", "slhf/events.py")
    _load("slhf.timing", "slhf/timing.py")


# ===========================================================================
# 1. Flag formatting
# ===========================================================================

class TestMakeFlag:
    def setup_method(self):
        from slhf.ctfd import _make_flag
        self._make_flag = _make_flag

    def test_sorts_alphabetically(self):
        assert self._make_flag(["WS-1042", "DC01"]) == "flag{DC01,WS-1042}"

    def test_single_value(self):
        assert self._make_flag(["DC01"]) == "flag{DC01}"

    def test_already_sorted(self):
        assert self._make_flag(["DC01", "WS-1042"]) == "flag{DC01,WS-1042}"

    def test_numeric_strings_sort_lexically(self):
        # Event IDs are strings; lexical sort is expected
        assert self._make_flag(["4688", "4624", "4662"]) == "flag{4624,4662,4688}"

    def test_mitre_ids(self):
        assert self._make_flag(["T1059.001", "T1003.006"]) == "flag{T1003.006,T1059.001}"


# ===========================================================================
# 2. Playbook loader — schema validation
# ===========================================================================

class TestPlaybookLoader:
    def _write_yaml(self, tmp_path: Path, subdir: str, name: str, content: dict) -> Path:
        d = tmp_path / subdir
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{name}.yaml"
        p.write_text(yaml.dump(content))
        return p

    def test_valid_attack_playbook_loads(self, tmp_path):
        from slhf.playbook_loader import load_playbooks
        self._write_yaml(tmp_path, "attack", "test", {
            "playbook_id": "test_attack",
            "classification": "malicious",
            "phases": [{"id": "step1", "event_id": 4688}],
        })
        attacks, benign = load_playbooks(str(tmp_path))
        assert len(attacks) == 1
        assert attacks[0]["playbook_id"] == "test_attack"

    def test_valid_benign_playbook_loads(self, tmp_path):
        from slhf.playbook_loader import load_playbooks
        self._write_yaml(tmp_path, "benign", "test", {
            "playbook_id": "test_benign",
            "classification": "suspicious",
            "phases": [{"id": "step1", "event_id": 4662}],
        })
        attacks, benign = load_playbooks(str(tmp_path))
        assert len(benign) == 1

    def test_missing_required_field_raises(self, tmp_path):
        from slhf.playbook_loader import load_playbooks, PlaybookValidationError
        self._write_yaml(tmp_path, "attack", "bad", {
            "playbook_id": "bad",
            # missing classification and phases
        })
        with pytest.raises(PlaybookValidationError, match="Missing required fields"):
            load_playbooks(str(tmp_path))

    def test_invalid_classification_raises(self, tmp_path):
        from slhf.playbook_loader import load_playbooks, PlaybookValidationError
        self._write_yaml(tmp_path, "attack", "bad", {
            "playbook_id": "bad",
            "classification": "unknown_type",
            "phases": [{"id": "s1", "event_id": 4688}],
        })
        with pytest.raises(PlaybookValidationError, match="Invalid classification"):
            load_playbooks(str(tmp_path))

    def test_empty_phases_raises(self, tmp_path):
        from slhf.playbook_loader import load_playbooks, PlaybookValidationError
        self._write_yaml(tmp_path, "attack", "bad", {
            "playbook_id": "bad",
            "classification": "malicious",
            "phases": [],
        })
        with pytest.raises(PlaybookValidationError, match="non-empty list"):
            load_playbooks(str(tmp_path))

    def test_phase_missing_id_raises(self, tmp_path):
        from slhf.playbook_loader import load_playbooks, PlaybookValidationError
        self._write_yaml(tmp_path, "attack", "bad", {
            "playbook_id": "bad",
            "classification": "malicious",
            "phases": [{"event_id": 4688}],   # missing id
        })
        with pytest.raises(PlaybookValidationError, match="missing required 'id'"):
            load_playbooks(str(tmp_path))

    def test_malformed_yaml_raises(self, tmp_path):
        from slhf.playbook_loader import load_playbooks, PlaybookValidationError
        p = tmp_path / "attack" / "bad.yaml"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("key: [unclosed bracket")
        with pytest.raises(PlaybookValidationError, match="YAML parse error"):
            load_playbooks(str(tmp_path))

    def test_missing_directory_returns_empty(self, tmp_path):
        from slhf.playbook_loader import load_playbooks
        attacks, benign = load_playbooks(str(tmp_path))
        assert attacks == []
        assert benign == []


# ===========================================================================
# 3. Injector — all phase types produce correct event fields
# ===========================================================================

class TestInjector:
    def setup_method(self):
        _stub_slhf_modules()
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "slhf.injector", str(ROOT / "slhf" / "injector.py")
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["slhf.injector"] = mod
        spec.loader.exec_module(mod)
        self.injector = mod

    def _topo(self):
        class H:
            def __init__(self, n): self.name = n
        return {
            "all": [H("DC01"), H("WS-1")], "windows": [H("WS-1")],
            "linux": [H("LX01")], "dcs": [H("DC01")],
            "workstations": [H("WS-1")], "servers": [],
        }

    def _run(self, phases, anchors=None, classification="malicious"):
        pb = {
            "playbook_id": "test", "classification": classification,
            "phases": phases, "anchors": anchors or [], "correlation": [],
        }
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end   = datetime(2026, 1, 9, tzinfo=timezone.utc)
        return self.injector.inject_playbook(
            random.Random(42), pb, self._topo(), start, end,
            {"min_time_gap_seconds": 60}
        )

    def test_4624_sets_logon_type(self):
        evts = self._run([{"id": "s1", "event_id": 4624, "conditions": {"logon_type": 10}}])
        assert evts[0]["logon"]["logon_type"] == 10

    def test_4688_process_chain_sets_parent(self):
        evts = self._run([{
            "id": "s1", "event_id": 4688,
            "process_chain": {"parent": "wscript.exe", "child": "powershell.exe"},
        }])
        assert evts[0]["process"]["name"] == "powershell.exe"
        assert evts[0]["parent_process"]["name"] == "wscript.exe"

    def test_4688_process_only_gets_default_parent(self):
        """process-only phase must never produce None parent (regression test)."""
        evts = self._run([{"id": "s1", "event_id": 4688, "process": {"name": "mimikatz.exe"}}])
        assert evts[0]["process"]["name"] == "mimikatz.exe"
        assert evts[0]["parent_process"]["name"] is not None
        assert evts[0]["parent_process"]["name"] != ""

    def test_cred_tool_gets_cmd_parent(self):
        evts = self._run([{"id": "s1", "event_id": 4688, "process": {"name": "mimikatz.exe"}}])
        assert evts[0]["parent_process"]["name"] == "cmd.exe"

    def test_4662_sets_properties(self):
        evts = self._run([{
            "id": "s1", "event_id": 4662,
            "object": {"type": "domainDNS", "properties": ["Replicating Directory Changes All"]},
        }])
        assert "Replicating Directory Changes All" in evts[0]["object"]["properties"]

    def test_syslog_phase_produces_syslog_event(self):
        evts = self._run([{
            "id": "s1", "source": "syslog", "app": "apache",
            "message_contains": "POST /cgi-bin/",
        }])
        assert evts[0]["source"] == "syslog"
        assert "POST /cgi-bin/" in evts[0]["message"]

    def test_benign_phase_has_no_attack_id(self):
        evts = self._run(
            [{"id": "s1", "event_id": 4688, "process": {"name": "powershell.exe"}}],
            classification="suspicious",
        )
        assert evts[0]["metadata"]["attack_id"] is None

    def test_excluded_hosts_steers_benign_away(self):
        """Benign playbooks must prefer hosts not used by attacks."""
        class H:
            def __init__(self, n): self.name = n
        # Two workstations; exclude the first
        topo = {
            "all": [H("DC01"), H("WS-ATK"), H("WS-SAFE")],
            "windows": [H("WS-ATK"), H("WS-SAFE")],
            "linux": [], "dcs": [H("DC01")],
            "workstations": [H("WS-ATK"), H("WS-SAFE")],
            "servers": [],
        }
        pb = {
            "playbook_id": "benign_test", "classification": "suspicious",
            "phases": [{"id": "s1", "event_id": 4688,
                        "process_chain": {"parent": "wscript.exe", "child": "powershell.exe"}}],
            "anchors": [], "correlation": [],
        }
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end   = datetime(2026, 1, 9, tzinfo=timezone.utc)
        # Run 20 times; WS-ATK should never be chosen when excluded
        for seed in range(20):
            evts = self.injector.inject_playbook(
                random.Random(seed), pb, topo, start, end,
                {"min_time_gap_seconds": 60},
                excluded_hosts=frozenset({"WS-ATK"}),
            )
            for e in evts:
                assert e["hostname"] != "WS-ATK", f"seed={seed}: benign landed on excluded host"

    def test_phase_timestamps_are_spread(self):
        """Multi-phase attacks must span at least 30 seconds."""
        evts = self._run([
            {"id": "s1", "event_id": 4624, "conditions": {}},
            {"id": "s2", "event_id": 4688, "process_chain": {"parent": "cmd.exe", "child": "net.exe"}},
            {"id": "s3", "event_id": 4662, "object": {"type": "domainDNS", "properties": []}},
        ])
        from slhf.timing import iso_z
        from datetime import datetime, timezone
        def pts(e):
            ts = e["timestamp"]
            if ts.endswith("Z"):
                ts = ts[:-1] + "+00:00"
            return datetime.fromisoformat(ts)
        spread = (pts(evts[-1]) - pts(evts[0])).total_seconds()
        assert spread >= 30, f"spread was only {spread:.1f}s"


# ===========================================================================
# 4. Provability validator — each failure code fires correctly
# ===========================================================================

class TestProvabilityValidator:
    def setup_method(self):
        from slhf.diagnostic_report import ValidationIssue
        sys.modules["slhf.diagnostic_report"].ValidationIssue = ValidationIssue
        from slhf.provability_validator import ProvabilityValidator, ValidationFailed
        self.PV = ProvabilityValidator
        self.VF = ValidationFailed

    def _base_event(self, ts="2026-01-01T10:00:00Z", host="DC01",
                    eid=4662, attack_id="test", logon_id="0x1234",
                    props=None):
        """Return a minimal 4662 event that satisfies all checks."""
        return {
            "timestamp": ts, "hostname": host, "channel": "Security",
            "event_id": eid,
            "logon": {"logon_id": logon_id},
            "process": {"name": "lsass.exe"},
            "parent_process": {"name": "wscript.exe"},
            "object": {"properties": props or ["Replicating Directory Changes All"]},
            "source": None,
            "message": None,
            "metadata": {"attack_id": attack_id, "noise": False},
        }

    def _base_4624(self, logon_id="0x1234", host="WS-1"):
        return {
            "timestamp": "2026-01-01T09:00:00Z", "hostname": host,
            "channel": "Security", "event_id": 4624,
            "logon": {"logon_id": logon_id},
            "process": {"name": None}, "parent_process": {"name": None},
            "object": {"properties": []}, "source": None, "message": None,
            "metadata": {"attack_id": "test", "noise": False},
        }

    def _label(self, host="DC01", eid=4662, attack_id="test",
               phase="cred", ts="2026-01-01T10:00:00Z"):
        return {"timestamp": ts, "host": host, "event_id": eid,
                "attack_id": attack_id, "phase": phase, "technique": "T1003",
                "anchor": True}

    def _fp_event(self, host="WS-BENIGN"):
        """A non-malicious event that looks anchor-like (LOLBIN pattern)."""
        return {
            "timestamp": "2026-01-01T08:00:00Z", "hostname": host,
            "channel": "Security", "event_id": 4688,
            "logon": {"logon_id": "0xAAAA"},
            "process": {"name": "powershell.exe"},
            "parent_process": {"name": "wscript.exe"},
            "object": {"properties": []}, "source": None, "message": None,
            "metadata": {"attack_id": None, "noise": True},
        }

    def _validate(self, events, labels):
        try:
            self.PV(events, labels).validate(fail_fast=True)
            return None
        except self.VF as vf:
            return vf.code

    def test_passes_with_valid_data(self):
        e4662 = self._base_event()
        e4624 = self._base_4624()
        fp    = self._fp_event()
        labels = [
            self._label(ts="2026-01-01T09:00:00Z", eid=4624, phase="access"),
            self._label(ts="2026-01-01T10:00:00Z", eid=4662, phase="cred"),
        ]
        assert self._validate([e4662, e4624, fp], labels) is None

    def test_gt_host_missing(self):
        e = self._base_event(host="GHOST")
        label = self._label(host="GHOST")
        code = self._validate([self._base_4624(), self._fp_event()], [label])
        assert code == "GT_HOST_MISSING"

    def test_dcsync_no_logon_id(self):
        e = self._base_event()
        e["logon"]["logon_id"] = None
        labels = [
            self._label(ts="2026-01-01T09:00:00Z", eid=4624, phase="a"),
            self._label(ts="2026-01-01T10:00:00Z", eid=4662, phase="b"),
        ]
        code = self._validate([e, self._base_4624(), self._fp_event()], labels)
        assert code == "DCSYNC_NO_LOGON_ID"

    def test_dcsync_no_4624(self):
        e = self._base_event()   # has logon_id but no matching 4624
        labels = [
            self._label(ts="2026-01-01T09:00:00Z", eid=4624, phase="a"),
            self._label(ts="2026-01-01T10:00:00Z", eid=4662, phase="b"),
        ]
        # Only the 4662 event — no 4624 in the events list
        code = self._validate([e, self._fp_event()], labels)
        assert code == "DCSYNC_NO_4624"

    def test_proc_missing_lineage(self):
        e4688 = {
            "timestamp": "2026-01-01T10:00:00Z", "hostname": "WS-1",
            "channel": "Security", "event_id": 4688,
            "logon": {"logon_id": "0x1234"},
            "process": {"name": None},            # missing
            "parent_process": {"name": None},     # missing
            "object": {"properties": []}, "source": None, "message": None,
            "metadata": {"attack_id": "test", "noise": False},
        }
        labels = [self._label(host="WS-1", eid=4688, ts="2026-01-01T10:00:00Z")]
        code = self._validate([e4688, self._fp_event()], labels)
        assert code == "PROC_MISSING_LINEAGE"

    def test_timeline_too_short(self):
        e4662 = self._base_event(ts="2026-01-01T10:00:00Z")
        e4624 = self._base_4624()
        fp    = self._fp_event()
        # Both labels at nearly the same timestamp → < 30 s spread
        labels = [
            self._label(ts="2026-01-01T10:00:00Z", eid=4662, phase="a"),
            self._label(ts="2026-01-01T10:00:01Z", eid=4662, phase="b"),
        ]
        code = self._validate([e4662, e4624, fp], labels)
        assert code == "TIMELINE_TOO_SHORT"

    def test_no_false_positives(self):
        e4662 = self._base_event()
        e4624 = self._base_4624()
        labels = [
            self._label(ts="2026-01-01T09:00:00Z", eid=4624, phase="a"),
            self._label(ts="2026-01-01T10:00:00Z", eid=4662, phase="b"),
        ]
        # No FP-like host in events
        code = self._validate([e4662, e4624], labels)
        assert code == "NO_FALSE_POSITIVES"

    def test_no_discriminator(self):
        e4662 = self._base_event()
        e4624 = self._base_4624()
        # Give the FP host the SAME DCSync anchor as the malicious host
        fp_dcsync = {
            "timestamp": "2026-01-01T08:00:00Z", "hostname": "WS-BENIGN",
            "channel": "Security", "event_id": 4662,
            "logon": {"logon_id": "0xBBBB"},
            "process": {"name": None}, "parent_process": {"name": None},
            "object": {"properties": ["Replicating Directory Changes All"]},
            "source": None, "message": None,
            "metadata": {"attack_id": None, "noise": True},
        }
        labels = [
            self._label(ts="2026-01-01T09:00:00Z", eid=4624, phase="a"),
            self._label(ts="2026-01-01T10:00:00Z", eid=4662, phase="b"),
        ]
        code = self._validate([e4662, e4624, fp_dcsync], labels)
        assert code == "NO_DISCRIMINATOR"


# ===========================================================================
# 5. CLI argument validation
# ===========================================================================

class TestCLI:
    def setup_method(self):
        import importlib, importlib.util
        spec = importlib.util.spec_from_file_location("cli", str(ROOT / "cli.py"))
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.cli = mod

    def _parse(self, args):
        return self.cli._build_parser().parse_args(args)

    def test_valid_args_parse(self):
        a = self._parse(["--output", "./out", "--seed", "42", "--attacks", "2", "--days", "3"])
        assert a.seed == 42
        assert a.attacks == 2

    def test_attacks_zero_rejected(self):
        with pytest.raises(SystemExit):
            self._parse(["--output", "./out", "--attacks", "0"])

    def test_attacks_negative_rejected(self):
        with pytest.raises(SystemExit):
            self._parse(["--output", "./out", "--attacks", "-1"])

    def test_days_zero_rejected(self):
        with pytest.raises(SystemExit):
            self._parse(["--output", "./out", "--days", "0"])

    def test_anomalies_zero_allowed(self):
        a = self._parse(["--output", "./out", "--anomalies", "0"])
        assert a.anomalies == 0

    def test_noise_multiplier_valid(self):
        a = self._parse(["--output", "./out", "--noise-multiplier", "0.25"])
        assert a.noise_multiplier == pytest.approx(0.25)

    def test_noise_multiplier_zero_rejected(self):
        with pytest.raises(SystemExit):
            self._parse(["--output", "./out", "--noise-multiplier", "0"])

    def test_noise_multiplier_negative_rejected(self):
        with pytest.raises(SystemExit):
            self._parse(["--output", "./out", "--noise-multiplier", "-1.0"])

    def test_noise_multiplier_non_numeric_rejected(self):
        with pytest.raises(SystemExit):
            self._parse(["--output", "./out", "--noise-multiplier", "fast"])

    def test_list_playbooks_flag_parsed(self):
        a = self._parse(["--list-playbooks"])
        assert a.list_playbooks is True

    def test_output_not_required_with_list_playbooks(self):
        # Should parse without --output when --list-playbooks is set
        a = self._parse(["--list-playbooks"])
        assert a.output is None


# ===========================================================================
# 6. RNG determinism and seed width
# ===========================================================================

class TestRng:
    def test_same_seed_same_output(self):
        from slhf.rng import DeterministicRng
        r1 = DeterministicRng(42).derive("test")
        r2 = DeterministicRng(42).derive("test")
        assert [r1.random() for _ in range(10)] == [r2.random() for _ in range(10)]

    def test_different_labels_differ(self):
        from slhf.rng import DeterministicRng
        r1 = DeterministicRng(42).derive("label_a")
        r2 = DeterministicRng(42).derive("label_b")
        assert r1.random() != r2.random()

    def test_different_seeds_differ(self):
        from slhf.rng import DeterministicRng
        r1 = DeterministicRng(1).derive("x")
        r2 = DeterministicRng(2).derive("x")
        assert r1.random() != r2.random()

    def test_full_digest_used(self):
        """Verify we use all 32 bytes of the SHA-256 digest, not just 8."""
        import hashlib, inspect
        src = inspect.getsource(__import__("slhf.rng", fromlist=["DeterministicRng"]).DeterministicRng.derive)
        # The old code used h[:8]; the new code uses the full h
        assert "h[:8]" not in src, "Only 8 bytes of digest used — should use full digest"


# ===========================================================================
# 7. Investigation rules — dynamic derivation
# ===========================================================================

class TestInvestigationRules:
    def test_dcsync_playbook_derives_steps(self):
        from slhf.investigation_rules import required_steps_for_attack
        pb = {
            "phases": [
                {"id": "init", "event_id": 4624, "conditions": {}},
                {"id": "cred", "event_id": 4662,
                 "object": {"properties": ["Replicating Directory Changes All"]}},
            ],
            "correlation": ["logon_id"],
        }
        steps = required_steps_for_attack("windows_dcsync_chain", playbook=pb)
        assert "identify_4662" in steps
        assert "pivot_logon_id" in steps
        assert "find_4624" in steps

    def test_lolbin_playbook_derives_steps(self):
        from slhf.investigation_rules import required_steps_for_attack
        pb = {
            "phases": [
                {"id": "exec", "event_id": 4688,
                 "process_chain": {"parent": "wscript.exe", "child": "powershell.exe"}},
            ],
            "correlation": [],
        }
        steps = required_steps_for_attack("windows_lolbin_chain", playbook=pb)
        assert "identify_powershell" in steps
        assert "trace_parent_chain" in steps

    def test_static_fallback_still_works(self):
        from slhf.investigation_rules import required_steps_for_attack
        steps = required_steps_for_attack("windows_dcsync_chain", playbook=None)
        assert "identify_4662" in steps

    def test_unknown_attack_returns_empty(self):
        from slhf.investigation_rules import required_steps_for_attack
        assert required_steps_for_attack("nonexistent_attack", playbook=None) == []
