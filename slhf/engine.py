from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, FrozenSet, List, Tuple

from slhf.rng import DeterministicRng
from slhf.topology import generate_topology
from slhf.playbook_loader import load_playbooks
from slhf.noise import generate_windows_noise, generate_syslog_noise
from slhf.injector import inject_playbook
from slhf.ground_truth import GroundTruth
from slhf.emitters import write_windows_jsonl, write_syslog
from slhf.ctfd import generate_ctfd_export
from slhf.scenario_brief import write_scenario_documents


# Module-level dict populated on each write pass so the regenerator can
# include selected playbook IDs in the analytics report.
_selected_playbook_ids: Dict[str, List[str]] = {}


def generate_dataset(
    *,
    output_dir: str,
    seed: int,
    attack_count: int,
    anomaly_count: int,
    days: int,
    noise_level: str,
    noise_multiplier: float = 1.0,
    playbook_dir: str,
    config: Dict[str, Any],
    write_outputs: bool,
    time_window: Tuple[datetime, datetime] | None = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Generate a complete synthetic dataset in memory.

    When *write_outputs* is False (dry-run / validation pass) nothing is
    written to disk.  The caller can then pass the returned events and labels
    to :func:`write_outputs_from_cache` to persist them without regenerating.
    """

    drng = DeterministicRng(seed)
    rng  = drng.derive("global")

    topo = generate_topology(rng)

    attacks, benign = load_playbooks(playbook_dir)

    selected_attacks = rng.sample(attacks, k=min(attack_count, len(attacks)))
    selected_anoms   = rng.sample(benign,  k=min(anomaly_count, len(benign)))

    if time_window is not None:
        start, end = time_window
    else:
        end   = datetime.now(timezone.utc)
        start = end - timedelta(days=days)

    events: List[Dict[str, Any]] = []

    events += generate_windows_noise(
        drng.derive("noise:windows"), topo["windows"], start, end,
        noise_level, noise_multiplier,
    )
    events += generate_syslog_noise(
        drng.derive("noise:syslog"), topo["linux"], start, end,
        noise_level, noise_multiplier,
    )

    # Inject attacks first and collect which hosts/anchor-types they use.
    attack_events: List[Dict[str, Any]] = []
    for pb in selected_attacks:
        evts = inject_playbook(
            drng.derive(f"attack:{pb['playbook_id']}"), pb, topo, start, end, config
        )
        attack_events.extend(evts)
    events.extend(attack_events)

    malicious_host_names: FrozenSet[str] = frozenset(
        e["hostname"] for e in attack_events
        if e.get("hostname") and (e.get("metadata") or {}).get("attack_id")
    )

    from slhf.provability_validator import _anchor_tag as _atag
    attack_anchor_types: FrozenSet[str] = frozenset(
        tag for e in attack_events for tag in [_atag(e)] if tag
    )

    # Partition benign playbooks: prefer those whose anchor types don't
    # overlap with the attacks.  Fall back to the overlapping pool when all
    # attack anchor types are saturated (e.g. --attacks 9).
    probe_topo   = {k: v[:1] if v else v for k, v in topo.items()}
    probe_end    = start + timedelta(days=1)
    probe_config = dict(config, min_time_gap_seconds=1)

    non_overlap_anoms: List[Any] = []
    overlap_anoms:     List[Any] = []

    for pb in selected_anoms:
        probe_evts = inject_playbook(
            drng.derive(f"probe:{pb['playbook_id']}"), pb,
            probe_topo, start, probe_end, probe_config,
        )
        pb_anchors = frozenset(tag for e in probe_evts for tag in [_atag(e)] if tag)
        if not pb_anchors or pb_anchors.isdisjoint(attack_anchor_types):
            non_overlap_anoms.append(pb)
        else:
            overlap_anoms.append(pb)

    safe_anoms: List[Any] = non_overlap_anoms if non_overlap_anoms else overlap_anoms

    for pb in safe_anoms:
        events += inject_playbook(
            drng.derive(f"benign:{pb['playbook_id']}"), pb, topo, start, end, config,
            excluded_hosts=malicious_host_names,
        )

    events.sort(key=lambda e: e.get("timestamp", ""))

    gt = GroundTruth()
    gt.build(events)

    if write_outputs:
        _persist(events, gt, output_dir, config, selected_attacks, selected_anoms)

    return events, gt.labels


def write_outputs_from_cache(
    *,
    events: List[Dict[str, Any]],
    labels: List[Dict[str, Any]],
    output_dir: str,
    config: Dict[str, Any],
) -> None:
    """
    Write a previously validated in-memory dataset to disk.

    This avoids regenerating the dataset a second time on the write pass,
    saving the full noise-generation + sort cost (~1-2 s at high noise).
    The caller is responsible for ensuring *events* and *labels* came from a
    successful :func:`generate_dataset` call.
    """
    gt = GroundTruth()
    gt.labels = list(labels)   # labels already built; just wrap for compatibility
    _persist(events, gt, output_dir, config,
             selected_attacks=None, selected_anoms=None)


def _persist(
    events: List[Dict[str, Any]],
    gt: GroundTruth,
    output_dir: str,
    config: Dict[str, Any],
    selected_attacks,
    selected_anoms,
) -> None:
    """Write all output artefacts to *output_dir*."""
    os.makedirs(output_dir, exist_ok=True)
    write_windows_jsonl(events, output_dir)
    write_syslog(events, output_dir)
    gt.save(output_dir)
    _write_timeline_report(events, gt.labels, output_dir)
    generate_ctfd_export(events, gt.labels, output_dir)
    write_scenario_documents(events, gt.labels, config, output_dir)

    if selected_attacks is not None:
        _selected_playbook_ids["attacks"]   = [p["playbook_id"] for p in selected_attacks]
        _selected_playbook_ids["anomalies"] = [p["playbook_id"] for p in (selected_anoms or [])]


def _write_timeline_report(
    events: List[Dict[str, Any]], labels: List[Dict[str, Any]], out_dir: str
) -> None:
    os.makedirs(os.path.join(out_dir, "reports"), exist_ok=True)
    fp = os.path.join(out_dir, "reports", "timeline.md")

    anchors = sorted(
        (l for l in labels if l.get("anchor")),
        key=lambda x: x.get("timestamp", ""),
    )

    phase_first: Dict[str, str] = {}
    for l in labels:
        ph, ts = l.get("phase"), l.get("timestamp")
        if ph and ts:
            phase_first.setdefault(ph, ts)

    phase_order = [p for p, _ in sorted(phase_first.items(), key=lambda kv: kv[1])]

    lines = ["# Attack Timeline (Ground Truth)", ""]
    lines.append("## Phase order")
    for p in phase_order:
        lines.append(f"- {p}")

    lines.append("\n## Anchor events")
    for a in anchors:
        lines.append(
            f"- {a['timestamp']} | {a['host']} | "
            f"EventID {a['event_id']} | {a.get('attack_id')} | {a.get('phase')}"
        )

    with open(fp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
