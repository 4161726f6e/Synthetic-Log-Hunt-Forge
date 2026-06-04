from __future__ import annotations

import json
import os
import traceback
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from slhf.adaptive_regenerator import adapt_config
from slhf.analytics import write_analytics_report
from slhf.diagnostic_report import write_validation_report
from slhf.engine import generate_dataset, write_outputs_from_cache
from slhf.learning.learner import record_failure, record_success
from slhf.learning.metrics import record_run
from slhf.learning.tuner import apply_learned_defaults
from slhf.provability_validator import ProvabilityValidator, ValidationFailed


def generate_with_adaptive_retries(
    *,
    output_dir: str,
    base_seed: int,
    attack_count: int,
    anomaly_count: int,
    days: int,
    noise_level: str,
    noise_multiplier: float = 1.0,
    max_attempts: int = 10,
):
    playbook_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "playbooks")
    )

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.join(output_dir, "validation_chain"), exist_ok=True)

    config: Dict[str, Any] = apply_learned_defaults({
        "seed":               base_seed,
        "attack_count":       attack_count,
        "anomaly_count":      anomaly_count,
        "days":               days,
        "noise_level":        noise_level,
        "noise_multiplier":   noise_multiplier,
        "min_time_gap_seconds": 60,
    })

    attempt_history: List[Dict[str, Any]] = []

    for attempt in range(1, max_attempts + 1):
        seed = int(config["seed"])

        end   = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        time_window = (start, end)

        shared_kwargs = dict(
            output_dir=output_dir,
            seed=seed,
            attack_count=attack_count,
            anomaly_count=anomaly_count,
            days=days,
            noise_level=noise_level,
            noise_multiplier=noise_multiplier,
            playbook_dir=playbook_dir,
            config=config,
            time_window=time_window,
        )

        try:
            # Dry-run: generate in memory and validate.
            events, labels = generate_dataset(**shared_kwargs, write_outputs=False)
            ProvabilityValidator(events, labels).validate(fail_fast=True)

            # Validation passed — write the cached events directly to disk
            # without regenerating them.  This saves ~1-2s per successful run
            # (one full noise generation + sort at high noise levels).
            write_outputs_from_cache(
                events=events,
                labels=labels,
                output_dir=output_dir,
                config=config,
            )

            record_success(config)
            record_run(True, attempt, seed, attempt_history)
            _write_chain_summary(output_dir, True, seed, attempt, attempt_history)

            from slhf.engine import _selected_playbook_ids
            write_analytics_report(
                output_dir,
                attempt_history,
                config,
                selected_attacks=_selected_playbook_ids.get("attacks"),
                selected_anomalies=_selected_playbook_ids.get("anomalies"),
                total_events=len(events),
                label_count=len(labels),
            )

            print(f"✅ Dataset generated successfully (seed={seed}, attempts={attempt})")
            return

        except ValidationFailed as vf:
            root_cause = vf.code
            record_failure(root_cause)

            report_name = f"attempt_{attempt:03d}_validation_report.json"
            report_path = write_validation_report(
                output_dir=output_dir,
                name=os.path.join("validation_chain", report_name),
                stage=f"attempt_{attempt}",
                passed=False,
                issues=vf.issues,
                context={"seed": seed, "attempt": attempt, "config": dict(config)},
            )

            attempt_history.append({
                "attempt":    attempt,
                "seed":       seed,
                "root_cause": root_cause,
                "report":     report_path,
            })

            config = adapt_config(config, {"root_cause": root_cause})
            config["seed"] = seed + 1

        except Exception as e:
            root_cause = getattr(e, "code", "UNKNOWN")
            tb_str = traceback.format_exc()
            record_failure(str(root_cause))

            try:
                from slhf.diagnostic_report import ValidationIssue
                report_name = f"attempt_{attempt:03d}_validation_report.json"
                write_validation_report(
                    output_dir=output_dir,
                    name=os.path.join("validation_chain", report_name),
                    stage=f"attempt_{attempt}",
                    passed=False,
                    issues=[ValidationIssue(
                        code="UNEXPECTED_EXCEPTION",
                        severity="error",
                        message=f"{type(e).__name__}: {e}",
                    )],
                    context={
                        "seed": seed,
                        "attempt": attempt,
                        "config": dict(config),
                        "traceback": tb_str,
                    },
                )
            except Exception:
                pass

            print(f"\n⚠️  Unexpected error on attempt {attempt} (seed={seed}):")
            print(tb_str)

            attempt_history.append({
                "attempt":    attempt,
                "seed":       seed,
                "root_cause": str(root_cause),
                "traceback":  tb_str,
                "report":     None,
            })
            config["seed"] = seed + 1

    record_run(False, max_attempts, None, attempt_history)
    _write_chain_summary(output_dir, False, None, max_attempts, attempt_history)
    raise RuntimeError(
        f"Failed to generate valid dataset after {max_attempts} attempts. "
        "See validation_chain/ for details."
    )


def _write_chain_summary(
    output_dir: str, success: bool, final_seed, attempts: int, history: List[Dict[str, Any]]
):
    summary = {
        "status":        "success" if success else "failed",
        "final_seed":    final_seed,
        "attempts":      attempts,
        "failure_chain": history,
    }
    fp = os.path.join(output_dir, "validation_chain", "summary.json")
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
