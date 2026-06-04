import argparse
import os
import sys


def _positive_int(name: str):
    """Return an argparse type function that enforces a positive integer."""
    def _check(value: str) -> int:
        try:
            v = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"--{name} must be an integer, got {value!r}")
        if v < 1:
            raise argparse.ArgumentTypeError(f"--{name} must be >= 1, got {v}")
        return v
    _check.__name__ = name
    return _check


def _non_negative_int(name: str):
    """Return an argparse type function that enforces a non-negative integer."""
    def _check(value: str) -> int:
        try:
            v = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"--{name} must be an integer, got {value!r}")
        if v < 0:
            raise argparse.ArgumentTypeError(f"--{name} must be >= 0, got {v}")
        return v
    _check.__name__ = name
    return _check


def _noise_multiplier(value: str) -> float:
    """Argparse type for --noise-multiplier: a positive float."""
    try:
        v = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"--noise-multiplier must be a number, got {value!r}"
        )
    if v <= 0:
        raise argparse.ArgumentTypeError(
            f"--noise-multiplier must be > 0, got {v}"
        )
    return v


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Synthetic Log Hunt Forge (SLHF)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Standard 3-day dataset with 2 attacks and 3 benign decoys
  python cli.py --output ./out --seed 1337 --attacks 2 --anomalies 3 --days 3

  # Quiet dataset for a quick test (low noise, fewer events)
  python cli.py --output ./out --seed 42 --noise low --noise-multiplier 0.25

  # List available playbooks without generating anything
  python cli.py --list-playbooks
""",
    )

    p.add_argument("--output", help="Output directory (required unless --list-playbooks)")
    p.add_argument(
        "--seed", type=int, default=1337,
        help="Random seed (default: 1337). Increment for a different scenario.",
    )
    p.add_argument(
        "--attacks", type=_positive_int("attacks"), default=2,
        help="Number of attack playbooks to inject (default: 2, min: 1).",
    )
    p.add_argument(
        "--anomalies", type=_non_negative_int("anomalies"), default=3,
        help="Number of benign-but-suspicious decoy playbooks (default: 3, min: 0).",
    )
    p.add_argument(
        "--days", type=_positive_int("days"), default=3,
        help="Width of the observation window in days (default: 3, min: 1).",
    )
    p.add_argument(
        "--noise", choices=["low", "medium", "high"], default="high",
        help="Noise level preset (default: high).",
    )
    p.add_argument(
        "--noise-multiplier", type=_noise_multiplier, default=1.0,
        metavar="FLOAT",
        help=(
            "Scale factor applied on top of --noise preset (default: 1.0). "
            "Use < 1.0 for faster generation / smaller files (e.g. 0.25), "
            "> 1.0 for denser noise (e.g. 2.0)."
        ),
    )
    p.add_argument(
        "--max-attempts", type=_positive_int("max-attempts"), default=10,
        help="Max validation retry attempts before giving up (default: 10).",
    )
    p.add_argument(
        "--list-playbooks", action="store_true",
        help="Print all available playbooks and exit. Does not generate a dataset.",
    )
    p.add_argument(
        "--reset-metrics", action="store_true",
        help=(
            "Clear accumulated run metrics and failure history, then exit. "
            "Useful after fixing bugs that inflated the historical failure counts."
        ),
    )
    return p


def _cmd_list_playbooks() -> None:
    """Print all available attack and benign playbooks."""
    from slhf.playbook_loader import load_playbooks

    playbook_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "playbooks")

    if not os.path.isdir(playbook_dir):
        print(f"Playbook directory not found: {playbook_dir}", file=sys.stderr)
        sys.exit(1)

    attacks, benign = load_playbooks(playbook_dir)

    def _print_group(label: str, playbooks):
        print(f"\n{label} ({len(playbooks)})")
        print("-" * (len(label) + 4))
        if not playbooks:
            print("  (none)")
            return
        for pb in playbooks:
            pid   = pb.get("playbook_id", "?")
            desc  = pb.get("description", "").strip().replace("\n", " ")
            phases = [p.get("id", "?") for p in pb.get("phases", [])]
            print(f"  {pid}")
            if desc:
                print(f"    {desc}")
            if phases:
                print(f"    phases: {' -> '.join(phases)}")

    print("Available playbooks")
    print("=" * 40)
    _print_group("Attack playbooks  [classification: malicious]", attacks)
    _print_group("Benign playbooks  [classification: suspicious]", benign)
    print()


def _cmd_reset_metrics() -> None:
    """Clear memory_store.json and metrics_store.json from the data directory."""
    from slhf.learning.learner import _mem_path, save_memory
    from slhf.learning.metrics import _metrics_path, save_metrics

    mem_path     = _mem_path()
    metrics_path = _metrics_path()

    save_memory({"failure_patterns": {}, "successful_configs": []})
    save_metrics({"runs": []})

    print(f"✅ Metrics reset.")
    print(f"   Memory store:  {mem_path}")
    print(f"   Metrics store: {metrics_path}")


def _validate_args(args: argparse.Namespace) -> None:
    """Cross-argument checks that can't be expressed as individual type constraints."""
    if args.attacks > 50:
        print("warning: --attacks > 50 is almost certainly unintentional", file=sys.stderr)
    if args.anomalies > 50:
        print("warning: --anomalies > 50 is almost certainly unintentional", file=sys.stderr)
    if args.days > 365:
        print("warning: --days > 365 produces very sparse attack windows", file=sys.stderr)


def main() -> None:
    p = _build_parser()
    args = p.parse_args()

    if args.list_playbooks:
        _cmd_list_playbooks()
        return

    if args.reset_metrics:
        _cmd_reset_metrics()
        return

    if not args.output:
        p.error("--output is required (unless --list-playbooks is specified)")

    _validate_args(args)

    from slhf.regenerator import generate_with_adaptive_retries

    generate_with_adaptive_retries(
        output_dir=args.output,
        base_seed=args.seed,
        attack_count=args.attacks,
        anomaly_count=args.anomalies,
        days=args.days,
        noise_level=args.noise,
        noise_multiplier=args.noise_multiplier,
        max_attempts=args.max_attempts,
    )


if __name__ == "__main__":
    main()
