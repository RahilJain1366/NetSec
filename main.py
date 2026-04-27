"""
main.py
───────
CLI entry point for the network config security pipeline.

Usage
─────
  # Full evaluation run
  python main.py evaluate

  # Generate + validate a single prompt
  python main.py generate \
      --target nginx \
      --prompt "Serve api.example.com over HTTPS with strict TLS"

  # Show all rules for a target
  python main.py rules --target iptables

  # Quick smoke test (3 samples)
  python main.py evaluate --max-samples 3
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dotenv import load_dotenv
load_dotenv()

# Ensure package root is on sys.path
sys.path.insert(0, os.path.dirname(__file__))

from config import ConfigTarget, OUTPUT_DIR
from generator import LLMConfigGenerator
from validator import ValidationEngine
from evaluator import Evaluator
from observability import PipelineLogger, setup_logging

logger = logging.getLogger("main")

DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset.json")


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_evaluate(args: argparse.Namespace) -> None:
    run_id = setup_logging()
    logger.info("═══ Evaluation run  [run_id=%s] ═══", run_id)

    gen    = LLMConfigGenerator()
    engine = ValidationEngine()
    plog   = PipelineLogger(run_id, OUTPUT_DIR)
    ev     = Evaluator(
        dataset_path  = DATASET_PATH,
        generator     = gen,
        engine        = engine,
        pipeline_log  = plog,
        delay_seconds = args.delay,
        max_samples   = args.max_samples,
    )

    records, metrics = ev.run()
    paths = ev.save_results(records, metrics, run_id)
    plog.flush()

    # ── Print summary ──────────────────────────────────────────────────
    m = metrics.to_dict()
    print("\n" + "═" * 60)
    print(f"  EVALUATION SUMMARY   run_id={run_id}")
    print("═" * 60)
    print(f"  Samples evaluated  : {m['total']}")
    print(f"  Accuracy           : {m['accuracy']:.1%}")
    print(f"  Precision (insec.) : {m['precision_insecure']:.1%}")
    print(f"  Recall (insec.)    : {m['recall_insecure']:.1%}")
    print(f"  F1 (insecure)      : {m['f1_insecure']:.1%}")
    print(f"  False Positive Rate: {m['false_positive_rate']:.1%}")
    print(f"  Confusion matrix   : {m['confusion_matrix']}")
    print("\n  Risk score by category:")
    for cat, stats in m["risk_score_by_category"].items():
        print(f"    {cat:12s}  mean={stats['mean']:.3f}  std={stats['std']:.3f}  n={stats['n']}")
    print("═" * 60)
    print(f"\n  Detailed results → {paths['details']}")
    print(f"  Metrics          → {paths['metrics']}\n")


def cmd_generate(args: argparse.Namespace) -> None:
    run_id = setup_logging()
    target = ConfigTarget(args.target)
    gen    = LLMConfigGenerator()
    engine = ValidationEngine()
    plog   = PipelineLogger(run_id, OUTPUT_DIR)

    print(f"\n[Generating {target.value} config...]\n")
    gen_result = gen.generate(args.prompt, target)
    plog.log_generation(gen_result)

    if not gen_result.success:
        print(f"[ERROR] Generation failed: {gen_result.error}")
        return

    print("─── Generated Configuration ───")
    print(gen_result.raw_config)
    print("─── Validation Result ───")

    val = engine.validate(gen_result.raw_config, target)
    plog.log_validation(val)

    print(f"  Secure    : {val.is_secure}")
    print(f"  Risk Score: {val.risk_score:.3f}")
    if val.violations:
        print(f"  Violations ({len(val.violations)}):")
        for v in val.violations:
            print(f"    [{v.severity.value}] {v.rule_id} — {v.description}")
            print(f"           Evidence: {v.evidence}")
    else:
        print("  ✓ No violations detected")

    # Save output
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out = {
        "prompt":     args.prompt,
        "target":     target.value,
        "config":     gen_result.raw_config,
        "validation": val.to_dict(),
    }
    out_path = os.path.join(OUTPUT_DIR, f"single_{run_id}_{target.value}.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n  Output saved → {out_path}")
    plog.flush()


def cmd_rules(args: argparse.Namespace) -> None:
    setup_logging()
    target = ConfigTarget(args.target)
    engine = ValidationEngine()
    rules  = engine.list_rules(target)
    print(f"\nSecurity rules for target: {target.value}\n")
    print(f"  {'Rule ID':<12} {'Severity':<8} Description")
    print("  " + "─" * 70)
    for r in rules:
        print(f"  {r['rule_id']:<12} {r['severity']:<8} {r['description']}")
    print()


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Network Config Security Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # evaluate
    p_eval = sub.add_parser("evaluate", help="Run full evaluation over dataset")
    p_eval.add_argument("--max-samples", type=int, default=None,
                        help="Limit number of samples (for quick tests)")
    p_eval.add_argument("--delay", type=float, default=10,
                        help="Seconds between API calls (default 10)")

    # generate
    p_gen = sub.add_parser("generate", help="Generate + validate a single config")
    p_gen.add_argument("--target", required=True, choices=[t.value for t in ConfigTarget])
    p_gen.add_argument("--prompt", required=True)

    # rules
    p_rules = sub.add_parser("rules", help="List rules for a target")
    p_rules.add_argument("--target", required=True, choices=[t.value for t in ConfigTarget])

    args = parser.parse_args()

    if args.command == "evaluate":
        cmd_evaluate(args)
    elif args.command == "generate":
        cmd_generate(args)
    elif args.command == "rules":
        cmd_rules(args)


if __name__ == "__main__":
    main()
