"""
Reference snippets for wiring evaluate-mitm into main.py.
"""
  # Demo mode:
  python main.py evaluate-mitm --mitm-mode demo
"""

from __future__ import annotations

import json
import os
import uuid


# ─────────────────────────────────────────────────────────────────────────────
# BLOCK 1: paste this function into main.py after cmd_mitm()
# ─────────────────────────────────────────────────────────────────────────────

def cmd_evaluate_mitm(args):
    """
    End-to-end integrated evaluation:
      Real Dataset → Loader → Flow Normalization → MITM Analyzer
        → LLM Attack Evaluator → Integrated Security Report

    Modes
    -----
    dataset    : CSV / parquet file (UNSW-NB15, CIC-IDS2017, generic)
    nids-pkg   : auto-download via `pip install nids-datasets`
    pcap       : PCAP file (delegates to existing MITMNetworkAnalyzer)
    demo       : in-memory simulation (existing MITMNetworkAnalyzer)
    """
    from observability import setup_logging, PipelineLogger
    from config import OUTPUT_DIR

    run_id = setup_logging()

    from datasets.loader      import NIDSDatasetLoader
    from datasets.llm_evaluator import DatasetLLMEvaluator
    from datasets.report      import IntegratedReportBuilder
    from mitm.dataset_analyzer import DatasetMITMAnalyzer

    mode = args.mitm_mode

    # ── Step 1: Load flows ────────────────────────────────────────────────
    flows       = None
    mitm_result = None          # DatasetAnalysisResult or legacy MITMResult
    source_label = mode

    if mode in ("dataset", "nids-pkg"):
        if mode == "nids-pkg":
            files = [int(x) for x in (args.nids_files or ["1"])]
            print(
                f"\n[1/4] Downloading {args.nids_dataset}/{args.nids_subset} "
                f"files={files} via nids-datasets...\n"
            )
            loader = NIDSDatasetLoader.from_nids_package(
                dataset    = args.nids_dataset,
                subset     = args.nids_subset,
                files      = files,
                max_samples= args.max_samples,
                cache_csv  = args.cache_csv,
            )
            flows = loader.load(args.max_samples)
            source_label = f"{args.nids_dataset}/{args.nids_subset}"
        else:
            if not args.traffic_dataset:
                print("[ERROR] --traffic-dataset required for dataset mode")
                return
            print(f"\n[1/4] Loading dataset: {args.traffic_dataset}...\n")
            loader = NIDSDatasetLoader(args.traffic_dataset)
            flows  = loader.load(args.max_samples)
            source_label = os.path.basename(args.traffic_dataset)

        summary = loader.summary()
        print(f"  Dataset flavor : {summary.get('flavor', 'unknown')}")
        print(f"  Rows loaded    : {summary.get('total_rows', len(flows))}")
        print(f"  Label dist     : {summary.get('label_distribution', {})}")

        # ── Step 2: MITM analysis of flows ───────────────────────────────
        print(f"\n[2/4] Running MITM analysis on {len(flows)} flows...")
        analyzer    = DatasetMITMAnalyzer(use_heuristics=True)
        mitm_result = analyzer.analyze_dataset_flows(flows, source=source_label)

        print(f"  Risk score      : {mitm_result.risk_score:.3f}")
        print(f"  Indicators found: {len(mitm_result.indicators)}")
        print(f"  Attack types    : {list(mitm_result.attack_type_counts.keys())}")

    elif mode == "pcap":
        from mitm import MITMNetworkAnalyzer
        if not args.pcap_file:
            print("[ERROR] --pcap-file required for pcap mode")
            return
        print(f"\n[1/4] Loading PCAP: {args.pcap_file}...\n")
        analyzer    = MITMNetworkAnalyzer()
        mitm_result = analyzer.analyze_pcap(args.pcap_file)
        source_label = os.path.basename(args.pcap_file)

    elif mode == "demo":
        from mitm import MITMNetworkAnalyzer
        print("\n[1/4] Running MITM demo simulation...\n")
        analyzer    = MITMNetworkAnalyzer()
        mitm_result = analyzer.run_demo()
        source_label = "demo"
    else:
        print(f"[ERROR] Unknown --mitm-mode: {mode}")
        return

    # ── Step 3: Optional config generation + validation ───────────────────
    config_result = None
    config_target = ""
    if getattr(args, "target", None) and getattr(args, "prompt", None):
        from config import ConfigTarget
        from generator import LLMConfigGenerator
        from validator import ValidationEngine
        from observability import PipelineLogger

        plog          = PipelineLogger(run_id, OUTPUT_DIR)
        target        = ConfigTarget(args.target)
        config_target = target.value
        gen           = LLMConfigGenerator()
        engine        = ValidationEngine()

        print(f"\n[3/4] Generating & validating {target.value} config...")
        gen_result = gen.generate(args.prompt, target)
        if gen_result.success:
            config_result = engine.validate(gen_result.raw_config, target)
            print(f"  Config risk    : {config_result.risk_score:.3f}")
            print(f"  Config violations: {len(config_result.violations)}")
        else:
            print(f"  [WARN] Config generation failed: {gen_result.error}")
    else:
        print("\n[3/4] Skipping config generation (no --target/--prompt provided)")

    # ── Step 4: LLM threat interpretation ─────────────────────────────────
    print("\n[4/4] Running LLM threat interpretation via Groq...")
    llm_report = None

    if flows is not None and mitm_result is not None:
        # Dataset-based analysis → use DatasetLLMEvaluator
        evaluator  = DatasetLLMEvaluator()
        llm_report = evaluator.evaluate(mitm_result)
    else:
        # PCAP / demo → use existing MITMReporter
        try:
            from mitm import MITMReporter
            reporter   = MITMReporter()
            dummy_val  = config_result  # may be None
            legacy_rep = reporter.generate(
                target        = config_target or "network",
                config_result = dummy_val,
                network_result= mitm_result,
            )
            # Wrap into a duck-typed object the report builder can consume
            class _WrappedLLM:
                summary             = legacy_rep.summary
                severity_assessment = ""
                remediation_steps   = []
                attack_explanations = {}
                overall_risk_tier   = "HIGH" if legacy_rep.combined_risk >= 0.5 else "MEDIUM"
            llm_report = _WrappedLLM()
        except Exception:
            llm_report = None

    if llm_report:
        print(f"  Risk tier: {getattr(llm_report, 'overall_risk_tier', 'N/A')}")

    # ── Build & display integrated report ─────────────────────────────────
    builder = IntegratedReportBuilder()
    report  = builder.build(
        run_id         = run_id,
        config_result  = config_result,
        config_target  = config_target,
        analysis_result= mitm_result if flows is not None else None,
        llm_report     = llm_report,
    )

    print("\n" + "═" * 70)
    print(" INTEGRATED DATASET SECURITY REPORT")
    print("═" * 70)
    print(f"  Run ID            : {run_id}")
    print(f"  Dataset source    : {source_label}")
    print(f"  Total flows       : {report.dataset_total_flows}")
    print(f"  Attack flows      : {report.dataset_attack_flows}"
          f"  ({100*report.dataset_attack_flows//max(report.dataset_total_flows,1)}%)")
    print(f"  Dataset risk score: {report.dataset_risk:.3f}")
    print(f"  Config risk score : {report.config_risk:.3f}")
    print(f"  Combined risk     : {report.combined_risk:.3f}")
    print(f"  Overall risk tier : {report.llm_risk_tier or 'N/A'}")
    print(f"  Fully at risk     : {report.fully_at_risk}")

    if report.dataset_attack_types:
        print("\n  ─── Top Attack Types ───")
        for atype, cnt in sorted(
            report.dataset_attack_types.items(), key=lambda x: x[1], reverse=True
        )[:8]:
            print(f"    {atype:35s}  {cnt:>4} flows")

    if report.llm_summary:
        print("\n  ─── LLM Threat Summary ───")
        print(f"    {report.llm_summary}")

    if report.llm_remediation_steps:
        print("\n  ─── Remediation Steps ───")
        for i, step in enumerate(report.llm_remediation_steps, 1):
            print(f"    {i}. {step}")

    if report.config_violations:
        print(f"\n  ─── Config Violations ({len(report.config_violations)}) ───")
        for v in report.config_violations[:10]:
            print(f"    [{v['severity']}] {v['rule_id']} — {v['description']}")

    if report.top_indicators:
        print(f"\n  ─── Top MITM Indicators ({min(len(report.top_indicators),5)} shown) ───")
        for ind in report.top_indicators[:5]:
            print(f"    [{ind['severity']}] {ind['attack_type']}: {ind['description']}")
            print(f"      {ind['evidence']}")

    if flows is not None and hasattr(mitm_result, "precision"):
        print("\n  ─── Detection Metrics ───")
        print(f"    Precision : {mitm_result.precision:.3f}")
        print(f"    Recall    : {mitm_result.recall:.3f}")
        print(f"    F1        : {mitm_result.f1:.3f}")

    print("═" * 70)

    # ── Save results ──────────────────────────────────────────────────────
    from config import OUTPUT_DIR as _OUT
    out_path = builder.save(report, _OUT)
    print(f"\n  Output saved → {out_path}\n")


# ─────────────────────────────────────────────────────────────────────────────
# BLOCK 2: paste this inside main() → sub = parser.add_subparsers(...)
# ─────────────────────────────────────────────────────────────────────────────

EVALUATE_MITM_ARGPARSE = """
    # ── evaluate-mitm ─────────────────────────────────────────────────────────
    p = sub.add_parser(
        "evaluate-mitm",
        help="End-to-end: real dataset → MITM analysis → LLM threat interpretation"
    )
    # Mode selection
    p.add_argument(
        "--mitm-mode",
        required=True,
        choices=["dataset", "nids-pkg", "pcap", "demo"],
        help=(
            "dataset  : load CSV/parquet (UNSW-NB15, CIC-IDS2017, generic)\\n"
            "nids-pkg : auto-download via nids-datasets package\\n"
            "pcap     : analyze a PCAP file\\n"
            "demo     : in-memory simulation"
        ),
    )
    # Dataset / CSV / parquet
    p.add_argument("--traffic-dataset",  help="Path to CSV or parquet dataset file")
    p.add_argument("--max-samples",      type=int, default=None,
                   help="Cap the number of rows/flows to load")

    # nids-datasets package options
    p.add_argument("--nids-dataset",  default="UNSW-NB15",
                   choices=["UNSW-NB15", "CIC-IDS2017"],
                   help="Dataset name for nids-pkg mode")
    p.add_argument("--nids-subset",   default="Network-Flows",
                   help="Subset for nids-pkg mode (default: Network-Flows)")
    p.add_argument("--nids-files",    nargs="+", default=["1"],
                   help="File indices for nids-pkg mode (e.g. --nids-files 1 2 3)")
    p.add_argument("--cache-csv",     default=None,
                   help="Cache downloaded nids-package data to this CSV path")

    # PCAP
    p.add_argument("--pcap-file", help="Path to PCAP file (required for pcap mode)")

    # Optional config generation (adds config risk to combined score)
    p.add_argument("--target",  choices=[t.value for t in ConfigTarget], default=None,
                   help="Config target (nginx/iptables/dns) — enables config generation")
    p.add_argument("--prompt",  default=None,
                   help="Config generation prompt (required if --target is set)")
"""

# ─────────────────────────────────────────────────────────────────────────────
# BLOCK 3: add to dispatch dict inside main()
# ─────────────────────────────────────────────────────────────────────────────

DISPATCH_ADDITION = """
    "evaluate-mitm": cmd_evaluate_mitm,
"""


# ─────────────────────────────────────────────────────────────────────────────
# For reference: full IntegratedReportBuilder import needed inside main.py
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_IMPORT = """
from datasets.report import IntegratedReportBuilder
"""


if __name__ == "__main__":
    print(__doc__)
