"""
main.py — CLI entry point for the network config security pipeline.

Commands include evaluation, generation, remediation, comparison, MITM
analysis, dashboard, rules, and evaluate-mitm.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv()

from config import ConfigTarget, OUTPUT_DIR
from generator import LLMConfigGenerator
from validator import ValidationEngine
from evaluator import Evaluator
from observability import PipelineLogger, setup_logging

logger = logging.getLogger("main")

DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset.json")


# ── evaluate ──────────────────────────────────────────────────────────────────

def cmd_evaluate(args):
    run_id = setup_logging()
    logger.info("═══ Evaluation run [run_id=%s] ═══", run_id)
    gen    = LLMConfigGenerator()
    engine = ValidationEngine()
    plog   = PipelineLogger(run_id, OUTPUT_DIR)
    ev = Evaluator(
        dataset_path = DATASET_PATH,
        generator    = gen,
        engine       = engine,
        pipeline_log = plog,
        delay_seconds= args.delay,
        max_samples  = args.max_samples,
    )
    records, metrics = ev.run()
    paths = ev.save_results(records, metrics, run_id)
    plog.flush()
    m = metrics.to_dict()
    print("\n" + "═" * 60)
    print(f" EVALUATION SUMMARY run_id={run_id}")
    print("═" * 60)
    print(f" Samples evaluated : {m['total']}")
    print(f" Accuracy          : {m['accuracy']:.1%}")
    print(f" Precision (insec.): {m['precision_insecure']:.1%}")
    print(f" Recall (insec.)   : {m['recall_insecure']:.1%}")
    print(f" F1 (insecure)     : {m['f1_insecure']:.1%}")
    print(f" False Positive Rate: {m['false_positive_rate']:.1%}")
    print(f" Confusion matrix  : {m['confusion_matrix']}")
    print("\n Risk score by category:")
    for cat, stats in m["risk_score_by_category"].items():
        print(f"   {cat:12s} mean={stats['mean']:.3f} std={stats['std']:.3f} n={stats['n']}")
    print("═" * 60)
    print(f"\n Detailed results → {paths['details']}")
    print(f" Metrics → {paths['metrics']}\n")


# ── generate ──────────────────────────────────────────────────────────────────

def cmd_generate(args):
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
    print("\n─── Validation Result ───")
    val = engine.validate(gen_result.raw_config, target)
    plog.log_validation(val)
    print(f" Secure    : {val.is_secure}")
    print(f" Risk Score: {val.risk_score:.3f}")
    if val.violations:
        print(f" Violations ({len(val.violations)}):")
        for v in val.violations:
            print(f"   [{v.severity.value}] {v.rule_id} — {v.description}")
            print(f"   Evidence: {v.evidence}")
    else:
        print(" ✓ No violations detected")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, f"single_{run_id}_{target.value}.json")
    with open(out_path, "w") as f:
        json.dump({"prompt": args.prompt, "target": target.value,
                   "config": gen_result.raw_config, "validation": val.to_dict()}, f, indent=2)
    print(f"\n Output saved → {out_path}")
    plog.flush()


# ── remediate ─────────────────────────────────────────────────────────────────

def cmd_remediate(args):
    from remediator import RemediationEngine
    run_id = setup_logging()
    target = ConfigTarget(args.target)
    gen    = LLMConfigGenerator()
    engine = ValidationEngine()
    rem    = RemediationEngine(gen, engine, max_iterations=args.max_iter,
                               delay_seconds=args.delay)
    print(f"\n[Generating {target.value} config...]\n")
    gen_result = gen.generate(args.prompt, target)
    if not gen_result.success:
        print(f"[ERROR] Generation failed: {gen_result.error}")
        return
    print("─── Generated Configuration ───")
    print(gen_result.raw_config)
    val = engine.validate(gen_result.raw_config, target)
    print(f"\n─── Initial Validation ───")
    print(f" Secure: {val.is_secure}  Risk: {val.risk_score:.3f}  Violations: {len(val.violations)}")
    if not val.violations:
        print("\n ✓ Config is already secure — no remediation needed.")
        return
    print(f"\n[Remediating (max {args.max_iter} iterations)...]\n")
    result = rem.remediate(gen_result.raw_config, target, initial_validation=val)
    print("─── Remediation Result ───")
    print(f" Fully remediated  : {result.fully_remediated}")
    print(f" Iterations taken  : {result.iterations_taken}")
    print(f" Risk before       : {result.risk_before:.3f}")
    print(f" Risk after        : {result.risk_after:.3f}")
    print(f" Violations before : {len(result.violations_before)}")
    print(f" Violations after  : {len(result.violations_after)}")
    print("\n─── Diff ───")
    if result.unified_diff:
        print(result.unified_diff)
    else:
        print(" (no changes)")
    if result.violations_after:
        print("\n─── Remaining Violations ───")
        for v in result.violations_after:
            print(f"   [{v.severity.value}] {v.rule_id} — {v.description}")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, f"remediation_{run_id}_{target.value}.json")
    with open(out_path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    print(f"\n Output saved → {out_path}\n")


# ── compare ───────────────────────────────────────────────────────────────────

def cmd_compare(args):
    from comparator import LLMComparator
    from evaluator.evaluator import Evaluator as Ev
    run_id = setup_logging()
    logger.info("═══ Model comparison run [run_id=%s] ═══", run_id)
    engine = ValidationEngine()
    comp   = LLMComparator(
        model_a_name = args.model_a,
        model_b_name = args.model_b,
        engine       = engine,
        delay_seconds= args.delay,
        max_samples  = args.max_samples,
    )
    ev      = Ev(DATASET_PATH, LLMConfigGenerator(), engine,
                 PipelineLogger(run_id, OUTPUT_DIR), max_samples=args.max_samples)
    samples = ev.load_dataset()
    records, summary = comp.run(samples)
    paths = comp.save(records, summary, run_id)
    s = summary.to_dict()
    print("\n" + "═" * 60)
    print(f" COMPARISON SUMMARY run_id={run_id}")
    print("═" * 60)
    print(f" Model A       : {s['model_a']}")
    print(f" Model B       : {s['model_b']}")
    print(f" Samples       : {s['total_samples']}")
    print(f" Agreement rate: {s['agreement_rate']:.1%}")
    print(f" Model A wins  : {s['model_a_wins']}")
    print(f" Model B wins  : {s['model_b_wins']}")
    print(f" Ties          : {s['ties']}")
    print(f" Both wrong    : {s['both_wrong']}")
    print(f"\n Model A — Accuracy: {s['model_a_metrics']['accuracy']:.1%}  F1: {s['model_a_metrics']['f1_insecure']:.1%}")
    print(f" Model B — Accuracy: {s['model_b_metrics']['accuracy']:.1%}  F1: {s['model_b_metrics']['f1_insecure']:.1%}")
    print("═" * 60)
    print(f"\n Records → {paths['records']}")
    print(f" Summary → {paths['summary']}\n")


# ── dashboard ─────────────────────────────────────────────────────────────────

def cmd_dashboard(args):
    setup_logging()
    print(f"\n 🔐 NetConfig Security Dashboard")
    print(f" Open → http://localhost:{args.port}\n")
    from dashboard.app import app
    app.run(debug=args.debug, port=args.port, host="0.0.0.0")


# ── rules ─────────────────────────────────────────────────────────────────────

def cmd_rules(args):
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


# ── mitm ──────────────────────────────────────────────────────────────────────

def cmd_mitm(args):
    """Run MITM attack detection analysis."""
    setup_logging()
    from mitm import MITMNetworkAnalyzer, MITMReporter
    analyzer = MITMNetworkAnalyzer()
    if args.mode == "demo":
        print("\n[Running MITM demo (in-memory simulation)...]\n")
        result = analyzer.run_demo()
    elif args.mode == "pcap":
        if not args.pcap_file:
            print("[ERROR] --pcap-file required for pcap mode")
            return
        print(f"\n[Analyzing PCAP: {args.pcap_file}...]\n")
        result = analyzer.analyze_pcap(args.pcap_file)
    elif args.mode == "live":
        if not args.interface:
            print("[ERROR] --interface required for live capture (e.g., eth0)")
            return
        print(f"\n[Starting live capture on {args.interface}...]\n")
        result = analyzer.capture_live(
            iface   = args.interface,
            count   = args.count,
            timeout = args.timeout,
        )
    print("─── MITM Analysis Results ───")
    print(f" Mode            : {result.mode}")
    print(f" Packets analyzed: {result.packets_seen}")
    print(f" Duration        : {result.duration_secs:.2f}s")
    print(f" Risk score      : {result.risk_score:.3f}")
    print(f" Indicators found: {len(result.indicators)}")
    if result.indicators:
        print("\n─── Detected MITM Indicators ───")
        for ind in result.indicators:
            print(f"   [{ind.severity}] {ind.attack_type:20s} — {ind.description}")
            print(f"   Evidence: {ind.evidence}")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, f"mitm_{uuid.uuid4().hex[:8]}_{args.mode}.json")
    with open(out_path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    print(f"\n Output saved → {out_path}\n")


# ── analyze ───────────────────────────────────────────────────────────────────

def cmd_analyze_with_mitm(args):
    """Generate config, validate, and show MITM vulnerabilities."""
    from mitm import MITMNetworkAnalyzer, MITMReporter
    run_id = setup_logging()
    target = ConfigTarget(args.target)
    gen    = LLMConfigGenerator()
    engine = ValidationEngine()
    plog   = PipelineLogger(run_id, OUTPUT_DIR)

    print(f"\n[1/4] Generating {target.value} config...\n")
    gen_result = gen.generate(args.prompt, target)
    plog.log_generation(gen_result)
    if not gen_result.success:
        print(f"[ERROR] Generation failed: {gen_result.error}")
        return
    print("─── Generated Configuration ───")
    print(gen_result.raw_config)

    print("\n[2/4] Validating configuration...")
    val = engine.validate(gen_result.raw_config, target)
    plog.log_validation(val)
    print(f" Secure    : {val.is_secure}")
    print(f" Risk Score: {val.risk_score:.3f}")
    print(f" Violations: {len(val.violations)}")

    print("\n[3/4] Running MITM network analysis...")
    analyzer    = MITMNetworkAnalyzer()
    mitm_result = analyzer.run_demo()
    print(f" MITM Risk Score: {mitm_result.risk_score:.3f}")
    print(f" Indicators     : {len(mitm_result.indicators)}")

    print("\n[4/4] Generating integrated attack path report...")
    reporter = MITMReporter()
    report   = reporter.generate(
        target         = target.value,
        config_result  = val,
        network_result = mitm_result,
    )

    print("\n" + "═" * 70)
    print(" INTEGRATED SECURITY ANALYSIS")
    print("═" * 70)
    print(f"\n Config Risk Score : {report.config_risk:.3f}")
    print(f" Network Risk Score: {report.network_risk:.3f}")
    print(f" Combined Risk     : {report.combined_risk:.3f}")
    print(f" Target at MITM Risk: {report.fully_at_risk}")
    print(f"\n Config Violations : {len(report.config_findings)}")
    print(f" MITM Indicators   : {len(report.network_findings)}")

    if report.config_findings:
        print("\n ─── Config Vulnerabilities ───")
        for viol in report.config_findings:
            print(f"   [{viol['severity']}] {viol['rule_id']} — {viol['description']}")

    if report.network_findings:
        print("\n ─── MITM Indicators Detected ───")
        for ind in report.network_findings:
            print(f"   [{ind['severity']}] {ind['attack_type']} — {ind['description']}")

    print("\n ─── Attack Path (ordered by phase) ───")
    for step in report.attack_path:
        print(f"\n Phase: {step.phase}")
        for finding in step.findings:
            print(f"   • {finding}")

    print(f"\n Summary: {report.summary}")
    print("═" * 70)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, f"analyze_{run_id}_{target.value}.json")
    with open(out_path, "w") as f:
        json.dump(report.to_dict(), f, indent=2)
    print(f"\n Output saved → {out_path}\n")
    plog.flush()


# ── evaluate-mitm ────────────────────────────────────────────────────────────

def cmd_evaluate_mitm(args):
    """End-to-end dataset MITM analysis and report generation."""
    run_id = setup_logging()

    from datasets.loader        import NIDSDatasetLoader
    from datasets.llm_evaluator import DatasetLLMEvaluator
    from datasets.report        import IntegratedReportBuilder
    from mitm.dataset_analyzer  import DatasetMITMAnalyzer

    mode         = args.mitm_mode
    flows        = None
    mitm_result  = None
    source_label = mode
    loader       = None

    # ── Step 1: Load / acquire flows ──────────────────────────────────────
    if mode in ("dataset", "nids-pkg"):

        if mode == "nids-pkg":
            files = [int(x) for x in (args.nids_files or ["1"])]
            print(
                f"\n[1/4] Downloading {args.nids_dataset}/{args.nids_subset} "
                f"files={files} via nids-datasets...\n"
            )
            loader = NIDSDatasetLoader.from_nids_package(
                dataset     = args.nids_dataset,
                subset      = args.nids_subset,
                files       = files,
                max_samples = args.max_samples,
                cache_csv   = args.cache_csv,
            )
            flows        = loader.load(args.max_samples)
            source_label = f"{args.nids_dataset}/{args.nids_subset}"

        else:  # dataset (CSV / parquet)
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
        lbl = summary.get('label_distribution', {})
        if lbl:
            print("  Label dist     :")
            for lname, cnt in sorted(lbl.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"    {lname:30s}: {cnt}")

        # ── Step 2: MITM analysis ──────────────────────────────────────────
        print(f"\n[2/4] Running MITM analysis on {len(flows)} flows...")
        analyzer    = DatasetMITMAnalyzer(use_heuristics=True)
        mitm_result = analyzer.analyze_dataset_flows(flows, source=source_label)
        print(f"  Risk score      : {mitm_result.risk_score:.3f}")
        print(f"  Indicators found: {len(mitm_result.indicators)}")
        print(f"  Attack types    : {list(mitm_result.attack_type_counts.keys())[:8]}")

    elif mode == "pcap":
        from mitm import MITMNetworkAnalyzer
        if not args.pcap_file:
            print("[ERROR] --pcap-file required for pcap mode")
            return
        print(f"\n[1/4] Analyzing PCAP: {args.pcap_file}...\n")
        mitm_result  = MITMNetworkAnalyzer().analyze_pcap(args.pcap_file)
        source_label = os.path.basename(args.pcap_file)

    elif mode == "demo":
        from mitm import MITMNetworkAnalyzer
        print("\n[1/4] Running MITM demo simulation...\n")
        mitm_result  = MITMNetworkAnalyzer().run_demo()
        source_label = "demo"

    else:
        print(f"[ERROR] Unknown --mitm-mode: {mode}")
        return

    # ── Step 3: Optional config generation + validation ───────────────────
    config_result = None
    config_target = ""

    if getattr(args, "target", None) and getattr(args, "prompt", None):
        plog          = PipelineLogger(run_id, OUTPUT_DIR)
        target        = ConfigTarget(args.target)
        config_target = target.value
        gen           = LLMConfigGenerator()
        engine        = ValidationEngine()
        print(f"\n[3/4] Generating & validating {target.value} config...")
        gen_result = gen.generate(args.prompt, target)
        if gen_result.success:
            config_result = engine.validate(gen_result.raw_config, target)
            print(f"  Config risk      : {config_result.risk_score:.3f}")
            print(f"  Config violations: {len(config_result.violations)}")
        else:
            print(f"  [WARN] Config generation failed: {gen_result.error}")
    else:
        print("\n[3/4] Skipping config generation (no --target / --prompt provided)")

    # ── Step 4: LLM threat interpretation ─────────────────────────────────
    print("\n[4/4] Running LLM threat interpretation via Groq...")
    llm_report = None

    if flows is not None and mitm_result is not None:
        evaluator  = DatasetLLMEvaluator()
        llm_report = evaluator.evaluate(mitm_result)
    else:
        try:
            from mitm import MITMReporter
            reporter = MITMReporter()
            leg      = reporter.generate(
                target         = config_target or "network",
                config_result  = config_result,
                network_result = mitm_result,
            )
            class _W:
                summary             = leg.summary
                severity_assessment = ""
                remediation_steps   = []
                attack_explanations = {}
                overall_risk_tier   = ("HIGH" if leg.combined_risk >= 0.5 else "MEDIUM")
            llm_report = _W()
        except Exception:
            llm_report = None

    if llm_report:
        print(f"  Risk tier : {getattr(llm_report, 'overall_risk_tier', 'N/A')}")

    # ── Build integrated report ───────────────────────────────────────────
    builder = IntegratedReportBuilder()
    report  = builder.build(
        run_id          = run_id,
        config_result   = config_result,
        config_target   = config_target,
        analysis_result = mitm_result if flows is not None else None,
        llm_report      = llm_report,
    )

    print("\n" + "═" * 70)
    print(" INTEGRATED DATASET SECURITY REPORT")
    print("═" * 70)
    print(f"  Run ID             : {run_id}")
    print(f"  Dataset source     : {source_label}")
    print(f"  Total flows        : {report.dataset_total_flows}")
    if report.dataset_total_flows:
        pct = 100 * report.dataset_attack_flows // max(report.dataset_total_flows, 1)
        print(f"  Attack flows       : {report.dataset_attack_flows}  ({pct}%)")
    print(f"  Dataset risk score : {report.dataset_risk:.3f}")
    print(f"  Config risk score  : {report.config_risk:.3f}")
    print(f"  Combined risk      : {report.combined_risk:.3f}")
    print(f"  Overall risk tier  : {report.llm_risk_tier or 'N/A'}")
    print(f"  Fully at risk      : {report.fully_at_risk}")

    if report.dataset_attack_types:
        print("\n  ─── Top Attack Types ───")
        for atype, cnt in sorted(
            report.dataset_attack_types.items(), key=lambda x: x[1], reverse=True
        )[:8]:
            print(f"    {atype:35s}  {cnt:>4} flows")

    if report.llm_summary:
        print("\n  ─── LLM Threat Summary ───")
        # Format the threat summary for display
        words, line = report.llm_summary.split(), ""
        for w in words:
            if len(line) + len(w) > 70:
                print(f"    {line}")
                line = w
            else:
                line = (line + " " + w).strip()
        if line:
            print(f"    {line}")

    if report.llm_remediation_steps:
        print("\n  ─── Remediation Steps ───")
        for i, step in enumerate(report.llm_remediation_steps, 1):
            print(f"    {i}. {step}")

    if report.config_violations:
        print(f"\n  ─── Config Violations ({len(report.config_violations)}) ───")
        for v in report.config_violations[:10]:
            print(f"    [{v['severity']}] {v['rule_id']} — {v['description']}")

    if report.top_indicators:
        shown = report.top_indicators[:5]
        print(f"\n  ─── Top MITM Indicators ({len(shown)} shown) ───")
        for ind in shown:
            print(f"    [{ind['severity']}] {ind['attack_type']}: {ind['description']}")
            print(f"      ↳ {ind['evidence']}")

    if flows is not None and hasattr(mitm_result, "precision"):
        print("\n  ─── Detection Metrics (vs ground-truth labels) ───")
        print(f"    Precision : {mitm_result.precision:.3f}")
        print(f"    Recall    : {mitm_result.recall:.3f}")
        print(f"    F1        : {mitm_result.f1:.3f}")

    print("═" * 70)

    out_path = builder.save(report, OUTPUT_DIR)
    print(f"\n  Output saved → {out_path}\n")


# ── CLI wiring ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Network Config Security Pipeline")
    sub    = parser.add_subparsers(dest="command", required=True)

    # evaluate
    p = sub.add_parser("evaluate", help="Run evaluation over dataset")
    p.add_argument("--max-samples", type=int, default=None)
    p.add_argument("--delay", type=float, default=10.0)

    # generate
    p = sub.add_parser("generate", help="Generate + validate a single config")
    p.add_argument("--target", required=True, choices=[t.value for t in ConfigTarget])
    p.add_argument("--prompt", required=True)

    # remediate
    p = sub.add_parser("remediate", help="Generate, validate, and auto-fix a config")
    p.add_argument("--target", required=True, choices=[t.value for t in ConfigTarget])
    p.add_argument("--prompt", required=True)
    p.add_argument("--max-iter", type=int, default=3)
    p.add_argument("--delay", type=float, default=3.0)

    # compare
    p = sub.add_parser("compare", help="Compare two LLMs on the dataset")
    p.add_argument("--model-a", default="llama-3.1-8b-instant")
    p.add_argument("--model-b", default="mixtral-8x7b-32768")
    p.add_argument("--max-samples", type=int, default=None)
    p.add_argument("--delay", type=float, default=10.0)

    # dashboard
    p = sub.add_parser("dashboard", help="Launch the web UI")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--debug", action="store_true")

    # rules
    p = sub.add_parser("rules", help="List rules for a target")
    p.add_argument("--target", required=True, choices=[t.value for t in ConfigTarget])

    # mitm
    p = sub.add_parser("mitm", help="Run MITM attack detection")
    p.add_argument("--mode", required=True, choices=["demo", "pcap", "live"])
    p.add_argument("--pcap-file")
    p.add_argument("--interface")
    p.add_argument("--count",   type=int, default=500)
    p.add_argument("--timeout", type=int, default=60)

    # analyze
    p = sub.add_parser("analyze", help="Generate + validate + analyze MITM risks")
    p.add_argument("--target", required=True, choices=[t.value for t in ConfigTarget])
    p.add_argument("--prompt", required=True)

    # ── evaluate-mitm  (NEW) ──────────────────────────────────────────────
    p = sub.add_parser(
        "evaluate-mitm",
        help="End-to-end: real dataset → MITM analysis → LLM threat interpretation",
    )
    p.add_argument(
        "--mitm-mode",
        required=True,
        choices=["dataset", "nids-pkg", "pcap", "demo"],
        help=(
            "dataset  = load CSV/parquet (UNSW-NB15, CIC-IDS2017, generic)  |  "
            "nids-pkg = auto-download via nids-datasets package  |  "
            "pcap     = analyze a PCAP file  |  "
            "demo     = in-memory simulation"
        ),
    )
    # dataset / CSV / parquet
    p.add_argument("--traffic-dataset",
                   help="Path to CSV or parquet dataset file (required for dataset mode)")
    p.add_argument("--max-samples", type=int, default=None,
                   help="Cap the number of rows/flows to load")
    # nids-datasets package options
    p.add_argument("--nids-dataset", default="UNSW-NB15",
                   choices=["UNSW-NB15", "CIC-IDS2017"])
    p.add_argument("--nids-subset",  default="Network-Flows",
                   help="Subset name (default: Network-Flows)")
    p.add_argument("--nids-files",   nargs="+", default=["1"],
                   help="File indices for nids-pkg mode  e.g. --nids-files 1 2 3")
    p.add_argument("--cache-csv",    default=None,
                   help="Cache nids-package download to this CSV path (reused on reruns)")
    # PCAP
    p.add_argument("--pcap-file",
                   help="Path to PCAP file (required for pcap mode)")
    # Optional config generation
    p.add_argument("--target",  choices=[t.value for t in ConfigTarget], default=None,
                   help="Config target — enables config generation + validation")
    p.add_argument("--prompt",  default=None,
                   help="Config generation prompt (required when --target is set)")

    # ── dispatch ──────────────────────────────────────────────────────────
    args = parser.parse_args()

    dispatch = {
        "evaluate":      cmd_evaluate,
        "generate":      cmd_generate,
        "remediate":     cmd_remediate,
        "compare":       cmd_compare,
        "analyze":       cmd_analyze_with_mitm,
        "dashboard":     cmd_dashboard,
        "rules":         cmd_rules,
        "mitm":          cmd_mitm,
        "evaluate-mitm": cmd_evaluate_mitm,      # ← NEW
    }

    dispatch[args.command](args)


if __name__ == "__main__":
    main()
