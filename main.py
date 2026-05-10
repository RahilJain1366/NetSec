"""
main.py — CLI entry point for the network config security pipeline.

Commands
────────
  evaluate   — Run full evaluation over dataset
  generate   — Generate + validate a single config
  remediate  — Generate, validate, and auto-fix a config
  compare    — Compare two LLMs on the dataset
  analyze    — Generate config + validate + analyze MITM risks
  dashboard  — Launch the web UI
  rules      — List security rules for a target
  mitm       — Run MITM attack detection
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
    print(f"  Secure    : {val.is_secure}")
    print(f"  Risk Score: {val.risk_score:.3f}")
    if val.violations:
        print(f"  Violations ({len(val.violations)}):")
        for v in val.violations:
            print(f"    [{v.severity.value}] {v.rule_id} — {v.description}")
            print(f"           Evidence: {v.evidence}")
    else:
        print("  ✓ No violations detected")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, f"single_{run_id}_{target.value}.json")
    with open(out_path, "w") as f:
        json.dump({"prompt": args.prompt, "target": target.value,
                   "config": gen_result.raw_config, "validation": val.to_dict()}, f, indent=2)
    print(f"\n  Output saved → {out_path}")
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
    print(f"  Secure: {val.is_secure}  Risk: {val.risk_score:.3f}  Violations: {len(val.violations)}")

    if not val.violations:
        print("\n  ✓ Config is already secure — no remediation needed.")
        return

    print(f"\n[Remediating (max {args.max_iter} iterations)...]\n")
    result = rem.remediate(gen_result.raw_config, target, initial_validation=val)

    print("─── Remediation Result ───")
    print(f"  Fully remediated : {result.fully_remediated}")
    print(f"  Iterations taken : {result.iterations_taken}")
    print(f"  Risk before      : {result.risk_before:.3f}")
    print(f"  Risk after       : {result.risk_after:.3f}")
    print(f"  Violations before: {len(result.violations_before)}")
    print(f"  Violations after : {len(result.violations_after)}")

    print("\n─── Diff ───")
    if result.unified_diff:
        print(result.unified_diff)
    else:
        print("  (no changes)")

    if result.violations_after:
        print("\n─── Remaining Violations ───")
        for v in result.violations_after:
            print(f"  [{v.severity.value}] {v.rule_id} — {v.description}")

    # Save
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, f"remediation_{run_id}_{target.value}.json")
    with open(out_path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    print(f"\n  Output saved → {out_path}\n")


# ── compare ───────────────────────────────────────────────────────────────────

def cmd_compare(args):
    import json as _json
    from comparator import LLMComparator
    from evaluator.evaluator import Evaluator

    run_id = setup_logging()
    logger.info("═══ Model comparison run [run_id=%s] ═══", run_id)

    engine = ValidationEngine()
    comp   = LLMComparator(
        model_a_name  = args.model_a,
        model_b_name  = args.model_b,
        engine        = engine,
        delay_seconds = args.delay,
        max_samples   = args.max_samples,
    )

    # Load samples via Evaluator loader
    from evaluator.evaluator import Evaluator as Ev
    ev = Ev(DATASET_PATH, LLMConfigGenerator(), engine,
            PipelineLogger(run_id, OUTPUT_DIR),
            max_samples=args.max_samples)
    samples = ev.load_dataset()

    records, summary = comp.run(samples)
    paths = comp.save(records, summary, run_id)

    s = summary.to_dict()
    print("\n" + "═" * 60)
    print(f"  COMPARISON SUMMARY   run_id={run_id}")
    print("═" * 60)
    print(f"  Model A : {s['model_a']}")
    print(f"  Model B : {s['model_b']}")
    print(f"  Samples : {s['total_samples']}")
    print(f"  Agreement rate : {s['agreement_rate']:.1%}")
    print(f"  Model A wins   : {s['model_a_wins']}")
    print(f"  Model B wins   : {s['model_b_wins']}")
    print(f"  Ties           : {s['ties']}")
    print(f"  Both wrong     : {s['both_wrong']}")
    print(f"\n  Model A — Accuracy: {s['model_a_metrics']['accuracy']:.1%}  F1: {s['model_a_metrics']['f1_insecure']:.1%}")
    print(f"  Model B — Accuracy: {s['model_b_metrics']['accuracy']:.1%}  F1: {s['model_b_metrics']['f1_insecure']:.1%}")
    print("═" * 60)
    print(f"\n  Records → {paths['records']}")
    print(f"  Summary → {paths['summary']}\n")


# ── dashboard ─────────────────────────────────────────────────────────────────

def cmd_dashboard(args):
    setup_logging()
    print("\n  🔐 NetConfig Security Dashboard")
    print(f"  Open → http://localhost:{args.port}\n")
    # Import here so Flask isn't required for other commands
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

def cmd_mitm(args):
    """Run MITM attack detection analysis."""
    setup_logging()
    from mitm import MITMNetworkAnalyzer, MITMReporter
    
    analyzer = MITMNetworkAnalyzer()
    
    # Choose analysis mode
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
            iface=args.interface, 
            count=args.count, 
            timeout=args.timeout
        )
    
    # Print results
    print("─── MITM Analysis Results ───")
    print(f"  Mode             : {result.mode}")
    print(f"  Packets analyzed : {result.packets_seen}")
    print(f"  Duration         : {result.duration_secs:.2f}s")
    print(f"  Risk score       : {result.risk_score:.3f}")
    print(f"  Indicators found : {len(result.indicators)}")
    
    if result.indicators:
        print("\n─── Detected MITM Indicators ───")
        for ind in result.indicators:
            print(f"  [{ind.severity}] {ind.attack_type:20s} — {ind.description}")
            print(f"         Evidence: {ind.evidence}")
    
    # Save results
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, f"mitm_{uuid.uuid4().hex[:8]}_{args.mode}.json")
    with open(out_path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    print(f"\n  Output saved → {out_path}\n")

# ── analyze ───────────────────────────────────────────────────────────────────

def cmd_analyze_with_mitm(args):
    """Generate config, validate, and show MITM vulnerabilities."""
    from mitm import MITMNetworkAnalyzer, MITMReporter
    
    run_id = setup_logging()
    target = ConfigTarget(args.target)
    gen    = LLMConfigGenerator()
    engine = ValidationEngine()
    plog   = PipelineLogger(run_id, OUTPUT_DIR)
    
    # Step 1: Generate
    print(f"\n[1/4] Generating {target.value} config...\n")
    gen_result = gen.generate(args.prompt, target)
    plog.log_generation(gen_result)
    
    if not gen_result.success:
        print(f"[ERROR] Generation failed: {gen_result.error}")
        return
    
    print("─── Generated Configuration ───")
    print(gen_result.raw_config)
    
    # Step 2: Validate
    print("\n[2/4] Validating configuration...")
    val = engine.validate(gen_result.raw_config, target)
    plog.log_validation(val)
    print(f"  Secure    : {val.is_secure}")
    print(f"  Risk Score: {val.risk_score:.3f}")
    print(f"  Violations: {len(val.violations)}")
    
    # Step 3: MITM Analysis
    print("\n[3/4] Running MITM network analysis...")
    analyzer = MITMNetworkAnalyzer()
    mitm_result = analyzer.run_demo()
    print(f"  MITM Risk Score: {mitm_result.risk_score:.3f}")
    print(f"  Indicators     : {len(mitm_result.indicators)}")
    
    # Step 4: Generate integrated report
    print("\n[4/4] Generating integrated attack path report...")
    reporter = MITMReporter()
    report = reporter.generate(
        target=target.value,
        config_result=val,
        network_result=mitm_result
    )
    
    # Display results
    print("\n" + "═" * 70)
    print("  INTEGRATED SECURITY ANALYSIS")
    print("═" * 70)
    print(f"\n  Config Risk Score      : {report.config_risk:.3f}")
    print(f"  Network Risk Score     : {report.network_risk:.3f}")
    print(f"  Combined Risk Score    : {report.combined_risk:.3f}")
    print(f"  Target at MITM Risk    : {report.fully_at_risk}")
    
    print(f"\n  Config Violations      : {len(report.config_findings)}")
    print(f"  MITM Indicators        : {len(report.network_findings)}")
    
    if report.config_findings:
        print("\n  ─── Config Vulnerabilities ───")
        for viol in report.config_findings:
            print(f"    [{viol['severity']}] {viol['rule_id']} — {viol['description']}")
    
    if report.network_findings:
        print("\n  ─── MITM Indicators Detected ───")
        for ind in report.network_findings:
            print(f"    [{ind['severity']}] {ind['attack_type']} — {ind['description']}")
    
    print("\n  ─── Attack Path (ordered by phase) ───")
    for step in report.attack_path:
        print(f"\n    Phase: {step.phase}")
        for finding in step.findings:
            print(f"      • {finding}")
    
    print(f"\n  Summary: {report.summary}")
    print("═" * 70)
    
    # Save results
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, f"analyze_{run_id}_{target.value}.json")
    with open(out_path, "w") as f:
        json.dump(report.to_dict(), f, indent=2)
    print(f"\n  Output saved → {out_path}\n")
    plog.flush()

def cmd_evaluate_with_mitm(args):
    """Evaluate dataset end-to-end: generation → validation → MITM analysis."""
    from mitm import MITMNetworkAnalyzer, DatasetMITMAnalyzer, MITMReporter

    run_id = setup_logging()
    logger.info("═══ E2E evaluation with MITM [run_id=%s] ═══", run_id)

    gen    = LLMConfigGenerator()
    engine = ValidationEngine()
    plog   = PipelineLogger(run_id, OUTPUT_DIR)

    mitm_mode = "dataset" if args.mitm_mode == "traffic-dataset" else args.mitm_mode

    # Load dataset via Evaluator helper
    ev = Evaluator(DATASET_PATH, gen, engine, plog, max_samples=args.max_samples)
    samples = ev.load_dataset()

    analyzer = DatasetMITMAnalyzer() if mitm_mode == "dataset" else MITMNetworkAnalyzer()
    reporter = MITMReporter()

    dataset_net_res = None
    if mitm_mode == "dataset":
        if not args.traffic_dataset:
            print("[ERROR] --traffic-dataset required for dataset mode")
            return
        if not os.path.exists(args.traffic_dataset):
            print(f"[ERROR] Traffic dataset not found: {args.traffic_dataset}")
            return
        try:
            dataset_net_res = analyzer.analyze_dataset_file(
                args.traffic_dataset,
                max_traffic_rows=args.max_traffic_rows,
            )
            logger.info(
                "Loaded dataset traffic analysis once for %s | flows=%d indicators=%d risk=%.3f",
                args.traffic_dataset,
                getattr(dataset_net_res, "total_flows", 0),
                len(getattr(dataset_net_res, "indicators", [])),
                getattr(dataset_net_res, "risk_score", 0.0),
            )
        except Exception as exc:
            print(f"[ERROR] Failed to analyze traffic dataset: {exc}")
            return

    results = []
    for i, s in enumerate(samples, 1):
        logger.info("Sample %d/%d id=%s target=%s", i, len(samples), s.sample_id, s.target)
        gen_result = gen.generate(s.prompt, s.target)
        plog.log_generation(gen_result)

        val = engine.validate(gen_result.raw_config, s.target)
        plog.log_validation(val)

        if mitm_mode == "demo":
            net_res = analyzer.run_demo()
        elif mitm_mode == "pcap":
            if args.mitm_pcap_folder:
                p = os.path.join(args.mitm_pcap_folder, f"{s.sample_id}.pcap")
                net_res = analyzer.analyze_pcap(p) if os.path.exists(p) else analyzer.run_demo()
            else:
                net_res = analyzer.run_demo()
        elif mitm_mode == "dataset":
            net_res = dataset_net_res
        else:  # live
            net_res = analyzer.capture_live(iface=args.interface, count=args.count, timeout=args.timeout)

        mitm_report = reporter.generate(target=s.target.value, config_result=val, network_result=net_res)
        plog.log_event("evaluate_mitm_sample", {"sample_id": s.sample_id})

        results.append({
            "sample_id": s.sample_id,
            "target": s.target.value,
            "prompt": s.prompt,
            "generation": {"success": gen_result.success, "model": gen_result.model},
            "validation": val.to_dict(),
            "mitm_report": mitm_report.to_dict(),
        })

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, f"e2e_mitm_{run_id}.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info("Saved E2E MITM results → %s", out_path)
    print(f"\n  Results saved → {out_path}")
    plog.flush()

# ── CLI wiring ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Network Config Security Pipeline")
    sub = parser.add_subparsers(dest="command", required=True)

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
    p.add_argument("--mode", required=True, choices=["demo", "pcap", "live"],
                help="Analysis mode: demo (simulation), pcap (file), or live (capture)")
    p.add_argument("--pcap-file", help="Path to PCAP file (required for pcap mode)")
    p.add_argument("--interface", help="Network interface (required for live mode)")
    p.add_argument("--count", type=int, default=500, help="Number of packets to capture (live mode)")
    p.add_argument("--timeout", type=int, default=60, help="Capture timeout in seconds (live mode)")
    # analyze
    p = sub.add_parser("analyze", help="Generate + validate + analyze MITM risks")
    p.add_argument("--target", required=True, choices=[t.value for t in ConfigTarget])
    p.add_argument("--prompt", required=True)

    # evaluate-mitm
    p = sub.add_parser("evaluate-mitm", help="Run full evaluation + MITM analysis")
    p.add_argument("--max-samples", type=int, default=None)
    p.add_argument("--mitm-mode", choices=["demo","pcap","live","dataset","traffic-dataset"], default="demo")
    p.add_argument("--traffic-dataset", help="Path to traffic dataset (CSV/PCAP/flows) — used by dataset mode")
    p.add_argument("--max-traffic-rows", type=int, default=None, help="Cap the number of traffic rows loaded from --traffic-dataset")
    p.add_argument("--mitm-pcap-folder", help="Folder with pcaps named <sample_id>.pcap (used in pcap mode)")
    p.add_argument("--interface", help="Interface for live capture")
    p.add_argument("--count", type=int, default=500)
    p.add_argument("--timeout", type=int, default=60)
    
    args = parser.parse_args()
    
    dispatch = {
        "evaluate":  cmd_evaluate,
        "generate":  cmd_generate,
        "remediate": cmd_remediate,
        "compare":   cmd_compare,
        "analyze":   cmd_analyze_with_mitm,
        "dashboard": cmd_dashboard,
        "rules":     cmd_rules,
        "mitm":      cmd_mitm,
        "evaluate-mitm": cmd_evaluate_with_mitm,
    }

    dispatch[args.command](args)


if __name__ == "__main__":
    main()
