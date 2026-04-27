"""
evaluator/evaluator.py
──────────────────────
Evaluation framework: runs the full pipeline over the synthetic dataset
and computes classification metrics.

Metrics
───────
• Accuracy            = (TP + TN) / N
• Precision (insecure)= TP / (TP + FP)   — of configs we flagged as insecure, how many were?
• Recall (insecure)   = TP / (TP + FN)   — of truly insecure configs, how many did we catch?
• F1 (insecure)       = harmonic mean of precision and recall
• False Positive Rate = FP / (FP + TN)   — of safe configs, how many did we wrongly flag?
• Risk score stats    — mean/std per category

Predicted label
───────────────
A configuration is predicted INSECURE if the validator finds ≥1 violation.
This is intentionally conservative for a security tool.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from config import (
    ConfigTarget,
    EvaluationRecord,
    EvaluationSample,
    OUTPUT_DIR,
)
from generator import LLMConfigGenerator
from validator import ValidationEngine
from observability import PipelineLogger

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Metrics container
# ---------------------------------------------------------------------------

@dataclass
class EvaluationMetrics:
    total:         int = 0
    correct:       int = 0
    tp:            int = 0   # True Positive  (predicted insecure, actually insecure)
    tn:            int = 0   # True Negative  (predicted secure,   actually secure)
    fp:            int = 0   # False Positive (predicted insecure, actually secure)
    fn:            int = 0   # False Negative (predicted secure,   actually insecure)
    risk_scores:   dict[str, list[float]] = field(default_factory=dict)  # category → scores

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    def to_dict(self) -> dict:
        import statistics
        risk_summary = {}
        for cat, scores in self.risk_scores.items():
            risk_summary[cat] = {
                "mean": round(statistics.mean(scores), 3) if scores else 0,
                "std":  round(statistics.stdev(scores), 3) if len(scores) > 1 else 0,
                "n":    len(scores),
            }
        return {
            "total":              self.total,
            "correct":            self.correct,
            "accuracy":           round(self.accuracy,           3),
            "precision_insecure": round(self.precision,          3),
            "recall_insecure":    round(self.recall,             3),
            "f1_insecure":        round(self.f1,                 3),
            "false_positive_rate":round(self.false_positive_rate,3),
            "confusion_matrix":   {"TP": self.tp, "TN": self.tn, "FP": self.fp, "FN": self.fn},
            "risk_score_by_category": risk_summary,
        }


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

class Evaluator:
    """
    Runs the generate → validate pipeline for every sample in the dataset
    and computes aggregate metrics.

    Parameters
    ──────────
    dataset_path  : path to JSON file containing EvaluationSample records
    generator     : LLMConfigGenerator instance
    engine        : ValidationEngine instance
    pipeline_log  : PipelineLogger instance
    delay_seconds : inter-request delay to respect rate limits
    max_samples   : cap evaluation size (useful for quick smoke tests)
    """

    def __init__(
        self,
        dataset_path: str,
        generator: LLMConfigGenerator,
        engine: ValidationEngine,
        pipeline_log: PipelineLogger,
        delay_seconds: float = 1.5,
        max_samples: Optional[int] = None,
    ) -> None:
        self.dataset_path  = dataset_path
        self.generator     = generator
        self.engine        = engine
        self.pipeline_log  = pipeline_log
        self.delay_seconds = delay_seconds
        self.max_samples   = max_samples

    # ------------------------------------------------------------------
    def load_dataset(self) -> list[EvaluationSample]:
        with open(self.dataset_path, encoding="utf-8") as f:
            raw = json.load(f)
        samples = [
            EvaluationSample(
                sample_id       = r["sample_id"],
                prompt          = r["prompt"],
                target          = ConfigTarget(r["target"]),
                expected_secure = r["expected_secure"],
                category        = r["category"],
                notes           = r.get("notes", ""),
            )
            for r in raw
        ]
        if self.max_samples:
            samples = samples[: self.max_samples]
        logger.info("Loaded %d samples from dataset", len(samples))
        return samples

    # ------------------------------------------------------------------
    def run(self) -> tuple[list[EvaluationRecord], EvaluationMetrics]:
        samples = self.load_dataset()
        records: list[EvaluationRecord] = []
        metrics = EvaluationMetrics()

        for i, sample in enumerate(samples, 1):
            logger.info(
                "── Sample %d/%d  [%s] %s ──",
                i, len(samples), sample.sample_id, sample.category.upper(),
            )

            # 1. Generate
            gen_result = self.generator.generate(sample.prompt, sample.target)
            self.pipeline_log.log_generation(gen_result)

            # 2. Validate
            if gen_result.success:
                val_result = self.engine.validate(gen_result.raw_config, sample.target)
            else:
                # Generation failed — treat as insecure (conservative)
                from config import ValidationResult, Violation, Severity
                val_result = ValidationResult(
                    config_target=sample.target.value,
                    raw_config="",
                    violations=[Violation(
                        rule_id="SYS-002",
                        description="LLM generation failed",
                        severity=Severity.HIGH,
                        evidence=gen_result.error or "unknown",
                    )],
                    is_secure=False,
                    risk_score=1.0,
                )
            self.pipeline_log.log_validation(val_result)

            # 3. Predict (conservative: any violation → insecure)
            predicted_secure = val_result.is_secure
            correct          = predicted_secure == sample.expected_secure

            rec = EvaluationRecord(
                sample=sample,
                generation=gen_result,
                validation=val_result,
                predicted_secure=predicted_secure,
                correct=correct,
            )
            records.append(rec)
            self.pipeline_log.log_evaluation(rec)

            # 4. Update metrics
            metrics.total   += 1
            metrics.correct += int(correct)

            truly_insecure = not sample.expected_secure
            pred_insecure  = not predicted_secure

            if truly_insecure and pred_insecure:
                metrics.tp += 1
            elif not truly_insecure and not pred_insecure:
                metrics.tn += 1
            elif not truly_insecure and pred_insecure:
                metrics.fp += 1
            else:
                metrics.fn += 1

            cat = sample.category
            metrics.risk_scores.setdefault(cat, []).append(val_result.risk_score)

            # 5. Rate-limit pause
            if i < len(samples):
                time.sleep(self.delay_seconds)

        return records, metrics

    # ------------------------------------------------------------------
    def save_results(
        self,
        records: list[EvaluationRecord],
        metrics: EvaluationMetrics,
        run_id: str,
    ) -> dict[str, str]:
        """Persist detailed results and metrics. Returns paths dict."""
        os.makedirs(OUTPUT_DIR, exist_ok=True)

        # ── Per-sample details ─────────────────────────────────────────
        details = []
        for rec in records:
            details.append({
                "sample_id":        rec.sample.sample_id,
                "category":         rec.sample.category,
                "target":           rec.sample.target.value,
                "expected_secure":  rec.sample.expected_secure,
                "predicted_secure": rec.predicted_secure,
                "correct":          rec.correct,
                "risk_score":       rec.validation.risk_score if rec.validation else None,
                "violation_count":  len(rec.validation.violations) if rec.validation else 0,
                "violations":       [v.to_dict() for v in rec.validation.violations] if rec.validation else [],
                "generated_config": rec.generation.raw_config if rec.generation else "",
                "prompt":           rec.sample.prompt,
                "notes":            rec.sample.notes,
            })

        details_path = os.path.join(OUTPUT_DIR, f"run_{run_id}_details.json")
        with open(details_path, "w", encoding="utf-8") as f:
            json.dump(details, f, indent=2)

        # ── Metrics summary ────────────────────────────────────────────
        metrics_path = os.path.join(OUTPUT_DIR, f"run_{run_id}_metrics.json")
        with open(metrics_path, "w", encoding="utf-8") as f:
            json.dump(metrics.to_dict(), f, indent=2)

        logger.info("Results saved: %s  |  Metrics: %s", details_path, metrics_path)
        return {"details": details_path, "metrics": metrics_path}
