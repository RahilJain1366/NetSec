"""
comparator/comparator.py
────────────────────────
Multi-LLM comparison engine.

Runs the same dataset through two different models and produces
a side-by-side comparison report:

  Model A (llama-3.1-8b-instant)  vs  Model B (mixtral-8x7b-32768)
  ─────────────────────────────────────────────────────────────────
  Per-sample: predicted label, violations, risk score, correct?
  Aggregate:  accuracy, precision, recall, F1 per model
  Delta:      where models agree/disagree, which is better

Output
──────
  outputs/comparison_<run_id>.json   — full per-sample data
  outputs/comparison_<run_id>_summary.json — aggregate metrics
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from config import ConfigTarget, EvaluationSample, OUTPUT_DIR
from generator.llm_generator import LLMConfigGenerator
from validator.engine import ValidationEngine
from evaluator.evaluator import EvaluationMetrics

logger = logging.getLogger(__name__)


# ── Per-sample comparison record ─────────────────────────────────────────────

@dataclass
class ComparisonRecord:
    sample_id:        str
    prompt:           str
    target:           str
    category:         str
    expected_secure:  bool

    # Model A
    model_a_name:     str
    model_a_config:   str
    model_a_secure:   bool
    model_a_risk:     float
    model_a_violations: list[dict]
    model_a_correct:  bool

    # Model B
    model_b_name:     str
    model_b_config:   str
    model_b_secure:   bool
    model_b_risk:     float
    model_b_violations: list[dict]
    model_b_correct:  bool

    # Agreement
    models_agree:     bool
    winner:           str   # "model_a" | "model_b" | "tie" | "both_wrong"

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class ComparisonSummary:
    model_a_name:    str
    model_b_name:    str
    total_samples:   int
    model_a_metrics: dict
    model_b_metrics: dict
    agreement_rate:  float
    model_a_wins:    int
    model_b_wins:    int
    ties:            int
    both_wrong:      int
    avg_risk_diff:   float   # mean |risk_a - risk_b|

    def to_dict(self) -> dict:
        return {
            "model_a": self.model_a_name,
            "model_b": self.model_b_name,
            "total_samples":   self.total_samples,
            "agreement_rate":  round(self.agreement_rate, 3),
            "model_a_wins":    self.model_a_wins,
            "model_b_wins":    self.model_b_wins,
            "ties":            self.ties,
            "both_wrong":      self.both_wrong,
            "avg_risk_diff":   round(self.avg_risk_diff, 3),
            "model_a_metrics": self.model_a_metrics,
            "model_b_metrics": self.model_b_metrics,
        }


# ── Comparator ───────────────────────────────────────────────────────────────

class LLMComparator:
    """
    Runs the same samples through two LLM generators and compares results.

    Parameters
    ──────────
    model_a_name / model_b_name : Groq model strings
    engine                      : shared ValidationEngine
    delay_seconds               : pause between calls (rate limiting)
    max_samples                 : cap for quick tests
    """

    def __init__(
        self,
        model_a_name: str,
        model_b_name: str,
        engine: ValidationEngine,
        delay_seconds: float = 10.0,
        max_samples: Optional[int] = None,
    ) -> None:
        self.gen_a  = LLMConfigGenerator(model=model_a_name)
        self.gen_b  = LLMConfigGenerator(model=model_b_name)
        self.engine = engine
        self.delay  = delay_seconds
        self.max_samples = max_samples
        self.model_a_name = model_a_name
        self.model_b_name = model_b_name

    # ── Main run ──────────────────────────────────────────────────────────────
    def run(
        self, samples: list[EvaluationSample]
    ) -> tuple[list[ComparisonRecord], ComparisonSummary]:

        if self.max_samples:
            samples = samples[: self.max_samples]

        records: list[ComparisonRecord] = []

        # Metrics accumulators
        metrics_a = EvaluationMetrics()
        metrics_b = EvaluationMetrics()
        risk_diffs: list[float] = []
        agree = wins_a = wins_b = ties = both_wrong = 0

        for i, sample in enumerate(samples, 1):
            logger.info(
                "Comparing sample %d/%d [%s] %s",
                i, len(samples), sample.sample_id, sample.category,
            )

            # ── Model A ───────────────────────────────────────────────────────
            gen_a = self.gen_a.generate(sample.prompt, sample.target)
            time.sleep(self.delay)
            val_a = self.engine.validate(
                gen_a.raw_config if gen_a.success else "",
                sample.target,
            )
            time.sleep(self.delay)

            # ── Model B ───────────────────────────────────────────────────────
            gen_b = self.gen_b.generate(sample.prompt, sample.target)
            time.sleep(self.delay)
            val_b = self.engine.validate(
                gen_b.raw_config if gen_b.success else "",
                sample.target,
            )
            time.sleep(self.delay)

            # ── Evaluate ──────────────────────────────────────────────────────
            pred_a  = val_a.is_secure
            pred_b  = val_b.is_secure
            corr_a  = pred_a == sample.expected_secure
            corr_b  = pred_b == sample.expected_secure

            _update_metrics(metrics_a, sample.expected_secure, pred_a)
            _update_metrics(metrics_b, sample.expected_secure, pred_b)

            risk_diffs.append(abs(val_a.risk_score - val_b.risk_score))

            # Agreement / winner
            models_agree = pred_a == pred_b
            if models_agree:
                agree += 1
                if corr_a:
                    ties += 1
                    winner = "tie"
                else:
                    both_wrong += 1
                    winner = "both_wrong"
            elif corr_a and not corr_b:
                wins_a += 1
                winner = "model_a"
            elif corr_b and not corr_a:
                wins_b += 1
                winner = "model_b"
            else:
                both_wrong += 1
                winner = "both_wrong"

            records.append(ComparisonRecord(
                sample_id=sample.sample_id,
                prompt=sample.prompt,
                target=sample.target.value,
                category=sample.category,
                expected_secure=sample.expected_secure,
                model_a_name=self.model_a_name,
                model_a_config=gen_a.raw_config if gen_a.success else "",
                model_a_secure=pred_a,
                model_a_risk=round(val_a.risk_score, 3),
                model_a_violations=[v.to_dict() for v in val_a.violations],
                model_a_correct=corr_a,
                model_b_name=self.model_b_name,
                model_b_config=gen_b.raw_config if gen_b.success else "",
                model_b_secure=pred_b,
                model_b_risk=round(val_b.risk_score, 3),
                model_b_violations=[v.to_dict() for v in val_b.violations],
                model_b_correct=corr_b,
                models_agree=models_agree,
                winner=winner,
            ))

            logger.info(
                "  A=%s(%.3f) B=%s(%.3f) agree=%s winner=%s",
                "secure" if pred_a else "insecure", val_a.risk_score,
                "secure" if pred_b else "insecure", val_b.risk_score,
                models_agree, winner,
            )

        summary = ComparisonSummary(
            model_a_name=self.model_a_name,
            model_b_name=self.model_b_name,
            total_samples=len(samples),
            model_a_metrics=metrics_a.to_dict(),
            model_b_metrics=metrics_b.to_dict(),
            agreement_rate=agree / len(samples) if samples else 0,
            model_a_wins=wins_a,
            model_b_wins=wins_b,
            ties=ties,
            both_wrong=both_wrong,
            avg_risk_diff=sum(risk_diffs) / len(risk_diffs) if risk_diffs else 0,
        )

        return records, summary

    # ── Save ──────────────────────────────────────────────────────────────────
    def save(
        self,
        records: list[ComparisonRecord],
        summary: ComparisonSummary,
        run_id: str,
    ) -> dict[str, str]:
        os.makedirs(OUTPUT_DIR, exist_ok=True)

        rec_path = os.path.join(OUTPUT_DIR, f"comparison_{run_id}_records.json")
        sum_path = os.path.join(OUTPUT_DIR, f"comparison_{run_id}_summary.json")

        with open(rec_path, "w") as f:
            json.dump([r.to_dict() for r in records], f, indent=2)
        with open(sum_path, "w") as f:
            json.dump(summary.to_dict(), f, indent=2)

        logger.info("Comparison saved: %s | %s", rec_path, sum_path)
        return {"records": rec_path, "summary": sum_path}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _update_metrics(m: EvaluationMetrics, expected_secure: bool, predicted_secure: bool) -> None:
    m.total   += 1
    correct    = predicted_secure == expected_secure
    m.correct += int(correct)
    truly_insecure = not expected_secure
    pred_insecure  = not predicted_secure
    if truly_insecure and pred_insecure:
        m.tp += 1
    elif not truly_insecure and not pred_insecure:
        m.tn += 1
    elif not truly_insecure and pred_insecure:
        m.fp += 1
    else:
        m.fn += 1
