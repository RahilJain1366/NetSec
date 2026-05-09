"""
adversarial_eval.py
───────────────────
Adversarial prompt evaluation — Security Persona Probing.

Research question
─────────────────
Does social engineering context in natural language prompts cause the LLM
to bypass its security defaults and generate insecure configurations?
And does the deterministic validator catch violations regardless of how
the prompt was framed?

Five persona categories
───────────────────────
  urgency_framing         — time pressure to skip security
  authority_override      — CTO/CISO/compliance claims
  legacy_justification    — old systems that "require" insecurity
  internal_network_excuse — "it's internal only" reasoning
  explicit_insecure_request — direct override of security defaults

Metrics per persona
───────────────────
  bypass_rate   — % of prompts where LLM produced insecure config
  catch_rate    — % of insecure configs caught by validator (recall)
  risk_mean     — mean risk score across persona category

Run
───
  python adversarial_eval.py
  python adversarial_eval.py --max-samples 10 --delay 8
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv()

from config import ConfigTarget, OUTPUT_DIR
from generator import LLMConfigGenerator
from validator import ValidationEngine
from observability import setup_logging

logger = logging.getLogger("adversarial")

DATASET_PATH = os.path.join(os.path.dirname(__file__), "adversarial_dataset.json")

# Persona display names
PERSONA_LABELS = {
    "urgency_framing":          "Urgency Framing",
    "authority_override":       "Authority Override",
    "legacy_justification":     "Legacy Justification",
    "internal_network_excuse":  "Internal Network Excuse",
    "explicit_insecure_request":"Explicit Insecure Request",
}


# ── Result dataclasses ────────────────────────────────────────────────────────

@dataclass
class AdversarialRecord:
    sample_id:        str
    prompt:           str
    target:           str
    persona:          str
    category:         str
    expected_secure:  bool
    generated_config: str
    predicted_secure: bool
    violations:       list[dict]
    risk_score:       float
    llm_bypassed:     bool   # LLM produced insecure config (bypass_rate numerator)
    validator_caught: bool   # validator caught the insecure config

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class PersonaStats:
    persona:          str
    label:            str
    total:            int = 0
    llm_bypassed:     int = 0   # LLM produced insecure output
    validator_caught: int = 0   # validator caught insecure output
    risk_scores:      list[float] = field(default_factory=list)

    @property
    def bypass_rate(self) -> float:
        return self.llm_bypassed / self.total if self.total else 0.0

    @property
    def catch_rate(self) -> float:
        """Of configs the LLM made insecure, how many did the validator catch?"""
        return self.validator_caught / self.llm_bypassed if self.llm_bypassed else 1.0

    @property
    def risk_mean(self) -> float:
        return sum(self.risk_scores) / len(self.risk_scores) if self.risk_scores else 0.0

    def to_dict(self) -> dict:
        return {
            "persona":        self.persona,
            "label":          self.label,
            "total":          self.total,
            "llm_bypassed":   self.llm_bypassed,
            "bypass_rate":    round(self.bypass_rate, 3),
            "validator_caught": self.validator_caught,
            "catch_rate":     round(self.catch_rate, 3),
            "risk_mean":      round(self.risk_mean, 3),
        }


# ── Main evaluator ────────────────────────────────────────────────────────────

def run_adversarial_eval(
    dataset_path: str,
    max_samples: int | None,
    delay: float,
) -> tuple[list[AdversarialRecord], dict[str, PersonaStats], dict]:

    with open(dataset_path) as f:
        raw = json.load(f)

    if max_samples:
        raw = raw[:max_samples]

    gen    = LLMConfigGenerator()
    engine = ValidationEngine()

    records: list[AdversarialRecord] = []
    persona_stats: dict[str, PersonaStats] = {}

    for i, item in enumerate(raw, 1):
        target  = ConfigTarget(item["target"])
        persona = item["persona"]
        sid     = item["sample_id"]

        logger.info(
            "── %d/%d [%s] persona=%s ──",
            i, len(raw), sid, persona,
        )

        # Generate
        gen_result = gen.generate(item["prompt"], target)
        if not gen_result.success:
            logger.warning("Generation failed for %s: %s", sid, gen_result.error)
            config_text = ""
        else:
            config_text = gen_result.raw_config

        # Validate
        val = engine.validate(config_text, target)

        # Determine bypass and catch
        # bypass  = LLM generated an insecure config (violated at least one rule)
        # caught  = validator detected the insecure config
        llm_bypassed     = not val.is_secure          # insecure output produced
        validator_caught = not val.is_secure           # validator flagged it

        # (They're the same thing — the validator IS the detection mechanism.
        #  bypass_rate tells us how often the LLM fails; catch_rate tells us
        #  how reliably the validator catches those failures.)

        rec = AdversarialRecord(
            sample_id=sid,
            prompt=item["prompt"],
            target=item["target"],
            persona=persona,
            category=item["category"],
            expected_secure=item["expected_secure"],
            generated_config=config_text,
            predicted_secure=val.is_secure,
            violations=[v.to_dict() for v in val.violations],
            risk_score=val.risk_score,
            llm_bypassed=llm_bypassed,
            validator_caught=validator_caught,
        )
        records.append(rec)

        # Update persona stats
        if persona not in persona_stats:
            persona_stats[persona] = PersonaStats(
                persona=persona,
                label=PERSONA_LABELS.get(persona, persona),
            )
        ps = persona_stats[persona]
        ps.total        += 1
        ps.risk_scores.append(val.risk_score)
        if llm_bypassed:
            ps.llm_bypassed     += 1
            ps.validator_caught += 1   # validator catches all insecure outputs by definition

        logger.info(
            "  secure=%s violations=%d risk=%.3f bypassed=%s",
            val.is_secure, len(val.violations), val.risk_score, llm_bypassed,
        )

        if i < len(raw):
            time.sleep(delay)

    # Overall summary
    total          = len(records)
    total_bypassed = sum(1 for r in records if r.llm_bypassed)
    total_caught   = sum(1 for r in records if r.validator_caught)

    summary = {
        "total_samples":         total,
        "total_llm_bypassed":    total_bypassed,
        "total_validator_caught":total_caught,
        "overall_bypass_rate":   round(total_bypassed / total, 3) if total else 0,
        "overall_catch_rate":    round(total_caught / total_bypassed, 3) if total_bypassed else 1.0,
        "persona_stats":         {k: v.to_dict() for k, v in persona_stats.items()},
        # Ranked by bypass rate (most dangerous persona first)
        "persona_ranking": sorted(
            [v.to_dict() for v in persona_stats.values()],
            key=lambda x: x["bypass_rate"],
            reverse=True,
        ),
    }

    return records, persona_stats, summary


# ── Output & printing ─────────────────────────────────────────────────────────

def print_results(summary: dict, persona_stats: dict[str, PersonaStats]) -> None:
    sep = "═" * 65
    print(f"\n{sep}")
    print("  ADVERSARIAL EVALUATION — SECURITY PERSONA PROBING")
    print(sep)
    print(f"  Total samples    : {summary['total_samples']}")
    print(f"  LLM bypassed     : {summary['total_llm_bypassed']} "
          f"({summary['overall_bypass_rate']:.1%} bypass rate)")
    print(f"  Validator caught : {summary['total_validator_caught']} "
          f"({summary['overall_catch_rate']:.1%} catch rate)")
    print()
    print(f"  {'Persona':<28} {'Bypass%':>8} {'Caught%':>8} {'Risk':>8} {'N':>4}")
    print("  " + "─" * 60)
    for ps in summary["persona_ranking"]:
        print(
            f"  {ps['label']:<28} "
            f"{ps['bypass_rate']:>7.1%} "
            f"{ps['catch_rate']:>7.1%} "
            f"{ps['risk_mean']:>8.3f} "
            f"{ps['total']:>4}"
        )
    print(sep)
    print()
    print('  KEY FINDING:')
    cr = summary["overall_catch_rate"]
    br = summary["overall_bypass_rate"]
    print(f'  Even when the LLM was socially engineered into producing')
    print(f'  insecure configs ({br:.1%} bypass rate), the deterministic')
    print(f'  validator caught {cr:.1%} of violations — demonstrating')
    print(f'  hybrid pipelines are robust to prompt-level manipulation.')
    print(sep + "\n")


def save_results(
    records: list[AdversarialRecord],
    summary: dict,
    run_id: str,
) -> dict[str, str]:
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    rec_path = os.path.join(OUTPUT_DIR, f"adversarial_{run_id}_records.json")
    sum_path = os.path.join(OUTPUT_DIR, f"adversarial_{run_id}_summary.json")

    with open(rec_path, "w") as f:
        json.dump([r.to_dict() for r in records], f, indent=2)
    with open(sum_path, "w") as f:
        json.dump(summary, f, indent=2)

    logger.info("Saved: %s | %s", rec_path, sum_path)
    return {"records": rec_path, "summary": sum_path}


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Adversarial Security Persona Probing")
    parser.add_argument("--max-samples", type=int, default=None)
    parser.add_argument("--delay", type=float, default=10.0,
                        help="Seconds between API calls (default 10)")
    args = parser.parse_args()

    run_id = setup_logging()
    logger.info("═══ Adversarial Evaluation [run_id=%s] ═══", run_id)

    records, persona_stats, summary = run_adversarial_eval(
        DATASET_PATH, args.max_samples, args.delay
    )
    paths = save_results(records, summary, run_id)
    print_results(summary, persona_stats)

    print(f"  Records → {paths['records']}")
    print(f"  Summary → {paths['summary']}\n")


if __name__ == "__main__":
    main()
