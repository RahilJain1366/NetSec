"""
remediator/remediator.py
────────────────────────
Auto-remediation engine.

Pipeline
────────
  Insecure Config
       │
       ▼
  Validator  ──► Violations
       │
       ▼
  LLM Patcher  ──► Fixed Config
       │
       ▼
  Validator  ──► Remaining Violations?
       │
  (loop up to max_iterations)
       │
       ▼
  RemediationResult
    - original_config
    - final_config
    - unified_diff
    - iterations
    - violations_before / after
    - fully_remediated (bool)

Design decisions
────────────────
• Prompt is violation-aware: we tell the LLM exactly which rules fired and why,
  so it targets fixes precisely rather than rewriting the whole config.
• We cap iterations at 3 to prevent infinite loops on edge cases.
• difflib.unified_diff gives a standard patch-style diff (no extra dependencies).
• Each iteration's state is recorded for traceability.
"""

from __future__ import annotations

import difflib
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from config import ConfigTarget, Violation, ValidationResult
from validator.engine import ValidationEngine

logger = logging.getLogger(__name__)

# ── Remediation prompt template ───────────────────────────────────────────────
_REMEDIATION_SYSTEM = """You are a network security configuration remediation expert.
You will receive a configuration file that has known security violations.
Your job is to fix ONLY the reported violations — do not restructure or rewrite
sections that are already correct.

RULES
─────
1. Output ONLY the fixed configuration inside a fenced code block.
2. Fix every listed violation. Do not introduce new issues.
3. Preserve all existing correct directives exactly as-is.
4. Add inline comments on changed lines starting with  # FIXED:
5. No prose, no explanations outside the code block.
"""

def _remediation_prompt(
    config: str,
    target: ConfigTarget,
    violations: list[Violation],
) -> str:
    violation_list = "\n".join(
        f"  [{v.severity.value}] {v.rule_id}: {v.description}\n"
        f"    Evidence: {v.evidence}"
        for v in violations
    )
    return (
        f"Target: {target.value}\n\n"
        f"Security violations to fix:\n{violation_list}\n\n"
        f"Original config:\n```{target.value}\n{config}\n```\n\n"
        f"Return the fully fixed {target.value} config in a fenced code block."
    )


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class RemediationIteration:
    iteration:        int
    config:           str
    violations_found: list[Violation]
    risk_score:       float

@dataclass
class RemediationResult:
    target:              ConfigTarget
    original_config:     str
    final_config:        str
    unified_diff:        str
    inline_diff:         list[dict]          # line-by-line for UI rendering
    iterations_taken:    int
    max_iterations:      int
    violations_before:   list[Violation]
    violations_after:    list[Violation]
    fully_remediated:    bool
    risk_before:         float
    risk_after:          float
    history:             list[RemediationIteration] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target":            self.target.value,
            "fully_remediated":  self.fully_remediated,
            "iterations_taken":  self.iterations_taken,
            "risk_before":       round(self.risk_before, 3),
            "risk_after":        round(self.risk_after, 3),
            "violations_before": len(self.violations_before),
            "violations_after":  len(self.violations_after),
            "unified_diff":      self.unified_diff,
            "inline_diff":       self.inline_diff,
            "violations_detail_before": [v.to_dict() for v in self.violations_before],
            "violations_detail_after":  [v.to_dict() for v in self.violations_after],
        }


# ── Diff helpers ──────────────────────────────────────────────────────────────

def _build_unified_diff(original: str, fixed: str, target: str) -> str:
    """Standard unified diff string."""
    orig_lines  = original.splitlines(keepends=True)
    fixed_lines = fixed.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines, fixed_lines,
        fromfile=f"original.{target}",
        tofile=f"remediated.{target}",
        lineterm="",
    )
    return "".join(diff)


def _build_inline_diff(original: str, fixed: str) -> list[dict]:
    """
    Line-by-line diff for UI rendering.
    Each entry: { type: 'equal'|'added'|'removed', line: str }
    """
    orig_lines  = original.splitlines()
    fixed_lines = fixed.splitlines()
    sm = difflib.SequenceMatcher(None, orig_lines, fixed_lines)
    result = []
    for opcode, i1, i2, j1, j2 in sm.get_opcodes():
        if opcode == "equal":
            for line in orig_lines[i1:i2]:
                result.append({"type": "equal", "line": line})
        elif opcode == "replace":
            for line in orig_lines[i1:i2]:
                result.append({"type": "removed", "line": line})
            for line in fixed_lines[j1:j2]:
                result.append({"type": "added", "line": line})
        elif opcode == "delete":
            for line in orig_lines[i1:i2]:
                result.append({"type": "removed", "line": line})
        elif opcode == "insert":
            for line in fixed_lines[j1:j2]:
                result.append({"type": "added", "line": line})
    return result


# ── Main engine ───────────────────────────────────────────────────────────────

class RemediationEngine:
    """
    Iteratively patches insecure configurations using an LLM,
    re-validating after each patch until clean or max_iterations reached.

    Parameters
    ──────────
    generator     : LLMConfigGenerator (or compatible)
    engine        : ValidationEngine
    max_iterations: maximum patch-validate cycles (default 3)
    delay_seconds : pause between API calls
    """

    def __init__(
        self,
        generator,
        engine: ValidationEngine,
        max_iterations: int = 3,
        delay_seconds: float = 2.0,
    ) -> None:
        self.generator      = generator
        self.engine         = engine
        self.max_iterations = max_iterations
        self.delay_seconds  = delay_seconds

    # ── Public API ────────────────────────────────────────────────────────────
    def remediate(
        self,
        config: str,
        target: ConfigTarget,
        initial_validation: Optional[ValidationResult] = None,
    ) -> RemediationResult:
        """
        Attempt to remediate *config* for *target*.

        If *initial_validation* is supplied it is used as the first validation
        result (saves one API call when called right after generate+validate).
        """
        # Initial validation
        if initial_validation is not None:
            val = initial_validation
        else:
            val = self.engine.validate(config, target)

        violations_before = list(val.violations)
        risk_before       = val.risk_score
        history: list[RemediationIteration] = [
            RemediationIteration(0, config, list(val.violations), val.risk_score)
        ]

        if not val.violations:
            logger.info("Config already clean — no remediation needed")
            return self._build_result(
                target, config, config, violations_before, [],
                risk_before, 0.0, 0, history,
            )

        current_config = config
        current_val    = val

        for iteration in range(1, self.max_iterations + 1):
            logger.info(
                "Remediation iteration %d/%d | violations=%d",
                iteration, self.max_iterations, len(current_val.violations),
            )

            # Build remediation prompt and call LLM
            user_prompt = _remediation_prompt(
                current_config, target, current_val.violations
            )

            # Reuse the generator's internal call mechanism
            patched_result = self.generator.generate(user_prompt, target)

            if not patched_result.success or not patched_result.raw_config:
                logger.warning("Remediation LLM call failed on iteration %d", iteration)
                break

            patched_config = patched_result.raw_config

            # Re-validate
            time.sleep(self.delay_seconds)
            new_val = self.engine.validate(patched_config, target)
            history.append(
                RemediationIteration(
                    iteration, patched_config,
                    list(new_val.violations), new_val.risk_score,
                )
            )

            current_config = patched_config
            current_val    = new_val

            logger.info(
                "After iteration %d: violations=%d risk=%.3f",
                iteration, len(new_val.violations), new_val.risk_score,
            )

            if not new_val.violations:
                logger.info("✓ Fully remediated after %d iteration(s)", iteration)
                break

            time.sleep(self.delay_seconds)

        return self._build_result(
            target, config, current_config,
            violations_before, current_val.violations,
            risk_before, current_val.risk_score,
            len(history) - 1,   # iterations taken (excluding iteration 0)
            history,
        )

    # ── Internal ──────────────────────────────────────────────────────────────
    def _build_result(
        self,
        target:            ConfigTarget,
        original:          str,
        final:             str,
        violations_before: list[Violation],
        violations_after:  list[Violation],
        risk_before:       float,
        risk_after:        float,
        iterations:        int,
        history:           list[RemediationIteration],
    ) -> RemediationResult:
        unified = _build_unified_diff(original, final, target.value)
        inline  = _build_inline_diff(original, final)
        return RemediationResult(
            target=target,
            original_config=original,
            final_config=final,
            unified_diff=unified,
            inline_diff=inline,
            iterations_taken=iterations,
            max_iterations=self.max_iterations,
            violations_before=violations_before,
            violations_after=violations_after,
            fully_remediated=len(violations_after) == 0,
            risk_before=risk_before,
            risk_after=risk_after,
            history=history,
        )
