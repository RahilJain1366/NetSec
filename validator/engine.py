"""
validator/engine.py
───────────────────
Deterministic validation engine.

Responsibilities
────────────────
1. Select the applicable rule set for the target config type.
2. Run every rule against the raw config text.
3. Aggregate violations and compute a probabilistic risk score.
4. Return a structured ValidationResult.

Risk Score Formula
──────────────────
  score = 1 - exp(-λ * weighted_severity)

  where weighted_severity = Σ weight[sev] for each violation
        weight: HIGH=3, MEDIUM=1.5, LOW=0.5
        λ = 0.25  (tuned so 2 HIGH violations → ~0.78 risk)

This gives a smooth 0→1 score that saturates toward 1 for many/severe violations.
"""

from __future__ import annotations

import logging
import math
from typing import Optional

from config import (
    ConfigTarget,
    Severity,
    ValidationResult,
    Violation,
)
from .rules_base    import BaseRule
from .rules_nginx   import NGINX_RULES
from .rules_iptables import IPTABLES_RULES
from .rules_dns     import DNS_RULES

logger = logging.getLogger(__name__)

# Severity → numeric weight
_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.HIGH:   3.0,
    Severity.MEDIUM: 1.5,
    Severity.LOW:    0.5,
}

# Saturation parameter
_LAMBDA = 0.25

# Minimum config length to be considered non-empty
_MIN_CONFIG_LEN = 20


class ValidationEngine:
    """
    Runs modular security rules against a configuration text.

    Rules are organized by ConfigTarget.  Custom rules can be injected
    via the *extra_rules* parameter for extensibility.
    """

    _RULE_REGISTRY: dict[ConfigTarget, list[BaseRule]] = {
        ConfigTarget.NGINX:    NGINX_RULES,
        ConfigTarget.IPTABLES: IPTABLES_RULES,
        ConfigTarget.DNS:      DNS_RULES,
    }

    def __init__(self, extra_rules: Optional[dict[ConfigTarget, list[BaseRule]]] = None) -> None:
        if extra_rules:
            for target, rules in extra_rules.items():
                self._RULE_REGISTRY.setdefault(target, []).extend(rules)

    # ------------------------------------------------------------------
    def validate(self, config_text: str, target: ConfigTarget) -> ValidationResult:
        """
        Validate *config_text* for *target*.

        Returns a ValidationResult containing all detected violations,
        an is_secure flag, and a probabilistic risk score.
        """
        result = ValidationResult(
            config_target=target.value,
            raw_config=config_text,
        )

        # ── Sanity: empty / clearly hallucinated config ─────────────────
        if not config_text or len(config_text.strip()) < _MIN_CONFIG_LEN:
            result.parse_error = "Config text is empty or too short — likely a generation failure"
            result.is_secure   = False
            result.risk_score  = 1.0
            result.violations  = [
                Violation(
                    rule_id="SYS-001",
                    description="Empty or degenerate configuration generated",
                    severity=Severity.HIGH,
                    evidence=repr(config_text[:50]),
                )
            ]
            logger.warning("Empty/short config received for target=%s", target.value)
            return result

        # ── Run applicable rules ─────────────────────────────────────────
        rules = self._RULE_REGISTRY.get(target, [])
        if not rules:
            logger.warning("No rules registered for target=%s", target.value)

        all_violations: list[Violation] = []
        for rule in rules:
            try:
                found = rule.check(config_text)
                all_violations.extend(found)
                if found:
                    logger.debug(
                        "Rule %s fired: %d violation(s)", rule.rule_id, len(found)
                    )
            except Exception as exc:  # noqa: BLE001
                # Defensive: rule errors must never crash the pipeline
                logger.error("Rule %s raised an exception: %s", rule.rule_id, exc, exc_info=True)

        result.violations = all_violations
        result.is_secure  = len(all_violations) == 0
        result.risk_score = self._compute_risk_score(all_violations)

        logger.info(
            "Validation complete | target=%s violations=%d risk=%.3f",
            target.value, len(all_violations), result.risk_score,
        )
        return result

    # ------------------------------------------------------------------
    @staticmethod
    def _compute_risk_score(violations: list[Violation]) -> float:
        """
        Map violations to a 0–1 risk score using an exponential saturation curve.

        score = 1 − e^(−λ · Σ weight_i)
        """
        if not violations:
            return 0.0
        total_weight = sum(_SEVERITY_WEIGHT[v.severity] for v in violations)
        score = 1.0 - math.exp(-_LAMBDA * total_weight)
        return min(score, 1.0)

    # ------------------------------------------------------------------
    def list_rules(self, target: ConfigTarget) -> list[dict]:
        """Return metadata for all rules applicable to *target* (useful for docs/debug)."""
        rules = self._RULE_REGISTRY.get(target, [])
        return [
            {
                "rule_id":     r.rule_id,
                "description": r.description,
                "severity":    r.severity.value,
            }
            for r in rules
        ]
