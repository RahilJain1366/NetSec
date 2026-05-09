"""
validator/rules_base.py
───────────────────────
Abstract base for all security rules.

Each rule is a self-contained, independently testable unit that receives the
raw config text and returns a list of Violations (empty → passed).
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from config import Violation, Severity


class BaseRule(ABC):
    """
    Abstract security rule.

    Subclasses must define:
      rule_id   : unique short identifier, e.g. "NGX-001"
      description: human-readable description of what this rule checks
      severity  : default severity level
    """

    rule_id:     str
    description: str
    severity:    Severity

    @abstractmethod
    def check(self, config_text: str) -> list[Violation]:
        """
        Analyse *config_text* and return any violations.
        An empty list means the config passed this rule.
        """
        ...

    # Convenience factory
    def _violation(self, evidence: str) -> Violation:
        return Violation(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            evidence=evidence,
        )
