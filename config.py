"""
config.py — Global configuration, constants, and type definitions.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import os

# ---------------------------------------------------------------------------
# Model / API settings
# ---------------------------------------------------------------------------
GROQ_MODEL = "llama-3.1-8b-instant"
LLM_TEMPERATURE = 0.1          # Low temperature → deterministic / reproducible
LLM_MAX_TOKENS  = 2048
LLM_SEED        = 42           # For reproducibility where supported

# ---------------------------------------------------------------------------
# Supported configuration targets
# ---------------------------------------------------------------------------
class ConfigTarget(str, Enum):
    NGINX    = "nginx"
    IPTABLES = "iptables"
    DNS      = "dns"

# ---------------------------------------------------------------------------
# Violation severity
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"

# ---------------------------------------------------------------------------
# Domain objects
# ---------------------------------------------------------------------------
@dataclass
class Violation:
    rule_id:     str
    description: str
    severity:    Severity
    evidence:    str

    def to_dict(self) -> dict:
        return {
            "rule_id":     self.rule_id,
            "description": self.description,
            "severity":    self.severity.value,
            "evidence":    self.evidence,
        }

@dataclass
class ValidationResult:
    config_target:  str
    raw_config:     str
    violations:     list[Violation] = field(default_factory=list)
    is_secure:      bool = True
    risk_score:     float = 0.0   # 0.0 (safe) → 1.0 (critically insecure)
    parse_error:    Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "config_target":  self.config_target,
            "is_secure":      self.is_secure,
            "risk_score":     round(self.risk_score, 3),
            "violation_count": len(self.violations),
            "violations":     [v.to_dict() for v in self.violations],
            "parse_error":    self.parse_error,
        }

@dataclass
class GenerationResult:
    prompt:       str
    target:       ConfigTarget
    raw_config:   str
    model:        str
    temperature:  float
    success:      bool
    error:        Optional[str] = None

@dataclass
class EvaluationSample:
    sample_id:       str
    prompt:          str
    target:          ConfigTarget
    expected_secure: bool          # ground-truth label
    category:        str           # "secure" | "ambiguous" | "insecure"
    notes:           str = ""

@dataclass
class EvaluationRecord:
    sample:           EvaluationSample
    generation:       Optional[GenerationResult]
    validation:       Optional[ValidationResult]
    predicted_secure: bool
    correct:          bool

# ---------------------------------------------------------------------------
# Logging paths
# ---------------------------------------------------------------------------
LOG_DIR     = os.path.join(os.path.dirname(__file__), "logs")
OUTPUT_DIR  = os.path.join(os.path.dirname(__file__), "outputs")
