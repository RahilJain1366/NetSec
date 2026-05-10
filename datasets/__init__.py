"""
datasets package
================
Integration helpers for real network intrusion datasets.
"""

from .loader import NIDSDatasetLoader, DatasetFlavor, NormalizedFlow
from .llm_evaluator import DatasetLLMEvaluator, LLMThreatReport
from .report import IntegratedReportBuilder, IntegratedDatasetReport

__all__ = [
    "NIDSDatasetLoader",
    "DatasetFlavor",
    "NormalizedFlow",
    "DatasetLLMEvaluator",
    "LLMThreatReport",
    "IntegratedReportBuilder",
    "IntegratedDatasetReport",
]
