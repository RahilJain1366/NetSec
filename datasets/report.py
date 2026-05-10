"""
datasets/report.py
==================
Builds the final integrated report combining config validation, dataset flow
analysis, and LLM threat interpretation.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field


@dataclass
class IntegratedDatasetReport:
    run_id: str = ""
    timestamp: str = ""
    config_target: str = ""
    config_risk: float = 0.0
    config_violations: list = field(default_factory=list)
    dataset_source: str = ""
    dataset_total_flows: int = 0
    dataset_attack_flows: int = 0
    dataset_risk: float = 0.0
    dataset_precision: float = 0.0
    dataset_recall: float = 0.0
    dataset_f1: float = 0.0
    dataset_label_dist: dict = field(default_factory=dict)
    dataset_attack_types: dict = field(default_factory=dict)
    top_indicators: list = field(default_factory=list)
    llm_summary: str = ""
    llm_severity_assessment: str = ""
    llm_remediation_steps: list = field(default_factory=list)
    llm_attack_explanations: dict = field(default_factory=dict)
    llm_risk_tier: str = ""
    combined_risk: float = 0.0
    fully_at_risk: bool = False

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "config": {
                "target": self.config_target,
                "risk_score": self.config_risk,
                "violations": self.config_violations,
            },
            "dataset": {
                "source": self.dataset_source,
                "total_flows": self.dataset_total_flows,
                "attack_flows": self.dataset_attack_flows,
                "risk_score": self.dataset_risk,
                "metrics": {
                    "precision": self.dataset_precision,
                    "recall": self.dataset_recall,
                    "f1": self.dataset_f1,
                },
                "label_distribution": self.dataset_label_dist,
                "attack_type_counts": self.dataset_attack_types,
                "top_indicators": self.top_indicators,
            },
            "llm_threat_intel": {
                "summary": self.llm_summary,
                "severity_assessment": self.llm_severity_assessment,
                "remediation_steps": self.llm_remediation_steps,
                "attack_explanations": self.llm_attack_explanations,
                "risk_tier": self.llm_risk_tier,
            },
            "combined": {
                "risk_score": self.combined_risk,
                "fully_at_risk": self.fully_at_risk,
            },
        }


class IntegratedReportBuilder:
    def build(self, run_id: str, config_result=None, config_target: str = "", analysis_result=None, llm_report=None) -> IntegratedDatasetReport:
        report = IntegratedDatasetReport(run_id=run_id, timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

        if config_result:
            report.config_target = config_target
            report.config_risk = getattr(config_result, "risk_score", 0.0)
            report.config_violations = [
                {
                    "rule_id": v.rule_id,
                    "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                    "description": v.description,
                }
                for v in getattr(config_result, "violations", [])
            ]

        if analysis_result:
            ar = analysis_result
            report.dataset_source = ar.source
            report.dataset_total_flows = ar.total_flows
            report.dataset_attack_flows = ar.attack_flows
            report.dataset_risk = ar.risk_score
            report.dataset_precision = ar.precision
            report.dataset_recall = ar.recall
            report.dataset_f1 = ar.f1
            report.dataset_label_dist = ar.label_distribution
            report.dataset_attack_types = ar.attack_type_counts
            report.top_indicators = [
                {
                    "attack_type": ind.attack_type,
                    "severity": ind.severity,
                    "description": ind.description,
                    "evidence": ind.evidence,
                }
                for ind in sorted(
                    ar.indicators,
                    key=lambda i: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(i.severity, 0),
                    reverse=True,
                )[:20]
            ]

        if llm_report:
            report.llm_summary = llm_report.summary
            report.llm_severity_assessment = llm_report.severity_assessment
            report.llm_remediation_steps = llm_report.remediation_steps
            report.llm_attack_explanations = llm_report.attack_explanations
            report.llm_risk_tier = llm_report.overall_risk_tier

        config_w = 0.4
        dataset_w = 0.6
        report.combined_risk = config_w * report.config_risk + dataset_w * report.dataset_risk
        report.fully_at_risk = report.combined_risk >= 0.6
        return report

    def save(self, report: IntegratedDatasetReport, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, f"dataset_report_{report.run_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
        return path
