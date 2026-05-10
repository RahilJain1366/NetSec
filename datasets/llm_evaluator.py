"""
datasets/llm_evaluator.py
=========================
Uses the Groq LLM to interpret DatasetAnalysisResult into threat intelligence.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("datasets.llm_evaluator")


@dataclass
class LLMThreatReport:
    summary: str = ""
    attack_explanations: dict = field(default_factory=dict)
    severity_assessment: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    overall_risk_tier: str = ""
    raw_llm_response: str = ""

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "attack_explanations": self.attack_explanations,
            "severity_assessment": self.severity_assessment,
            "remediation_steps": self.remediation_steps,
            "overall_risk_tier": self.overall_risk_tier,
        }


class DatasetLLMEvaluator:
    def __init__(self, model: Optional[str] = None):
        try:
            from groq import Groq

            api_key = os.getenv("GROQ_API_KEY", "")
            self.client = Groq(api_key=api_key) if api_key else None
        except ImportError:
            self.client = None

        from_env = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
        self.model = model or from_env
        if not self.client:
            logger.warning("Groq client not available — falling back to rule-based report.")

    def evaluate(self, analysis_result) -> LLMThreatReport:
        if not self.client:
            return self._fallback_report(analysis_result)

        prompt = self._build_prompt(analysis_result)
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert network security analyst. "
                            "You receive a structured summary of network intrusion detection analysis results and produce a concise, actionable threat intelligence report in JSON format."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=1200,
            )
            raw = response.choices[0].message.content.strip()
            return self._parse_response(raw, analysis_result)
        except Exception as exc:
            logger.error("Groq API error during dataset evaluation: %s", exc)
            return self._fallback_report(analysis_result)

    def _build_prompt(self, ar) -> str:
        top_attacks = sorted(ar.attack_type_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        indicators_sample = [
            {
                "attack_type": ind.attack_type,
                "severity": ind.severity,
                "description": ind.description,
                "evidence": ind.evidence,
                "confirmed": ind.is_confirmed,
            }
            for ind in ar.indicators[:15]
        ]
        data = {
            "dataset_source": ar.source,
            "total_flows": ar.total_flows,
            "attack_flows": ar.attack_flows,
            "normal_flows": ar.normal_flows,
            "overall_risk_score": round(ar.risk_score, 4),
            "label_distribution": ar.label_distribution,
            "top_attack_types": dict(top_attacks),
            "detection_metrics": {
                "precision": round(ar.precision, 4),
                "recall": round(ar.recall, 4),
                "f1": round(ar.f1, 4),
            },
            "sample_indicators": indicators_sample,
        }
        return f"""
Analyze the following network intrusion detection results from a real NIDS dataset
and produce a JSON threat intelligence report.

Dataset Analysis Summary:
{json.dumps(data, indent=2)}

Return ONLY a valid JSON object (no markdown, no preamble) with exactly these fields:
{{
  "summary": "<2-3 sentence executive summary of the threat landscape>",
  "attack_explanations": {{
    "<ATTACK_TYPE>": "<brief technical explanation of what this attack does and its network signature>"
  }},
  "severity_assessment": "<paragraph assessing the overall severity and what network assets are at risk>",
  "remediation_steps": [
    "<actionable step 1>",
    "<actionable step 2>"
  ],
  "overall_risk_tier": "<one of: CRITICAL | HIGH | MEDIUM | LOW>"
}}
"""

    def _parse_response(self, raw: str, ar) -> LLMThreatReport:
        cleaned = raw
        if "```" in cleaned:
            cleaned = cleaned.split("```")[-2] if "```json" in cleaned else cleaned
            cleaned = cleaned.replace("```json", "").replace("```", "").strip()

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning("Could not parse LLM JSON response — using raw text")
            return LLMThreatReport(summary=raw, raw_llm_response=raw)

        return LLMThreatReport(
            summary=data.get("summary", ""),
            attack_explanations=data.get("attack_explanations", {}),
            severity_assessment=data.get("severity_assessment", ""),
            remediation_steps=data.get("remediation_steps", []),
            overall_risk_tier=data.get("overall_risk_tier", "UNKNOWN"),
            raw_llm_response=raw,
        )

    def _fallback_report(self, ar) -> LLMThreatReport:
        tier = (
            "CRITICAL" if ar.risk_score >= 0.7
            else "HIGH" if ar.risk_score >= 0.5
            else "MEDIUM" if ar.risk_score >= 0.3
            else "LOW"
        )
        top = sorted(ar.attack_type_counts.items(), key=lambda x: x[1], reverse=True)
        top_str = ", ".join(f"{k}({v})" for k, v in top[:5]) or "none"
        return LLMThreatReport(
            summary=(
                f"Dataset '{ar.source}' contains {ar.total_flows} flows, {ar.attack_flows} attack flows. "
                f"Top attack types: {top_str}. Risk score: {ar.risk_score:.3f}."
            ),
            attack_explanations={k: f"Attack type '{k}' detected {v} times." for k, v in top[:5]},
            severity_assessment=f"Overall risk tier: {tier}.",
            remediation_steps=[
                "Enable real-time ARP inspection on managed switches.",
                "Deploy DNS Security Extensions (DNSSEC).",
                "Apply network segmentation via VLANs.",
                "Enable IDS/IPS on perimeter firewall.",
                "Review firewall rules for anomalous outbound traffic.",
            ],
            overall_risk_tier=tier,
        )
