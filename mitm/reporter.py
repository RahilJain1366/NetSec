"""
mitm/reporter.py
────────────────
Unified MITM risk report combining:
  - Static config analysis (validator violations tagged as MITM vectors)
  - Live/offline network traffic analysis (Scapy indicators)

Produces a structured attack path showing how detected issues
chain together into a complete MITM scenario.
"""

from __future__ import annotations

import json
import math
import os
import logging
from dataclasses import dataclass, field
from typing import Optional

from config import ConfigTarget, ValidationResult, OUTPUT_DIR
from mitm.network_analyzer import NetworkAnalysisResult, MITMIndicator

logger = logging.getLogger(__name__)

# ── Attack vector taxonomy ────────────────────────────────────────────────────
# Maps rule IDs and network indicator types to MITM attack steps

RULE_MITM_MAP: dict[str, dict] = {
    # Config rules → MITM step
    "NGX-001":       {"step": 1, "label": "HTTP plaintext allowed",        "phase": "Intercept"},
    "NGX-002":       {"step": 1, "label": "No TLS configured",             "phase": "Intercept"},
    "NGX-003":       {"step": 2, "label": "Weak TLS — downgrade possible", "phase": "Downgrade"},
    "NGX-004":       {"step": 2, "label": "No HSTS — downgrade on return", "phase": "Downgrade"},
    "NGX-007":       {"step": 3, "label": "Unencrypted backend proxy leg", "phase": "Intercept"},
    "NGX-MITM-001":  {"step": 2, "label": "Weak cipher — decrypt traffic", "phase": "Decrypt"},
    "NGX-MITM-002":  {"step": 4, "label": "No OCSP — revoked cert usable", "phase": "Impersonate"},
    "NGX-MITM-003":  {"step": 4, "label": "Session tickets — hijack risk", "phase": "Hijack"},
    "NGX-MITM-004":  {"step": 2, "label": "No HSTS preload — first visit", "phase": "Downgrade"},
    "NGX-MITM-005":  {"step": 3, "label": "HTTP backend — intercept data", "phase": "Intercept"},
    "DNS-001":       {"step": 0, "label": "Open resolver — DNS poisoning",  "phase": "Redirect"},
    "DNS-002":       {"step": 0, "label": "Open recursion — spoof risk",    "phase": "Redirect"},
    "DNS-003":       {"step": 0, "label": "Zone transfer — recon for MITM", "phase": "Recon"},
    "DNS-006":       {"step": 0, "label": "No DNSSEC — responses forgeable","phase": "Redirect"},
    "DNS-MITM-001":  {"step": 0, "label": "No DNSSEC signing — zone fake",  "phase": "Redirect"},

    # Network indicators → MITM step
    "ARP_SPOOF":       {"step": 0, "label": "ARP spoofing — traffic rerouted","phase": "Position"},
    "DNS_SPOOF":       {"step": 0, "label": "DNS spoofing — redirect victim", "phase": "Redirect"},
    "DNS_INCONSISTENCY":{"step":0, "label": "DNS inconsistency — active spoof","phase": "Redirect"},
    "SSL_STRIP":       {"step": 2, "label": "SSL stripping — HTTPS→HTTP",    "phase": "Downgrade"},
    "TLS_DOWNGRADE":   {"step": 2, "label": "TLS downgrade negotiated",       "phase": "Downgrade"},
    "CLEARTEXT_CREDS": {"step": 3, "label": "Credentials in plaintext",       "phase": "Harvest"},
    "DUPLICATE_MAC":   {"step": 0, "label": "Proxy insertion detected",       "phase": "Position"},
}

PHASE_ORDER = ["Recon", "Position", "Redirect", "Intercept", "Downgrade", "Decrypt",
               "Impersonate", "Hijack", "Harvest"]


@dataclass
class AttackStep:
    phase:      str
    findings:   list[str]


@dataclass
class MITMReport:
    target:          Optional[str]
    config_risk:     float
    network_risk:    float
    combined_risk:   float
    attack_path:     list[AttackStep]
    config_findings: list[dict]
    network_findings: list[dict]
    summary:         str
    fully_at_risk:   bool

    def to_dict(self) -> dict:
        return {
            "target":           self.target,
            "config_risk":      round(self.config_risk, 3),
            "network_risk":     round(self.network_risk, 3),
            "combined_risk":    round(self.combined_risk, 3),
            "fully_at_risk":    self.fully_at_risk,
            "summary":          self.summary,
            "attack_path":      [
                {"phase": s.phase, "findings": s.findings}
                for s in self.attack_path
            ],
            "config_findings":  self.config_findings,
            "network_findings": self.network_findings,
        }

    def print_report(self) -> None:
        sep = "═" * 65
        print(f"\n{sep}")
        print("  MITM RISK REPORT")
        print(f"  Target : {self.target or 'N/A'}")
        print(f"  Config Risk  : {self.config_risk:.3f}")
        print(f"  Network Risk : {self.network_risk:.3f}")
        print(f"  Combined Risk: {self.combined_risk:.3f}  "
              f"({'CRITICAL' if self.combined_risk > 0.7 else 'HIGH' if self.combined_risk > 0.4 else 'MEDIUM' if self.combined_risk > 0.2 else 'LOW'})")
        print(sep)

        if self.attack_path:
            print("\n  ATTACK PATH")
            print("  " + "─" * 50)
            for step in self.attack_path:
                print(f"  [{step.phase.upper()}]")
                for f in step.findings:
                    print(f"    → {f}")

        if self.config_findings:
            print("\n  CONFIG VIOLATIONS (MITM-relevant)")
            print("  " + "─" * 50)
            for f in self.config_findings:
                print(f"  [{f['severity']:6s}] {f['rule_id']:<16} {f['description']}")
                print(f"           Evidence: {f['evidence']}")

        if self.network_findings:
            print("\n  NETWORK INDICATORS")
            print("  " + "─" * 50)
            for f in self.network_findings:
                print(f"  [{f['severity']:6s}] {f['attack_type']:<20} {f['description']}")
                print(f"           Evidence: {f['evidence']}")

        print(f"\n  SUMMARY: {self.summary}")
        print(sep + "\n")


# ── Reporter ──────────────────────────────────────────────────────────────────

class MITMReporter:
    """
    Combines config validation results and network analysis results
    into a unified MITM risk report with attack path reconstruction.
    """

    LAMBDA = 0.25
    SEVERITY_WEIGHT = {"HIGH": 3.0, "MEDIUM": 1.5, "LOW": 0.5}

    # Rules that are MITM-relevant (from base + MITM-specific)
    MITM_RULE_IDS = set(RULE_MITM_MAP.keys())

    def generate(
        self,
        target:          Optional[str]               = None,
        config_result:   Optional[ValidationResult]  = None,
        network_result:  Optional[NetworkAnalysisResult] = None,
    ) -> MITMReport:

        # ── Extract MITM-relevant config findings ──────────────────────────
        config_findings: list[dict] = []
        if config_result:
            for v in config_result.violations:
                if v.rule_id in self.MITM_RULE_IDS or "MITM" in v.rule_id:
                    config_findings.append(v.to_dict())

        # ── Extract network findings ───────────────────────────────────────
        network_findings: list[dict] = []
        if network_result:
            network_findings = [i.to_dict() for i in network_result.indicators]

        # ── Compute risk scores ────────────────────────────────────────────
        config_risk  = self._score(
            [f["severity"] for f in config_findings]
        )
        network_risk = network_result.risk_score if network_result else 0.0

        # Combined: weighted average favouring whichever is higher
        combined_risk = max(
            config_risk,
            network_risk,
            (config_risk + network_risk) / 2,
        )
        combined_risk = min(combined_risk, 1.0)

        # ── Build attack path ──────────────────────────────────────────────
        phase_findings: dict[str, list[str]] = {p: [] for p in PHASE_ORDER}

        for f in config_findings:
            meta = RULE_MITM_MAP.get(f["rule_id"])
            if meta:
                phase_findings[meta["phase"]].append(meta["label"])

        for f in network_findings:
            meta = RULE_MITM_MAP.get(f["attack_type"])
            if meta:
                phase_findings[meta["phase"]].append(
                    f"{meta['label']}: {f['evidence'][:60]}"
                )

        attack_path = [
            AttackStep(phase=p, findings=findings)
            for p in PHASE_ORDER
            for findings in [phase_findings[p]]
            if findings
        ]

        # ── Summary sentence ───────────────────────────────────────────────
        phases_active = [s.phase for s in attack_path]
        n_config  = len(config_findings)
        n_network = len(network_findings)

        if combined_risk > 0.7:
            severity_label = "CRITICAL"
        elif combined_risk > 0.4:
            severity_label = "HIGH"
        elif combined_risk > 0.2:
            severity_label = "MEDIUM"
        else:
            severity_label = "LOW"

        summary = (
            f"{severity_label} MITM risk (score {combined_risk:.3f}). "
            f"{n_config} config violation(s) and {n_network} network indicator(s) detected. "
            f"Active attack phases: {', '.join(phases_active) if phases_active else 'None'}."
        )

        return MITMReport(
            target=target,
            config_risk=config_risk,
            network_risk=network_risk,
            combined_risk=combined_risk,
            attack_path=attack_path,
            config_findings=config_findings,
            network_findings=network_findings,
            summary=summary,
            fully_at_risk=combined_risk > 0.6,
        )

    def save(self, report: MITMReport, run_id: str) -> str:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        path = os.path.join(OUTPUT_DIR, f"mitm_report_{run_id}.json")
        with open(path, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        logger.info("MITM report saved → %s", path)
        return path

    def _score(self, severities: list[str]) -> float:
        if not severities:
            return 0.0
        w = sum(self.SEVERITY_WEIGHT.get(s, 0) for s in severities)
        return min(1.0 - math.exp(-self.LAMBDA * w), 1.0)
