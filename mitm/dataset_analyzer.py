"""
mitm/dataset_analyzer.py
========================
MITM analyzer for NormalizedFlow objects produced by NIDSDatasetLoader.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import os

try:
    from datasets.loader import NIDSDatasetLoader
except Exception:
    NIDSDatasetLoader = None

logger = logging.getLogger("mitm.dataset_analyzer")


@dataclass
class DatasetFlowIndicator:
    attack_type: str
    severity: str
    description: str
    evidence: str
    flow_index: int = 0
    label: Optional[str] = None
    is_confirmed: bool = False


@dataclass
class DatasetAnalysisResult:
    mode: str = "dataset"
    source: str = ""
    total_flows: int = 0
    attack_flows: int = 0
    normal_flows: int = 0
    duration_secs: float = 0.0
    risk_score: float = 0.0
    indicators: List[DatasetFlowIndicator] = field(default_factory=list)
    label_distribution: Dict[str, int] = field(default_factory=dict)
    attack_type_counts: Dict[str, int] = field(default_factory=dict)
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "source": self.source,
            "total_flows": self.total_flows,
            "attack_flows": self.attack_flows,
            "normal_flows": self.normal_flows,
            "duration_secs": round(self.duration_secs, 3),
            "risk_score": round(self.risk_score, 4),
            "label_distribution": self.label_distribution,
            "attack_type_counts": self.attack_type_counts,
            "indicators_count": len(self.indicators),
            "indicators": [
                {
                    "attack_type": ind.attack_type,
                    "severity": ind.severity,
                    "description": ind.description,
                    "evidence": ind.evidence,
                    "flow_index": ind.flow_index,
                    "label": ind.label,
                    "is_confirmed": ind.is_confirmed,
                }
                for ind in self.indicators
            ],
            "metrics": {
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "true_negatives": self.true_negatives,
                "false_negatives": self.false_negatives,
                "precision": round(self.precision, 4),
                "recall": round(self.recall, 4),
                "f1": round(self.f1, 4),
            },
        }


_LABEL_TO_ATTACK = {
    "arp": ("ARP_SPOOFING", "HIGH"),
    "mitm": ("MITM", "CRITICAL"),
    "dns": ("DNS_ANOMALY", "HIGH"),
    "backdoor": ("BACKDOOR", "CRITICAL"),
    "exploits": ("EXPLOIT", "HIGH"),
    "shellcode": ("SHELLCODE", "CRITICAL"),
    "dos": ("DOS_ATTACK", "HIGH"),
    "ddos": ("DDOS_ATTACK", "HIGH"),
    "reconnaissance": ("RECONNAISSANCE", "MEDIUM"),
    "portscan": ("PORT_SCAN", "MEDIUM"),
    "fuzzers": ("FUZZING", "MEDIUM"),
    "generic": ("GENERIC_ATTACK", "MEDIUM"),
    "worms": ("WORM", "HIGH"),
    "analysis": ("TRAFFIC_ANALYSIS", "LOW"),
    "infiltration": ("INFILTRATION", "CRITICAL"),
    "bot": ("BOTNET", "HIGH"),
    "heartbleed": ("HEARTBLEED", "CRITICAL"),
    "brute force": ("BRUTE_FORCE", "HIGH"),
    "sql injection": ("SQL_INJECTION", "HIGH"),
    "xss": ("XSS", "MEDIUM"),
    "ftp-patator": ("FTP_BRUTEFORCE", "HIGH"),
    "ssh-patator": ("SSH_BRUTEFORCE", "HIGH"),
}

_HEURISTIC_CHECKS = [
    (
        "ARP_SPOOFING_HEURISTIC",
        "Duplicate gateway IP with different TTL — possible ARP spoofing",
        "HIGH",
        lambda f: f.src_ttl > 0 and f.dst_ttl > 0 and abs(f.src_ttl - f.dst_ttl) > 64,
    ),
    (
        "DNS_ANOMALY_HEURISTIC",
        "High-volume UDP traffic on non-standard port — possible DNS tunnelling",
        "MEDIUM",
        lambda f: f.protocol == "udp" and f.dst_port not in (None, 53, 5353) and f.src_bytes > 2000,
    ),
    (
        "PORT_SCAN_HEURISTIC",
        "Single source contacting many high ports — possible port scan",
        "MEDIUM",
        lambda f: f.dst_port is not None and f.dst_port > 1024 and f.src_pkts <= 2 and f.dst_pkts == 0,
    ),
    (
        "DATA_EXFILTRATION_HEURISTIC",
        "Asymmetric flow: far more bytes sent than received — possible exfiltration",
        "HIGH",
        lambda f: f.dst_bytes > 0 and f.src_bytes > 0 and (f.src_bytes / f.dst_bytes) > 50,
    ),
    (
        "GATEWAY_IMPERSONATION_HEURISTIC",
        "Short-lived flow with TTL=1 — possible gateway impersonation probe",
        "MEDIUM",
        lambda f: f.src_ttl == 1 and f.duration_secs < 0.1,
    ),
]


class DatasetMITMAnalyzer:
    def __init__(self, use_heuristics: bool = True):
        self.use_heuristics = use_heuristics
        # Cache for loaded/indexed datasets to avoid reloading large files repeatedly
        self._dataset_index_cache: Dict[str, Dict[str, List]] = {}

    def analyze_dataset_flows(self, flows: list, source: str = "dataset") -> DatasetAnalysisResult:
        t_start = time.time()
        indicators: List[DatasetFlowIndicator] = []
        label_dist: Dict[str, int] = {}
        attack_type_counts: Dict[str, int] = {}
        tp = fp = tn = fn = 0

        for idx, flow in enumerate(flows):
            label = (flow.label or "unknown").strip().lower()
            label_dist[label] = label_dist.get(label, 0) + 1
            detected = False

            for key, (atype, severity) in _LABEL_TO_ATTACK.items():
                if key in label:
                    indicators.append(
                        DatasetFlowIndicator(
                            attack_type=atype,
                            severity=severity,
                            description=f"Label '{flow.label}' matches known attack pattern",
                            evidence=(
                                f"src={flow.src_ip}:{flow.src_port} → dst={flow.dst_ip}:{flow.dst_port} "
                                f"proto={flow.protocol} bytes={flow.src_bytes}"
                            ),
                            flow_index=idx,
                            label=flow.label,
                            is_confirmed=flow.is_attack,
                        )
                    )
                    attack_type_counts[atype] = attack_type_counts.get(atype, 0) + 1
                    detected = True

            if self.use_heuristics:
                for hname, hdesc, hsev, hpred in _HEURISTIC_CHECKS:
                    try:
                        if hpred(flow):
                            indicators.append(
                                DatasetFlowIndicator(
                                    attack_type=hname,
                                    severity=hsev,
                                    description=hdesc,
                                    evidence=(
                                        f"src={flow.src_ip}:{flow.src_port} → dst={flow.dst_ip}:{flow.dst_port} "
                                        f"sttl={flow.src_ttl} dttl={flow.dst_ttl} dur={flow.duration_secs:.3f}s "
                                        f"bytes={flow.src_bytes}/{flow.dst_bytes}"
                                    ),
                                    flow_index=idx,
                                    label=flow.label,
                                    is_confirmed=flow.is_attack,
                                )
                            )
                            attack_type_counts[hname] = attack_type_counts.get(hname, 0) + 1
                            detected = True
                    except Exception:
                        pass

            ground_truth_attack = flow.is_attack
            if detected and ground_truth_attack:
                tp += 1
            elif detected and not ground_truth_attack:
                fp += 1
            elif not detected and not ground_truth_attack:
                tn += 1
            else:
                fn += 1

        severity_weights = {"LOW": 0.1, "MEDIUM": 0.3, "HIGH": 0.6, "CRITICAL": 1.0}
        raw_risk = sum(severity_weights.get(ind.severity, 0.3) for ind in indicators)
        risk_score = min(1.0, raw_risk / max(len(flows), 1))
        attack_count = sum(1 for f in flows if f.is_attack)
        normal_count = len(flows) - attack_count

        result = DatasetAnalysisResult(
            mode="dataset",
            source=source,
            total_flows=len(flows),
            attack_flows=attack_count,
            normal_flows=normal_count,
            duration_secs=time.time() - t_start,
            risk_score=risk_score,
            indicators=indicators,
            label_distribution=label_dist,
            attack_type_counts=attack_type_counts,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
        )
        logger.info("Dataset analysis complete: %d flows, %d indicators, risk=%.3f", len(flows), len(indicators), risk_score)
        return result

    def load_and_index_dataset(
        self,
        traffic_path: str,
        sample_key_field: str = "sample_id",
        max_traffic_rows: Optional[int] = None,
    ) -> Dict[str, List]:
        """Load a traffic dataset and index flows by `sample_key_field`.

        Returns a dict: { sample_id: [NormalizedFlow, ...], ... }
        """
        if traffic_path in self._dataset_index_cache:
            return self._dataset_index_cache[traffic_path]

        if not os.path.exists(traffic_path):
            self._dataset_index_cache[traffic_path] = {}
            return self._dataset_index_cache[traffic_path]

        if NIDSDatasetLoader is None:
            raise RuntimeError("NIDSDatasetLoader not available — install dataset dependencies (pandas, nids-datasets)")

        loader = NIDSDatasetLoader(traffic_path)
        flows = loader.load(max_samples=max_traffic_rows)

        index: Dict[str, List] = {}
        for f in flows:
            key = getattr(f, sample_key_field, None) or getattr(f, "session_id", None) or "__unknown__"
            index.setdefault(str(key), []).append(f)

        self._dataset_index_cache[traffic_path] = index
        return index

    def analyze_traffic_for_sample(
        self,
        traffic_path: str,
        sample_id: str,
        sample_key_field: str = "sample_id",
        max_traffic_rows: Optional[int] = None,
    ) -> DatasetAnalysisResult:
        """Analyze flows for a single sample id extracted from a dataset file.

        Uses `load_and_index_dataset` to avoid reloading the whole file per-sample.
        """
        idx = self.load_and_index_dataset(
            traffic_path,
            sample_key_field=sample_key_field,
            max_traffic_rows=max_traffic_rows,
        )
        flows = idx.get(str(sample_id), [])
        return self.analyze_dataset_flows(flows, source=f"{traffic_path}#{sample_id}")

    def analyze_dataset_file(self, traffic_path: str, max_traffic_rows: Optional[int] = None) -> DatasetAnalysisResult:
        """Analyze an entire traffic dataset file (all flows).

        This is a convenience wrapper that loads all flows and calls `analyze_dataset_flows`.
        """
        if not os.path.exists(traffic_path):
            return DatasetAnalysisResult(source=traffic_path, total_flows=0)

        if NIDSDatasetLoader is None:
            raise RuntimeError("NIDSDatasetLoader not available — install dataset dependencies (pandas, nids-datasets)")

        loader = NIDSDatasetLoader(traffic_path)
        flows = loader.load(max_samples=max_traffic_rows)
        return self.analyze_dataset_flows(flows, source=traffic_path)
