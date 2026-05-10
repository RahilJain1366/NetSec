"""
datasets/loader.py
==================
NIDSDatasetLoader — unified interface for real network-intrusion datasets.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator, List, Optional

import pandas as pd

logger = logging.getLogger("datasets.loader")


class DatasetFlavor(str, Enum):
    UNSW_NB15 = "UNSW-NB15"
    CIC_IDS2017 = "CIC-IDS2017"
    GENERIC_CSV = "generic-csv"
    GENERIC_PARQUET = "generic-parquet"


@dataclass
class NormalizedFlow:
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    duration_secs: float = 0.0
    src_bytes: int = 0
    dst_bytes: int = 0
    src_pkts: int = 0
    dst_pkts: int = 0
    src_ttl: int = 0
    dst_ttl: int = 0
    service: Optional[str] = None
    label: Optional[str] = None
    is_attack: bool = False
    raw: dict = field(default_factory=dict)


_GENERIC_FALLBACKS = {
    "src_ip": ["src_ip", "source ip", "srcip", "ip_src"],
    "dst_ip": ["dst_ip", "destination ip", "dstip", "ip_dst"],
    "src_port": ["src_port", "source port", "sport", "srcport"],
    "dst_port": ["dst_port", "destination port", "dsport", "dstport"],
    "protocol": ["protocol", "proto"],
    "duration_secs": ["flow duration", "dur", "duration"],
    "src_bytes": ["total length of fwd packets", "sbytes", "src_bytes", "fwd_bytes"],
    "dst_bytes": ["total length of bwd packets", "dbytes", "dst_bytes", "bwd_bytes"],
    "src_pkts": ["total fwd packets", "spkts", "src_pkts"],
    "dst_pkts": ["total backward packets", "dpkts", "dst_pkts"],
    "label": ["label", "attack_cat", "class", "category"],
}


class NIDSDatasetLoader:
    def __init__(self, path: str, flavor: Optional[DatasetFlavor] = None):
        self.path = path
        self.flavor = flavor or self._infer_flavor(path)
        self._df: Optional[pd.DataFrame] = None

    def load(self, max_samples: Optional[int] = None) -> List[NormalizedFlow]:
        logger.info("Loading dataset: %s (flavor=%s)", self.path, self.flavor)
        df = self._read_file(max_samples)
        self._df = df
        logger.info("  Rows loaded: %d, columns: %d", len(df), len(df.columns))
        flows = self._normalize(df)
        logger.info("  Normalized flows: %d", len(flows))
        return flows

    def iter_batches(self, batch_size: int = 50, max_samples: Optional[int] = None) -> Iterator[List[NormalizedFlow]]:
        flows = self.load(max_samples)
        for i in range(0, len(flows), batch_size):
            yield flows[i : i + batch_size]

    @classmethod
    def from_nids_package(
        cls,
        dataset: str = "UNSW-NB15",
        subset: str = "Network-Flows",
        files: List[int] = None,
        max_samples: Optional[int] = None,
        cache_csv: Optional[str] = None,
    ) -> "NIDSDatasetLoader":
        try:
            from nids_datasets import Dataset as NidsDataset
        except ImportError as exc:
            raise ImportError(
                "The `nids-datasets` package is not installed. Install it with: pip install nids-datasets"
            ) from exc

        if files is None:
            files = [1]

        flavor = DatasetFlavor.UNSW_NB15 if "UNSW" in dataset.upper() else DatasetFlavor.CIC_IDS2017

        if cache_csv and os.path.exists(cache_csv):
            logger.info("Using cached dataset CSV: %s", cache_csv)
            loader = cls(cache_csv, flavor=flavor)
            loader.load(max_samples)
            return loader

        logger.info("Downloading %s / %s / files=%s via nids-datasets ...", dataset, subset, files)
        data = NidsDataset(dataset=dataset, subset=[subset], files=files)
        hf_dataset = data.read(dataset=dataset, subset=subset, files=files)
        df = hf_dataset.to_pandas()
        if max_samples:
            df = df.head(max_samples)

        if cache_csv:
            os.makedirs(os.path.dirname(cache_csv) or ".", exist_ok=True)
            df.to_csv(cache_csv, index=False)
            logger.info("Cached dataset to %s", cache_csv)
            loader = cls(cache_csv, flavor=flavor)
        else:
            loader = cls.__new__(cls)
            loader.path = f"<nids-package:{dataset}/{subset}>"
            loader.flavor = flavor
            loader._df = df

        loader._df = df
        return loader

    def _read_file(self, max_samples: Optional[int]) -> pd.DataFrame:
        if self._df is not None:
            df = self._df
        elif os.path.isdir(self.path):
            csv_paths = []
            for root, _, files in os.walk(self.path):
                for name in files:
                    if name.lower().endswith(".csv"):
                        csv_paths.append(os.path.join(root, name))

            if not csv_paths:
                raise FileNotFoundError(f"No CSV files found under directory: {self.path}")

            csv_paths.sort()
            frames = [pd.read_csv(csv_path, low_memory=False) for csv_path in csv_paths]
            df = pd.concat(frames, ignore_index=True)
        elif self.path.endswith(".parquet"):
            df = pd.read_parquet(self.path)
        elif self.path.endswith(".csv"):
            df = pd.read_csv(self.path, low_memory=False)
        else:
            try:
                df = pd.read_parquet(self.path)
            except Exception:
                df = pd.read_csv(self.path, low_memory=False)

        df = df.fillna(0)
        if max_samples:
            df = df.head(max_samples)
        return df

    def _normalize(self, df: pd.DataFrame) -> List[NormalizedFlow]:
        if self.flavor == DatasetFlavor.UNSW_NB15:
            return self._normalize_unsw(df)
        if self.flavor == DatasetFlavor.CIC_IDS2017:
            return self._normalize_cic(df)
        return self._normalize_generic(df)

    def _normalize_unsw(self, df: pd.DataFrame) -> List[NormalizedFlow]:
        flows = []
        for _, row in df.iterrows():
            label_raw = str(row.get("attack_cat", "Normal")).strip()
            label_int = int(row.get("Label", 0))
            is_attack = label_int == 1 or label_raw.lower() not in ("normal", "0", "")
            label = label_raw if label_raw else ("attack" if is_attack else "normal")
            proto_raw = str(row.get("proto", "")).lower()
            flows.append(
                NormalizedFlow(
                    src_ip=str(row.get("srcip", "")),
                    dst_ip=str(row.get("dstip", "")),
                    src_port=_safe_int(row.get("sport")),
                    dst_port=_safe_int(row.get("dsport")),
                    protocol=proto_raw,
                    duration_secs=float(row.get("dur", 0.0)),
                    src_bytes=_safe_int(row.get("sbytes")),
                    dst_bytes=_safe_int(row.get("dbytes")),
                    src_pkts=_safe_int(row.get("Spkts")),
                    dst_pkts=_safe_int(row.get("Dpkts")),
                    src_ttl=_safe_int(row.get("sttl")),
                    dst_ttl=_safe_int(row.get("dttl")),
                    service=str(row.get("service", "")).strip() or None,
                    label=label,
                    is_attack=is_attack,
                    raw=row.to_dict(),
                )
            )
        return flows

    def _normalize_cic(self, df: pd.DataFrame) -> List[NormalizedFlow]:
        flows = []
        for _, row in df.iterrows():
            label_raw = str(row.get("Label", "BENIGN")).strip()
            is_attack = label_raw.upper() not in ("BENIGN", "NORMAL")
            label = label_raw.lower()
            dur_us = float(row.get("Flow Duration", 0))
            dur_secs = dur_us / 1_000_000.0
            proto_val = _safe_int(row.get("Protocol", 0))
            proto_str = {6: "tcp", 17: "udp", 1: "icmp"}.get(proto_val, str(proto_val))
            flows.append(
                NormalizedFlow(
                    src_ip=str(row.get("Source IP", "")),
                    dst_ip=str(row.get("Destination IP", "")),
                    src_port=_safe_int(row.get("Source Port")),
                    dst_port=_safe_int(row.get("Destination Port")),
                    protocol=proto_str,
                    duration_secs=dur_secs,
                    src_bytes=_safe_int(row.get("Total Length of Fwd Packets")),
                    dst_bytes=_safe_int(row.get("Total Length of Bwd Packets")),
                    src_pkts=_safe_int(row.get("Total Fwd Packets")),
                    dst_pkts=_safe_int(row.get("Total Backward Packets")),
                    label=label,
                    is_attack=is_attack,
                    raw=row.to_dict(),
                )
            )
        return flows

    def _normalize_generic(self, df: pd.DataFrame) -> List[NormalizedFlow]:
        col_lower_map = {c.lower(): c for c in df.columns}

        def pick(candidates):
            for cand in candidates:
                if cand.lower() in col_lower_map:
                    return col_lower_map[cand.lower()]
            return None

        col = {k: pick(v) for k, v in _GENERIC_FALLBACKS.items()}
        flows = []
        for _, row in df.iterrows():
            label_raw = str(row[col["label"]]).strip() if col["label"] else "unknown"
            is_attack = label_raw.lower() not in ("normal", "benign", "0", "")
            flows.append(
                NormalizedFlow(
                    src_ip=str(row[col["src_ip"]]) if col["src_ip"] else None,
                    dst_ip=str(row[col["dst_ip"]]) if col["dst_ip"] else None,
                    src_port=_safe_int(row[col["src_port"]]) if col["src_port"] else None,
                    dst_port=_safe_int(row[col["dst_port"]]) if col["dst_port"] else None,
                    protocol=str(row[col["protocol"]]).lower() if col["protocol"] else None,
                    duration_secs=float(row[col["duration_secs"]]) if col["duration_secs"] else 0.0,
                    src_bytes=_safe_int(row[col["src_bytes"]]) if col["src_bytes"] else 0,
                    dst_bytes=_safe_int(row[col["dst_bytes"]]) if col["dst_bytes"] else 0,
                    src_pkts=_safe_int(row[col["src_pkts"]]) if col["src_pkts"] else 0,
                    dst_pkts=_safe_int(row[col["dst_pkts"]]) if col["dst_pkts"] else 0,
                    label=label_raw,
                    is_attack=is_attack,
                    raw=row.to_dict(),
                )
            )
        return flows

    @staticmethod
    def _infer_flavor(path: str) -> DatasetFlavor:
        name = os.path.basename(path).lower()
        if "unsw" in name:
            return DatasetFlavor.UNSW_NB15
        if "cic" in name or "ids2017" in name or "cicids" in name:
            return DatasetFlavor.CIC_IDS2017
        if path.endswith(".parquet"):
            return DatasetFlavor.GENERIC_PARQUET
        return DatasetFlavor.GENERIC_CSV

    def summary(self) -> dict:
        if self._df is None:
            return {}
        df = self._df
        label_col = None
        for c in ["attack_cat", "Label", "label"]:
            if c in df.columns:
                label_col = c
                break
        label_dist = df[label_col].value_counts().to_dict() if label_col else {}
        return {
            "flavor": self.flavor.value,
            "path": self.path,
            "total_rows": len(df),
            "columns": list(df.columns),
            "label_distribution": label_dist,
        }


def _safe_int(val) -> int:
    try:
        return int(float(val))
    except (TypeError, ValueError):
        return 0
