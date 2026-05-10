# Dataset Integration Layer — NetSec Extension

## What was added

The `evaluate-mitm` command and supporting modules complete the pipeline into a
**Hybrid AI-Assisted Network Security Framework** for real-world intrusion dataset analysis.

```
Real NIDS Dataset
      ↓
NIDSDatasetLoader          datasets/loader.py
  • UNSW-NB15 / CIC-IDS2017 (parquet via nids-datasets package)
  • Generic CSV / parquet (auto-schema detection)
  • Normalises → list[NormalizedFlow]
      ↓
DatasetMITMAnalyzer        mitm/dataset_analyzer.py
  • Label-based detection (maps 20+ UNSW / CIC label categories → attack types)
  • Flow-level heuristics (TTL anomaly, DNS tunnelling, port scan, exfiltration …)
  • Returns DatasetAnalysisResult with precision / recall / F1 vs ground-truth
      ↓
DatasetLLMEvaluator        datasets/llm_evaluator.py
  • Sends structured analysis to Groq (llama-3.1-8b-instant by default)
  • Returns LLMThreatReport: summary, per-attack explanations, remediation steps
      ↓
IntegratedReportBuilder    datasets/report.py
  • Merges config validation + dataset analysis + LLM threat intel
  • Computes combined risk score (config 40% + dataset 60%)
  • Saves JSON to outputs/
```

## New files

| File | Purpose |
|------|---------|
| `datasets/__init__.py` | Package entry-point |
| `datasets/loader.py` | `NIDSDatasetLoader` — load + normalise any NIDS dataset |
| `datasets/llm_evaluator.py` | `DatasetLLMEvaluator` — Groq-powered threat interpretation |
| `datasets/report.py` | `IntegratedReportBuilder` — final merged report |
| `mitm/dataset_analyzer.py` | `DatasetMITMAnalyzer` — flow-level MITM detection |
| `main.py` | Updated with `evaluate-mitm` command |
| `main_additions.py` | Standalone diff you can paste into an existing main.py |

## Install new dependencies

```bash
pip install nids-datasets pyarrow pandas datasets
```

## Usage examples

### 1 — CSV / parquet dataset (simplest)

```bash
python main.py evaluate-mitm \
    --mitm-mode dataset \
    --traffic-dataset datasets/unsw_sample.csv \
    --max-samples 50
```

### 2 — Auto-download UNSW-NB15 via nids-datasets package

```bash
python main.py evaluate-mitm \
    --mitm-mode nids-pkg \
    --nids-dataset UNSW-NB15 \
    --nids-subset Network-Flows \
    --nids-files 1 \
    --max-samples 200 \
    --cache-csv datasets/unsw_flow_cache.csv
```

On the first run the package downloads and caches the parquet to
`datasets/unsw_flow_cache.csv`. Subsequent runs reuse the cache instantly.

### 3 — Combined: dataset analysis + config generation

```bash
python main.py evaluate-mitm \
    --mitm-mode dataset \
    --traffic-dataset datasets/unsw_sample.csv \
    --max-samples 100 \
    --target nginx \
    --prompt "Generate a secure nginx reverse proxy config for a financial API"
```

Adds config validation (risk weight 40%) on top of dataset analysis (60%).

### 4 — CIC-IDS2017

```bash
python main.py evaluate-mitm \
    --mitm-mode nids-pkg \
    --nids-dataset CIC-IDS2017 \
    --nids-subset Network-Flows \
    --nids-files 1 2 \
    --max-samples 500
```

### 5 — PCAP (existing MITMNetworkAnalyzer)

```bash
python main.py evaluate-mitm \
    --mitm-mode pcap \
    --pcap-file captures/lab_traffic.pcap
```

### 6 — Demo (no files needed)

```bash
python main.py evaluate-mitm --mitm-mode demo
```

## Output

All runs write a JSON report to `outputs/dataset_report_<run_id>.json`:

```json
{
  "run_id": "...",
  "timestamp": "...",
  "config": {
    "target": "nginx",
    "risk_score": 0.42,
    "violations": [...]
  },
  "dataset": {
    "source": "unsw_sample.csv",
    "total_flows": 50,
    "attack_flows": 31,
    "risk_score": 0.61,
    "metrics": { "precision": 0.84, "recall": 0.97, "f1": 0.90 },
    "label_distribution": { "exploits": 18, "dos": 7, "normal": 19, ... },
    "attack_type_counts": { "EXPLOIT": 18, "DOS_ATTACK": 7, ... },
    "top_indicators": [...]
  },
  "llm_threat_intel": {
    "summary": "...",
    "severity_assessment": "...",
    "remediation_steps": ["...", "..."],
    "attack_explanations": { "EXPLOIT": "...", "DOS_ATTACK": "..." },
    "risk_tier": "HIGH"
  },
  "combined": {
    "risk_score": 0.535,
    "fully_at_risk": false
  }
}
```

## Supported dataset schemas

| Dataset | Flavor auto-detected from | Key columns used |
|---------|--------------------------|-----------------|
| UNSW-NB15 | filename contains "unsw" | srcip, dstip, sport, dsport, proto, dur, sbytes, dbytes, Spkts, Dpkts, sttl, dttl, attack_cat, Label |
| CIC-IDS2017 | filename contains "cic" or "ids2017" | Source IP, Destination IP, Source Port, Destination Port, Protocol, Flow Duration, Total Length of Fwd/Bwd Packets, Label |
| Generic CSV/parquet | any other file | fuzzy column-name matching |

## Attack labels mapped

UNSW-NB15: `exploits`, `dos`, `fuzzers`, `generic`, `reconnaissance`, `worms`,
`shellcode`, `backdoor`, `analysis`, plus heuristic-detected `arp`, `dns`, `mitm`.

CIC-IDS2017: `DoS`, `DDoS`, `PortScan`, `Bot`, `Infiltration`, `Heartbleed`,
`Web Attack – Brute Force/XSS/SQL Injection`, `FTP-Patator`, `SSH-Patator`.

## Architecture decision notes

- **`DatasetMITMAnalyzer`** is a sibling to the existing `MITMNetworkAnalyzer` and
  does not modify it — zero breaking changes.
- **`DatasetLLMEvaluator`** reuses the same `GROQ_API_KEY` / `GROQ_MODEL` env
  vars already in `.env`.  Falls back to rule-based report when Groq is offline.
- The `NIDSDatasetLoader.from_nids_package()` class method wraps the `nids-datasets`
  PyPI package, caching downloads to CSV so repeated runs are fast.
- Combined risk weighting (config 40% + dataset 60%) can be tuned in
  `datasets/report.py → IntegratedReportBuilder.build()`.
