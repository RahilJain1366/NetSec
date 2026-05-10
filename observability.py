"""
observability.py
────────────────
Structured logging and traceability for the pipeline.

Features
────────
• JSON-structured log entries (one per line → grep / jq friendly)
• Separate files: pipeline.log (all events) + violations.log (security findings only)
• Console handler with human-readable format
• Each pipeline run tagged with a run_id for traceability
• Deterministic: timestamps are real but run_id is UUID-based
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from config import LOG_DIR, GenerationResult, ValidationResult, EvaluationRecord


# ---------------------------------------------------------------------------
# Bootstrap logging
# ---------------------------------------------------------------------------

def setup_logging(run_id: Optional[str] = None) -> str:
    """
    Configure root logger with:
    - Console handler (human-readable)
    - pipeline.log (JSON, all events)
    - violations.log (JSON, violations only)

    Returns the run_id (generated if not supplied).
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    rid = run_id or str(uuid.uuid4())[:8]

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers.clear()

    # Console
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        f"[%(asctime)s] [run={rid}] %(levelname)-7s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    ))
    root.addHandler(ch)

    # File: all events
    pipeline_path = os.path.join(LOG_DIR, "pipeline.log")
    fh = logging.FileHandler(pipeline_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(_JsonFormatter(run_id=rid))
    root.addHandler(fh)

    return rid


class _JsonFormatter(logging.Formatter):
    def __init__(self, run_id: str) -> None:
        super().__init__()
        self.run_id = run_id

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts":      datetime.now(timezone.utc).isoformat(),
            "run_id":  self.run_id,
            "level":   record.levelname,
            "logger":  record.name,
            "msg":     record.getMessage(),
        }
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Pipeline event logger
# ---------------------------------------------------------------------------

logger = logging.getLogger("pipeline")


class PipelineLogger:
    """
    Records structured events for each pipeline stage:
      - generation_event
      - validation_event
      - evaluation_event
    """

    def __init__(self, run_id: str, output_dir: str) -> None:
        self.run_id     = run_id
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self._records: list[dict] = []

    # ── Generation ───────────────────────────────────────────────────────
    def log_generation(self, gen: GenerationResult) -> None:
        event = {
            "event":       "generation",
            "ts":          _now(),
            "run_id":      self.run_id,
            "target":      gen.target.value,
            "model":       gen.model,
            "temperature": gen.temperature,
            "success":     gen.success,
            "error":       gen.error,
            "prompt":      gen.prompt,
            "config_len":  len(gen.raw_config),
            "config_preview": gen.raw_config[:200],
        }
        self._records.append(event)
        logger.debug("GENERATION | target=%s success=%s", gen.target.value, gen.success)

    # ── Validation ───────────────────────────────────────────────────────
    def log_validation(self, val: ValidationResult) -> None:
        event = {
            "event":      "validation",
            "ts":         _now(),
            "run_id":     self.run_id,
            "target":     val.config_target,
            "is_secure":  val.is_secure,
            "risk_score": val.risk_score,
            "violations": [v.to_dict() for v in val.violations],
            "parse_error": val.parse_error,
        }
        self._records.append(event)

        # violations-specific log
        if val.violations:
            vpath = os.path.join(LOG_DIR, "violations.log")
            with open(vpath, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")

        logger.info(
            "VALIDATION | target=%s secure=%s violations=%d risk=%.3f",
            val.config_target, val.is_secure, len(val.violations), val.risk_score,
        )

    # ── Evaluation ───────────────────────────────────────────────────────
    def log_evaluation(self, rec: EvaluationRecord) -> None:
        event = {
            "event":            "evaluation",
            "ts":               _now(),
            "run_id":           self.run_id,
            "sample_id":        rec.sample.sample_id,
            "category":         rec.sample.category,
            "target":           rec.sample.target.value,
            "expected_secure":  rec.sample.expected_secure,
            "predicted_secure": rec.predicted_secure,
            "correct":          rec.correct,
        }
        self._records.append(event)

    def log_event(self, event_name: str, payload: Optional[dict] = None) -> None:
        event = {
            "event": event_name,
            "ts": _now(),
            "run_id": self.run_id,
        }
        if payload:
            event.update(payload)
        self._records.append(event)

    # ── Flush ─────────────────────────────────────────────────────────────
    def flush(self) -> str:
        """Write all records to a structured JSON log file. Returns the path."""
        path = os.path.join(self.output_dir, f"run_{self.run_id}_events.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._records, f, indent=2, ensure_ascii=False)
        logger.info("Events flushed to %s (%d records)", path, len(self._records))
        return path


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

