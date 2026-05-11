"""Database model and helpers for persisted evaluation runs."""

from __future__ import annotations

import json
import os
from datetime import datetime
from sqlalchemy import create_engine, Column, String, DateTime, Float, Integer, JSON, Text
from sqlalchemy.orm import sessionmaker, Session, declarative_base

Base = declarative_base()


class Run(Base):
    __tablename__ = "runs"
    
    run_id = Column(String(36), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    target = Column(String(50), nullable=True)
    accuracy = Column(Float, default=0.0)
    precision_insecure = Column(Float, default=0.0)
    recall_insecure = Column(Float, default=0.0)
    f1_insecure = Column(Float, default=0.0)
    false_positive_rate = Column(Float, default=0.0)
    total = Column(Integer, default=0)
    confusion_matrix = Column(JSON, nullable=True)
    risk_score_by_category = Column(JSON, nullable=True)
    metrics_json = Column(Text, nullable=True)
    details_json = Column(Text, nullable=True)


def get_db_url() -> str:
    """Resolve database URL from environment, defaulting to local SQLite."""
    db_url = os.environ.get("DATABASE_URL")
    if db_url:
        return db_url
    # Fallback to SQLite for local development
    db_path = os.path.join(os.path.dirname(__file__), "netsec.db")
    return f"sqlite:///{db_path}"


def init_db():
    """Create database tables if they do not already exist."""
    engine = create_engine(get_db_url())
    Base.metadata.create_all(engine)
    return engine


def get_session() -> Session:
    """Get a database session."""
    engine = create_engine(get_db_url())
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()


def save_run_to_db(run_id: str, metrics: dict, details: dict, target: str = None):
    """Save a run to the database."""
    try:
        session = get_session()
        run = Run(
            run_id=run_id,
            target=target,
            accuracy=metrics.get("accuracy", 0.0),
            precision_insecure=metrics.get("precision_insecure", 0.0),
            recall_insecure=metrics.get("recall_insecure", 0.0),
            f1_insecure=metrics.get("f1_insecure", 0.0),
            false_positive_rate=metrics.get("false_positive_rate", 0.0),
            total=metrics.get("total", 0),
            confusion_matrix=metrics.get("confusion_matrix"),
            risk_score_by_category=metrics.get("risk_score_by_category"),
            metrics_json=json.dumps(metrics),
            details_json=json.dumps(details),
        )
        session.merge(run)
        session.commit()
        session.close()
    except Exception as e:
        print(f"[DB] Failed to save run: {e}")


def load_runs_from_db() -> list:
    """Load all runs from database, ordered by creation date descending."""
    try:
        session = get_session()
        runs = session.query(Run).order_by(Run.created_at.desc()).all()
        session.close()
        return [
            {
                "run_id": r.run_id,
                "total": r.total,
                "accuracy": r.accuracy,
                "precision": r.precision_insecure,
                "recall": r.recall_insecure,
                "f1": r.f1_insecure,
                "fpr": r.false_positive_rate,
            }
            for r in runs
        ]
    except Exception as e:
        print(f"[DB] Failed to load runs: {e}")
        return []