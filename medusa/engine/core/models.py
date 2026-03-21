"""SQLAlchemy ORM models for Session and Finding."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import Session as SASession, declarative_base, relationship, sessionmaker

Base = declarative_base()


class SessionModel(Base):
    """Engagement session model."""

    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    operator = Column(String, nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow)
    scope_hash = Column(String, nullable=False)
    status = Column(String, default="active")
    ai_token_usage = Column(Float, default=0.0)
    target = Column(String, default="")
    scope_ips = Column(JSON, default=list)
    scope_domains = Column(JSON, default=list)
    scope_cidrs = Column(JSON, default=list)

    findings = relationship(
        "FindingModel", back_populates="session", cascade="all, delete-orphan"
    )


class FindingModel(Base):
    """Finding model with full blueprint fields."""

    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String(36), ForeignKey("sessions.id"), nullable=False)
    ts = Column(DateTime, default=datetime.utcnow)
    module = Column(String, nullable=False)
    target = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False)
    cvss_vector = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    payload = Column(Text, nullable=True)
    request = Column(Text, nullable=True)
    response = Column(Text, nullable=True)
    screenshot_path = Column(String, nullable=True)
    pcap_path = Column(String, nullable=True)
    ai_explanation = Column(Text, nullable=True)
    ai_remediation = Column(Text, nullable=True)
    source = Column(String, default="tool")
    confidence = Column(String, default="high")
    verified = Column(String, default="unverified")
    cve_ids = Column(JSON, default=list)
    cwe_ids = Column(JSON, default=list)
    mitre_technique = Column(String, nullable=True)
    owasp_category = Column(String, nullable=True)
    tags = Column(JSON, default=list)
    details = Column(JSON, default=dict)

    session = relationship("SessionModel", back_populates="findings")


def init_db(database_url: str) -> SASession:
    """Initialize the database and create tables."""
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


__all__ = ["Base", "SessionModel", "FindingModel", "init_db"]
