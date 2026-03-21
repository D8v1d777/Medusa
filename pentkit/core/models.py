from __future__ import annotations
import uuid
from datetime import datetime
from typing import Literal, List, Optional
from sqlalchemy import Column, String, Float, DateTime, JSON, Text, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session as SASession

Base = declarative_base()

class SessionModel(Base):
    __tablename__ = 'sessions'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    operator = Column(String, nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow)
    scope_hash = Column(String, nullable=False)
    status = Column(String, default="active")
    ai_token_usage = Column(Float, default=0.0)
    
    findings = relationship("FindingModel", back_populates="session", cascade="all, delete-orphan")

class FindingModel(Base):
    __tablename__ = 'findings'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey('sessions.id'), nullable=False)
    ts = Column(DateTime, default=datetime.utcnow)
    module = Column(String, nullable=False)
    target = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False) # Literal["critical", "high", "medium", "low", "info"]
    cvss_vector = Column(String)
    cvss_score = Column(Float)
    payload = Column(Text)
    request = Column(Text)
    response = Column(Text)
    screenshot_path = Column(String)
    pcap_path = Column(String)
    ai_explanation = Column(Text)
    ai_remediation = Column(Text)
    source = Column(String, default="tool") # Literal["tool", "ai", "manual"]
    confidence = Column(String, default="high") # Literal["high", "medium", "low"]
    cve_ids = Column(JSON, default=list)
    tags = Column(JSON, default=list)
    details = Column(JSON, default=dict)
    
    session = relationship("SessionModel", back_populates="findings")

def init_db(database_url: str):
    """Initialize the SQLite database and create tables."""
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()

__all__ = ["Base", "SessionModel", "FindingModel", "init_db"]
