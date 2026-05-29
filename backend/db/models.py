import enum
from datetime import datetime

from db.database import Base
from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy import Enum as SqlEnum
from sqlalchemy.orm import relationship


class ComponentTypeEnum(str, enum.Enum):
    library = "library"
    product = "product"


class SeverityLevel(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    unknown = "unknown"


class EvidenceType(str, enum.Enum):
    analyst_report = "analyst_report"
    incident_link = "incident_link"
    virustotal = "virustotal"
    cve_discussion = "cve_discussion"
    audit_report = "audit_report"
    other = "other"


class Component(Base):
    __tablename__ = "components"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    version = Column(String, nullable=False)
    type = Column(SqlEnum(ComponentTypeEnum), nullable=False)
    ecosystem = Column(String, nullable=True)
    identifier = Column(String, nullable=True)
    last_updated = Column(DateTime, default=datetime.now(), nullable=False)
    notes = Column(Text, nullable=True)
    tags = Column(Text, nullable=True)          # comma-separated, e.g. "prod,db-server"

    # Source & distribution metadata
    repo_url = Column(String, nullable=True)    # GitHub/GitLab repo URL
    distrib_url = Column(String, nullable=True) # Download URL for artifact

    # OpenSSF Scorecard
    scorecard_score = Column(Float, nullable=True)
    scorecard_data = Column(Text, nullable=True)    # JSON blob of full scorecard
    scorecard_updated = Column(DateTime, nullable=True)

    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="component",
        cascade="all, delete-orphan",
    )
    evidence = relationship(
        "Evidence",
        back_populates="component",
        cascade="all, delete-orphan",
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, nullable=False)
    source = Column(String, nullable=False)
    severity = Column(SqlEnum(SeverityLevel), default=SeverityLevel.unknown, nullable=False)
    cvss_score = Column(Float, nullable=True)        # numeric CVSS base score, e.g. 9.1
    is_false_positive = Column(Boolean, default=False, nullable=False)
    false_positive_reason = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=datetime.now, nullable=False)
    component_id = Column(Integer, ForeignKey("components.id"))

    component = relationship("Component", back_populates="vulnerabilities")


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    component_id = Column(Integer, ForeignKey("components.id"), nullable=False)
    type = Column(SqlEnum(EvidenceType), nullable=False, default=EvidenceType.other)
    title = Column(String, nullable=False)
    url = Column(String, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.now, nullable=False)

    component = relationship("Component", back_populates="evidence")


class Settings(Base):
    """Key-value store for application settings (webhook, QG thresholds, etc.)"""
    __tablename__ = "settings"

    key = Column(String, primary_key=True)
    value = Column(Text, nullable=True)
