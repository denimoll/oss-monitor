import enum
from datetime import datetime

from db.database import Base
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
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

class Component(Base):
    __tablename__ = "components"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    version = Column(String, nullable=False)
    type = Column(SqlEnum(ComponentTypeEnum), nullable=False)
    ecosystem = Column(String, nullable=True)
    identifier = Column(String, nullable=True)
    last_updated = Column(DateTime, default=datetime.now(), nullable=False)

    vulnerabilities = relationship("Vulnerability", back_populates="component")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, nullable=False)
    source = Column(String, nullable=False)
    severity = Column(SqlEnum(SeverityLevel), default=SeverityLevel.unknown, nullable=False)
    is_false_positive = Column(Boolean, default=False, nullable=False)
    false_positive_reason = Column(Text, nullable=True)
    component_id = Column(Integer, ForeignKey("components.id"))

    component = relationship("Component", back_populates="vulnerabilities")
