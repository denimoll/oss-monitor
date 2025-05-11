import enum
from datetime import datetime

from db.database import Base
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy import Enum as SqlEnum
from sqlalchemy.orm import relationship


class ComponentTypeEnum(str, enum.Enum):
    library = "library"
    product = "product"

class Component(Base):
    __tablename__ = "components"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    version = Column(String)
    type = Column(SqlEnum(ComponentTypeEnum))
    ecosystem = Column(String, nullable=True)
    identifier = Column(String, nullable=True)
    last_updated = Column(DateTime, default=datetime.now(), nullable=False)

    vulnerabilities = relationship("Vulnerability", back_populates="component")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String)
    source = Column(String)
    component_id = Column(Integer, ForeignKey("components.id"))

    component = relationship("Component", back_populates="vulnerabilities")
