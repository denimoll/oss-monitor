from sqlalchemy import Column, Integer, String, Enum as SqlEnum, ForeignKey
from sqlalchemy.orm import relationship
from db.database import Base
import enum

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

    vulnerabilities = relationship("Vulnerability", back_populates="component")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String)
    source = Column(String)
    component_id = Column(Integer, ForeignKey("components.id"))

    component = relationship("Component", back_populates="vulnerabilities")
