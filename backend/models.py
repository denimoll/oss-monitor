from pydantic import BaseModel
from enum import Enum
from typing import Optional

class ComponentType(str, Enum):
    library = "library"
    product = "product"

class Ecosystem(str, Enum):
    npm = "npm"
    pypi = "pypi"
    maven = "maven"
    nuget = "nuget"
    go = "go"
    crates = "crates.io"

class ComponentRequest(BaseModel):
    type: ComponentType
    name: str
    version: str
    ecosystem: Optional[Ecosystem] = None
    identifier_override: Optional[str] = None
    