from pydantic import BaseModel
from enum import Enum

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
    ecosystem: Ecosystem | None = None
    identifier_override: str | None = None
    