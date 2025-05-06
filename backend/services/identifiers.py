from models import ComponentRequest, ComponentType

def generate_identifier(data: ComponentRequest) -> str:
    if data.identifier_override:
        return data.identifier_override.strip()

    if data.type == ComponentType.library:
        if not data.ecosystem:
            raise ValueError("Ecosystem is required for libraries.")
        return f"pkg:{data.ecosystem}/{data.name}@{data.version}"

    elif data.type == ComponentType.product:
        return None

    raise ValueError("Unknown component type.")
