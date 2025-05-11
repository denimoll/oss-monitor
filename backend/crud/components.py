import logging
from datetime import datetime

from db.models import Component, Vulnerability
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

# Configure logger
logger = logging.getLogger(__name__)


async def get_all_components(db):
    """
    Retrieve all components from the database, including their vulnerabilities.
    """
    logger.info("Retrieving all components with their vulnerabilities")
    result = await db.execute(select(Component).options(selectinload(Component.vulnerabilities)))
    return result.scalars().all()


async def create_component_with_vulns(
        db: AsyncSession,
        component_data: dict,
        vulnerabilities: list[dict]) -> Component:
    """
    Create a new component with associated vulnerabilities in the database.
    If the component already exists (based on name, version, type, and ecosystem), return it instead.
    """
    logger.info(f"Checking for existing component: {component_data['name']}@{component_data['version']}")
    stmt = select(Component).where(
        Component.name == component_data["name"],
        Component.version == component_data["version"],
        Component.type == component_data["type"],
        Component.ecosystem == component_data.get("ecosystem")
    )
    result = await db.execute(stmt)
    existing_component = result.scalar_one_or_none()

    if existing_component:
        logger.info("Component already exists, skipping creation")
        return existing_component

    # Create and add new component
    component_data["last_updated"] = datetime.now()
    component = Component(**component_data)
    db.add(component)
    await db.flush() # Flush to assign primary key

    logger.info(f"Adding {len(vulnerabilities)} vulnerabilities to component")
    for vuln in vulnerabilities:
        db.add(Vulnerability(
            cve_id=vuln["id"],
            source=vuln["source"],
            component=component
        ))

    await db.commit()
    await db.refresh(component)
    logger.info(f"Component '{component.name}' saved successfully with vulnerabilities")
    return component


async def get_component_by_id(db, component_id: int):
    """
    Retrieve a specific component by its ID, including its vulnerabilities.
    """
    logger.info(f"Retrieving component by ID: {component_id}")
    result = await db.execute(
        select(Component)
        .options(selectinload(Component.vulnerabilities))
        .where(Component.id == component_id)
    )
    component = result.scalar_one_or_none()
    return component


async def delete_component(db, component_id: int) -> bool:
    """
    Delete a component from the database by its ID.
    Returns True if the component was found and deleted, otherwise False.
    """
    logger.info(f"Attempting to delete component ID: {component_id}")
    result = await db.execute(
        select(Component).where(Component.id == component_id)
    )
    component = result.scalar_one_or_none()

    if not component:
        logger.warning(f"Component ID {component_id} not found")
        return False

    await db.delete(component)
    await db.commit()
    logger.info(f"Component ID {component_id} successfully deleted")
    return True
