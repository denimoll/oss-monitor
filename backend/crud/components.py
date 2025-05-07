from db.models import Component, Vulnerability
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload


async def get_all_components(db):
    result = await db.execute(select(Component).options(selectinload(Component.vulnerabilities)))
    return result.scalars().all()


async def create_component_with_vulns(
        db: AsyncSession,
        component_data: dict,
        vulnerabilities: list[dict]) -> Component:
    
    stmt = select(Component).where(
        Component.name == component_data["name"],
        Component.version == component_data["version"],
        Component.type == component_data["type"],
        Component.ecosystem == component_data.get("ecosystem")
    )
    result = await db.execute(stmt)
    existing_component = result.scalar_one_or_none()

    if existing_component:
        return existing_component

    component = Component(**component_data)
    db.add(component)
    await db.flush()

    # Добавление уязвимостей
    for vuln in vulnerabilities:
        db.add(Vulnerability(
            cve_id=vuln["id"],
            source=vuln["source"],
            component=component
        ))

    await db.commit()
    await db.refresh(component)
    return component


async def get_component_by_id(db, component_id: int):
    result = await db.execute(
        select(Component)
        .options(selectinload(Component.vulnerabilities))
        .where(Component.id == component_id)
    )
    component = result.scalar_one_or_none()
    return component


async def delete_component(db, component_id: int) -> bool:
    result = await db.execute(
        select(Component).where(Component.id == component_id)
    )
    component = result.scalar_one_or_none()
    if not component:
        return False

    await db.delete(component)
    await db.commit()
    return True
