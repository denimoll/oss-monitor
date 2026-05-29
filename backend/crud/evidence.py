import logging
from datetime import datetime

from db.models import Evidence
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

logger = logging.getLogger(__name__)


async def get_evidence_for_component(db: AsyncSession, component_id: int) -> list[Evidence]:
    result = await db.execute(
        select(Evidence).where(Evidence.component_id == component_id).order_by(Evidence.created_at.desc())
    )
    return result.scalars().all()


async def create_evidence(db: AsyncSession, component_id: int, data: dict) -> Evidence:
    evidence = Evidence(
        component_id=component_id,
        type=data["type"],
        title=data["title"],
        url=data.get("url"),
        notes=data.get("notes"),
        created_at=datetime.now(),
    )
    db.add(evidence)
    await db.commit()
    await db.refresh(evidence)
    logger.info(f"Evidence '{evidence.title}' added for component {component_id}")
    return evidence


async def delete_evidence(db: AsyncSession, evidence_id: int) -> bool:
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    evidence = result.scalar_one_or_none()
    if not evidence:
        return False
    await db.delete(evidence)
    await db.commit()
    logger.info(f"Evidence {evidence_id} deleted")
    return True
