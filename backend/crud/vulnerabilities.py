from db.models import Vulnerability
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
import logging

# Configure logging
logger = logging.getLogger(__name__)

async def update_false_positive(db: AsyncSession, vuln_id: int, is_fp: bool, reason: str = None) -> bool:
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    
    if not vuln:
        logger.debug(f"No vulnerability found with ID {vuln_id}")
        return False

    vuln.is_false_positive = is_fp
    vuln.false_positive_reason = reason if is_fp else None
    await db.commit()
    logger.debug(f"Updated vulnerability ID {vuln_id} false_positive to {is_fp}")
    return True
