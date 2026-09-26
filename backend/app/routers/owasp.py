from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db
from app.models import User, Finding, Scan
from app.schemas import OWASPFindingsResponse, OWASPStatsResponse
from app.auth import get_current_user
from app.services.owasp_mapper import categorize_findings_by_owasp, calculate_owasp_stats

router = APIRouter(prefix="/api/v1/owasp", tags=["OWASP Top 10 Mapping Engine"])


@router.get("/{scan_id}", response_model=OWASPFindingsResponse)
async def get_owasp_findings_by_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    GET /api/v1/owasp/{scan_id}
    Retrieves scan findings mapped to OWASP Top 10 2021 categories (A01-A10).
    Enforces user isolation.
    """
    stmt_scan = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    res_scan = await db.execute(stmt_scan)
    scan = res_scan.scalars().first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan #{scan_id} not found or access denied."
        )

    stmt = select(Finding).where(Finding.scan_id == scan_id, Finding.user_id == current_user.id)
    result = await db.execute(stmt)
    findings = result.scalars().all()

    mapped_data = categorize_findings_by_owasp(scan_id, findings)
    return OWASPFindingsResponse(**mapped_data)


@router.get("/stats/{scan_id}", response_model=OWASPStatsResponse)
async def get_owasp_stats_by_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    GET /api/v1/owasp/stats/{scan_id}
    Returns OWASP category distribution stats, severity breakdown, and category-severity matrix.
    Enforces user isolation.
    """
    stmt_scan = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    res_scan = await db.execute(stmt_scan)
    scan = res_scan.scalars().first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan #{scan_id} not found or access denied."
        )

    stmt = select(Finding).where(Finding.scan_id == scan_id, Finding.user_id == current_user.id)
    result = await db.execute(stmt)
    findings = result.scalars().all()

    stats_data = calculate_owasp_stats(scan_id, findings)
    return OWASPStatsResponse(**stats_data)
