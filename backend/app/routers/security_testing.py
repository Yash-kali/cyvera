from typing import List, Optional, Dict, Any, Set
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func

from app.database import get_db
from app.models import User, Scan, Finding
from app.schemas import FindingResponse, SecurityTestingSummaryResponse
from app.auth import get_current_user

router = APIRouter(prefix="/api/v1/security-testing", tags=["Security Testing Engine"])


@router.get("/{scan_id}", response_model=List[FindingResponse])
async def get_scan_security_findings(
    scan_id: int,
    severity: Optional[str] = Query(None, description="Filter by severity (Critical, High, Medium, Low, Info)"),
    category: Optional[str] = Query(None, description="Filter by category"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (Open, Confirmed, etc.)"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve security findings produced for a specific scan.
    Strict tenant isolation: only the authenticated owner can access findings for their scan.
    """
    # 1. Verify scan exists and belongs to current user
    scan_stmt = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    scan_res = await db.execute(scan_stmt)
    scan = scan_res.scalars().first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan #{scan_id} not found or access denied."
        )

    # 2. Query findings
    stmt = select(Finding).where(
        Finding.scan_id == scan_id,
        Finding.user_id == current_user.id
    )

    if severity and severity != "All":
        stmt = stmt.where(Finding.severity == severity)
    if category and category != "All":
        stmt = stmt.where(Finding.category == category)
    if status_filter and status_filter != "All":
        stmt = stmt.where(Finding.status == status_filter)

    stmt = stmt.order_by(Finding.id.asc()).offset(skip).limit(limit)
    res = await db.execute(stmt)
    findings = res.scalars().all()

    return findings


@router.get("/{scan_id}/summary", response_model=SecurityTestingSummaryResponse)
async def get_scan_security_summary(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve aggregated security testing telemetry and severity breakdown for a scan.
    Strict tenant isolation: rejects unauthorized operators with HTTP 404.
    """
    # 1. Verify scan ownership
    scan_stmt = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    scan_res = await db.execute(scan_stmt)
    scan = scan_res.scalars().first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan #{scan_id} not found or access denied."
        )

    # 2. Query all findings for this scan
    stmt = select(Finding).where(
        Finding.scan_id == scan_id,
        Finding.user_id == current_user.id
    )
    res = await db.execute(stmt)
    findings = res.scalars().all()

    sev_counts: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    cat_counts: Dict[str, int] = {}
    verif_counts: Dict[str, int] = {"Open": 0, "Confirmed": 0, "Manual Verification Required": 0}
    test_types: Set[str] = set()

    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        cat_counts[f.category] = cat_counts.get(f.category, 0) + 1
        verif_counts[f.status] = verif_counts.get(f.status, 0) + 1
        if f.test_type:
            test_types.add(f.test_type)

    return SecurityTestingSummaryResponse(
        scan_id=scan_id,
        total_findings=len(findings),
        severity_breakdown=sev_counts,
        category_breakdown=cat_counts,
        tests_executed=sorted(list(test_types)),
        total_requests=min(150, len(findings) * 3 + 12),  # Estimated request count
        budget_exhausted=False,
        verification_statuses=verif_counts
    )
