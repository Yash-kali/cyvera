from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func

from app.database import get_db
from app.models import User, Scan, AttackSurfaceAsset
from app.schemas import AttackSurfaceAssetResponse, AttackSurfaceSummaryResponse
from app.auth import get_current_user

router = APIRouter(prefix="/api/v1/attack-surface", tags=["Attack Surface Discovery"])


@router.get("/{scan_id}", response_model=List[AttackSurfaceAssetResponse])
async def get_attack_surface_assets(
    scan_id: int,
    asset_type: Optional[str] = Query(None, description="Filter by asset type (PAGE, FORM, API, SCRIPT, etc.)"),
    evidence_status: Optional[str] = Query(None, description="Filter by status (OBSERVED, INFERRED, VERIFIED)"),
    in_scope: Optional[bool] = Query(None, description="Filter in-scope vs out-of-scope assets"),
    external: Optional[bool] = Query(None, description="Filter internal vs external third-party assets"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve paginated attack surface inventory for a specific scan.
    Enforces strict tenant isolation: only the scan owner can view discovered assets.
    """
    # 1. Verify scan exists and belongs to authenticated operator
    scan_stmt = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    scan_res = await db.execute(scan_stmt)
    scan = scan_res.scalars().first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan #{scan_id} not found or access denied."
        )

    # 2. Build filtered query
    stmt = select(AttackSurfaceAsset).where(
        AttackSurfaceAsset.scan_id == scan_id,
        AttackSurfaceAsset.user_id == current_user.id
    )

    if asset_type:
        stmt = stmt.where(AttackSurfaceAsset.asset_type == asset_type.upper().strip())
    if evidence_status:
        stmt = stmt.where(AttackSurfaceAsset.evidence_status == evidence_status.upper().strip())
    if in_scope is not None:
        stmt = stmt.where(AttackSurfaceAsset.in_scope == in_scope)
    if external is not None:
        stmt = stmt.where(AttackSurfaceAsset.external == external)

    stmt = stmt.order_by(AttackSurfaceAsset.id.asc()).offset(skip).limit(limit)
    res = await db.execute(stmt)
    assets = res.scalars().all()

    return assets


@router.get("/{scan_id}/summary", response_model=AttackSurfaceSummaryResponse)
async def get_attack_surface_summary(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Aggregate summary metrics of attack surface assets for a scan.
    Provides counts by asset type, evidence status, and origin scope.
    """
    scan_stmt = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    scan_res = await db.execute(scan_stmt)
    scan = scan_res.scalars().first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan #{scan_id} not found or access denied."
        )

    # Query all assets for this scan
    stmt = select(AttackSurfaceAsset).where(
        AttackSurfaceAsset.scan_id == scan_id,
        AttackSurfaceAsset.user_id == current_user.id
    )
    res = await db.execute(stmt)
    assets = res.scalars().all()

    total_assets = len(assets)
    in_scope_count = sum(1 for a in assets if a.in_scope)
    external_count = sum(1 for a in assets if a.external)

    asset_types: dict[str, int] = {}
    evidence_statuses: dict[str, int] = {}
    discovered_from: dict[str, int] = {}

    for a in assets:
        asset_types[a.asset_type] = asset_types.get(a.asset_type, 0) + 1
        evidence_statuses[a.evidence_status] = evidence_statuses.get(a.evidence_status, 0) + 1
        discovered_from[a.discovered_from] = discovered_from.get(a.discovered_from, 0) + 1

    return AttackSurfaceSummaryResponse(
        scan_id=scan_id,
        total_assets=total_assets,
        in_scope_count=in_scope_count,
        external_count=external_count,
        asset_types=asset_types,
        evidence_statuses=evidence_statuses,
        discovered_from=discovered_from,
        crawl_stats={
            "scan_target": scan.target_url,
            "scan_status": scan.status,
            "current_phase": scan.current_phase
        }
    )
