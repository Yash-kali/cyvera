from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db
from app.models import User, ReconResult
from app.schemas import ReconInspectRequest, ReconResultResponse
from app.auth import get_current_user
from app.services.recon import perform_asset_recon_audit

router = APIRouter(prefix="/api/v1/recon", tags=["Asset Security & Posture Audit"])


@router.post("/inspect", response_model=ReconResultResponse, status_code=status.HTTP_201_CREATED)
async def inspect_asset_security(
    req: ReconInspectRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Execute defensive asset security posture inspection on target URL.
    Audits SSL/TLS certificate, HTTP security headers, and DNS/IP resolution.
    Stores audit findings in PostgreSQL.
    """
    from app.services.target_validator import validate_target
    val_res = validate_target(req.target_url)
    if not val_res.is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target validation failed: {val_res.error_message}"
        )

    audit_data = await perform_asset_recon_audit(val_res.target_url)
    
    recon_entry = ReconResult(
        user_id=current_user.id,
        scan_id=req.scan_id,
        target_url=audit_data["target_url"],
        ip_address=audit_data["ip_address"],
        web_server=audit_data["web_server"],
        ssl_issuer=audit_data["ssl_issuer"],
        ssl_expires_days=audit_data["ssl_expires_days"],
        security_score=audit_data["security_score"],
        details=audit_data["details"]
    )
    
    db.add(recon_entry)
    await db.commit()
    await db.refresh(recon_entry)
    
    return recon_entry


@router.get("/history", response_model=List[ReconResultResponse])
async def get_recon_history(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get history of defensive asset security inspections for current operator."""
    stmt = select(ReconResult).where(ReconResult.user_id == current_user.id).order_by(ReconResult.created_at.desc())
    result = await db.execute(stmt)
    results = result.scalars().all()
    return results
