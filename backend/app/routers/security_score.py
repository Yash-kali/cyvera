from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db
from app.models import User, Scan, Finding, ReconResult
from app.schemas import SecurityScoreResponse
from app.auth import get_current_user
from app.services.security_score import calculate_security_score

router = APIRouter(prefix="/api/v1/security-score", tags=["Security Score Engine"])


@router.get("/{scan_id}", response_model=SecurityScoreResponse)
async def get_security_score(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    GET /api/v1/security-score/{scan_id}
    Returns calculated Security Score (0-100), Grade (A-F), and Risk Level.
    Enforces user isolation: only the owner can query the security score.
    """
    stmt_scan = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    res_scan = await db.execute(stmt_scan)
    scan = res_scan.scalars().first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan #{scan_id} not found or access denied."
        )

    # Query associated findings & recon data belonging to this user
    stmt_findings = select(Finding).where(Finding.scan_id == scan_id, Finding.user_id == current_user.id)
    res_findings = await db.execute(stmt_findings)
    findings = res_findings.scalars().all()

    stmt_recon = select(ReconResult).where(ReconResult.scan_id == scan_id, ReconResult.user_id == current_user.id)
    res_recon = await db.execute(stmt_recon)
    recon_result = res_recon.scalars().first()

    score_payload = calculate_security_score(
        scan_id=scan.id,
        target_url=scan.target_url,
        findings=findings,
        recon_result=recon_result
    )

    # Persist score metadata in DB
    try:
        scan.security_score = score_payload["score"]
        scan.security_grade = score_payload["grade"]
        scan.risk_level = score_payload["risk_level"]
        scan.score_details = score_payload
        await db.commit()
    except Exception:
        await db.rollback()

    return SecurityScoreResponse(**score_payload)
