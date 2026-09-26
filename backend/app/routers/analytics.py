from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db
from app.models import User, Finding, Scan
from app.schemas import (
    RiskSummaryResponse,
    AssetRiskItem,
    AnalyticsOverviewResponse
)
from app.auth import get_current_user
from app.services.risk_engine import (
    calculate_risk_metrics,
    calculate_asset_risk_breakdown,
    calculate_analytics_overview
)

router = APIRouter(prefix="/api/v1/analytics", tags=["Risk Assessment & Analytics"])


@router.get("/overview", response_model=AnalyticsOverviewResponse)
async def get_analytics_overview(
    severity: Optional[str] = Query(None, description="Severity filter: Critical, High, Medium, Low, Info, All"),
    scan_type: Optional[str] = Query(None, description="Scan profile filter: Quick, Standard, Full, All"),
    date_range: Optional[str] = Query("30d", description="Date window: 7d, 30d, 90d, all"),
    status: Optional[str] = Query(None, description="Scan status: Pending, Running, Completed, Failed, All"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Consolidated, production-grade security analytics endpoint.
    Aggregates real scans and findings scoped strictly to authenticated user.
    Applies multi-parameter database-driven filters (severity, scan_type, date_range, status).
    Returns complete KPIs, scan profile distribution, OWASP distribution, chronological trends, and asset risk index.
    """
    stmt_scans = select(Scan).where(Scan.user_id == current_user.id).order_by(Scan.created_at.desc())
    res_scans = await db.execute(stmt_scans)
    scans = res_scans.scalars().all()

    stmt_findings = select(Finding).where(Finding.user_id == current_user.id).order_by(Finding.created_at.desc())
    res_findings = await db.execute(stmt_findings)
    findings = res_findings.scalars().all()

    overview = calculate_analytics_overview(
        scans=scans,
        findings=findings,
        severity_filter=severity,
        scan_type_filter=scan_type,
        date_range=date_range,
        status_filter=status
    )
    return overview


@router.get("/risk-summary", response_model=RiskSummaryResponse)
async def get_risk_summary(
    severity: Optional[str] = Query(None, description="Severity filter: Critical, High, Medium, Low, Info, All"),
    scan_type: Optional[str] = Query(None, description="Scan profile filter: Quick, Standard, Full, All"),
    date_range: Optional[str] = Query("30d", description="Date window: 7d, 30d, 90d, all"),
    status: Optional[str] = Query(None, description="Scan status: Pending, Running, Completed, Failed, All"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    CVSS-inspired Vulnerability Risk Assessment.
    Computes active Weighted Risk Score (R), Security Health Score (S), Grade letter,
    and Severity Mapping Distribution (Critical, High, Medium, Low, Info) respecting filter parameters.
    """
    stmt_scans = select(Scan).where(Scan.user_id == current_user.id)
    res_scans = await db.execute(stmt_scans)
    scans = res_scans.scalars().all()

    stmt_findings = select(Finding).where(Finding.user_id == current_user.id)
    res_findings = await db.execute(stmt_findings)
    findings = res_findings.scalars().all()

    overview = calculate_analytics_overview(
        scans=scans,
        findings=findings,
        severity_filter=severity,
        scan_type_filter=scan_type,
        date_range=date_range,
        status_filter=status
    )
    return {
        "security_score": overview["security_score"],
        "risk_score": overview["risk_score"],
        "grade": overview["grade"],
        "grade_color": overview["grade_color"],
        "total_findings": overview["total_findings"],
        "open_findings": overview["open_findings"],
        "resolved_findings": overview["resolved_findings"],
        "sla_compliance_rate": overview["sla_compliance_rate"],
        "severity_distribution": overview["severity_distribution"]
    }


@router.get("/asset-risk", response_model=List[AssetRiskItem])
async def get_asset_risk_analytics(
    severity: Optional[str] = Query(None, description="Severity filter: Critical, High, Medium, Low, Info, All"),
    scan_type: Optional[str] = Query(None, description="Scan profile filter: Quick, Standard, Full, All"),
    date_range: Optional[str] = Query("30d", description="Date window: 7d, 30d, 90d, all"),
    status: Optional[str] = Query(None, description="Scan status: Pending, Running, Completed, Failed, All"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Computes target domain asset-level risk scores and vulnerability ratings respecting filter parameters."""
    stmt_scans = select(Scan).where(Scan.user_id == current_user.id)
    res_scans = await db.execute(stmt_scans)
    scans = res_scans.scalars().all()

    stmt_findings = select(Finding).where(Finding.user_id == current_user.id)
    res_findings = await db.execute(stmt_findings)
    findings = res_findings.scalars().all()

    overview = calculate_analytics_overview(
        scans=scans,
        findings=findings,
        severity_filter=severity,
        scan_type_filter=scan_type,
        date_range=date_range,
        status_filter=status
    )
    return overview["asset_risks"]
