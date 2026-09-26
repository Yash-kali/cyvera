from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Response, HTTPException, status, Query, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db
from app.models import User, Scan, Finding, ReconResult, Report, AIExplanation, AttackSurfaceAsset
from app.schemas import ReportResponse, ReportGeneratePayload
from app.auth import get_current_user
from app.services.pdf_generator import generate_security_pdf_report
from app.services.security_score import calculate_security_score
from app.services.owasp_mapper import calculate_owasp_stats

router = APIRouter(prefix="/api/v1/reports", tags=["Adaptive PDF Reports"])


@router.post("/generate/{scan_id}", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def generate_pdf_report_for_scan(
    scan_id: int,
    payload: Optional[ReportGeneratePayload] = Body(None),
    scan_profile: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    POST /api/v1/reports/generate/{scan_id}
    Generates dynamic adaptive enterprise PDF Security Report (Quick, Standard, or Full).
    Strictly scoped to current_user.id and canonical scan data.
    """
    # 1. Authorize and fetch the target scan strictly scoped to current user
    stmt_scan = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    res_scan = await db.execute(stmt_scan)
    scan = res_scan.scalars().first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan #{scan_id} not found or access denied."
        )

    # 2. Determine requested profile
    profile_input = "standard"
    if payload and payload.scan_profile:
        profile_input = payload.scan_profile
    elif scan_profile:
        profile_input = scan_profile
    elif scan.scan_type:
        profile_input = scan.scan_type

    p_lower = str(profile_input).lower()
    if "quick" in p_lower:
        profile_type = "Quick"
    elif "full" in p_lower:
        profile_type = "Full"
    elif "standard" in p_lower:
        profile_type = "Standard"
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid report profile '{profile_input}'. Allowed profiles: quick, standard, full."
        )

    title_prefix = f"{profile_type} Vulnerability Audit Report"
    target_url = scan.target_url

    # 3. Retrieve canonical findings for scan
    stmt_f = select(Finding).where(Finding.scan_id == scan.id, Finding.user_id == current_user.id)
    res_f = await db.execute(stmt_f)
    findings = res_f.scalars().all()

    # 4. Retrieve canonical AI explanations for these findings
    finding_ids = [f.id for f in findings]
    ai_explanations = []
    if finding_ids:
        stmt_ai = select(AIExplanation).where(
            AIExplanation.finding_id.in_(finding_ids),
            AIExplanation.user_id == current_user.id
        )
        res_ai = await db.execute(stmt_ai)
        ai_explanations = res_ai.scalars().all()

    # 5. Retrieve canonical recon telemetry
    stmt_r = select(ReconResult).where(ReconResult.scan_id == scan.id, ReconResult.user_id == current_user.id)
    res_r = await db.execute(stmt_r)
    recon = res_r.scalars().first()

    resolved_ip = recon.ip_address if recon and recon.ip_address and recon.ip_address != "N/A" else None

    # 5b. Retrieve discovered attack surface assets
    stmt_assets = select(AttackSurfaceAsset).where(AttackSurfaceAsset.scan_id == scan.id)
    res_assets = await db.execute(stmt_assets)
    attack_surface_assets = res_assets.scalars().all()

    # 6. Retrieve canonical score from authoritative persisted scan details or compute
    if scan.score_details and isinstance(scan.score_details, dict) and "score" in scan.score_details:
        score_data = scan.score_details
    else:
        score_data = calculate_security_score(scan.id, target_url, findings, recon)
    owasp_stats = calculate_owasp_stats(scan.id, findings)

    # 7. Generate PDF bytes and real page count
    pdf_bytes, actual_pages = generate_security_pdf_report(
        user_name=current_user.username,
        target_url=target_url,
        scan_id=scan.id,
        scan_type=profile_type,
        ip_address=resolved_ip,
        findings=findings,
        recon_result=recon,
        score_data=score_data,
        owasp_stats=owasp_stats,
        ai_explanations=ai_explanations,
        attack_surface_assets=attack_surface_assets
    )

    # 8. Idempotent storage: Update existing report or insert new
    report_id_str = f"REP-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{scan.id:04d}-{profile_type[:1].upper()}"

    stmt_existing = select(Report).where(
        Report.scan_id == scan.id,
        Report.user_id == current_user.id,
        Report.report_type == profile_type
    )
    res_existing = await db.execute(stmt_existing)
    report_entry = res_existing.scalars().first()

    if report_entry:
        report_entry.pdf_bytes = pdf_bytes
        report_entry.pages = actual_pages
        report_entry.title = f"{title_prefix} #{scan.id}"
        report_entry.target_url = target_url
        report_entry.created_at = datetime.now(timezone.utc)
    else:
        # Avoid potential string collision if ID was previously used
        stmt_by_str = select(Report).where(Report.report_id_str == report_id_str)
        if (await db.execute(stmt_by_str)).scalars().first():
            report_id_str = f"REP-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{scan.id:04d}-{profile_type[:1].upper()}"

        report_entry = Report(
            user_id=current_user.id,
            scan_id=scan.id,
            report_id_str=report_id_str,
            report_type=profile_type,
            title=f"{title_prefix} #{scan.id}",
            target_url=target_url,
            pages=actual_pages,
            pdf_bytes=pdf_bytes
        )
        db.add(report_entry)

    await db.commit()
    await db.refresh(report_entry)

    return ReportResponse(
        id=report_entry.id,
        report_id_str=report_entry.report_id_str,
        report_type=report_entry.report_type,
        title=report_entry.title,
        target_url=report_entry.target_url,
        scan_id=report_entry.scan_id,
        pages=report_entry.pages,
        created_at=report_entry.created_at,
        download_url=f"/api/v1/reports/download/{report_entry.id}"
    )


@router.get("/download/{report_id}")
async def download_pdf_report_by_id(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    GET /api/v1/reports/download/{report_id}
    Streams downloadable ReportLab PDF report binary file.
    Strictly authorized to current_user.id. Rejects unauthorized access with HTTP 404.
    """
    if report_id.isdigit():
        stmt = select(Report).where(Report.id == int(report_id), Report.user_id == current_user.id)
    else:
        stmt = select(Report).where(Report.report_id_str == report_id, Report.user_id == current_user.id)

    result = await db.execute(stmt)
    report = result.scalars().first()

    if not report or not report.pdf_bytes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report artifact #{report_id} not found or access denied."
        )

    safe_id_str = "".join(c for c in report.report_id_str if c.isalnum() or c in ("-", "_"))
    filename = f"AutoPentest_AI_{report.report_type}_Report_{safe_id_str}.pdf"
    return Response(
        content=report.pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Access-Control-Expose-Headers": "Content-Disposition"
        }
    )



@router.get("/{scan_id}", response_model=List[ReportResponse])
async def get_reports_by_scan_id(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    GET /api/v1/reports/{scan_id}
    Returns list of reports generated for a specific scan ID.
    """
    stmt = select(Report).where(Report.scan_id == scan_id, Report.user_id == current_user.id).order_by(Report.created_at.desc())
    result = await db.execute(stmt)
    reports = result.scalars().all()

    return [
        ReportResponse(
            id=r.id,
            report_id_str=r.report_id_str,
            report_type=r.report_type,
            title=r.title,
            target_url=r.target_url,
            scan_id=r.scan_id,
            pages=r.pages,
            created_at=r.created_at,
            download_url=f"/api/v1/reports/download/{r.id}"
        )
        for r in reports
    ]


@router.get("", response_model=List[ReportResponse])
@router.get("/", response_model=List[ReportResponse], include_in_schema=False)
@router.get("/list", response_model=List[ReportResponse], include_in_schema=False)
async def get_all_reports(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    GET /api/v1/reports
    Retrieves list of generated PDF reports for authenticated user.
    """
    stmt = select(Report).where(Report.user_id == current_user.id).order_by(Report.created_at.desc())
    result = await db.execute(stmt)
    reports = result.scalars().all()

    return [
        ReportResponse(
            id=r.id,
            report_id_str=r.report_id_str,
            report_type=r.report_type,
            title=r.title,
            target_url=r.target_url,
            scan_id=r.scan_id,
            pages=r.pages,
            created_at=r.created_at,
            download_url=f"/api/v1/reports/download/{r.id}"
        )
        for r in reports
    ]


@router.delete("/{report_id}", status_code=status.HTTP_200_OK)
async def delete_report_by_id(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    DELETE /api/v1/reports/{report_id}
    Deletes a single report artifact by ID or report_id_str.
    """
    if report_id.isdigit():
        stmt = select(Report).where(Report.id == int(report_id), Report.user_id == current_user.id)
    else:
        stmt = select(Report).where(Report.report_id_str == report_id, Report.user_id == current_user.id)

    res = await db.execute(stmt)
    report = res.scalars().first()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report artifact #{report_id} not found or access denied."
        )

    await db.delete(report)
    await db.commit()

    return {"message": f"Report artifact #{report_id} deleted successfully.", "report_id": report_id}


@router.post("/delete-bulk", status_code=status.HTTP_200_OK)
async def delete_reports_bulk(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    POST /api/v1/reports/delete-bulk
    Bulk deletes multiple selected report artifacts by ID list.
    """
    report_ids = payload.get("report_ids", [])
    if not report_ids or not isinstance(report_ids, list):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="report_ids must be a non-empty list.")

    from sqlalchemy import delete
    int_ids = [int(rid) for rid in report_ids if str(rid).isdigit()]
    str_ids = [str(rid) for rid in report_ids if not str(rid).isdigit()]

    if int_ids:
        await db.execute(delete(Report).where(Report.id.in_(int_ids), Report.user_id == current_user.id))
    if str_ids:
        await db.execute(delete(Report).where(Report.report_id_str.in_(str_ids), Report.user_id == current_user.id))

    await db.commit()
    return {"message": f"Successfully deleted {len(report_ids)} selected report artifacts.", "deleted_report_ids": report_ids}

