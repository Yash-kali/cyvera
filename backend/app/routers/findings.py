from typing import List, Optional, Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status, Query, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db
from app.models import User, Finding, Scan
from app.schemas import (
    FindingCreate,
    FindingStatusUpdate,
    FindingResponse,
    SARIFImportPayload
)
from app.auth import get_current_user
from app.services.sarif_parser import parse_and_normalize_sarif, normalize_severity

router = APIRouter(prefix="/api/v1/findings", tags=["Vulnerability Triage & Remediation"])


@router.post("", response_model=FindingResponse, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=FindingResponse, status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def create_finding(
    finding_in: FindingCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Log a new security vulnerability finding in database.
    Enforces user authorization on optional scan_id and normalizes severity.
    """
    if finding_in.scan_id is not None:
        stmt_scan = select(Scan).where(Scan.id == finding_in.scan_id, Scan.user_id == current_user.id)
        res_scan = await db.execute(stmt_scan)
        scan = res_scan.scalars().first()
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan #{finding_in.scan_id} not found or access denied."
            )

    canonical_severity = normalize_severity(finding_in.severity, finding_in.cvss_score)

    finding = Finding(
        user_id=current_user.id,
        scan_id=finding_in.scan_id,
        title=finding_in.title[:255],
        description=finding_in.description,
        severity=canonical_severity,
        cvss_score=finding_in.cvss_score,
        cve_id=finding_in.cve_id[:100] if finding_in.cve_id else None,
        affected_url=finding_in.affected_url[:2048],
        remediation_guidance=finding_in.remediation_guidance,
        status="Open"
    )
    
    db.add(finding)
    await db.commit()
    await db.refresh(finding)
    
    return finding


@router.post("/import-sarif", response_model=List[FindingResponse], status_code=status.HTTP_201_CREATED)
async def import_sarif_report(
    payload: Any = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Ingest batch vulnerability reports (SARIF 2.1.0 / pipeline findings / wrapped envelopes).
    Parses, normalizes severities, deduplicates against existing records, and associates with user.
    """
    # 1. Parse raw body into python dict/list
    payload_data = payload
    if hasattr(payload, "model_dump"):
        payload_data = payload.model_dump(exclude_unset=True)
    elif isinstance(payload, str):
        import json
        try:
            payload_data = json.loads(payload)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Malformed JSON: {str(e)}")

    if not isinstance(payload_data, (dict, list)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Payload must be a JSON object or array.")

    # 2. Extract and verify scan_id if present
    scan_id = None
    if isinstance(payload_data, dict):
        scan_id = payload_data.get("scan_id")
        if scan_id is not None:
            stmt_scan = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
            res_scan = await db.execute(stmt_scan)
            scan = res_scan.scalars().first()
            if not scan:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Scan #{scan_id} not found or access denied."
                )

    # 3. Parse and normalize through SARIF engine
    try:
        candidates = parse_and_normalize_sarif(payload_data, scan_id=scan_id)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Error parsing SARIF report: {str(e)}")

    if not candidates:
        return []

    # 4. Deduplicate and persist
    persisted_findings: List[Finding] = []
    
    for item in candidates:
        target_scan_id = item.get("scan_id")
        # Check existing finding in same user & scan scope
        stmt_exist = select(Finding).where(
            Finding.user_id == current_user.id,
            Finding.scan_id == target_scan_id,
            Finding.title == item["title"],
            Finding.affected_url == item["affected_url"]
        )
        res_exist = await db.execute(stmt_exist)
        existing = res_exist.scalars().first()

        if existing:
            # Update fields while preserving existing triage status
            existing.description = item["description"]
            existing.severity = item["severity"]
            existing.cvss_score = item["cvss_score"]
            existing.cve_id = item["cve_id"]
            existing.remediation_guidance = item["remediation_guidance"]
            persisted_findings.append(existing)
        else:
            new_f = Finding(
                user_id=current_user.id,
                scan_id=target_scan_id,
                title=item["title"][:255],
                description=item["description"],
                severity=item["severity"],
                cvss_score=item["cvss_score"],
                cve_id=item["cve_id"][:100] if item.get("cve_id") else None,
                affected_url=item["affected_url"][:2048],
                remediation_guidance=item["remediation_guidance"],
                status="Open"
            )
            db.add(new_f)
            persisted_findings.append(new_f)

    await db.commit()
    for f in persisted_findings:
        await db.refresh(f)

    return persisted_findings


@router.get("", response_model=List[FindingResponse])
@router.get("/", response_model=List[FindingResponse], include_in_schema=False)
async def get_findings(
    scan_id: Optional[int] = Query(None, description="Filter findings by specific Scan ID"),
    severity: Optional[str] = Query(None, description="Filter by severity (Critical, High, Medium, Low, Info)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by triage status (Open, Resolved, etc)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve list of vulnerability findings for the authenticated operator.
    Supports filtering by scan ID, severity, and triage status.
    """
    stmt = select(Finding).where(Finding.user_id == current_user.id)
    
    if scan_id is not None:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if severity and severity != "All":
        stmt = stmt.where(Finding.severity == severity)
    if status_filter and status_filter != "All":
        stmt = stmt.where(Finding.status == status_filter)
        
    stmt = stmt.order_by(Finding.created_at.desc())
    result = await db.execute(stmt)
    findings = result.scalars().all()
    
    return findings


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding_by_id(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve single vulnerability finding. Enforces user isolation."""
    stmt = select(Finding).where(Finding.id == finding_id, Finding.user_id == current_user.id)
    result = await db.execute(stmt)
    finding = result.scalars().first()
    
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding #{finding_id} not found or access denied."
        )
    return finding


@router.patch("/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    finding_id: int,
    status_update: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update triage status of a vulnerability finding (e.g. Open -> Resolved, Mitigated, False Positive).
    Persists status reliably in database.
    """
    stmt = select(Finding).where(Finding.id == finding_id, Finding.user_id == current_user.id)
    result = await db.execute(stmt)
    finding = result.scalars().first()
    
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding #{finding_id} not found or access denied."
        )
        
    finding.status = status_update.status
    await db.commit()
    await db.refresh(finding)
    
    return finding


@router.delete("/{finding_id}", status_code=status.HTTP_200_OK)
async def delete_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a vulnerability finding. Enforces user isolation."""
    stmt = select(Finding).where(Finding.id == finding_id, Finding.user_id == current_user.id)
    result = await db.execute(stmt)
    finding = result.scalars().first()
    
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding #{finding_id} not found or access denied."
        )
        
    await db.delete(finding)
    await db.commit()
    
    return {"status": "deleted", "finding_id": finding_id}
