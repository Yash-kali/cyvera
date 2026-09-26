from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import User, Scan
from app.schemas import ScanCreate, ScanResponse, ScanProgressResponse
from app.auth import get_current_user
from app.services.target_validator import validate_target
from app.services.scan_worker import scan_worker
from app.services.scan_progress import progress_manager

router = APIRouter(prefix="/api/v1/scans", tags=["Security Scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def create_scan(
    scan_in: ScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new Target Security Scan for the authenticated operator.
    Enforces:
    1. Explicit legal authorization attestation (authorization_confirmed == True).
    2. Comprehensive target safety validation (blocks localhost, private networks, cloud metadata, SSRF).
    3. Persistent database record creation.
    4. Enqueuing to persistent scan worker.
    """
    # 1. Authorization Attestation Check
    if not scan_in.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Target authorization must be explicitly confirmed before initiating a security assessment."
        )

    # 2. Strict Target Validation & SSRF Blocklist Check
    val_res = validate_target(scan_in.target_url)
    if not val_res.is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target validation failed: {val_res.error_message}"
        )

    now = datetime.now(timezone.utc)
    new_scan = Scan(
        user_id=current_user.id,
        target_url=val_res.target_url,
        scan_type=scan_in.scan_type,
        status="Pending",
        current_phase="PENDING",
        authorization_confirmed=True,
        authorization_timestamp=now,
        started_at=now,
        progress=0
    )

    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)

    # 3. Enqueue to Scan Worker
    scan_worker.enqueue_scan(new_scan.id, new_scan.target_url)

    return ScanResponse(
        id=new_scan.id,
        user_id=new_scan.user_id,
        target_url=new_scan.target_url,
        scan_type=new_scan.scan_type,
        status=new_scan.status,
        security_score=new_scan.security_score,
        security_grade=new_scan.security_grade,
        risk_level=new_scan.risk_level,
        vulnerabilities_count=0,
        critical_count=0,
        authorization_confirmed=new_scan.authorization_confirmed,
        authorization_timestamp=new_scan.authorization_timestamp,
        current_phase=new_scan.current_phase,
        progress=new_scan.progress,
        started_at=new_scan.started_at,
        completed_at=new_scan.completed_at,
        failure_reason=new_scan.failure_reason,
        created_at=new_scan.created_at,
    )


@router.post("/{scan_id}/cancel", status_code=status.HTTP_200_OK)
async def cancel_scan_by_id(
    scan_id: int,
    current_user: User = Depends(get_current_user)
):
    """
    POST /api/v1/scans/{scan_id}/cancel
    Cancels an in-flight security scan.
    Requires authentication, validates scan ownership, and transitions state cleanly to 'Cancelled'.
    """
    res = await scan_worker.cancel_scan(scan_id, current_user.id)
    if not res["success"]:
        raise HTTPException(
            status_code=res["status"],
            detail=res["message"]
        )
    return res


@router.get("", response_model=List[ScanResponse])
@router.get("/", response_model=List[ScanResponse], include_in_schema=False)
async def get_scan_history(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get Scan History list for the current authenticated user."""
    stmt = (
        select(Scan)
        .options(selectinload(Scan.findings))
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
    )
    result = await db.execute(stmt)
    scans = result.scalars().all()

    response_list = []
    for s in scans:
        vuln_count = len(s.findings) if s.findings else 0
        crit_count = len([f for f in s.findings if f.severity and f.severity.lower() == "critical"]) if s.findings else 0
        response_list.append(
            ScanResponse(
                id=s.id,
                user_id=s.user_id,
                target_url=s.target_url,
                scan_type=s.scan_type,
                status=s.status,
                security_score=s.security_score,
                security_grade=s.security_grade,
                risk_level=s.risk_level,
                vulnerabilities_count=vuln_count,
                critical_count=crit_count,
                authorization_confirmed=getattr(s, "authorization_confirmed", False),
                authorization_timestamp=getattr(s, "authorization_timestamp", None),
                current_phase=getattr(s, "current_phase", "PENDING"),
                progress=getattr(s, "progress", 0),
                started_at=getattr(s, "started_at", None),
                completed_at=getattr(s, "completed_at", None),
                failure_reason=getattr(s, "failure_reason", None),
                created_at=s.created_at,
            )
        )
    return response_list


@router.get("/status/{scan_id}", response_model=ScanProgressResponse)
async def get_scan_status(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    GET /api/v1/scans/status/{scan_id}
    Returns real-time scan progress status JSON object.
    Enforces user isolation: only the owner can query scan progress.
    """
    stmt = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    result = await db.execute(stmt)
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan #{scan_id} not found or access denied."
        )
    progress_data = progress_manager.get_progress(scan_id)
    # Reconcile with authoritative database state if scan is in terminal state or cache is uninitialized
    if scan.status in ["Completed", "Failed", "Cancelled"] or progress_data.get("progress", 0) < scan.progress:
        progress_data = progress_manager.reconcile_with_db(scan)

    return ScanProgressResponse(
        scan_id=scan.id,
        stage=progress_data.get("stage", "Scan Progress"),
        progress=progress_data.get("progress_percent", progress_data.get("progress", scan.progress)),
        message=progress_data.get("message", "Processing..."),
        status=progress_data.get("status", scan.status),
        timestamp=progress_data.get("timestamp")
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_details(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get Scan Details by ID."""
    stmt = (
        select(Scan)
        .options(selectinload(Scan.findings))
        .where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    result = await db.execute(stmt)
    scan = result.scalars().first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record #{scan_id} not found or access denied."
        )

    vuln_count = len(scan.findings) if scan.findings else 0
    crit_count = len([f for f in scan.findings if f.severity and f.severity.lower() == "critical"]) if scan.findings else 0
    return ScanResponse(
        id=scan.id,
        user_id=scan.user_id,
        target_url=scan.target_url,
        scan_type=scan.scan_type,
        status=scan.status,
        security_score=scan.security_score,
        security_grade=scan.security_grade,
        risk_level=scan.risk_level,
        vulnerabilities_count=vuln_count,
        critical_count=crit_count,
        authorization_confirmed=getattr(scan, "authorization_confirmed", False),
        authorization_timestamp=getattr(scan, "authorization_timestamp", None),
        current_phase=getattr(scan, "current_phase", "PENDING"),
        progress=getattr(scan, "progress", 0),
        started_at=getattr(scan, "started_at", None),
        completed_at=getattr(scan, "completed_at", None),
        failure_reason=getattr(scan, "failure_reason", None),
        created_at=scan.created_at,
    )


@router.post("/{scan_id}/cancel", status_code=status.HTTP_200_OK)
async def cancel_scan_endpoint(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    POST /api/v1/scans/{scan_id}/cancel
    Requests cooperative, idempotent, tenant-isolated cancellation of an ongoing scan.
    Transitions state: CANCELLING -> CANCELLED.
    """
    stmt = select(Scan).where(Scan.id == scan_id)
    res = await db.execute(stmt)
    scan = res.scalars().first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan #{scan_id} not found."
        )

    # Multi-tenant isolation: verify ownership
    if scan.user_id != current_user.id and not getattr(current_user, "is_superuser", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not have permission to cancel this scan."
        )

    # Idempotent: If already cancelled or completed
    if scan.status in ["Completed", "Failed", "Cancelled"]:
        return {
            "message": f"Scan #{scan_id} is already in terminal state '{scan.status}'.",
            "scan_id": scan_id,
            "status": scan.status
        }

    # Signal worker to cancel
    res = await scan_worker.cancel_scan(scan_id, user_id=current_user.id)
    return res


@router.delete("/{scan_id}", status_code=status.HTTP_200_OK)
async def delete_scan_by_id(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    DELETE /api/v1/scans/{scan_id}
    Deletes a single scan record and all associated findings, recon, and report artifacts.
    Also aborts any active scan worker task.
    """
    stmt = select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    res = await db.execute(stmt)
    scan = res.scalars().first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan #{scan_id} not found or access denied."
        )

    # Cancel background worker task if active
    if scan_id in scan_worker.active_tasks and not scan_worker.active_tasks[scan_id].done():
        scan_worker.active_tasks[scan_id].cancel()

    from sqlalchemy import delete
    from app.models import Finding, ReconResult, Report

    await db.execute(delete(Finding).where(Finding.scan_id == scan_id))
    await db.execute(delete(ReconResult).where(ReconResult.scan_id == scan_id))
    await db.execute(delete(Report).where(Report.scan_id == scan_id))
    await db.execute(delete(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id))
    await db.commit()

    return {"message": f"Scan #{scan_id} and all associated telemetry deleted successfully.", "scan_id": scan_id}


@router.post("/delete-bulk", status_code=status.HTTP_200_OK)
async def delete_scans_bulk(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    POST /api/v1/scans/delete-bulk
    Bulk deletes multiple selected scan records by ID list.
    """
    scan_ids = payload.get("scan_ids", [])
    if not scan_ids or not isinstance(scan_ids, list):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="scan_ids must be a non-empty list of integers.")

    from sqlalchemy import delete
    from app.models import Finding, ReconResult, Report

    for sid in scan_ids:
        if sid in scan_worker.active_tasks and not scan_worker.active_tasks[sid].done():
            scan_worker.active_tasks[sid].cancel()

        await db.execute(delete(Finding).where(Finding.scan_id == sid))
        await db.execute(delete(ReconResult).where(ReconResult.scan_id == sid))
        await db.execute(delete(Report).where(Report.scan_id == sid))
        await db.execute(delete(Scan).where(Scan.id == sid, Scan.user_id == current_user.id))

    await db.commit()
    return {"message": f"Successfully deleted {len(scan_ids)} selected scans.", "deleted_scan_ids": scan_ids}


# WebSocket Endpoint under router (/api/v1/scans/ws/{scan_id})
from fastapi import Query
from typing import Optional
from app.auth import verify_websocket_token
from app.logging_config import logger

@router.websocket("/ws/{scan_id}")
async def scan_progress_websocket_router(
    websocket: WebSocket,
    scan_id: int,
    token: Optional[str] = Query(None)
):
    """
    WebSocket endpoint: /api/v1/scans/ws/{scan_id}
    Streams real-time scan progress payloads with strict JWT authentication and tenant isolation.
    """
    # 1. Token retrieval and validation: Cookie -> Authorization header -> Query param
    if not token:
        cookie_token = websocket.cookies.get("ws_ticket") or websocket.cookies.get("autopentest_session") or websocket.cookies.get("access_token")
        if cookie_token:
            token = cookie_token

    if not token:
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

    if not token:
        await websocket.close(code=4401, reason="Authentication token required")
        return

    token_data = verify_websocket_token(token)
    if not token_data or not token_data.username:
        await websocket.close(code=4401, reason="Invalid or expired access token")
        return

    from app.database import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        stmt_user = select(User).where(User.username == token_data.username)
        res_user = await session.execute(stmt_user)
        user = res_user.scalars().first()

        if not user:
            await websocket.close(code=4401, reason="User account not found")
            return

        stmt_scan = select(Scan).where(Scan.id == scan_id)
        res_scan = await session.execute(stmt_scan)
        scan = res_scan.scalars().first()

        if not scan:
            await websocket.close(code=4404, reason="Scan record not found")
            return

        if scan.user_id != user.id and not getattr(user, "is_superuser", False):
            logger.warning(
                f"Tenant isolation violation attempt: User #{user.id} ({user.username}) tried accessing Scan #{scan_id} owned by User #{scan.user_id}"
            )
            await websocket.close(code=4403, reason="Forbidden: Multi-tenant scan access denied")
            return

    # Connection accepted & registered (authoritatively reconciled against DB record)
    await progress_manager.connect(websocket, scan_id, scan=scan)
    try:
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        progress_manager.disconnect(websocket, scan_id)
    except Exception:
        progress_manager.disconnect(websocket, scan_id)
