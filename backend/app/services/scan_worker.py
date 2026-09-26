import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional, Any, List
from sqlalchemy.future import select
from sqlalchemy import delete

from app.database import AsyncSessionLocal
from app.models import Scan, ReconResult, Finding, Report, User, AttackSurfaceAsset
from app.services.target_validator import validate_target
from app.services.recon import perform_asset_recon_audit
from app.services.discovery_engine import DiscoveryEngine
from app.services.security_score import calculate_security_score
from app.services.security_testing import SecurityTestingEngine
from app.services.owasp_mapper import calculate_owasp_stats
from app.services.pdf_generator import generate_security_pdf_report
from app.services.scan_config import DEFAULT_SAFETY_CONFIG
from app.services.scan_progress import progress_manager
from app.logging_config import logger


class ScanCancelledException(Exception):
    """Raised when an operator aborts an active scan."""
    pass


class ScanWorker:
    """
    Phase 7F Production-Grade Real-Time Scan Orchestrator & Worker.
    Features:
    - Truthful, stage-weighted real-time progress model (no fake sleep/loops)
    - Canonical state machine:
      PENDING -> VALIDATING_TARGET -> RECON -> DISCOVERY -> SECURITY_TESTING -> SCORING -> REPORTING -> COMPLETED
      Terminal: CANCELLED, FAILED; Intermediate: CANCELLING
    - Real-time WebSocket event broadcasting (state_changed, progress, asset_discovered,
      finding_discovered, score_updated, report_started, completed, cancelled, heartbeat)
    - Cooperative, idempotent cancellation checkpoints
    - Persistent database state transitions & crash recovery
    - Multi-tenant isolation enforcement
    - Request budget telemetry tracking (150 max HTTP requests)
    - Strict target safety & SafeHttpClient transport
    """

    def __init__(self, max_concurrent_jobs: int = 4):
        self.worker_id = f"worker-{uuid.uuid4().hex[:8]}"
        self.semaphore = asyncio.Semaphore(max_concurrent_jobs)
        self.active_tasks: Dict[int, asyncio.Task] = {}
        self.heartbeat_tasks: Dict[int, asyncio.Task] = {}
        self.requests_used: Dict[int, int] = {}
        self.cancellation_requested: Dict[int, bool] = {}
        logger.info(f"Initialized ScanWorker {self.worker_id} with concurrency limit {max_concurrent_jobs}")

    def is_cancelled(self, scan_id: int) -> bool:
        """Check if scan cancellation was requested."""
        return self.cancellation_requested.get(scan_id, False)

    def request_cancellation(self, scan_id: int) -> bool:
        """Mark cancellation requested in-memory for immediate cooperative check."""
        self.cancellation_requested[scan_id] = True
        if scan_id in self.active_tasks and not self.active_tasks[scan_id].done():
            self.active_tasks[scan_id].cancel()
        return True

    async def recover_stale_scans(self, stale_threshold_seconds: int = 60) -> int:
        """
        Detects scans left in RUNNING, CANCELLING, or PENDING state with no recent heartbeat
        (e.g., following a worker crash or server restart) and safely marks them FAILED.
        """
        recovered_count = 0
        now = datetime.now(timezone.utc)
        async with AsyncSessionLocal() as session:
            stmt = select(Scan).where(
                Scan.status.in_(["Running", "Cancelling", "Pending"])
            )
            res = await session.execute(stmt)
            scans = res.scalars().all()

            for scan in scans:
                last_hb = scan.last_heartbeat_at or scan.started_at or scan.created_at
                if last_hb is None or (now - last_hb).total_seconds() > stale_threshold_seconds:
                    logger.warning(
                        f"Crash recovery: Scan #{scan.id} (Status: {scan.status}) has stale heartbeat ({last_hb}). Marking Failed."
                    )
                    scan.status = "Failed"
                    scan.current_phase = "FAILED"
                    scan.failure_reason = "Scan worker interrupted unexpectedly; recovered during startup."
                    scan.completed_at = now
                    recovered_count += 1

            if recovered_count > 0:
                await session.commit()

        return recovered_count

    async def transition_state(
        self,
        session,
        scan: Scan,
        new_phase: str,
        stage_title: str,
        progress: int,
        scanner_name: Optional[str] = None,
        message: Optional[str] = None,
        status: str = "Running"
    ):
        """Persist state transition to DB and broadcast scan.state_changed + scan.progress."""
        prev_phase = scan.current_phase or "PENDING"
        now = datetime.now(timezone.utc)

        scan.current_phase = new_phase
        scan.progress = progress
        scan.last_heartbeat_at = now
        scan.status = status
        if scanner_name:
            scan.current_scanner = scanner_name

        await session.commit()

        req_used = self.requests_used.get(scan.id, 0)
        req_rem = max(0, 150 - req_used)

        # 1. State change event if phase changed
        if prev_phase != new_phase:
            await progress_manager.broadcast_state_changed(
                scan_id=scan.id,
                previous_state=prev_phase,
                new_state=new_phase,
                stage=stage_title,
                progress_percent=progress,
                message=message or f"Transitioned to {stage_title}",
                status=status
            )

        # 2. Progress event
        await progress_manager.broadcast_progress(
            scan_id=scan.id,
            stage=stage_title,
            progress=progress,
            message=message or f"Stage {stage_title}: {progress}% completed",
            status=status,
            state=new_phase,
            requests_used=req_used,
            requests_remaining=req_rem
        )

    async def update_heartbeat(
        self,
        session,
        scan: Scan,
        phase: str,
        progress: int,
        scanner_name: Optional[str] = None,
        message: Optional[str] = None,
        status: str = "Running"
    ):
        """Update scan heartbeat and progress without full state transition."""
        now = datetime.now(timezone.utc)
        scan.current_phase = phase
        scan.progress = progress
        scan.last_heartbeat_at = now
        scan.status = status
        if scanner_name:
            scan.current_scanner = scanner_name

        await session.commit()

        req_used = self.requests_used.get(scan.id, 0)
        req_rem = max(0, 150 - req_used)

        await progress_manager.broadcast_progress(
            scan_id=scan.id,
            stage=phase.replace("_", " ").title(),
            progress=progress,
            message=message or f"Phase {phase}: {progress}% completed",
            status=status,
            state=phase,
            requests_used=req_used,
            requests_remaining=req_rem
        )

    async def check_cancellation(self, session, scan_id: int) -> bool:
        """Cooperative cancellation check against persistent database state."""
        stmt = select(Scan).where(Scan.id == scan_id)
        res = await session.execute(stmt)
        scan = res.scalars().first()
        if scan and scan.cancel_requested:
            raise ScanCancelledException(f"Scan #{scan_id} cancellation requested by operator.")
        return False

    async def _heartbeat_loop(self, scan_id: int):
        """Periodic background worker heartbeat communicating vitality."""
        while True:
            await asyncio.sleep(3.0)
            try:
                async with AsyncSessionLocal() as session:
                    stmt = select(Scan).where(Scan.id == scan_id)
                    res = await session.execute(stmt)
                    scan = res.scalars().first()
                    if not scan or scan.status in ["Completed", "Failed", "Cancelled"]:
                        break

                    now = datetime.now(timezone.utc)
                    scan.last_heartbeat_at = now
                    await session.commit()

                    req_used = self.requests_used.get(scan_id, 0)
                    req_rem = max(0, 150 - req_used)

                    await progress_manager.broadcast_heartbeat(
                        scan_id=scan_id,
                        state=scan.current_phase,
                        progress_percent=scan.progress,
                        worker_id=self.worker_id,
                        requests_used=req_used,
                        requests_remaining=req_rem
                    )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Heartbeat loop tick error for scan #{scan_id}: {e}")

    def enqueue_scan(self, scan_id: int, target_url: str):
        """Enqueue scan execution task in background."""
        task = asyncio.create_task(self.run_job(scan_id, target_url))
        self.active_tasks[scan_id] = task
        task.add_done_callback(lambda t: self.active_tasks.pop(scan_id, None))
        return task

    async def cancel_scan(self, scan_id: int, user_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Handles operator request to cancel an active scan.
        Guarantees authorization, state transition, and clean task cancellation.
        """
        self.request_cancellation(scan_id)
        async with AsyncSessionLocal() as session:
            stmt = select(Scan).where(Scan.id == scan_id)
            if user_id is not None:
                stmt = stmt.where(Scan.user_id == user_id)
            res = await session.execute(stmt)
            scan = res.scalars().first()

            if not scan:
                return {"success": False, "status": 404, "message": f"Scan #{scan_id} not found or access denied."}

            if scan.status in ["Completed", "Failed", "Cancelled"]:
                return {"success": True, "status": 200, "message": f"Scan #{scan_id} is already in terminal state '{scan.status}'."}

            if scan.status == "Cancelling":
                return {"success": True, "status": 200, "message": f"Scan #{scan_id} is already cancelling."}

            scan.cancel_requested = True
            scan.status = "Cancelling"
            scan.current_phase = "CANCELLING"
            await session.commit()

            # Abort active in-memory task if running
            if scan_id in self.active_tasks and not self.active_tasks[scan_id].done():
                self.active_tasks[scan_id].cancel()

            # Broadcast cancel requested event
            await progress_manager.broadcast_cancel_requested(scan_id, scan.progress)

            return {"success": True, "status": 200, "message": f"Scan #{scan_id} cancellation initiated."}

    async def run_job(self, scan_id: int, target_url: str):
        """
        Execute full scan job through truthful, evidence-based lifecycle stages:
        1. VALIDATING_TARGET (0% - 10%): Strict SSRF & private IP check
        2. RECON (10% - 25%): Real DNS, TLS, and HTTP security header inspection
        3. DISCOVERY (25% - 50%): Attack surface discovery with live asset events
        4. SECURITY_TESTING (50% - 80%): Authorized security testing with live finding events
        5. SCORING (80% - 88%): Canonical security score calculation
        6. REPORTING (88% - 100%): ReportLab PDF report generation & DB persistence
        7. COMPLETED (100%): Terminal state
        """
        self.requests_used[scan_id] = 0

        # Start periodic background heartbeat task
        hb_task = asyncio.create_task(self._heartbeat_loop(scan_id))
        self.heartbeat_tasks[scan_id] = hb_task

        async with self.semaphore:
            now = datetime.now(timezone.utc)
            async with AsyncSessionLocal() as session:
                stmt = select(Scan).where(Scan.id == scan_id)
                res = await session.execute(stmt)
                scan = res.scalars().first()

                if not scan:
                    logger.error(f"ScanWorker: Scan #{scan_id} not found in database.")
                    hb_task.cancel()
                    return

                scan.worker_id = self.worker_id
                scan.worker_started_at = now
                scan.started_at = now
                scan.status = "Running"
                await session.commit()

            try:
                # -------------------------------------------------------------
                # PHASE 1: TARGET VALIDATION (0% - 10%)
                # -------------------------------------------------------------
                async with AsyncSessionLocal() as session:
                    stmt = select(Scan).where(Scan.id == scan_id)
                    res = await session.execute(stmt)
                    scan = res.scalars().first()

                    await self.check_cancellation(session, scan_id)
                    await self.transition_state(
                        session, scan,
                        new_phase="VALIDATING_TARGET",
                        stage_title="Target Validation",
                        progress=5,
                        scanner_name="target-validator",
                        message=f"Validating target URL and SSRF safety boundaries for {scan.target_url}..."
                    )

                    val_res = validate_target(scan.target_url)
                    if not val_res.is_valid:
                        scan.status = "Failed"
                        scan.current_phase = "FAILED"
                        scan.failure_reason = f"Target validation failed: {val_res.error_message}"
                        scan.completed_at = datetime.now(timezone.utc)
                        await session.commit()
                        await progress_manager.broadcast_failure(scan_id, scan.failure_reason)
                        return

                    target = val_res.target_url
                    scan_profile = scan.scan_type or "Standard"
                    user_id = scan.user_id

                    await self.transition_state(
                        session, scan,
                        new_phase="VALIDATING_TARGET",
                        stage_title="Target Validation",
                        progress=10,
                        scanner_name="target-validator",
                        message=f"Target validated successfully: {target}"
                    )

                # -------------------------------------------------------------
                # PHASE 2: RECONNAISSANCE (10% - 25%)
                # -------------------------------------------------------------
                async with AsyncSessionLocal() as session:
                    stmt = select(Scan).where(Scan.id == scan_id)
                    res = await session.execute(stmt)
                    scan = res.scalars().first()

                    await self.check_cancellation(session, scan_id)
                    await self.transition_state(
                        session, scan,
                        new_phase="RECON",
                        stage_title="Network Reconnaissance",
                        progress=12,
                        scanner_name="recon-auditor",
                        message=f"Initiating network reconnaissance for {target}..."
                    )

                    # Real asset reconnaissance with granular truthful progress
                    async def on_recon_progress(step: str, pct: int, msg: str):
                        await self.check_cancellation(session, scan_id)
                        # Scale recon 0-100% to 12-25%
                        scaled_pct = 12 + int(pct * 0.13)
                        self.requests_used[scan_id] = self.requests_used.get(scan_id, 0) + 1
                        await self.update_heartbeat(
                            session, scan,
                            phase="RECON",
                            progress=scaled_pct,
                            scanner_name="recon-auditor",
                            message=msg
                        )

                    audit_data = await perform_asset_recon_audit(target, on_progress=on_recon_progress)
                    # SafeHttpClient request accounting: 1 HTTP inspection request made during network recon
                    self.requests_used[scan_id] = 1

                    # Delete previous recon result if re-running
                    await session.execute(delete(ReconResult).where(ReconResult.scan_id == scan_id))

                    recon_entry = ReconResult(
                        user_id=user_id,
                        scan_id=scan_id,
                        target_url=audit_data["target_url"],
                        ip_address=audit_data["ip_address"],
                        web_server=audit_data["web_server"],
                        ssl_issuer=audit_data["ssl_issuer"],
                        ssl_expires_days=audit_data["ssl_expires_days"],
                        security_score=audit_data["security_score"],
                        details=audit_data["details"]
                    )
                    session.add(recon_entry)
                    await session.commit()
                    await session.refresh(recon_entry)

                    await self.transition_state(
                        session, scan,
                        new_phase="RECON",
                        stage_title="Network Reconnaissance",
                        progress=25,
                        scanner_name="recon-auditor",
                        message=f"Reconnaissance complete: Resolved IPv4={audit_data['ip_address']}, TLS={audit_data.get('details', {}).get('tls', {}).get('status', 'VALID')}"
                    )

                # -------------------------------------------------------------
                # PHASE 3: ATTACK SURFACE DISCOVERY (25% - 50%)
                # -------------------------------------------------------------
                async with AsyncSessionLocal() as session:
                    stmt = select(Scan).where(Scan.id == scan_id)
                    res = await session.execute(stmt)
                    scan = res.scalars().first()

                    await self.check_cancellation(session, scan_id)
                    await self.transition_state(
                        session, scan,
                        new_phase="DISCOVERY",
                        stage_title="Attack Surface Discovery",
                        progress=27,
                        scanner_name="crawler-discovery",
                        message=f"Discovering endpoints, forms, APIs & scripts on {target}..."
                    )

                    engine = DiscoveryEngine(
                        target_url=target,
                        max_depth=2,
                        max_urls=200,
                        max_requests=min(80, 150 - self.requests_used.get(scan_id, 0)),
                        max_concurrency=4
                    )

                    discovered_count = 0

                    async def on_discovery_event(event_name: str, payload: Dict[str, Any]):
                        nonlocal discovered_count
                        await self.check_cancellation(session, scan_id)
                        discovered_count += 1
                        self.requests_used[scan_id] = self.requests_used.get(scan_id, 0) + 1
                        url_msg = payload.get("url", payload.get("target_url", ""))

                        # Scale progress dynamically 27% to 49%
                        scaled_pct = min(49, 27 + discovered_count)
                        await self.update_heartbeat(
                            session, scan,
                            phase="DISCOVERY",
                            progress=scaled_pct,
                            scanner_name="crawler-discovery",
                            message=f"Discovered {event_name}: {url_msg}"[:120]
                        )

                        # Broadcast live asset event
                        await progress_manager.broadcast_asset_discovered(
                            scan_id=scan_id,
                            asset=payload,
                            progress_percent=scaled_pct
                        )

                    def check_cancel_sync():
                        return scan.cancel_requested if scan else False

                    discovery_res = await engine.execute_discovery(
                        is_cancelled=check_cancel_sync,
                        on_event=on_discovery_event
                    )
                    # Sync global SafeHttpClient accounting with actual crawler requests executed
                    pre_disc_reqs = 1
                    self.requests_used[scan_id] = pre_disc_reqs + getattr(engine, "requests_total", 0)

                    # Clean old discovery results if re-running
                    await session.execute(delete(AttackSurfaceAsset).where(AttackSurfaceAsset.scan_id == scan_id))

                    # Persist discovered assets
                    for a_data in discovery_res.get("assets", []):
                        asset_row = AttackSurfaceAsset(
                            scan_id=scan_id,
                            user_id=user_id,
                            asset_type=a_data["asset_type"],
                            url=a_data["url"],
                            normalized_url=a_data["normalized_url"],
                            hostname=a_data["hostname"],
                            path=a_data["path"],
                            query_parameters=a_data["query_parameters"],
                            http_method=a_data["http_method"],
                            content_type=a_data["content_type"],
                            status_code=a_data["status_code"],
                            discovered_from=a_data["discovered_from"],
                            source_url=a_data["source_url"],
                            evidence=a_data["evidence"],
                            confidence=a_data["confidence"],
                            evidence_status=a_data["evidence_status"],
                            in_scope=a_data["in_scope"],
                            external=a_data["external"],
                            duplicate_key=a_data["duplicate_key"]
                        )
                        session.add(asset_row)

                    await session.commit()

                    total_assets_discovered = len(discovery_res.get("assets", []))
                    await self.transition_state(
                        session, scan,
                        new_phase="DISCOVERY",
                        stage_title="Attack Surface Discovery",
                        progress=50,
                        scanner_name="crawler-discovery",
                        message=f"Attack surface discovery completed: {total_assets_discovered} assets inventoried."
                    )

                # -------------------------------------------------------------
                # PHASE 4: SECURITY TESTING (50% - 80%)
                # -------------------------------------------------------------
                async with AsyncSessionLocal() as session:
                    stmt = select(Scan).where(Scan.id == scan_id)
                    res = await session.execute(stmt)
                    scan = res.scalars().first()

                    await self.check_cancellation(session, scan_id)
                    await self.transition_state(
                        session, scan,
                        new_phase="SECURITY_TESTING",
                        stage_title="Security Testing",
                        progress=52,
                        scanner_name="vulnerability-engine",
                        message=f"Initializing evidence-based security testing against attack surface for {target}..."
                    )

                    stmt_assets = select(AttackSurfaceAsset).where(
                        AttackSurfaceAsset.scan_id == scan_id,
                        AttackSurfaceAsset.in_scope == True,
                        AttackSurfaceAsset.external == False
                    )
                    res_assets = await session.execute(stmt_assets)
                    discovered_assets = res_assets.scalars().all()

                    # Clean any previous Phase 7E findings for this scan if re-running
                    await session.execute(
                        delete(Finding).where(
                            Finding.scan_id == scan_id,
                            Finding.source == "Phase7E_SecurityTesting"
                        )
                    )

                    remaining_budget = max(20, 150 - self.requests_used.get(scan_id, 0))
                    testing_engine = SecurityTestingEngine(
                        target_url=target,
                        max_requests=remaining_budget,
                        max_concurrency=4
                    )

                    async def on_test_progress(event_type: str, pct: int, msg: str):
                        await self.check_cancellation(session, scan_id)
                        # Scale 0-100% to 52-78%
                        scaled_pct = 52 + int(pct * 0.26)
                        self.requests_used[scan_id] = self.requests_used.get(scan_id, 0) + 1
                        await self.update_heartbeat(
                            session, scan,
                            phase="SECURITY_TESTING",
                            progress=scaled_pct,
                            scanner_name="vulnerability-engine",
                            message=msg
                        )

                    async def on_test_finding(finding_dict: Dict[str, Any]):
                        await self.check_cancellation(session, scan_id)
                        # Broadcast live finding event
                        await progress_manager.broadcast_finding_discovered(
                            scan_id=scan_id,
                            finding=finding_dict,
                            progress_percent=scan.progress,
                            message=f"Verified security finding: {finding_dict.get('title')}"[:120]
                        )

                    def check_cancel_sync():
                        return scan.cancel_requested if scan else False

                    test_results = await testing_engine.execute_testing(
                        scan_id=scan_id,
                        user_id=user_id,
                        assets=discovered_assets,
                        authorization_confirmed=scan.authorization_confirmed,
                        is_cancelled=check_cancel_sync,
                        on_progress=on_test_progress,
                        on_finding=on_test_finding
                    )
                    # Sync global SafeHttpClient accounting with actual security tester probes executed
                    disc_total = getattr(engine, "requests_total", 0)
                    self.requests_used[scan_id] = 1 + disc_total + getattr(testing_engine.budget, "used_requests", 0)

                    # Persist genuine correlated findings into database
                    now_utc = datetime.now(timezone.utc)
                    for f_cand in test_results.get("findings", []):
                        f_row = Finding(
                            user_id=user_id,
                            scan_id=scan_id,
                            asset_id=f_cand.asset_id,
                            title=f_cand.title[:255],
                            category=f_cand.category,
                            description=f_cand.description,
                            severity=f_cand.severity,
                            confidence=f_cand.confidence,
                            cvss_score=f_cand.cvss_score,
                            cve_id=f_cand.cve_id,
                            affected_url=f_cand.affected_url[:2048],
                            status=f_cand.status,
                            remediation_guidance=f_cand.remediation,
                            evidence=f_cand.evidence.to_dict() if hasattr(f_cand.evidence, "to_dict") else f_cand.evidence,
                            first_observed=now_utc,
                            last_observed=now_utc,
                            source="Phase7E_SecurityTesting",
                            test_type=f_cand.test_type
                        )
                        session.add(f_row)

                    await session.commit()

                    total_findings_count = len(test_results.get("findings", []))
                    await self.transition_state(
                        session, scan,
                        new_phase="SECURITY_TESTING",
                        stage_title="Security Testing",
                        progress=80,
                        scanner_name="vulnerability-engine",
                        message=f"Security testing complete: {total_findings_count} canonical findings correlated."
                    )

                # -------------------------------------------------------------
                # PHASE 5: SCORING (80% - 88%)
                # -------------------------------------------------------------
                async with AsyncSessionLocal() as session:
                    stmt = select(Scan).where(Scan.id == scan_id)
                    res = await session.execute(stmt)
                    scan = res.scalars().first()

                    await self.check_cancellation(session, scan_id)
                    await self.transition_state(
                        session, scan,
                        new_phase="SCORING",
                        stage_title="Security Scoring",
                        progress=84,
                        scanner_name="risk-scoring-engine",
                        message=f"Calculating canonical security score and posture grade for {target}..."
                    )

                    stmt_recon = select(ReconResult).where(ReconResult.scan_id == scan_id)
                    res_recon = await session.execute(stmt_recon)
                    recon_entry = res_recon.scalars().first()

                    stmt_f = select(Finding).where(Finding.scan_id == scan_id)
                    res_f = await session.execute(stmt_f)
                    findings = res_f.scalars().all()

                    score_data = calculate_security_score(scan_id, target, findings, recon_entry)
                    owasp_stats = calculate_owasp_stats(scan_id, findings)

                    # Accurately record global SafeHttpClient request accounting in persisted score details
                    total_reqs_used = self.requests_used.get(scan_id, 0)
                    score_data["requests_used"] = total_reqs_used
                    score_data["requests_remaining"] = max(0, 150 - total_reqs_used)
                    score_data["requests_budget"] = 150

                    scan.security_score = score_data["score"]
                    scan.security_grade = score_data["grade"]
                    scan.risk_level = score_data["risk_level"]
                    scan.score_details = score_data
                    await session.commit()

                    # Broadcast score updated event
                    await progress_manager.broadcast_score_updated(
                        scan_id=scan_id,
                        score=score_data["score"],
                        grade=score_data["grade"],
                        risk=score_data["risk_level"],
                        deductions=score_data.get("deductions"),
                        progress_percent=88
                    )

                # -------------------------------------------------------------
                # PHASE 6: REPORTING (88% - 100%)
                # -------------------------------------------------------------
                async with AsyncSessionLocal() as session:
                    stmt = select(Scan).where(Scan.id == scan_id)
                    res = await session.execute(stmt)
                    scan = res.scalars().first()

                    await self.check_cancellation(session, scan_id)
                    await self.transition_state(
                        session, scan,
                        new_phase="REPORTING",
                        stage_title="Report Generation",
                        progress=90,
                        scanner_name="pdf-report-generator",
                        message=f"Compiling executive ReportLab {scan_profile} PDF security report..."
                    )

                    await progress_manager.broadcast_report_started(scan_id, progress_percent=92)

                    stmt_user = select(User).where(User.id == scan.user_id)
                    res_user = await session.execute(stmt_user)
                    user = res_user.scalars().first()
                    user_name = user.username if user else "Security Lead"

                    stmt_assets = select(AttackSurfaceAsset).where(AttackSurfaceAsset.scan_id == scan_id)
                    res_assets = await session.execute(stmt_assets)
                    attack_surface_assets = res_assets.scalars().all()

                    pdf_bytes, actual_pages = generate_security_pdf_report(
                        user_name=user_name,
                        target_url=target,
                        scan_id=scan_id,
                        scan_type=scan_profile,
                        ip_address=audit_data.get("ip_address"),
                        findings=findings,
                        recon_result=recon_entry,
                        score_data=score_data,
                        owasp_stats=owasp_stats,
                        attack_surface_assets=attack_surface_assets
                    )

                    p_lower = scan_profile.lower()
                    title_prefix = "Quick Recon Audit Report" if "quick" in p_lower else ("Full Penetration Testing Report" if "full" in p_lower else "Standard Vulnerability Audit Report")
                    report_id_str = f"REP-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{scan_id:04d}-{scan_profile[:1].upper()}"

                    await session.execute(delete(Report).where(Report.scan_id == scan_id))
                    report_entry = Report(
                        user_id=user_id,
                        scan_id=scan_id,
                        report_id_str=report_id_str,
                        report_type=scan_profile.capitalize(),
                        title=f"{title_prefix} #{scan_id}",
                        target_url=target,
                        pages=actual_pages,
                        pdf_bytes=pdf_bytes
                    )
                    session.add(report_entry)

                    # Mark Scan Completed (Terminal State)
                    scan.status = "Completed"
                    scan.current_phase = "COMPLETED"
                    scan.progress = 100
                    scan.completed_at = datetime.now(timezone.utc)
                    await session.commit()
                    await session.refresh(report_entry)

                    # Broadcast completed event with final request telemetry
                    total_reqs_used = self.requests_used.get(scan_id, 0)
                    await progress_manager.broadcast_completed(
                        scan_id=scan_id,
                        target_url=target,
                        score=score_data["score"],
                        grade=score_data["grade"],
                        risk=score_data["risk_level"],
                        total_assets=len(attack_surface_assets),
                        total_findings=len(findings),
                        report_id=report_entry.id,
                        requests_used=total_reqs_used,
                        requests_remaining=max(0, 150 - total_reqs_used)
                    )

            except (asyncio.CancelledError, ScanCancelledException) as ce:
                logger.info(f"Scan #{scan_id} successfully cancelled: {str(ce)}")
                async with AsyncSessionLocal() as session:
                    stmt = select(Scan).where(Scan.id == scan_id)
                    res = await session.execute(stmt)
                    scan = res.scalars().first()
                    if scan:
                        scan.status = "Cancelled"
                        scan.current_phase = "CANCELLED"
                        scan.completed_at = datetime.now(timezone.utc)
                        scan.failure_reason = "Scan cancelled by operator."
                        await session.commit()

                await progress_manager.broadcast_cancelled(
                    scan_id=scan_id,
                    progress_percent=scan.progress if scan else 0,
                    message="Scan was cancelled by the operator."
                )

            except Exception as e:
                logger.exception(f"Scan #{scan_id} failed with unhandled error: {e}")
                async with AsyncSessionLocal() as session:
                    stmt = select(Scan).where(Scan.id == scan_id)
                    res = await session.execute(stmt)
                    scan = res.scalars().first()
                    if scan:
                        scan.status = "Failed"
                        scan.current_phase = "FAILED"
                        scan.failure_reason = f"Execution failed: {str(e)[:500]}"
                        scan.completed_at = datetime.now(timezone.utc)
                        await session.commit()

                await progress_manager.broadcast_failure(scan_id, str(e))

            finally:
                # Stop heartbeat task and clean up per-scan in-memory state
                hb_task.cancel()
                self.heartbeat_tasks.pop(scan_id, None)
                self.requests_used.pop(scan_id, None)
                self.cancellation_requested.pop(scan_id, None)


# Global ScanWorker instance
scan_worker = ScanWorker()
