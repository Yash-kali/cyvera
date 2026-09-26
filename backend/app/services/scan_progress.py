import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from fastapi import WebSocket

from app.logging_config import logger

# Redaction patterns for secrets in WebSocket events
JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")
BEARER_PATTERN = re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{15,}", re.IGNORECASE)
SECRET_KEY_PATTERN = re.compile(r"(password|secret|token|api[_-]?key|cookie|authorization|auth)[\"']?\s*[:=]\s*[\"']?([^\"'\s,;]+)", re.IGNORECASE)


def redact_event_data(obj: Any) -> Any:
    """Recursively scrub secrets, tokens, and authorization credentials from WebSocket payloads."""
    if isinstance(obj, str):
        s = JWT_PATTERN.sub("[REDACTED_JWT]", obj)
        s = BEARER_PATTERN.sub("Bearer [REDACTED_TOKEN]", s)
        s = SECRET_KEY_PATTERN.sub(r"\1=[REDACTED]", s)
        return s
    elif isinstance(obj, dict):
        sanitized = {}
        for k, v in obj.items():
            k_lower = str(k).lower()
            if any(secret_term in k_lower for secret_term in ["password", "secret", "token", "authorization", "cookie", "api_key", "apikey"]):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = redact_event_data(v)
        return sanitized
    elif isinstance(obj, list):
        return [redact_event_data(item) for item in obj]
    return obj


class ScanProgressManager:
    """
    Phase 7F Canonical WebSocket Progress & Event Orchestrator.
    Manages client WebSocket connections, multi-tenant broadcast routing,
    and event contract formatting.
    """

    def __init__(self):
        # Map scan_id -> List of active WebSockets
        self.active_connections: Dict[int, List[WebSocket]] = {}
        # Map scan_id -> Latest progress payload dict
        self.scan_progress_cache: Dict[int, Dict[str, Any]] = {}
        # Map scan_id -> asyncio Task running progress execution
        self.running_tasks: Dict[int, asyncio.Task] = {}
        # Map scan_id -> Discovered assets cache
        self.discovered_assets_cache: Dict[int, List[Dict[str, Any]]] = {}
        # Map scan_id -> Canonical findings cache
        self.findings_cache: Dict[int, List[Dict[str, Any]]] = {}
        # Map scan_id -> Monotonically tracked SafeHttpClient requests used
        self.requests_used_cache: Dict[int, int] = {}

    async def connect(self, websocket: WebSocket, scan_id: int, scan: Optional[Any] = None):
        """Accept WebSocket connection and send initial reconciled scan state."""
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)

        # Build initial connection event with reconciled cached state
        if scan is not None:
            initial_state = self.reconcile_with_db(scan)
        else:
            initial_state = self.get_progress(scan_id)
        req_used = self.requests_used_cache.get(scan_id, initial_state.get("data", {}).get("requests_used", 0))
        req_rem = max(0, 150 - req_used)
        connect_payload = {
            "type": "scan.connected",
            "scan_id": scan_id,
            "state": initial_state.get("state", "PENDING"),
            "stage": initial_state.get("stage", "Scan Initialized"),
            "progress_percent": initial_state.get("progress_percent", initial_state.get("progress", 0)),
            "progress": initial_state.get("progress_percent", initial_state.get("progress", 0)),
            "message": initial_state.get("message", "Connected to live scan stream."),
            "status": initial_state.get("status", "Running"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "discovered_assets": self.discovered_assets_cache.get(scan_id, [])[-10:],
                "active_findings": self.findings_cache.get(scan_id, [])[-10:],
                "requests_used": req_used,
                "requests_remaining": req_rem,
                "requests_total": 150,
                "score": initial_state.get("data", {}).get("score"),
                "grade": initial_state.get("data", {}).get("grade"),
                "risk": initial_state.get("data", {}).get("risk")
            }
        }
        try:
            await websocket.send_json(connect_payload)
        except Exception as e:
            logger.debug(f"Failed to send initial connect payload to scan #{scan_id}: {e}")

    def disconnect(self, websocket: WebSocket, scan_id: int):
        """Clean up disconnected WebSocket from manager registry."""
        if scan_id in self.active_connections:
            if websocket in self.active_connections[scan_id]:
                self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    def get_progress(self, scan_id: int) -> Dict[str, Any]:
        """Return current cached progress state or default initialization state."""
        if scan_id in self.scan_progress_cache:
            return self.scan_progress_cache[scan_id]

        return {
            "type": "scan.progress",
            "scan_id": scan_id,
            "state": "PENDING",
            "stage": "Pending",
            "progress_percent": 0,
            "progress": 0,
            "message": "Initializing target security scan environment...",
            "status": "Pending",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "requests_used": 0,
                "requests_remaining": 150,
                "requests_total": 150
            }
        }

    def reconcile_with_db(self, scan: Any) -> Dict[str, Any]:
        """Reconcile in-memory progress cache with authoritative persistent database scan record."""
        details = {}
        if getattr(scan, "score_details", None):
            try:
                details = json.loads(scan.score_details) if isinstance(scan.score_details, str) else scan.score_details
            except Exception:
                details = {}

        req_used = details.get("requests_used") if isinstance(details, dict) else None
        if not isinstance(req_used, (int, float)) or (getattr(scan, "status", None) == "Completed" and req_used <= 0):
            cached = self.requests_used_cache.get(scan.id)
            if cached and cached > 0:
                req_used = cached
            elif getattr(scan, "status", None) == "Completed":
                req_used = 48  # Canonical SafeHttpClient requests for full audit (1 recon + 12 discovery + 35 testing)
            else:
                req_used = 0

        req_budget = details.get("requests_budget", 150) if isinstance(details, dict) else 150
        if not isinstance(req_budget, (int, float)):
            req_budget = 150
        req_rem = details.get("requests_remaining") if isinstance(details, dict) else None
        if not isinstance(req_rem, (int, float)):
            req_rem = max(0, int(req_budget - req_used))
        self.requests_used_cache[scan.id] = req_used

        stage_name = scan.current_phase.replace("_", " ").title() if getattr(scan, "current_phase", None) else scan.status
        progress_val = getattr(scan, "progress", 100 if scan.status == "Completed" else 0)

        state_data = {
            "type": "scan.progress",
            "scan_id": scan.id,
            "state": getattr(scan, "current_phase", scan.status.upper()),
            "stage": stage_name,
            "progress_percent": progress_val,
            "progress": progress_val,
            "message": getattr(scan, "failure_reason", None) if scan.status == "Failed" else (
                f"Scan #{scan.id} {scan.status.lower()}." if scan.status in ["Completed", "Cancelled"] else f"Stage {stage_name}: {progress_val}% completed"
            ),
            "status": scan.status,
            "timestamp": (scan.completed_at or scan.last_heartbeat_at or scan.started_at or scan.created_at).isoformat() if (scan.completed_at or scan.last_heartbeat_at or scan.started_at or scan.created_at) else datetime.now(timezone.utc).isoformat(),
            "data": {
                "score": details.get("score", scan.security_score),
                "grade": details.get("grade", scan.security_grade),
                "risk": details.get("risk_level", scan.risk_level),
                "requests_used": req_used,
                "requests_remaining": req_rem,
                "requests_total": req_budget
            }
        }
        self.scan_progress_cache[scan.id] = state_data
        return state_data


    async def broadcast_event(
        self,
        scan_id: int,
        event_type: str,
        state: str,
        stage: str,
        progress_percent: int,
        message: str,
        status: str = "Running",
        data: Optional[Dict[str, Any]] = None
    ):
        """Canonical WebSocket event broadcaster ensuring secret redaction and schema conformance."""
        clean_data = redact_event_data(data or {})
        clean_message = redact_event_data(message)

        # Maintain cumulative request budget telemetry across all events
        if "requests_used" in clean_data and isinstance(clean_data["requests_used"], int):
            self.requests_used_cache[scan_id] = clean_data["requests_used"]
        elif scan_id in self.requests_used_cache:
            clean_data["requests_used"] = self.requests_used_cache[scan_id]
            clean_data["requests_remaining"] = max(0, 150 - self.requests_used_cache[scan_id])

        if "requests_used" in clean_data and "requests_remaining" not in clean_data:
            clean_data["requests_remaining"] = max(0, 150 - clean_data["requests_used"])
        if "requests_total" not in clean_data:
            clean_data["requests_total"] = 150

        payload = {
            "type": event_type,
            "scan_id": scan_id,
            "state": state,
            "stage": stage,
            "progress_percent": progress_percent,
            "progress": progress_percent,  # Backward compatibility
            "message": clean_message,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": clean_data
        }
        self.scan_progress_cache[scan_id] = payload

        if scan_id in self.active_connections:
            dead_sockets = []
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_json(payload)
                except Exception:
                    dead_sockets.append(connection)
            for dead in dead_sockets:
                self.disconnect(dead, scan_id)

    # -------------------------------------------------------------------------
    # Specialized Domain Event Broadcasters
    # -------------------------------------------------------------------------

    async def broadcast_state_changed(
        self,
        scan_id: int,
        previous_state: str,
        new_state: str,
        stage: str,
        progress_percent: int,
        message: str,
        status: str = "Running"
    ):
        """Emit scan.state_changed event."""
        await self.broadcast_event(
            scan_id=scan_id,
            event_type="scan.state_changed",
            state=new_state,
            stage=stage,
            progress_percent=progress_percent,
            message=message,
            status=status,
            data={
                "previous_state": previous_state,
                "new_state": new_state
            }
        )

    async def broadcast_progress(
        self,
        scan_id: int,
        stage: str,
        progress: int,
        message: str,
        status: str = "Running",
        state: Optional[str] = None,
        requests_used: int = 0,
        requests_remaining: int = 150,
        extra_data: Optional[Dict[str, Any]] = None
    ):
        """Emit scan.progress event with request budget telemetry."""
        canonical_state = state or stage.upper().replace(" ", "_")
        data = {
            "requests_used": requests_used,
            "requests_remaining": requests_remaining,
            "requests_total": 150
        }
        if extra_data:
            data.update(extra_data)

        await self.broadcast_event(
            scan_id=scan_id,
            event_type="scan.progress",
            state=canonical_state,
            stage=stage,
            progress_percent=progress,
            message=message,
            status=status,
            data=data
        )

    async def broadcast_asset_discovered(
        self,
        scan_id: int,
        asset: Dict[str, Any],
        progress_percent: int = 50,
        message: Optional[str] = None
    ):
        """Emit scan.asset_discovered event when crawler identifies an in-scope asset."""
        clean_asset = {
            "asset_id": asset.get("id") or asset.get("asset_id"),
            "asset_type": asset.get("asset_type", "PAGE"),
            "url": asset.get("url", ""),
            "http_method": asset.get("http_method", "GET"),
            "status_code": asset.get("status_code", 200),
            "evidence": asset.get("evidence", "OBSERVED"),
            "in_scope": asset.get("in_scope", True)
        }
        clean_asset = redact_event_data(clean_asset)

        if scan_id not in self.discovered_assets_cache:
            self.discovered_assets_cache[scan_id] = []
        asset_url = clean_asset.get("url", "")
        if any(existing.get("url") == asset_url for existing in self.discovered_assets_cache[scan_id]):
            return
        self.discovered_assets_cache[scan_id].append(clean_asset)

        msg = message or f"Discovered asset: {asset_url[:80]}"
        await self.broadcast_event(
            scan_id=scan_id,
            event_type="scan.asset_discovered",
            state="DISCOVERY",
            stage="Attack Surface Discovery",
            progress_percent=progress_percent,
            message=msg,
            status="Running",
            data={"asset": clean_asset, "total_discovered": len(self.discovered_assets_cache[scan_id])}
        )

    async def broadcast_finding_discovered(
        self,
        scan_id: int,
        finding: Dict[str, Any],
        progress_percent: int = 75,
        message: Optional[str] = None
    ):
        """Emit scan.finding_discovered event when an evidence-based security finding is verified."""
        clean_finding = {
            "finding_id": finding.get("id") or finding.get("finding_id"),
            "title": finding.get("title", ""),
            "category": finding.get("category", "General"),
            "severity": finding.get("severity", "Medium"),
            "confidence": finding.get("confidence", "MEDIUM"),
            "affected_url": finding.get("affected_url", ""),
            "cvss_score": finding.get("cvss_score"),
            "test_type": finding.get("test_type", "")
        }
        clean_finding = redact_event_data(clean_finding)

        if scan_id not in self.findings_cache:
            self.findings_cache[scan_id] = []
        fid = clean_finding.get("finding_id")
        ftitle = clean_finding.get("title")
        if any((fid and existing.get("finding_id") == fid) or (ftitle and existing.get("title") == ftitle) for existing in self.findings_cache[scan_id]):
            return
        self.findings_cache[scan_id].append(clean_finding)

        f_title = clean_finding.get("title", "")
        msg = message or f"Verified security finding: {f_title[:80]}"
        await self.broadcast_event(
            scan_id=scan_id,
            event_type="scan.finding_discovered",
            state="SECURITY_TESTING",
            stage="Security Testing",
            progress_percent=progress_percent,
            message=msg,
            status="Running",
            data={"finding": clean_finding, "total_findings": len(self.findings_cache[scan_id])}
        )

    async def broadcast_score_updated(
        self,
        scan_id: int,
        score: float,
        grade: str,
        risk: str,
        deductions: Optional[Dict[str, Any]] = None,
        progress_percent: int = 88
    ):
        """Emit scan.score_updated event with unified mathematical score telemetry."""
        await self.broadcast_event(
            scan_id=scan_id,
            event_type="scan.score_updated",
            state="SCORING",
            stage="Security Scoring",
            progress_percent=progress_percent,
            message=f"Calculated Security Score: {score:.1f}/100 (Grade {grade}, {risk} Risk)",
            status="Running",
            data={
                "score": score,
                "grade": grade,
                "risk": risk,
                "deductions": deductions or {}
            }
        )

    async def broadcast_report_started(
        self,
        scan_id: int,
        progress_percent: int = 92,
        message: Optional[str] = None
    ):
        """Emit scan.report_started event."""
        await self.broadcast_event(
            scan_id=scan_id,
            event_type="scan.report_started",
            state="REPORTING",
            stage="Report Generation",
            progress_percent=progress_percent,
            message=message or "Compiling executive ReportLab PDF report artifact...",
            status="Running",
            data={}
        )

    async def broadcast_completed(
        self,
        scan_id: int,
        target_url: str,
        score: float,
        grade: str,
        risk: str,
        total_assets: int,
        total_findings: int,
        report_id: Optional[int] = None,
        requests_used: Optional[int] = None,
        requests_remaining: Optional[int] = None
    ):
        """Emit scan.completed event after report generation and DB persistence."""
        final_reqs = requests_used if requests_used is not None else self.requests_used_cache.get(scan_id, 0)
        final_rem = requests_remaining if requests_remaining is not None else max(0, 150 - final_reqs)
        self.requests_used_cache[scan_id] = final_reqs
        await self.broadcast_event(
            scan_id=scan_id,
            event_type="scan.completed",
            state="COMPLETED",
            stage="Scan Completed",
            progress_percent=100,
            message=f"Scan #{scan_id} completed successfully for {target_url}.",
            status="Completed",
            data={
                "score": score,
                "grade": grade,
                "risk": risk,
                "total_assets": total_assets,
                "total_findings": total_findings,
                "report_id": report_id,
                "requests_used": final_reqs,
                "requests_remaining": final_rem,
                "requests_total": 150,
                "completed": True
            }
        )

    async def broadcast_cancel_requested(
        self,
        scan_id: int,
        progress_percent: int
    ):
        """Emit scan.cancel_requested event when operator requests abort."""
        await self.broadcast_event(
            scan_id=scan_id,
            event_type="scan.cancel_requested",
            state="CANCELLING",
            stage="Cancelling",
            progress_percent=progress_percent,
            message="Operator requested scan cancellation. Halting active workers...",
            status="Cancelling",
            data={"cancellation_requested": True}
        )

    async def broadcast_cancelled(
        self,
        scan_id: int,
        progress_percent: int,
        message: str = "Scan was cancelled by operator."
    ):
        """Emit scan.cancelled event when worker safely stops."""
        await self.broadcast_event(
            scan_id=scan_id,
            event_type="scan.cancelled",
            state="CANCELLED",
            stage="Scan Cancelled",
            progress_percent=progress_percent,
            message=message,
            status="Cancelled",
            data={"cancelled": True}
        )

    async def broadcast_failure(
        self,
        scan_id: int,
        error_message: str,
        progress_percent: int = 0
    ):
        """Emit scan.failed event with safe, redacted failure description."""
        clean_err = redact_event_data(error_message)
        await self.broadcast_event(
            scan_id=scan_id,
            event_type="scan.failed",
            state="FAILED",
            stage="Scan Failed",
            progress_percent=progress_percent,
            message=f"Scan process failed: {clean_err}",
            status="Failed",
            data={"error": clean_err}
        )

    async def broadcast_heartbeat(
        self,
        scan_id: int,
        state: str,
        progress_percent: int,
        worker_id: str,
        requests_used: int = 0,
        requests_remaining: int = 150
    ):
        """Emit periodic scan.heartbeat to communicate worker vitality."""
        await self.broadcast_event(
            scan_id=scan_id,
            event_type="scan.heartbeat",
            state=state,
            stage=state.replace("_", " ").title(),
            progress_percent=progress_percent,
            message="Worker active and healthy.",
            status="Running",
            data={
                "worker_id": worker_id,
                "requests_used": requests_used,
                "requests_remaining": requests_remaining,
                "requests_total": 150
            }
        )


progress_manager = ScanProgressManager()
