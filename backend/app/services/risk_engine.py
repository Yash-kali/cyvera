from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict

from app.services.owasp_mapper import map_finding_to_owasp, OWASP_TOP_10_2021


def _normalize_dt(dt: Any) -> Optional[datetime]:
    if not dt:
        return None
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except Exception:
            return None
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    return None


def calculate_risk_metrics(findings: List[Any]) -> Dict[str, Any]:
    """
    CVSS-Inspired Risk Calculation Engine.
    Evaluates active findings to compute Weighted Risk Score (R),
    Security Health Score (S), and Security Grade letter.
    """
    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }
    
    total_findings = len(findings)
    open_findings = 0
    resolved_findings = 0
    
    weights = {
        "Critical": 25.0,
        "High": 15.0,
        "Medium": 5.0,
        "Low": 1.0,
        "Info": 0.0
    }
    
    active_risk_raw = 0.0
    
    for f in findings:
        sev = getattr(f, "severity", "Medium")
        stat = getattr(f, "status", "Open")
        
        if sev in severity_counts:
            severity_counts[sev] += 1
            
        if stat in ["Open", "In Review"]:
            open_findings += 1
            active_risk_raw += weights.get(sev, 5.0)
        elif stat in ["Resolved", "Mitigated"]:
            resolved_findings += 1

    # Clamp Risk Score between 0 and 100
    risk_score = round(min(100.0, active_risk_raw), 1)
    security_score = round(max(0.0, 100.0 - risk_score), 1)
    
    # Grade Calculation
    if total_findings == 0:
        grade = "GRADE A+"
        grade_color = "emerald"
    elif security_score >= 95.0:
        grade = "GRADE A+"
        grade_color = "emerald"
    elif security_score >= 85.0:
        grade = "GRADE A"
        grade_color = "green"
    elif security_score >= 70.0:
        grade = "GRADE B"
        grade_color = "cyan"
    elif security_score >= 50.0:
        grade = "GRADE C"
        grade_color = "amber"
    elif security_score >= 30.0:
        grade = "GRADE D"
        grade_color = "orange"
    else:
        grade = "GRADE F"
        grade_color = "rose"

    sla_compliance_rate = round((resolved_findings / total_findings * 100.0), 1) if total_findings > 0 else 100.0

    return {
        "security_score": security_score,
        "risk_score": risk_score,
        "grade": grade,
        "grade_color": grade_color,
        "total_findings": total_findings,
        "open_findings": open_findings,
        "resolved_findings": resolved_findings,
        "sla_compliance_rate": sla_compliance_rate,
        "severity_distribution": severity_counts
    }


def calculate_asset_risk_breakdown(findings: List[Any]) -> List[Dict[str, Any]]:
    """Group findings by affected URL and compute target asset risk scores."""
    if not findings:
        return []

    asset_groups: Dict[str, List[Any]] = {}
    
    for f in findings:
        url = getattr(f, "affected_url", "https://staging-api.autopentest.ai")
        if url not in asset_groups:
            asset_groups[url] = []
        asset_groups[url].append(f)
        
    asset_breakdown = []
    weights = {"Critical": 30.0, "High": 20.0, "Medium": 8.0, "Low": 2.0, "Info": 0.0}
    
    for url, items in asset_groups.items():
        raw_risk = 0.0
        crit_cnt = 0
        high_cnt = 0
        
        for item in items:
            sev = getattr(item, "severity", "Medium")
            stat = getattr(item, "status", "Open")
            if stat in ["Open", "In Review"]:
                raw_risk += weights.get(sev, 5.0)
                if sev == "Critical":
                    crit_cnt += 1
                elif sev == "High":
                    high_cnt += 1
                    
        asset_risk = round(min(100.0, raw_risk), 1)
        asset_sec_score = round(max(0.0, 100.0 - asset_risk), 1)
        
        if asset_sec_score >= 85:
            risk_rating = "LOW_RISK"
        elif asset_sec_score >= 60:
            risk_rating = "MEDIUM_RISK"
        else:
            risk_rating = "HIGH_RISK"

        asset_breakdown.append({
            "target_url": url,
            "total_findings": len(items),
            "critical_count": crit_cnt,
            "high_count": high_cnt,
            "asset_risk_score": asset_risk,
            "asset_security_score": asset_sec_score,
            "risk_rating": risk_rating
        })
        
    return asset_breakdown


def calculate_analytics_overview(
    scans: List[Any],
    findings: List[Any],
    severity_filter: Optional[str] = None,
    scan_type_filter: Optional[str] = None,
    date_range: Optional[str] = "30d",
    status_filter: Optional[str] = None
) -> Dict[str, Any]:
    """
    Consolidated Analytics Calculation Engine.
    Filters user scans and findings by date_range, scan_type, status, and severity.
    Computes all KPI aggregates, scan profile distributions, OWASP mappings,
    chronological date-series trends, and per-asset risk scores.
    """
    now = datetime.now(timezone.utc)
    cutoff = None
    if date_range == "7d":
        cutoff = now - timedelta(days=7)
    elif date_range == "30d":
        cutoff = now - timedelta(days=30)
    elif date_range == "90d":
        cutoff = now - timedelta(days=90)

    # 1. Filter Scans
    filtered_scans = []
    for s in scans:
        s_dt = _normalize_dt(getattr(s, "created_at", None))
        if cutoff and s_dt and s_dt < cutoff:
            continue
        if scan_type_filter and scan_type_filter.lower() != "all":
            if getattr(s, "scan_type", "").lower() != scan_type_filter.lower():
                continue
        if status_filter and status_filter.lower() != "all":
            if getattr(s, "status", "").lower() != status_filter.lower():
                continue
        filtered_scans.append(s)

    valid_scan_ids = {s.id for s in filtered_scans}
    has_scan_filter = bool(
        (scan_type_filter and scan_type_filter.lower() != "all") or
        (status_filter and status_filter.lower() != "all")
    )

    # 2. Filter Findings
    filtered_findings = []
    for f in findings:
        f_dt = _normalize_dt(getattr(f, "created_at", None))
        if cutoff and f_dt and f_dt < cutoff:
            continue
        if has_scan_filter and getattr(f, "scan_id", None) not in valid_scan_ids:
            continue
        if severity_filter and severity_filter.lower() != "all":
            if getattr(f, "severity", "").lower() != severity_filter.lower():
                continue
        filtered_findings.append(f)

    # 3. Scan Profile & Status Metrics
    total_scans = len(filtered_scans)
    completed_scans = sum(1 for s in filtered_scans if getattr(s, "status", "") == "Completed")
    running_scans = sum(1 for s in filtered_scans if getattr(s, "status", "") in ("Running", "Pending"))
    failed_scans = sum(1 for s in filtered_scans if getattr(s, "status", "") == "Failed")

    scan_profile_dist = {
        "Quick": sum(1 for s in filtered_scans if getattr(s, "scan_type", "") == "Quick"),
        "Standard": sum(1 for s in filtered_scans if getattr(s, "scan_type", "") == "Standard"),
        "Full": sum(1 for s in filtered_scans if getattr(s, "scan_type", "") == "Full")
    }

    # 4. Finding & Risk Metrics
    metrics = calculate_risk_metrics(filtered_findings)
    if total_scans == 0 and len(filtered_findings) == 0:
        metrics["grade"] = "STANDBY"
        metrics["grade_color"] = "slate"

    sev_dist = metrics["severity_distribution"]

    # 5. OWASP Top 10 Distribution
    owasp_counts = {code: 0 for code in OWASP_TOP_10_2021}
    for f in filtered_findings:
        code = map_finding_to_owasp(f)
        if code in owasp_counts:
            owasp_counts[code] += 1

    owasp_distribution = [
        {
            "code": code,
            "name": OWASP_TOP_10_2021[code]["name"],
            "count": owasp_counts[code]
        }
        for code in sorted(OWASP_TOP_10_2021.keys())
    ]

    # 6. Chronological Date-Series Trends
    date_stats = defaultdict(lambda: {"findings": 0, "scans": 0, "risk_score": 0.0})

    for s in filtered_scans:
        s_dt = _normalize_dt(getattr(s, "created_at", None))
        if s_dt:
            d_str = s_dt.strftime("%Y-%m-%d")
            date_stats[d_str]["scans"] += 1

    weights = {"Critical": 25.0, "High": 15.0, "Medium": 5.0, "Low": 1.0, "Info": 0.0}
    for f in filtered_findings:
        f_dt = _normalize_dt(getattr(f, "created_at", None))
        if f_dt:
            d_str = f_dt.strftime("%Y-%m-%d")
            date_stats[d_str]["findings"] += 1
            sev = getattr(f, "severity", "Medium")
            stat = getattr(f, "status", "Open")
            if stat in ["Open", "In Review"]:
                date_stats[d_str]["risk_score"] += weights.get(sev, 5.0)

    trend_data = []
    for d_str in sorted(date_stats.keys()):
        trend_data.append({
            "date": d_str,
            "findings": date_stats[d_str]["findings"],
            "scans": date_stats[d_str]["scans"],
            "risk_score": round(min(100.0, date_stats[d_str]["risk_score"]), 1)
        })

    # 7. Asset Risk Breakdown
    asset_risks = calculate_asset_risk_breakdown(filtered_findings)

    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "running_scans": running_scans,
        "failed_scans": failed_scans,
        "total_findings": metrics["total_findings"],
        "open_findings": metrics["open_findings"],
        "resolved_findings": metrics["resolved_findings"],
        "critical_findings": sev_dist["Critical"],
        "high_findings": sev_dist["High"],
        "medium_findings": sev_dist["Medium"],
        "low_findings": sev_dist["Low"],
        "info_findings": sev_dist["Info"],
        "security_score": metrics["security_score"],
        "risk_score": metrics["risk_score"],
        "grade": metrics["grade"],
        "grade_color": metrics["grade_color"],
        "sla_compliance_rate": metrics["sla_compliance_rate"],
        "severity_distribution": sev_dist,
        "scan_profile_distribution": scan_profile_dist,
        "owasp_distribution": owasp_distribution,
        "trend_data": trend_data,
        "asset_risks": asset_risks
    }
