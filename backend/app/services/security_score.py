from typing import List, Dict, Any, Optional
import urllib.parse

def calculate_security_score(
    scan_id: int,
    target_url: str,
    findings: List[Any],
    recon_result: Optional[Any] = None
) -> Dict[str, Any]:
    """
    AutoPentest AI - Security Scoring Engine Service.
    
    Evaluates:
    1. Critical Vulnerabilities (-20 pts each)
    2. High Vulnerabilities (-10 pts each)
    3. Medium Vulnerabilities (-5 pts each)
    4. SSL/TLS Issues (-10 pts each)
    5. Missing Security Headers (-3 pts each)
    6. Open Ports (-2 pts each)
    
    Returns:
    {
      "score": 82,
      "grade": "A",
      "risk_level": "Low",
      "factors": { ... },
      "deductions": { ... },
      "scan_id": 1,
      "target_url": "https://example.com"
    }
    """
    # Canonical deduplication before tallying severity counts to prevent observation inflation
    canonical_findings = []
    seen_keys = set()
    for f in findings:
        title = getattr(f, "title", "")
        test_type = getattr(f, "test_type", "") or getattr(f, "category", "")
        aff_url = getattr(f, "affected_url", "") or getattr(f, "affected_asset", "") or ""
        parsed = urllib.parse.urlparse(aff_url)
        origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else aff_url

        if test_type in ("SECURITY_HEADERS", "COOKIE_SECURITY", "API_SECURITY", "Security Misconfiguration"):
            canon_key = (test_type, title, origin)
        else:
            canon_key = (test_type, title, aff_url)

        if canon_key not in seen_keys:
            seen_keys.add(canon_key)
            canonical_findings.append(f)

    critical_cnt = 0
    high_cnt = 0
    medium_cnt = 0
    low_cnt = 0
    info_cnt = 0

    for f in canonical_findings:
        sev = getattr(f, "severity", "Medium")
        stat = getattr(f, "status", "Open")
        if stat in ["Open", "In Review", "Confirmed", "Manual Verification Required"]:
            if sev == "Critical":
                critical_cnt += 1
            elif sev == "High":
                high_cnt += 1
            elif sev == "Medium":
                medium_cnt += 1
            elif sev == "Low":
                low_cnt += 1
            elif sev == "Info":
                info_cnt += 1

    ssl_issues_cnt = 0
    missing_headers_cnt = 0
    headers_deduction = 0.0
    missing_headers_list = []
    open_ports_cnt = 0

    # Header security weighting matrix
    HEADER_WEIGHTS = {
        "content-security-policy": 4.0,
        "strict-transport-security": 3.5,
        "x-content-type-options": 2.0,
        "x-frame-options": 2.0,
        "referrer-policy": 1.0,
        "permissions-policy": 1.0,
        "cross-origin-opener-policy": 0.5,
        "cross-origin-resource-policy": 0.5,
        "cross-origin-embedder-policy": 0.5,
    }

    if recon_result and hasattr(recon_result, "details") and isinstance(recon_result.details, dict):
        details = recon_result.details
        tls_info = details.get("tls", {})
        if isinstance(tls_info, dict):
            if not tls_info.get("ssl_enabled", True) or tls_info.get("status") != "VALID":
                ssl_issues_cnt += 1
            elif tls_info.get("days_remaining", 100) is not None and tls_info.get("days_remaining", 100) < 15:
                ssl_issues_cnt += 1

        headers_info = details.get("headers", {})
        if isinstance(headers_info, dict):
            header_details = headers_info.get("header_details", [])
            if isinstance(header_details, list):
                for h in header_details:
                    if isinstance(h, dict) and h.get("status") == "MISSING":
                        h_name = str(h.get("header", "")).strip()
                        missing_headers_list.append(h_name)
                        weight = HEADER_WEIGHTS.get(h_name.lower(), 1.0)
                        headers_deduction += weight
                missing_headers_cnt = len(missing_headers_list)

    # Deductions matrix
    critical_deduction = critical_cnt * 20.0
    high_deduction = high_cnt * 10.0
    medium_deduction = medium_cnt * 5.0
    low_deduction = low_cnt * 2.0
    ssl_deduction = ssl_issues_cnt * 10.0
    ports_deduction = open_ports_cnt * 2.0

    total_deductions = (
        critical_deduction +
        high_deduction +
        medium_deduction +
        low_deduction +
        ssl_deduction +
        headers_deduction +
        ports_deduction
    )

    base_score = 100.0
    raw_score = max(0.0, min(100.0, base_score - total_deductions))
    # Round cleanly to 1 decimal place or whole number
    score = round(raw_score, 1)
    if score.is_integer():
        score = int(score)

    # Grade & Risk Rating Logic
    if score >= 90:
        grade = "A"
        risk_level = "Low"
    elif score >= 80:
        grade = "B"
        risk_level = "Low"
    elif score >= 70:
        grade = "C"
        risk_level = "Medium"
    elif score >= 50:
        grade = "D"
        risk_level = "High"
    else:
        grade = "F"
        risk_level = "Critical"

    confirmed_findings_count = critical_cnt + high_cnt + medium_cnt + low_cnt
    observations_count = missing_headers_cnt + (1 if ssl_issues_cnt > 0 else 0)

    return {
        "score": score,
        "grade": grade,
        "risk_level": risk_level,
        "confirmed_findings_count": confirmed_findings_count,
        "observations_count": observations_count,
        "factors": {
            "critical_vulnerabilities": critical_cnt,
            "high_vulnerabilities": high_cnt,
            "medium_vulnerabilities": medium_cnt,
            "low_vulnerabilities": low_cnt,
            "info_observations": info_cnt,
            "ssl_issues": ssl_issues_cnt,
            "missing_security_headers": missing_headers_cnt,
            "open_ports": open_ports_cnt
        },
        "deductions": {
            "critical_vulnerabilities": critical_deduction,
            "high_vulnerabilities": high_deduction,
            "medium_vulnerabilities": medium_deduction,
            "low_vulnerabilities": low_deduction,
            "ssl_issues": ssl_deduction,
            "missing_security_headers": round(headers_deduction, 1),
            "open_ports": ports_deduction
        },
        "methodology": (
            "Algorithmic score starting at 100.0 with weighted deductions: "
            "Critical (-20 pts), High (-10 pts), Medium (-5 pts), Low (-2 pts), "
            "SSL/TLS anomalies (-10 pts), and weighted missing security headers (0.5 to 4.0 pts each)."
        ),
        "scan_id": scan_id,
        "target_url": target_url
    }

