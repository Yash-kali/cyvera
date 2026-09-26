from typing import List, Dict, Any
import urllib.parse

# Standard OWASP Top 10 2021 Categories
OWASP_TOP_10_2021 = {
    "A01": {"code": "A01", "name": "Broken Access Control", "category_key": "A01 Broken Access Control"},
    "A02": {"code": "A02", "name": "Cryptographic Failures", "category_key": "A02 Cryptographic Failures"},
    "A03": {"code": "A03", "name": "Injection", "category_key": "A03 Injection"},
    "A04": {"code": "A04", "name": "Insecure Design", "category_key": "A04 Insecure Design"},
    "A05": {"code": "A05", "name": "Security Misconfiguration", "category_key": "A05 Security Misconfiguration"},
    "A06": {"code": "A06", "name": "Vulnerable Components", "category_key": "A06 Vulnerable Components"},
    "A07": {"code": "A07", "name": "Authentication Failures", "category_key": "A07 Authentication Failures"},
    "A08": {"code": "A08", "name": "Software Integrity Failures", "category_key": "A08 Software Integrity Failures"},
    "A09": {"code": "A09", "name": "Logging Failures", "category_key": "A09 Logging Failures"},
    "A10": {"code": "A10", "name": "SSRF", "category_key": "A10 SSRF"},
}


def map_finding_to_owasp(finding: Any) -> str:
    """
    Automated keyword & pattern mapping algorithm to assign a finding to OWASP Top 10 2021 (A01-A10).
    """
    title = str(getattr(finding, "title", "")).lower()
    desc = str(getattr(finding, "description", "")).lower()
    cve = str(getattr(finding, "cve_id", "")).lower()
    combined = f"{title} {desc} {cve}"

    if any(k in combined for k in ["access control", "bola", "idor", "privilege escalation", "unauthorized", "cors", "override"]):
        return "A01"
    elif any(k in combined for k in ["crypto", "ssl", "tls", "cipher", "hsts", "plaintext", "cert"]):
        return "A02"
    elif any(k in combined for k in ["injection", "sqli", "xss", "command injection", "rce", "template injection"]):
        return "A03"
    elif any(k in combined for k in ["design", "architecture", "business logic", "rate limit", "threat model"]):
        return "A04"
    elif any(k in combined for k in ["header", "misconfiguration", "config", "default credential", "debug", "directory listing"]):
        return "A05"
    elif any(k in combined for k in ["component", "library", "outdated", "dependency", "cve-2024", "cve-2023", "webp", "runc"]):
        return "A06"
    elif any(k in combined for k in ["auth", "login", "session", "password", "jwt", "token", "credential"]):
        return "A07"
    elif any(k in combined for k in ["integrity", "deserialization", "update", "ci/cd", "pipeline", "tamper"]):
        return "A08"
    elif any(k in combined for k in ["log", "logging", "audit", "monitoring", "detection"]):
        return "A09"
    elif any(k in combined for k in ["ssrf", "server-side request forgery", "internal ip", "metadata endpoint"]):
        return "A10"
    
    # Default fallback category assignment based on title hash or misconfiguration
    return "A05"


def categorize_findings_by_owasp(scan_id: int, findings: List[Any]) -> Dict[str, Any]:
    """
    Group findings into standard OWASP Top 10 categories (A01–A10).
    """
    category_map: Dict[str, List[Any]] = {code: [] for code in OWASP_TOP_10_2021}

    for f in findings:
        code = map_finding_to_owasp(f)
        category_map[code].append(f)

    categories_list = []
    for code, info in OWASP_TOP_10_2021.items():
        matched_findings = category_map.get(code, [])
        categories_list.append({
            "code": info["code"],
            "name": info["name"],
            "category_key": info["category_key"],
            "count": len(matched_findings),
            "findings": matched_findings
        })

    return {
        "scan_id": scan_id,
        "total_findings": len(findings),
        "categories": categories_list
    }


def calculate_owasp_stats(scan_id: int, findings: List[Any]) -> Dict[str, Any]:
    """
    Calculate OWASP category statistics, severity aggregation, and category-severity matrix.
    Uses canonical deduplication so duplicate asset observations do not inflate risk totals.
    """
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

    category_counts = {info["category_key"]: 0 for info in OWASP_TOP_10_2021.values()}
    severity_breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    matrix: Dict[str, Dict[str, int]] = {
        info["category_key"]: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for info in OWASP_TOP_10_2021.values()
    }

    for f in canonical_findings:
        code = map_finding_to_owasp(f)
        cat_key = OWASP_TOP_10_2021[code]["category_key"]
        sev = getattr(f, "severity", "Medium")

        category_counts[cat_key] = category_counts.get(cat_key, 0) + 1
        if sev in severity_breakdown:
            severity_breakdown[sev] += 1
        if cat_key in matrix and sev in matrix[cat_key]:
            matrix[cat_key][sev] += 1

    top_category = max(category_counts, key=category_counts.get) if any(v > 0 for v in category_counts.values()) else "A01 Broken Access Control"

    return {
        "scan_id": scan_id,
        "total_mapped_findings": len(canonical_findings),
        "category_counts": category_counts,
        "severity_breakdown": severity_breakdown,
        "category_severity_matrix": matrix,
        "top_vulnerable_category": top_category
    }
