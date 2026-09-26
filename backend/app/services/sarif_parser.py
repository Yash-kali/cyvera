import re
import json
from typing import List, Dict, Any, Optional, Tuple

MAX_SARIF_PAYLOAD_BYTES = 10 * 1024 * 1024  # 10 MB limit
MAX_SARIF_FINDINGS_COUNT = 500               # 500 findings limit per batch

# Canonical application severities
CANONICAL_SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]

# Sensitive data redaction patterns
REDACTION_PATTERNS = [
    (re.compile(r'(?i)(bearer\s+)[a-z0-9\-_\.]{16,}'), r'\1[REDACTED_TOKEN]'),
    (re.compile(r'(?i)(password\s*[:=]\s*)[^\s,;&"\']+'), r'\1[REDACTED_PASSWORD]'),
    (re.compile(r'(?i)(api[_\-]?key\s*[:=]\s*)[^\s,;&"\']+'), r'\1[REDACTED_API_KEY]'),
    (re.compile(r'(?i)(secret\s*[:=]\s*)[^\s,;&"\']+'), r'\1[REDACTED_SECRET]'),
    (re.compile(r'(?i)(access[_\-]?token\s*[:=]\s*)[^\s,;&"\']+'), r'\1[REDACTED_TOKEN]'),
]


def redact_sensitive_evidence(text: Optional[str]) -> str:
    """Sanitizes evidence text by masking secrets, bearer tokens, and credentials."""
    if not text:
        return ""
    sanitized = str(text)
    for pattern, replacement in REDACTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def normalize_severity(
    level_or_sev: Any,
    cvss_score: Optional[float] = None
) -> str:
    """
    Normalizes arbitrary scanner severity strings into canonical Cyvera tiers:
    'Critical', 'High', 'Medium', 'Low', 'Info'.

    If a valid CVSS v3 score is provided, the standard CVSS 3.1 qualitative rating
    is considered to refine the tier:
      - 9.0 - 10.0: Critical
      - 7.0 - 8.9: High
      - 4.0 - 6.9: Medium
      - 0.1 - 3.9: Low
      - 0.0: Info
    Safe fallback for unmapped/unknown values is 'Info'.
    """
    if cvss_score is not None and isinstance(cvss_score, (int, float)):
        score = float(cvss_score)
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0.0:
            return "Low"
        elif score == 0.0:
            return "Info"

    if not level_or_sev:
        return "Info"

    sev_clean = str(level_or_sev).strip().lower()

    if sev_clean in ["critical", "crit", "fatal", "blocker"]:
        return "Critical"
    elif sev_clean in ["high", "error", "severe"]:
        return "High"
    elif sev_clean in ["medium", "med", "moderate", "warning", "warn"]:
        return "Medium"
    elif sev_clean in ["low", "minor", "note", "notice"]:
        return "Low"
    elif sev_clean in ["info", "informational", "none", "unspecified"]:
        return "Info"

    # Default safe fallback
    return "Info"


def extract_cve_or_cwe(tags_and_texts: List[str]) -> Optional[str]:
    """Finds CVE, CWE, or OWASP identifier in rule properties or tags."""
    joined = " ".join(str(t) for t in tags_and_texts if t)
    
    # 1. Match CVE pattern
    cve_match = re.search(r'(?i)\b(CVE-\d{4}-\d{4,7})\b', joined)
    if cve_match:
        return cve_match.group(1).upper()
        
    # 2. Match CWE pattern
    cwe_match = re.search(r'(?i)\b(CWE-\d{1,5})\b', joined)
    if cwe_match:
        return cwe_match.group(1).upper()

    # 3. Match OWASP pattern
    owasp_match = re.search(r'(?i)\b(OWASP-A\d{2}(?:-\d{4})?)\b', joined)
    if owasp_match:
        return owasp_match.group(1).upper()

    # 4. Check for A01..A10
    a_match = re.search(r'(?i)\b(A0[1-9]|A10)\b', joined)
    if a_match:
        return f"OWASP-{a_match.group(1).upper()}"

    return None


def parse_and_normalize_sarif(
    payload: Any,
    default_target_url: str = "https://target-asset.internal",
    scan_id: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Production-grade SARIF 2.1.0 Parser and Ingestion Engine.
    
    Supports:
    1. Standard OASIS SARIF 2.1.0 document (with `runs` array).
    2. Wrapped SARIF payload with `sarif_data` envelope.
    3. Pipeline/scanner findings payload with `findings` list.
    4. Direct list of vulnerability dictionaries.

    Returns canonical list of Finding dictionaries ready for persistence.
    """
    if isinstance(payload, str):
        if len(payload.encode('utf-8')) > MAX_SARIF_PAYLOAD_BYTES:
            raise ValueError(f"SARIF payload exceeds maximum allowed size of {MAX_SARIF_PAYLOAD_BYTES // (1024 * 1024)}MB.")
        try:
            payload = json.loads(payload)
        except Exception as e:
            raise ValueError(f"Malformed SARIF JSON: {str(e)}")

    if not isinstance(payload, (dict, list)):
        raise ValueError("SARIF document must be a JSON object or array.")

    # Check for wrapped 'sarif_data' envelope
    if isinstance(payload, dict) and "sarif_data" in payload and isinstance(payload["sarif_data"], (dict, list)):
        inner_scan_id = payload.get("scan_id", scan_id)
        return parse_and_normalize_sarif(payload["sarif_data"], default_target_url=default_target_url, scan_id=inner_scan_id)

    normalized_findings: List[Dict[str, Any]] = []

    # Case A: Standard SARIF 2.1.0 with 'runs' array
    if isinstance(payload, dict) and "runs" in payload and isinstance(payload["runs"], list):
        for run in payload["runs"]:
            if not isinstance(run, dict):
                continue

            # Extract tool driver rules
            tool = run.get("tool", {})
            driver = tool.get("driver", {}) if isinstance(tool, dict) else {}
            tool_name = driver.get("name", "SARIF Security Scanner") if isinstance(driver, dict) else "SARIF Security Scanner"
            
            rules_raw = driver.get("rules", []) if isinstance(driver, dict) else []
            rules_by_id: Dict[str, Dict[str, Any]] = {}
            rules_by_idx: Dict[int, Dict[str, Any]] = {}

            if isinstance(rules_raw, list):
                for idx, r in enumerate(rules_raw):
                    if isinstance(r, dict):
                        r_id = r.get("id")
                        if r_id:
                            rules_by_id[str(r_id)] = r
                        rules_by_idx[idx] = r

            results = run.get("results", [])
            if not isinstance(results, list):
                continue

            for res in results:
                if not isinstance(res, dict):
                    continue

                if len(normalized_findings) >= MAX_SARIF_FINDINGS_COUNT:
                    break

                rule_id = str(res.get("ruleId", ""))
                rule_idx = res.get("ruleIndex")
                rule = rules_by_id.get(rule_id) or (rules_by_idx.get(rule_idx) if isinstance(rule_idx, int) else {}) or {}

                # 1. Title
                title = (
                    rule.get("name") or
                    rule.get("shortDescription", {}).get("text") or
                    res.get("message", {}).get("text", "")[:120] or
                    rule_id or
                    "Security Finding"
                ).strip()

                # 2. Location & Target URI
                loc_uri = default_target_url
                loc_str = ""
                locations = res.get("locations", [])
                if isinstance(locations, list) and len(locations) > 0 and isinstance(locations[0], dict):
                    phys = locations[0].get("physicalLocation", {})
                    if isinstance(phys, dict):
                        art = phys.get("artifactLocation", {})
                        if isinstance(art, dict) and art.get("uri"):
                            loc_uri = str(art.get("uri"))

                        region = phys.get("region", {})
                        if isinstance(region, dict):
                            start_line = region.get("startLine")
                            start_col = region.get("startColumn")
                            if start_line:
                                loc_str = f"Line {start_line}"
                                if start_col:
                                    loc_str += f", Column {start_col}"

                # 3. Message & Evidence
                msg_obj = res.get("message", {})
                message_text = msg_obj.get("text", "") if isinstance(msg_obj, dict) else str(msg_obj)
                message_text = redact_sensitive_evidence(message_text)

                # 4. Description
                rule_desc = rule.get("fullDescription", {}).get("text") or rule.get("shortDescription", {}).get("text") or ""
                description_parts = []
                if rule_desc:
                    description_parts.append(rule_desc.strip())
                if message_text and message_text != rule_desc:
                    description_parts.append(message_text.strip())
                if loc_str:
                    description_parts.append(f"Source Reference: {loc_str}")

                description = "\n\n".join(description_parts) if description_parts else title

                # 5. Severity & CVSS
                res_props = res.get("properties", {}) if isinstance(res.get("properties"), dict) else {}
                rule_props = rule.get("properties", {}) if isinstance(rule.get("properties"), dict) else {}

                cvss_candidate = res_props.get("cvss") or res_props.get("security-severity") or rule_props.get("security-severity") or rule_props.get("cvss")
                cvss_score = None
                if cvss_candidate is not None:
                    try:
                        cvss_score = round(float(cvss_candidate), 1)
                    except (ValueError, TypeError):
                        cvss_score = None

                level = res.get("level") or rule.get("defaultConfiguration", {}).get("level") or res_props.get("severity") or "warning"
                severity = normalize_severity(level, cvss_score)

                # 6. CVE / CWE Identifier
                tags = rule_props.get("tags", []) if isinstance(rule_props.get("tags"), list) else []
                cve_cwe = extract_cve_or_cwe([rule_id, rule.get("name", "")] + [str(t) for t in tags])

                # 7. Remediation Guidance
                help_obj = rule.get("help", {})
                remediation = help_obj.get("text") or help_obj.get("markdown") if isinstance(help_obj, dict) else None
                if not remediation and rule.get("helpUri"):
                    remediation = f"Refer to vendor advisory: {rule.get('helpUri')}"
                if not remediation:
                    remediation = "Apply security patch, upgrade vulnerable component, or implement input validation and proper access controls."

                remediation = redact_sensitive_evidence(remediation)

                normalized_findings.append({
                    "scan_id": scan_id,
                    "title": title[:255],
                    "description": description,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "cve_id": cve_cwe[:100] if cve_cwe else f"{tool_name[:20]}-{rule_id[:50]}",
                    "affected_url": loc_uri[:2048],
                    "remediation_guidance": remediation,
                    "status": "Open"
                })

        return normalized_findings

    # Case B: Custom JSON payload with 'findings' array (e.g. from frontend modal)
    findings_list = None
    if isinstance(payload, dict) and "findings" in payload and isinstance(payload["findings"], list):
        findings_list = payload["findings"]
        scan_id = payload.get("scan_id", scan_id)
    elif isinstance(payload, list):
        findings_list = payload

    if findings_list is not None:
        for item in findings_list:
            if not isinstance(item, dict):
                continue

            if len(normalized_findings) >= MAX_SARIF_FINDINGS_COUNT:
                break

            title = str(item.get("title", "Imported Vulnerability Finding")).strip()
            description = str(item.get("description", title)).strip()
            
            cvss_val = item.get("cvss_score")
            cvss_score = None
            if cvss_val is not None:
                try:
                    cvss_score = round(float(cvss_val), 1)
                except (ValueError, TypeError):
                    cvss_score = None

            severity = normalize_severity(item.get("severity"), cvss_score)
            cve_id = item.get("cve_id") or extract_cve_or_cwe([title, description])
            affected_url = str(item.get("affected_url", default_target_url)).strip()
            remediation = str(item.get("remediation_guidance", "Apply security patch or implement defensive controls.")).strip()

            normalized_findings.append({
                "scan_id": item.get("scan_id", scan_id),
                "title": title[:255],
                "description": redact_sensitive_evidence(description),
                "severity": severity,
                "cvss_score": cvss_score,
                "cve_id": str(cve_id)[:100] if cve_id else None,
                "affected_url": affected_url[:2048],
                "remediation_guidance": redact_sensitive_evidence(remediation),
                "status": "Open"
            })

        return normalized_findings

    # If payload was a dictionary without runs or findings, check if it has single result fields
    if isinstance(payload, dict) and ("title" in payload or "ruleId" in payload):
        return parse_and_normalize_sarif([payload], default_target_url=default_target_url, scan_id=scan_id)

    return []
