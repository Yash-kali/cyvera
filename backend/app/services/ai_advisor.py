import os
import json
import urllib.request
from typing import Dict, Any

# Gemini API key from environment variable if available
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")


def build_prompt(title: str, description: str, cve_id: str, affected_url: str) -> str:
    """Format structured prompt instructing Google Gemini API to output exact 7 sections in JSON format."""
    return f"""
You are a Senior Cybersecurity Architect and AI Vulnerability Advisor.
Analyze the following security finding and return ONLY a valid JSON object containing 7 professional sections:

Target URL: {affected_url}
CVE / ID: {cve_id}
Finding Title: {title}
Technical Summary: {description}

Return ONLY JSON with this exact structure:
{{
  "executive_summary": "Concise 2-sentence C-level executive risk overview.",
  "technical_explanation": "In-depth root cause analysis explaining why this flaw exists in the application layer.",
  "business_impact": "Financial, compliance (PCI-DSS/GDPR), data confidentiality, and reputation risk analysis.",
  "attack_scenario": "Step 1: ... Step 2: ... Step 3: ... (Conceptual breakdown of how this vulnerability manifests).",
  "remediation_steps": "Actionable developer fix instructions and resolution steps.",
  "secure_coding_recommendations": "Best-practice secure coding recommendations, parameter validation, or framework configuration.",
  "owasp_mapping": "OWASP Category (e.g. A01:2021-Broken Access Control)"
}}
"""


def generate_fallback_ai_explanation(title: str, description: str, cve_id: str, affected_url: str) -> Dict[str, str]:
    """
    High-quality security knowledge engine fallback when external LLM API key is not present.
    Generates concise, professional, and security-focused 7-section structured output.
    """
    cve_upper = (cve_id or "").upper()
    title_lower = title.lower()

    if "runc" in title_lower or "2024-21626" in cve_upper:
        return {
            "executive_summary": "A critical container escape flaw allows unauthorized execution of commands on the underlying host kernel, leading to potential infrastructure compromise.",
            "technical_explanation": "The runc runtime leaks internal file descriptors during container startup. An attacker inside the container can overwrite the host runc binary via /proc/self/exe fd access.",
            "business_impact": "Complete loss of host confidentiality, integrity, and availability. May result in cloud tenant isolation failure and regulatory non-compliance.",
            "attack_scenario": "Step 1: Attacker gains entry to container. Step 2: Attacker accesses leaked host file descriptor. Step 3: Attacker overwrites host binary to gain root access on the host node.",
            "remediation_steps": "Upgrade runc runtime to version 1.1.12+ and update container host OS packages immediately.",
            "secure_coding_recommendations": "Ensure container runtimes use seccomp filters and close open file descriptors before calling execve in process initialization.",
            "owasp_mapping": "A06:2021-Vulnerable and Outdated Components"
        }
    elif "bola" in title_lower or "access" in title_lower or "api1" in cve_upper:
        return {
            "executive_summary": "An API endpoint fails to verify user ownership of requested object keys, exposing sensitive operator resources to unauthorized access.",
            "technical_explanation": "The API endpoint accepts a resource identifier parameter but does not check if the requesting authenticated user's ID matches the owner_id of the record in database queries.",
            "business_impact": "Unauthorized exposure of private customer data, violation of GDPR/CCPA privacy laws, and potential API key compromise.",
            "attack_scenario": "Step 1: Attacker logs into an unprivileged account. Step 2: Attacker inspects API calls to /api/v1/keys. Step 3: Attacker increments resource ID parameter to fetch other users' API keys.",
            "remediation_steps": "Enforce object-level access controls in FastAPI endpoint: filter database query using `where(Key.user_id == current_user.id)`.",
            "secure_coding_recommendations": "Implement centralized authorization middleware or policy engines (OPA) that validate tenant ownership on every REST endpoint request.",
            "owasp_mapping": "A01:2021-Broken Access Control"
        }
    elif "webp" in title_lower or "4863" in cve_upper:
        return {
            "executive_summary": "A heap buffer overflow in image rendering dependencies allows remote code execution when processing untrusted WebP images.",
            "technical_explanation": "Insufficient bounds checking in Huffman coding table initialization allows malicious WebP image payloads to write beyond allocated heap boundaries.",
            "business_impact": "Potential system compromise, process crash, and service disruption across image-processing microservices.",
            "attack_scenario": "Step 1: Attacker uploads a crafted WebP image file. Step 2: Server worker attempts to parse image headers. Step 3: Heap overflow triggers code execution with web server process privileges.",
            "remediation_steps": "Update libwebp library dependency to version 1.3.2 or later across all worker base images.",
            "secure_coding_recommendations": "Sandboxing media processing workloads and utilizing memory-safe image parsing libraries or container isolation.",
            "owasp_mapping": "A06:2021-Vulnerable and Outdated Components"
        }
    else:
        return {
            "executive_summary": f"Security finding '{title}' exposes target asset {affected_url} to potential risk requiring developer remediation.",
            "technical_explanation": f"The finding '{title}' indicates an unmitigated configuration or coding pattern: {description}",
            "business_impact": "Increased attack surface, potential data exposure, and failure to meet strict security baseline standards.",
            "attack_scenario": "Step 1: Reconnaissance identifies target endpoint. Step 2: Malformed or unauthenticated request is sent. Step 3: Security policy violation is triggered.",
            "remediation_steps": f"Apply security patch or configuration update to address: {description}",
            "secure_coding_recommendations": "Follow defense-in-depth security principles, strict input validation, and principle of least privilege across application services.",
            "owasp_mapping": "A05:2021-Security Misconfiguration"
        }


def explain_vulnerability_with_ai(title: str, description: str, cve_id: str, affected_url: str) -> Dict[str, str]:
    """
    Main AI Advisory Service method: Queries Google Gemini API if key exists,
    otherwise uses high-quality security advisory knowledge fallback.
    """
    if GEMINI_API_KEY:
        try:
            prompt_text = build_prompt(title, description, cve_id, affected_url)
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
            
            payload = {
                "contents": [{"parts": [{"text": prompt_text}]}],
                "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}
            }
            
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            
            with urllib.request.urlopen(req, timeout=8) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                text_out = res_data["candidates"][0]["content"]["parts"][0]["text"]
                parsed_json = json.loads(text_out)
                return {
                    "executive_summary": parsed_json.get("executive_summary", ""),
                    "technical_explanation": parsed_json.get("technical_explanation", parsed_json.get("technical_description", "")),
                    "business_impact": parsed_json.get("business_impact", ""),
                    "attack_scenario": parsed_json.get("attack_scenario", ""),
                    "remediation_steps": parsed_json.get("remediation_steps", parsed_json.get("remediation_guidance", "")),
                    "secure_coding_recommendations": parsed_json.get("secure_coding_recommendations", "Enforce input sanitization and parameter validation."),
                    "owasp_mapping": parsed_json.get("owasp_mapping", "A05:2021-Security Misconfiguration")
                }
        except Exception as e:
            print(f"Gemini API request fallback: {e}")

    return generate_fallback_ai_explanation(title, description, cve_id, affected_url)
