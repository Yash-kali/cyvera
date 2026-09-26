import os
import json
import urllib.request
from typing import Dict, Any, Optional, List

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")


def generate_fallback_copilot_reply(user_message: str, context: Optional[Dict[str, Any]] = None) -> str:
    """
    Intelligent cybersecurity expert knowledge fallback engine for Copilot chat.
    Responds with detailed technical answers, code examples, remediation guidance, and OWASP mappings.
    """
    msg_lower = user_message.lower().strip()
    
    # Context details if active
    ctx_title = context.get("title", "Target Vulnerability Finding") if context else "Target Vulnerability Finding"
    ctx_url = context.get("affected_url", "target scope endpoint") if context else "target scope endpoint"
    ctx_cve = context.get("cve_id", "OWASP-TOP10") if context else "OWASP-TOP10"

    if "explain" in msg_lower or "what is" in msg_lower or "overview" in msg_lower:
        return f"""### 🛡️ Vulnerability Analysis: {ctx_title}

**Context Scope:** `{ctx_url}` | **Identifier:** `{ctx_cve}`

This vulnerability represents an unmitigated application security flaw. In a typical web application or API gateway:
1. **Root Cause:** Input parameters or resource access requests are processed without strict authorization validation or boundary sanitization.
2. **Threat Vector:** Attackers can intercept REST API calls or send crafted HTTP payloads to manipulate application state.
3. **Risk Exposure:** Left unaddressed, this weakness allows unauthorized data exposure or privilege escalation.
"""

    elif "fix" in msg_lower or "remediat" in msg_lower or "how to" in msg_lower or "solve" in msg_lower:
        return f"""### 🔧 Remediation & Fix Guidance

To remediate **{ctx_title}** on `{ctx_url}`:

1. **Input Validation:** Enforce strict type validation and regex whitelist checks on incoming parameters.
2. **Access Control:** Enforce object-level access control in your backend route dependencies (e.g. `where(Resource.user_id == current_user.id)`).
3. **Security Headers:** Ensure response headers include `Strict-Transport-Security`, `Content-Security-Policy`, and `X-Frame-Options`.
4. **Dependency Patching:** Upgrade underlying packages and base container images to non-vulnerable release tags.
"""

    elif "code" in msg_lower or "example" in msg_lower or "snippet" in msg_lower:
        return f"""### 💻 Secure Code Example (FastAPI / Python)

Here is a secure implementation pattern resolving **{ctx_title}**:

```python
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

@router.get("/api/v1/resource/{{resource_id}}")
async def get_secure_resource(
    resource_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Enforce Tenant Isolation & Object-Level Authorization
    stmt = select(Resource).where(
        Resource.id == resource_id,
        Resource.user_id == current_user.id  # Critical Access Ownership Check
    )
    result = await db.execute(stmt)
    resource = result.scalars().first()
    
    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource not found or access denied."
        )
        
    return resource
```
"""

    elif "impact" in msg_lower or "business" in msg_lower or "risk" in msg_lower:
        return f"""### 📉 Business & Risk Impact Analysis

For **{ctx_title}**:
* **Financial Risk:** Potential regulatory penalties under GDPR, CCPA, or PCI-DSS compliance frameworks due to unauthorized data exposure.
* **Reputational Risk:** Loss of customer trust and brand credibility following public disclosure or security incident notifications.
* **Operational Impact:** Forced emergency patch cycles, service downtime, and incident response overhead.
"""

    elif "owasp" in msg_lower or "category" in msg_lower:
        return f"""### 📊 OWASP Top 10 2021 Standard Mapping

**Category:** `A01:2021 - Broken Access Control` (or `A05:2021 - Security Misconfiguration`)

* **OWASP ID:** A01:2021
* **Description:** Failures in access control enforcement allow unauthorized operators to act outside their intended permissions.
* **Common Weakness Enumeration (CWE):** CWE-284, CWE-639 (BOLA/IDOR).
"""

    else:
        return f"""### 🤖 AutoPentest AI Security Copilot

I have analyzed your query regarding **{ctx_title}** on `{ctx_url}`.

**Key Assistance Options:**
* Ask **"How can I fix it?"** for step-by-step remediation instructions.
* Ask **"Show secure code examples"** for hardened FastAPI/Python code snippets.
* Ask **"What is the business impact?"** for risk analysis.
* Ask **"Which OWASP category does this belong to?"** for compliance mapping.
"""


def process_copilot_chat(
    user_message: str,
    context: Optional[Dict[str, Any]] = None,
    history: Optional[List[Dict[str, Any]]] = None
) -> str:
    """
    Query Google Gemini API for real-time AI Security Copilot responses,
    falling back to specialized DevSecOps knowledge engine if offline.
    """
    if GEMINI_API_KEY:
        try:
            ctx_info = f"Context: {json.dumps(context)}" if context else "Context: General Cybersecurity Question"
            prompt_text = f"""
You are AutoPentest AI Security Copilot, a Senior Cybersecurity Architect, DevSecOps Expert, and Penetration Tester.
Provide a clear, helpful, formatted Markdown response to the operator's query.

{ctx_info}

User Question: {user_message}
"""
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
            payload = {
                "contents": [{"parts": [{"text": prompt_text}]}],
                "generationConfig": {"temperature": 0.3}
            }

            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )

            with urllib.request.urlopen(req, timeout=8) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                return res_data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            print(f"Gemini Copilot API error fallback: {e}")

    return generate_fallback_copilot_reply(user_message, context)
