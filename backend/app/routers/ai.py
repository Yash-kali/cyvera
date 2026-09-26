from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db
from app.models import User, Finding, AIExplanation
from app.schemas import AIExplanationRequest, AIExplanationResponse
from app.auth import get_current_user
from app.services.ai_advisor import explain_vulnerability_with_ai

router = APIRouter(prefix="/api/v1/ai", tags=["Gemini Security Advisor"])


@router.post("/analyze/{finding_id}", response_model=AIExplanationResponse, status_code=status.HTTP_201_CREATED)
@router.post("/explain-vulnerability", response_model=AIExplanationResponse, status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def analyze_finding_with_ai(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    POST /api/v1/ai/analyze/{finding_id}
    Generates 7-section AI vulnerability analysis via Google Gemini API:
    1. Executive Summary
    2. Technical Explanation
    3. Business Impact
    4. Attack Scenario
    5. Remediation Steps
    6. Secure Coding Recommendations
    7. OWASP Mapping
    
    Stores result in database.
    """
    stmt = select(Finding).where(Finding.id == finding_id, Finding.user_id == current_user.id)
    result = await db.execute(stmt)
    finding = result.scalars().first()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding #{finding_id} not found or access denied."
        )

    # Check if AI explanation already exists in database storage
    stmt_exp = select(AIExplanation).where(AIExplanation.finding_id == finding.id, AIExplanation.user_id == current_user.id)
    res_exp = await db.execute(stmt_exp)
    existing = res_exp.scalars().first()

    if existing:
        return existing

    # Invoke Gemini AI Advisor Engine
    ai_out = explain_vulnerability_with_ai(
        title=finding.title,
        description=finding.description,
        cve_id=finding.cve_id or "SECURITY-FINDING",
        affected_url=finding.affected_url
    )

    ai_entry = AIExplanation(
        user_id=current_user.id,
        finding_id=finding.id,
        executive_summary=ai_out["executive_summary"],
        technical_description=ai_out["technical_explanation"],
        business_impact=ai_out["business_impact"],
        attack_scenario=ai_out["attack_scenario"],
        remediation_guidance=ai_out["remediation_steps"],
        secure_coding_recommendations=ai_out["secure_coding_recommendations"],
        owasp_mapping=ai_out["owasp_mapping"]
    )

    db.add(ai_entry)
    await db.commit()
    await db.refresh(ai_entry)

    return ai_entry


@router.get("/result/{finding_id}", response_model=AIExplanationResponse)
async def get_stored_ai_explanation(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    GET /api/v1/ai/result/{finding_id}
    Retrieves stored AI analysis result for a specific vulnerability finding ID.
    Enforces user isolation.
    """
    # Verify finding exists and belongs to current user
    finding_stmt = select(Finding).where(Finding.id == finding_id, Finding.user_id == current_user.id)
    finding_res = await db.execute(finding_stmt)
    finding = finding_res.scalars().first()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding #{finding_id} not found or access denied."
        )

    stmt = select(AIExplanation).where(AIExplanation.finding_id == finding_id, AIExplanation.user_id == current_user.id)
    result = await db.execute(stmt)
    exp = result.scalars().first()

    if not exp:

        ai_out = explain_vulnerability_with_ai(
            title=finding.title,
            description=finding.description,
            cve_id=finding.cve_id or "SECURITY-FINDING",
            affected_url=finding.affected_url
        )

        exp = AIExplanation(
            user_id=current_user.id,
            finding_id=finding.id,
            executive_summary=ai_out["executive_summary"],
            technical_description=ai_out["technical_explanation"],
            business_impact=ai_out["business_impact"],
            attack_scenario=ai_out["attack_scenario"],
            remediation_guidance=ai_out["remediation_steps"],
            secure_coding_recommendations=ai_out["secure_coding_recommendations"],
            owasp_mapping=ai_out["owasp_mapping"]
        )
        db.add(exp)
        await db.commit()
        await db.refresh(exp)

    return exp
