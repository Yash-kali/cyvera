import asyncio
import os
import sys
import hashlib
import io
from pypdf import PdfReader

backend_path = os.path.abspath('backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app.database import AsyncSessionLocal
from sqlalchemy import select
from app.models import Scan, Finding, ReconResult, AttackSurfaceAsset, AIExplanation
from app.services.security_score import calculate_security_score
from app.services.owasp_mapper import calculate_owasp_stats
from app.services.pdf_generator import generate_security_pdf_report

async def test_scan_22_pdf():
    async with AsyncSessionLocal() as session:
        scan = (await session.execute(select(Scan).where(Scan.id == 22))).scalars().first()
        if not scan:
            print("Scan 22 not found")
            return
        
        findings = (await session.execute(select(Finding).where(Finding.scan_id == 22))).scalars().all()
        recon = (await session.execute(select(ReconResult).where(ReconResult.scan_id == 22))).scalars().first()
        assets = (await session.execute(select(AttackSurfaceAsset).where(AttackSurfaceAsset.scan_id == 22))).scalars().all()
        ai_explanations = (await session.execute(select(AIExplanation).where(AIExplanation.finding_id.in_([f.id for f in findings])))).scalars().all() if findings else []
        
        print(f"Raw findings in DB for Scan 22: {len(findings)}")
        
        score_data = calculate_security_score(scan.id, scan.target_url, findings, recon)
        print(f"Calculated Score: {score_data.get('score')}, Grade: {score_data.get('grade')}, Risk: {score_data.get('risk_level')}")
        print(f"Deductions breakdown: {score_data.get('deductions')}")
        
        owasp_stats = calculate_owasp_stats(scan.id, findings)
        print(f"OWASP Mapped Total: {owasp_stats.get('total_mapped_findings')}")
        print(f"OWASP counts: {owasp_stats.get('category_counts')}")
        
        pdf_bytes, page_count = generate_security_pdf_report(
            user_name="admin",
            target_url=scan.target_url,
            scan_id=scan.id,
            scan_type="Quick",
            ip_address=recon.ip_address if recon else None,
            findings=findings,
            recon_result=recon,
            score_data=score_data,
            owasp_stats=owasp_stats,
            ai_explanations=ai_explanations,
            attack_surface_assets=assets
        )
        
        print(f"Generated PDF Page Count: {page_count}")
        print(f"Generated PDF Size: {len(pdf_bytes)} bytes")
        sha = hashlib.sha256(pdf_bytes).hexdigest()
        print(f"SHA-256: {sha}")
        
        # Save artifact for inspection
        out_path = os.path.abspath("AutoPentest_AI_Quick_Report_22_Remediated.pdf")
        with open(out_path, "wb") as f:
            f.write(pdf_bytes)
        print(f"Saved artifact to: {out_path}")

        reader = PdfReader(io.BytesIO(pdf_bytes))
        full_text = ""
        for idx, page in enumerate(reader.pages):
            txt = page.extract_text() or ""
            full_text += f"--- Page {idx+1} ---\n" + txt + "\n"
            
        print(f"Contains literal '<i>Header not set</i>': {'<i>Header not set</i>' in full_text}")
        print(f"Contains '&lt;i&gt;': {'&lt;i&gt;' in full_text}")
        print(f"Contains 'Header not set': {'Header not set' in full_text}")
        print(f"Contains FINDING-001: {'FINDING-001' in full_text}")
        print(f"Contains FINDING-004: {'FINDING-004' in full_text}")
        print(f"Contains FINDING-005: {'FINDING-005' in full_text}")
        print(f"Contains FINDING-010: {'FINDING-010' in full_text}")
        print(f"Contains FINDING-064: {'FINDING-064' in full_text}")
        print(f"Contains hardcoded '0 (8 Obs)': {'0 (8 Obs)' in full_text}")
        print(f"Contains WATERMARK: {'CONFIDENTIAL ASSESSMENT' in full_text or 'WATERMARK' in full_text}")

if __name__ == "__main__":
    asyncio.run(test_scan_22_pdf())
