import sys, os
sys.path.insert(0, os.path.abspath('backend'))
import asyncio
from app.database import AsyncSessionLocal
from app.models import Scan, ReconResult, AttackSurfaceAsset, Finding, Report
from app.services.security_score import calculate_security_score
from app.services.pdf_generator import generate_security_pdf_report
from sqlalchemy import select, delete

async def update_report(scan_id):
    async with AsyncSessionLocal() as session:
        res = await session.execute(select(Scan).filter(Scan.id == scan_id))
        scan = res.scalars().first()
        res_r = await session.execute(select(ReconResult).filter(ReconResult.scan_id == scan_id))
        recon = res_r.scalars().first()
        res_f = await session.execute(select(Finding).filter(Finding.scan_id == scan_id))
        findings = res_f.scalars().all()
        res_a = await session.execute(select(AttackSurfaceAsset).filter(AttackSurfaceAsset.scan_id == scan_id))
        assets = res_a.scalars().all()

        score_data = calculate_security_score(scan.id, scan.target_url, findings, recon)
        pdf_bytes, pages = generate_security_pdf_report(
            user_name="admin",
            target_url=scan.target_url,
            scan_id=scan.id,
            scan_type=scan.scan_type or "Standard",
            ip_address=recon.ip_address if recon else None,
            findings=findings,
            recon_result=recon,
            score_data=score_data,
            attack_surface_assets=assets
        )
        profile_letter = (scan.scan_type or "Standard")[:1].upper()
        report_id_str = f"REP-20260925-{scan.id:04d}-{profile_letter}"
        await session.execute(delete(Report).where(Report.scan_id == scan_id))
        rep = Report(
            user_id=scan.user_id,
            scan_id=scan.id,
            report_id_str=report_id_str,
            report_type=scan.scan_type.capitalize() if scan.scan_type else "Standard",
            title=f"Standard Vulnerability Audit Report #{scan.id}",
            target_url=scan.target_url,
            pages=pages,
            pdf_bytes=pdf_bytes
        )
        session.add(rep)
        await session.commit()
        score_val = score_data['score']
        print(f"Updated Report #{scan_id}: {pages} pages, score={score_val}")

async def main():
    await update_report(20)
    await update_report(21)

asyncio.run(main())
