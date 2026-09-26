import os
import sys
import pypdf

sys.path.insert(0, os.path.join(os.getcwd(), 'backend'))

import asyncio
from app.database import AsyncSessionLocal
from app.models import Scan, ReconResult, AttackSurfaceAsset, Finding
from app.services.security_score import calculate_security_score
from app.services.pdf_generator import generate_security_pdf_report
from sqlalchemy import select

async def main():
    async with AsyncSessionLocal() as db:
        res20 = await db.execute(select(Scan).filter(Scan.id == 20))
        s20 = res20.scalars().first()
        res_r20 = await db.execute(select(ReconResult).filter(ReconResult.scan_id == 20))
        r20 = res_r20.scalars().first()
        res_f20 = await db.execute(select(Finding).filter(Finding.scan_id == 20))
        f20 = res_f20.scalars().all()
        res_a20 = await db.execute(select(AttackSurfaceAsset).filter(AttackSurfaceAsset.scan_id == 20))
        a20 = res_a20.scalars().all()
        sc20 = calculate_security_score(s20.id, s20.target_url, f20, r20)

        pdf20, p20 = generate_security_pdf_report(
            user_name="Security Auditor",
            target_url=s20.target_url,
            scan_id=s20.id,
            scan_type=s20.scan_type or "Standard",
            ip_address=r20.ip_address if r20 else None,
            findings=f20,
            recon_result=r20,
            score_data=sc20,
            attack_surface_assets=a20
        )
        with open('scratch/test_report_20.pdf', 'wb') as f:
            f.write(pdf20)

        res21 = await db.execute(select(Scan).filter(Scan.id == 21))
        s21 = res21.scalars().first()
        res_r21 = await db.execute(select(ReconResult).filter(ReconResult.scan_id == 21))
        r21 = res_r21.scalars().first()
        res_f21 = await db.execute(select(Finding).filter(Finding.scan_id == 21))
        f21 = res_f21.scalars().all()
        res_a21 = await db.execute(select(AttackSurfaceAsset).filter(AttackSurfaceAsset.scan_id == 21))
        a21 = res_a21.scalars().all()
        sc21 = calculate_security_score(s21.id, s21.target_url, f21, r21)

        pdf21, p21 = generate_security_pdf_report(
            user_name="Security Auditor",
            target_url=s21.target_url,
            scan_id=s21.id,
            scan_type=s21.scan_type or "Standard",
            ip_address=r21.ip_address if r21 else None,
            findings=f21,
            recon_result=r21,
            score_data=sc21,
            attack_surface_assets=a21
        )
        with open('scratch/test_report_21.pdf', 'wb') as f:
            f.write(pdf21)

        return s20, sc20, a20, p20, s21, sc21, a21, p21

s20, sc20, a20, p20, s21, sc21, a21, p21 = asyncio.run(main())

reader20 = pypdf.PdfReader('scratch/test_report_20.pdf')
reader21 = pypdf.PdfReader('scratch/test_report_21.pdf')

print("Scan 20 (Portfolio):")
print(f"  Target: {s20.target_url}")
print(f"  Score: {sc20['score']} ({sc20['grade']}, {sc20['risk_level']})")
print(f"  Findings: {sc20['confirmed_findings_count']}, Observations: {sc20['observations_count']}")
print(f"  Assets: {len(a20)}")
print(f"  PDF Pages: {len(reader20.pages)}")

print("\nScan 21 (Netmaxin):")
print(f"  Target: {s21.target_url}")
print(f"  Score: {sc21['score']} ({sc21['grade']}, {sc21['risk_level']})")
print(f"  Findings: {sc21['confirmed_findings_count']}, Observations: {sc21['observations_count']}")
print(f"  Assets: {len(a21)}")
print(f"  PDF Pages: {len(reader21.pages)}")

# Check text in PDFs
text20 = "\n".join([p.extract_text() for p in reader20.pages])
text21 = "\n".join([p.extract_text() for p in reader21.pages])

print("\nVerifications:")
print(f"  Scan 20 has watermark text: {'CONFIDENTIAL SECURITY AUDIT' in text20.upper() and 'watermark' in text20.lower()}")
print(f"  Scan 21 Netmaxin IPv6 correctly labeled: {'IPv6 Addresses' in text21 and '2a02:4780' in text21}")
print(f"  Scan 21 has no 'Primary IPv4 Address: 2a02': {'Primary IPv4 Address' not in text21}")
print(f"  Scan 20 has OWASP section: {'OWASP' in text20}")
print(f"  Scan 21 has OWASP section: {'OWASP' in text21}")
print(f"  Scan 20 has dynamic TOC: {'TABLE OF CONTENTS' in text20}")
print(f"  Scan 21 has dynamic TOC: {'TABLE OF CONTENTS' in text21}")
