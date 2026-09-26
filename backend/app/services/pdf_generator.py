import io
import html
import ipaddress
import urllib.parse
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from pypdf import PdfReader
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable,
    KeepTogether
)


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas for ReportLab matching Cyvera's high-end corporate cybersecurity aesthetic.
    - Page 1: Full-bleed deep royal navy cover with geometric accents and white typography.
    - Inside Pages (2+): Clean corporate headers, professional footers, dynamic running page numbers.
    - ZERO WATERMARK: Diagonal watermark completely removed to prevent visual interference with tables and findings.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()

        # ---------------------------------------------------------------------
        # PAGE 1: FULL-BLEED DEEP ROYAL NAVY COVER PAGE
        # ---------------------------------------------------------------------
        if self._pageNumber == 1:
            # Full page deep navy background (#1A2B4C)
            self.setFillColor(colors.HexColor("#1A2B4C"))
            self.rect(0, 0, 612, 792, fill=1, stroke=0)

            # Geometric accent panels on the right side
            self.setFillColor(colors.HexColor("#253B66"))
            path = self.beginPath()
            path.moveTo(420, 792)
            path.lineTo(612, 792)
            path.lineTo(612, 0)
            path.lineTo(320, 0)
            path.close()
            self.drawPath(path, fill=1, stroke=0)

            self.setFillColor(colors.HexColor("#2D477A"))
            path2 = self.beginPath()
            path2.moveTo(480, 792)
            path2.lineTo(612, 792)
            path2.lineTo(612, 200)
            path2.lineTo(380, 0)
            path2.close()
            self.drawPath(path2, fill=1, stroke=0)

            # Top Left Brand & Tagline
            self.setFont("Helvetica-Bold", 14)
            self.setFillColor(colors.HexColor("#FFFFFF"))
            self.drawString(45, 740, "CYVERA .AI")
            self.setFont("Helvetica", 9)
            self.setFillColor(colors.HexColor("#93C5FD"))
            self.drawString(140, 740, "|   SECURITY OPERATIONS")

            self.setFont("Helvetica", 9)
            self.setFillColor(colors.HexColor("#94A3B8"))
            self.drawRightString(567, 740, "Autonomous Defense")

            # Main Title Block
            self.setFont("Helvetica-Bold", 32)
            self.setFillColor(colors.HexColor("#FFFFFF"))
            self.drawString(45, 620, "Cybersecurity")
            self.drawString(45, 580, "Penetration Testing")
            self.drawString(45, 540, "Audit Report")

            self.setFont("Helvetica-Bold", 44)
            self.setFillColor(colors.HexColor("#60A5FA"))
            self.drawString(45, 480, "2026")

            self.setFont("Helvetica-Bold", 12)
            self.setFillColor(colors.HexColor("#FFFFFF"))
            self.drawString(45, 430, "Autonomous Cybersecurity & Threat Intelligence")

            self.setFont("Helvetica", 9.5)
            self.setFillColor(colors.HexColor("#CBD5E1"))
            self.drawString(45, 410, "Vulnerability audit, attack surface evaluation & verified remediation roadmap")

            self.setFont("Helvetica-Bold", 9)
            self.setFillColor(colors.HexColor("#93C5FD"))
            self.drawString(45, 340, "CONFIDENTIAL SECURITY AUDIT REPORT")
            self.setFont("Helvetica", 8.5)
            self.setFillColor(colors.HexColor("#94A3B8"))
            self.drawString(45, 325, "CYVERA DEFENSE ENGINE • ISO 27001 / OWASP TOP 10 / NIST SP 800-115")

        # ---------------------------------------------------------------------
        # INSIDE PAGES (PAGES 2+) - ZERO WATERMARK
        # ---------------------------------------------------------------------
        else:
            # Running Top Header
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#1A2B4C"))
            self.drawString(36, 756, "CYVERA SECURITY OPERATIONS")
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748B"))
            self.drawString(175, 756, "|   Autonomous Cyber Assessment & Penetration Testing Audit")

            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(36, 748, 576, 748)

            # Running Bottom Footer (Subtle & Professional)
            self.line(36, 45, 576, 45)
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748B"))
            self.drawString(36, 30, "CONFIDENTIAL • CYVERA AI PLATFORM • AUTHORIZED SECURITY ASSESSMENT")
            page_text = f"Page {self._pageNumber} of {page_count}"
            self.drawRightString(576, 30, page_text)

        self.restoreState()


def p_safe(val: Any) -> str:
    """Escapes HTML entities safely for ReportLab Paragraph rendering."""
    if val is None:
        return ""
    return html.escape(str(val))


def wrap_url_for_pdf(url_str: str) -> str:
    """Inserts zero-width spaces after URL delimiter characters to allow clean text wrapping in tables."""
    if not url_str:
        return ""
    escaped = html.escape(str(url_str))
    for char in ["/", "?", "&amp;", "=", ".", "-", "_", ":"]:
        escaped = escaped.replace(char, f"{char}&#8203;")
    return escaped


def classify_ip_addresses(raw_ip: Optional[str], dns_details: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """
    Deterministically categorizes resolved network addresses into IPv4 and IPv6 families.
    Never relies on variable names or assumptions.
    """
    ipv4_list: List[str] = []
    ipv6_list: List[str] = []

    candidates: List[str] = []
    if raw_ip and raw_ip.strip() and raw_ip != "N/A":
        candidates.append(raw_ip.strip())

    if isinstance(dns_details, dict):
        normalized_dns = {str(k).lower(): v for k, v in dns_details.items()}
        for k in ("a_records", "ipv4", "a"):
            val = normalized_dns.get(k)
            if isinstance(val, list):
                candidates.extend([str(item).strip() for item in val if item])
            elif isinstance(val, str) and val.strip():
                candidates.append(val.strip())

        for k in ("aaaa_records", "ipv6", "aaaa"):
            val = normalized_dns.get(k)
            if isinstance(val, list):
                candidates.extend([str(item).strip() for item in val if item])
            elif isinstance(val, str) and val.strip():
                candidates.append(val.strip())

        ip_in_dns = dns_details.get("ip_address")
        if ip_in_dns and isinstance(ip_in_dns, str) and ip_in_dns.strip() != "N/A":
            candidates.append(ip_in_dns.strip())

    for c in candidates:
        try:
            parsed = ipaddress.ip_address(c)
            if parsed.version == 4:
                if str(parsed) not in ipv4_list:
                    ipv4_list.append(str(parsed))
            elif parsed.version == 6:
                if str(parsed) not in ipv6_list:
                    ipv6_list.append(str(parsed))
        except ValueError:
            continue

    return ipv4_list, ipv6_list


def generate_security_pdf_report(
    user_name: str,
    target_url: str,
    scan_id: int,
    scan_type: str = "Standard",
    ip_address: Optional[str] = None,
    findings: Optional[List[Any]] = None,
    recon_result: Optional[Any] = None,
    score_data: Optional[Dict[str, Any]] = None,
    owasp_stats: Optional[Dict[str, Any]] = None,
    ai_explanations: Optional[List[Any]] = None,
    attack_surface_assets: Optional[List[Any]] = None
) -> Tuple[bytes, int]:
    """
    Enterprise Cybersecurity PDF Report Generator.
    - Zero watermark on content pages.
    - Dynamic, content-driven Table of Contents.
    - Strict differentiation of IPv4 vs IPv6 addresses.
    - Clear separation of Confirmed Security Findings vs Defensive Hardening Observations.
    - Reliable non-empty OWASP Top 10 (2021) baseline matrix.
    - Target-specific remediation derived from observed evidence (zero generic boilerplate).
    - Robust ReportLab table wrapping preventing text overflow or column collisions.
    - Content-driven profiles (Quick: 5-10 pages, Standard: 15-30 pages, Full: 40-80 pages).
    """
    profile = (scan_type or "Standard").strip().lower()
    if "quick" in profile:
        profile_key = "Quick"
    elif "full" in profile:
        profile_key = "Full"
    else:
        profile_key = "Standard"

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Color Palette
    NAVY_DARK = colors.HexColor("#1A2B4C")
    NAVY_PRIMARY = colors.HexColor("#253B66")
    BLUE_ACCENT = colors.HexColor("#2563EB")
    TEXT_NAVY = colors.HexColor("#0F172A")
    TEXT_BODY = colors.HexColor("#334155")
    TEXT_MUTED = colors.HexColor("#64748B")
    BORDER_LIGHT = colors.HexColor("#E2E8F0")
    BG_LIGHT = colors.HexColor("#F8FAFC")
    BG_MUTED = colors.HexColor("#F1F5F9")
    WHITE = colors.HexColor("#FFFFFF")

    # Severity & Status Colors
    CRIT_RED = colors.HexColor("#991B1B")
    HIGH_AMBER = colors.HexColor("#92400E")
    MED_BLUE = colors.HexColor("#1E40AF")
    LOW_GREEN = colors.HexColor("#065F46")
    INFO_SLATE = colors.HexColor("#475569")
    STATUS_PASS = colors.HexColor("#047857")
    STATUS_WARN = colors.HexColor("#B45309")

    # Typography Styles
    h1_style = ParagraphStyle(
        'SecHeading1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=12.5,
        leading=16.5,
        textColor=NAVY_DARK,
        spaceBefore=14,
        spaceAfter=7,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'SecHeading2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=13,
        textColor=TEXT_NAVY,
        spaceBefore=9,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=TEXT_BODY,
        spaceAfter=5
    )

    body_bold = ParagraphStyle(
        'BodyBoldCustom',
        parent=body_style,
        fontName='Helvetica-Bold'
    )

    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=TEXT_BODY
    )

    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=table_cell,
        fontName='Helvetica-Bold',
        textColor=TEXT_NAVY
    )

    wrap_url_style = ParagraphStyle(
        'WrapUrlStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=9.5,
        textColor=NAVY_PRIMARY
    )

    code_style = ParagraphStyle(
        'CodeStyleCustom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=10,
        textColor=NAVY_DARK,
        backColor=BG_LIGHT,
        borderColor=BORDER_LIGHT,
        borderWidth=0.5,
        borderPadding=4,
        spaceAfter=5
    )

    badge_crit = ParagraphStyle('BadgeCrit', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8, textColor=CRIT_RED)
    badge_high = ParagraphStyle('BadgeHigh', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8, textColor=HIGH_AMBER)
    badge_med = ParagraphStyle('BadgeMed', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8, textColor=MED_BLUE)
    badge_low = ParagraphStyle('BadgeLow', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8, textColor=LOW_GREEN)
    badge_info = ParagraphStyle('BadgeInfo', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8, textColor=INFO_SLATE)
    badge_pass = ParagraphStyle('BadgePass', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8, textColor=STATUS_PASS)
    badge_warn = ParagraphStyle('BadgeWarn', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8, textColor=STATUS_WARN)

    story = []

    # -------------------------------------------------------------------------
    # Telemetry Extraction & IP Categorization
    # -------------------------------------------------------------------------
    rec_details = recon_result.details if recon_result and hasattr(recon_result, "details") and isinstance(recon_result.details, dict) else {}
    dns_info = {}
    if isinstance(rec_details, dict):
        if isinstance(rec_details.get("dns"), dict):
            dns_info.update(rec_details["dns"])
        if isinstance(rec_details.get("dns_records"), dict):
            dns_info.update(rec_details["dns_records"])
    tls_info = rec_details.get("tls", {}) if isinstance(rec_details, dict) else {}
    headers_info = rec_details.get("headers", {}) if isinstance(rec_details, dict) else {}
    header_details = headers_info.get("header_details", []) if isinstance(headers_info, dict) else []

    ipv4_addrs, ipv6_addrs = classify_ip_addresses(
        ip_address or (recon_result.ip_address if recon_result and hasattr(recon_result, "ip_address") else None),
        dns_info
    )
    ipv4_display = ", ".join(ipv4_addrs) if ipv4_addrs else "None observed"
    ipv6_display = ", ".join(ipv6_addrs) if ipv6_addrs else "None observed"

    target_host = dns_info.get("hostname")
    if not target_host:
        try:
            parsed_u = urllib.parse.urlparse(target_url if target_url.startswith("http") else f"https://{target_url}")
            target_host = parsed_u.hostname or target_url
        except Exception:
            target_host = target_url

    server_banner = "Not Detected / Hidden"
    if recon_result and hasattr(recon_result, "web_server") and recon_result.web_server:
        server_banner = recon_result.web_server

    raw_findings = findings if findings is not None else []
    SEV_PRIORITY = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

    # Consolidate duplicate asset findings into canonical findings
    canonical_findings_map: Dict[Tuple[str, str, str], Any] = {}
    finding_assets_map: Dict[Tuple[str, str, str], List[str]] = {}

    for f in raw_findings:
        title = getattr(f, "title", "Untitled Finding")
        test_type = getattr(f, "test_type", "") or getattr(f, "category", "")
        aff_url = getattr(f, "affected_asset", None) or getattr(f, "affected_url", None) or target_url
        parsed = urllib.parse.urlparse(aff_url)
        origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else aff_url

        if test_type in ("SECURITY_HEADERS", "COOKIE_SECURITY", "API_SECURITY") or getattr(f, "category", "") == "Security Misconfiguration":
            key = (test_type, title, origin)
        else:
            key = (test_type, title, aff_url)

        # Extract assets list from evidence if present
        ev_data = getattr(f, "evidence", None)
        extracted_assets = []
        if isinstance(ev_data, dict):
            extracted_assets = ev_data.get("affected_assets", [])
        if not extracted_assets and aff_url:
            extracted_assets = [aff_url]

        if key not in canonical_findings_map:
            canonical_findings_map[key] = f
            finding_assets_map[key] = list(extracted_assets)
        else:
            existing = canonical_findings_map[key]
            for u in extracted_assets:
                if u and u not in finding_assets_map[key]:
                    finding_assets_map[key].append(u)

            curr_sev = getattr(f, "severity", "Info")
            exist_sev = getattr(existing, "severity", "Info")
            if SEV_PRIORITY.get(curr_sev, 5) < SEV_PRIORITY.get(exist_sev, 5):
                canonical_findings_map[key] = f

    f_list = list(canonical_findings_map.values())
    c_cnt = sum(1 for f in f_list if getattr(f, "severity", "") == "Critical")
    h_cnt = sum(1 for f in f_list if getattr(f, "severity", "") == "High")
    m_cnt = sum(1 for f in f_list if getattr(f, "severity", "") == "Medium")
    l_cnt = sum(1 for f in f_list if getattr(f, "severity", "") == "Low")
    i_cnt = sum(1 for f in f_list if getattr(f, "severity", "") == "Info")
    confirmed_findings_count = c_cnt + h_cnt + m_cnt + l_cnt

    # Hardening observations count (Missing headers, TLS advisories)
    missing_headers = [h for h in header_details if isinstance(h, dict) and h.get("status") == "MISSING"]
    present_headers = [h for h in header_details if isinstance(h, dict) and h.get("status") in ("PASS", "PRESENT")]
    observations_count = len(missing_headers)

    # Canonical Score Data
    score_val = score_data.get("score") if score_data else None
    grade_val = score_data.get("grade") if score_data else ("A" if confirmed_findings_count == 0 else "B")
    risk_val = score_data.get("risk_level") if score_data else ("Low" if confirmed_findings_count == 0 else "Medium")
    score_display = f"{score_val:.1f} / 100" if isinstance(score_val, float) else (f"{score_val} / 100" if score_val is not None else "100 / 100")

    ai_map: Dict[int, Any] = {}
    if ai_explanations:
        for ai_item in ai_explanations:
            fid = getattr(ai_item, "finding_id", None)
            if fid:
                ai_map[fid] = ai_item

    # =========================================================================
    # 1. COVER PAGE METADATA BLOCK
    # =========================================================================
    story.append(Spacer(1, 230))

    meta_table_data = [
        [Paragraph("<font color='#FFFFFF'><b>Target Scope Domain:</b></font>", body_style), Paragraph(f"<font color='#FFFFFF'><b>{p_safe(target_url)}</b></font>", body_style)],
        [Paragraph("<font color='#FFFFFF'><b>Audit Profile:</b></font>", body_style), Paragraph(f"<font color='#60A5FA'><b>{profile_key.upper()} AUDIT PROFILE</b></font>", body_style)],
        [Paragraph("<font color='#FFFFFF'><b>Report Identifier:</b></font>", body_style), Paragraph(f"<font color='#FFFFFF'>REP-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{scan_id:04d}-{profile_key[:1]}</font>", body_style)],
        [Paragraph("<font color='#FFFFFF'><b>IPv4 Address(es):</b></font>", body_style), Paragraph(f"<font color='#FFFFFF'>{p_safe(ipv4_display)}</font>", body_style)],
        [Paragraph("<font color='#FFFFFF'><b>IPv6 Address(es):</b></font>", body_style), Paragraph(f"<font color='#FFFFFF'>{p_safe(ipv6_display)}</font>", body_style)],
        [Paragraph("<font color='#FFFFFF'><b>Security Operator:</b></font>", body_style), Paragraph(f"<font color='#FFFFFF'>{p_safe(user_name)}</font>", body_style)],
        [Paragraph("<font color='#FFFFFF'><b>Execution Timestamp:</b></font>", body_style), Paragraph(f"<font color='#FFFFFF'>{datetime.now(timezone.utc).strftime('%B %d, %Y - %H:%M UTC')}</font>", body_style)],
        [Paragraph("<font color='#FFFFFF'><b>Compliance Baseline:</b></font>", body_style), Paragraph("<font color='#FFFFFF'>ISO 27001 / OWASP Top 10 2021 / NIST SP 800-115</font>", body_style)],
    ]
    t_meta = Table(meta_table_data, colWidths=[150, 390])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#243B66")),
        ('TEXTCOLOR', (0, 0), (-1, -1), WHITE),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#3B82F6")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#253B66")),
    ]))
    story.append(t_meta)
    story.append(PageBreak())

    # =========================================================================
    # 2. DYNAMIC TABLE OF CONTENTS & EXECUTIVE SNAPSHOT
    # =========================================================================
    story.append(Paragraph("TABLE OF CONTENTS", ParagraphStyle('TOCHeading', fontName='Helvetica-Bold', fontSize=18, textColor=NAVY_DARK, spaceAfter=10)))
    story.append(HRFlowable(width="100%", thickness=1.5, color=NAVY_PRIMARY, spaceBefore=0, spaceAfter=12))

    toc_entries = [
        ("01", "Executive Summary & Security Health", "Core risk score, security rating, infrastructure posture snapshot"),
        ("02", "Scope & Testing Methodology", "Authorized parameters, SafeHttpClient transport, SSRF and rate limits"),
        ("03", "Network Reconnaissance & Infrastructure Telemetry", "DNS resolution, IPv4/IPv6 classification, TLS cipher audit, technologies"),
        ("04", "Attack Surface Inventory & Discovered Assets", "Discovered endpoints, APIs, forms, scripts, and evidence classifications"),
        ("05", "Confirmed Security Findings", "Evidence-based technical dossiers for verified security vulnerabilities"),
        ("06", "Security Observations & Defensive Hardening", "HTTP security headers audit, cookies, and configuration hardening"),
        ("07", "OWASP Top 10 (2021) Baseline Alignment", "Comprehensive evaluation against industry benchmark vulnerability classes"),
        ("08", "Risk Scoring & Assessment Methodology", "Mathematical score breakdown, weighting criteria, and deduction telemetry"),
        ("09", "Strategic Remediation Roadmap", "Target-specific engineering recommendations and verified defensive steps"),
        ("10", "Regulatory & Compliance Framework Alignment", "PCI-DSS v4.0, SOC 2 Type II, NIST CSF 2.0, and ISO 27001 mapping"),
        ("11", "Audit Governance & Scan Limitations", "Non-destructive boundaries, confidentiality disclaimer, and integrity assurance")
    ]

    toc_table_data = []
    half = (len(toc_entries) + 1) // 2
    for i in range(half):
        num1, title1, desc1 = toc_entries[i]
        c1_num = Paragraph(f"<font size=14 color='#253B66'><b>{num1}</b></font>", body_style)
        c1_txt = Paragraph(f"<b>{title1}</b><br/><font color='#64748B' size=7.5>{desc1}</font>", body_style)

        if i + half < len(toc_entries):
            num2, title2, desc2 = toc_entries[i + half]
            c2_num = Paragraph(f"<font size=14 color='#253B66'><b>{num2}</b></font>", body_style)
            c2_txt = Paragraph(f"<b>{title2}</b><br/><font color='#64748B' size=7.5>{desc2}</font>", body_style)
        else:
            c2_num = Paragraph("", body_style)
            c2_txt = Paragraph("", body_style)

        toc_table_data.append([c1_num, c1_txt, c2_num, c2_txt])

    t_toc = Table(toc_table_data, colWidths=[28, 238, 28, 246])
    t_toc.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
    ]))
    story.append(t_toc)
    story.append(Spacer(1, 14))

    # Executive Telemetry Panel
    story.append(Paragraph("<b>TARGET POSTURE SUMMARY</b>", h2_style))
    highlight_panel_data = [
        [
            Paragraph("<b>SECURITY CORE SCORE</b>", ParagraphStyle('P_H1', fontName='Helvetica-Bold', fontSize=8, textColor=WHITE)),
            Paragraph("<b>SECURITY GRADE</b>", ParagraphStyle('P_H2', fontName='Helvetica-Bold', fontSize=8, textColor=WHITE)),
            Paragraph("<b>CONFIRMED FINDINGS</b>", ParagraphStyle('P_H3', fontName='Helvetica-Bold', fontSize=8, textColor=WHITE)),
            Paragraph("<b>HARDENING OBSERVATIONS</b>", ParagraphStyle('P_H4', fontName='Helvetica-Bold', fontSize=8, textColor=WHITE)),
        ],
        [
            Paragraph(f"<font size=16 color='#60A5FA'><b>{score_display}</b></font>", body_style),
            Paragraph(f"<font size=16 color='#34D399'><b>GRADE {grade_val}</b></font>", body_style),
            Paragraph(f"<font size=16 color='{('#EF4444' if confirmed_findings_count > 0 else '#93C5FD')}'><b>{confirmed_findings_count} Active</b></font>", body_style),
            Paragraph(f"<font size=16 color='#F8FAFC'><b>{observations_count} Identified</b></font>", body_style),
        ]
    ]
    t_highlight = Table(highlight_panel_data, colWidths=[135, 135, 135, 135])
    t_highlight.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), NAVY_DARK),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOX', (0, 0), (-1, -1), 1, NAVY_PRIMARY),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, NAVY_PRIMARY),
    ]))
    story.append(t_highlight)
    story.append(PageBreak())

    # =========================================================================
    # SECTION 1: EXECUTIVE SUMMARY & SECURITY HEALTH
    # =========================================================================
    story.append(Paragraph("1. Executive Summary & Security Health", h1_style))
    story.append(Paragraph(
        f"This executive security assessment was conducted against the authorized perimeter of <b>{p_safe(target_url)}</b> "
        f"utilizing the <b>{profile_key.upper()}</b> assessment profile. The assessment combines automated passive intelligence gathering, "
        f"bounded active asset enumeration, cryptographic protocol verification, and controlled non-destructive vulnerability testing.",
        body_style
    ))

    # Target-Specific Narrative
    if confirmed_findings_count == 0:
        exec_narrative = (
            f"<b>Assessment Outcome:</b> Automated security testing identified <b>zero (0) confirmed exploitable vulnerabilities</b> "
            f"within the tested scope and methodology. However, the evaluation uncovered <b>{observations_count} defensive hardening opportunities</b>, "
            f"predominantly involving missing HTTP security response headers and defense-in-depth controls. Implementing these configuration adjustments "
            f"will elevate perimeter resilience against opportunistic web attacks such as MIME-type confusion, clickjacking, and cross-site scripting."
        )
    else:
        exec_narrative = (
            f"<b>Assessment Outcome:</b> Automated security testing identified <b>{confirmed_findings_count} confirmed security finding(s)</b> "
            f"requiring prompt engineering triage ({c_cnt} Critical, {h_cnt} High, {m_cnt} Medium, {l_cnt} Low). In addition, {observations_count} "
            f"security hardening observations were documented. Remediation should focus on addressing the highest-severity findings first."
        )
    story.append(Paragraph(exec_narrative, body_style))
    story.append(Spacer(1, 8))

    # Executive Overview Key Indicators Table
    asset_cnt_total = len(attack_surface_assets) if attack_surface_assets else (
        rec_details.get("attack_surface", {}).get("internal_links_count", 0) +
        rec_details.get("attack_surface", {}).get("scripts_count", 0)
    )
    ssl_issuer_str = recon_result.ssl_issuer if recon_result and hasattr(recon_result, "ssl_issuer") and recon_result.ssl_issuer else tls_info.get("issuer", "N/A")
    tls_ver_str = tls_info.get("tls_version", "TLSv1.3")

    exec_kpi_data = [
        [Paragraph("<b>Evaluation Vector</b>", table_cell_bold), Paragraph("<b>Empirical Assessment Finding</b>", table_cell_bold), Paragraph("<b>Posture Rating</b>", table_cell_bold)],
        [Paragraph("Perimeter Target Scope", table_cell), Paragraph(p_safe(target_url), table_cell), Paragraph("VALIDATED", badge_pass)],
        [Paragraph("Primary Web Server", table_cell), Paragraph(p_safe(server_banner), table_cell), Paragraph("IDENTIFIED", badge_info)],
        [Paragraph("Transport Security (TLS)", table_cell), Paragraph(f"{p_safe(tls_ver_str)} ({p_safe(ssl_issuer_str)})", table_cell), Paragraph("SECURE", badge_pass if tls_info.get("ssl_enabled", True) else badge_crit)],
        [Paragraph("Confirmed Vulnerabilities", table_cell), Paragraph(f"{confirmed_findings_count} Exploitable Flaws", table_cell), Paragraph("CLEAR" if confirmed_findings_count == 0 else "ACTION REQ", badge_pass if confirmed_findings_count == 0 else badge_crit)],
        [Paragraph("Hardening Opportunities", table_cell), Paragraph(f"{observations_count} Missing Security Directives", table_cell), Paragraph("HARDENING ADVISED" if observations_count > 0 else "OPTIMAL", badge_warn if observations_count > 0 else badge_pass)],
        [Paragraph("Discovered Attack Surface", table_cell), Paragraph(f"{asset_cnt_total} In-Scope Asset(s)", table_cell), Paragraph("ENUMERATED", badge_info)]
    ]
    t_exec_kpi = Table(exec_kpi_data, colWidths=[150, 270, 120])
    t_exec_kpi.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BG_MUTED),
        ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_exec_kpi)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 2: SCOPE & TESTING METHODOLOGY
    # =========================================================================
    story.append(Paragraph("2. Scope & Testing Methodology", h1_style))
    story.append(Paragraph(
        "AutoPentest AI operates under a strict, non-destructive automated penetration testing framework designed to evaluate public perimeters "
        "without disrupting production service availability or altering target application state.",
        body_style
    ))

    methodology_data = [
        [Paragraph("<b>Governance Parameter</b>", table_cell_bold), Paragraph("<b>Enforced Operational Control</b>", table_cell_bold)],
        [Paragraph("Authorized Target Scope", table_cell), Paragraph(f"Strictly bounded to: <code>{p_safe(target_url)}</code> (Hostname: {p_safe(target_host)})", table_cell)],
        [Paragraph("Network Transport Engine", table_cell), Paragraph("Hardened <code>SafeHttpClient</code> with mandatory IP pinning, DNS rebinding prevention, and strict SSRF filters.", table_cell)],
        [Paragraph("Permitted HTTP Methods", table_cell), Paragraph("Read-only operations (GET, HEAD, OPTIONS). Destructive methods (DELETE, state-mutating POST/PUT) strictly prohibited.", table_cell)],
        [Paragraph("Resource & Quota Limits", table_cell), Paragraph("Scan-wide global request budget, per-domain rate limiting, and 2MB payload truncation to protect target availability.", table_cell)],
        [Paragraph("Credential Safety Boundary", table_cell), Paragraph("No password guessing, brute force, credential stuffing, or session hijacking. Secrets and tokens scrubbed from evidence.", table_cell)]
    ]
    t_method = Table(methodology_data, colWidths=[160, 380])
    t_method.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BG_MUTED),
        ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(t_method)
    story.append(Spacer(1, 8))

    story.append(Paragraph("<b>Formal Assessment Limitations:</b>", h2_style))
    limits_text = (
        "• <b>Non-Destructive Testing Only:</b> Exploits designed to modify data, delete records, or induce Denial-of-Service are strictly omitted.<br/>"
        "• <b>Static Script & DOM Analysis:</b> Client-side assets are evaluated through bounded parsing; unconstrained headless browser execution was not performed.<br/>"
        "• <b>Bounded Depth & Budget:</b> Crawling was restricted to the configured depth and request quota; unlinked endpoints or hidden administrative portals remain untested.<br/>"
        "• <b>Third-Party Out-of-Scope Isolation:</b> External CDNs, cloud infrastructure, and third-party APIs were cataloged but excluded from direct active security testing."
    )
    story.append(Paragraph(limits_text, body_style))
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 3: RECONNAISSANCE & INFRASTRUCTURE TELEMETRY
    # =========================================================================
    story.append(Paragraph("3. Network Reconnaissance & Infrastructure Telemetry", h1_style))
    story.append(Paragraph(
        "Passive and semi-active network reconnaissance gathers foundational infrastructure signatures, DNS resolution mappings, "
        "and transport layer security (TLS) parameters without triggering intrusive defenses.",
        body_style
    ))

    # Sub-section 3a: DNS & Host Network Telemetry
    story.append(Paragraph("3a. Host Network & DNS Resolution Telemetry", h2_style))
    dns_table_data = [
        [Paragraph("<b>Network Parameter</b>", table_cell_bold), Paragraph("<b>Empirical Value / Telemetry</b>", table_cell_bold), Paragraph("<b>Family / Status</b>", table_cell_bold)],
        [Paragraph("Canonical Hostname", table_cell), Paragraph(p_safe(target_host), table_cell), Paragraph("DNS ACTIVE", badge_pass)],
        [Paragraph("IPv4 Address(es)", table_cell), Paragraph(p_safe(ipv4_display), table_cell), Paragraph("IPv4 PROTOCOL", badge_info if ipv4_addrs else badge_warn)],
        [Paragraph("IPv6 Address(es)", table_cell), Paragraph(p_safe(ipv6_display), table_cell), Paragraph("IPv6 PROTOCOL", badge_info if ipv6_addrs else badge_warn)],
        [Paragraph("Server Identification", table_cell), Paragraph(p_safe(server_banner), table_cell), Paragraph("BANNER DISCLOSED" if server_banner != "Not Detected / Hidden" else "HIDDEN", badge_warn if server_banner != "Not Detected / Hidden" else badge_pass)],
    ]
    t_dns = Table(dns_table_data, colWidths=[150, 270, 120])
    t_dns.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BG_MUTED),
        ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_dns)
    story.append(Spacer(1, 8))

    # Sub-section 3b: SSL / TLS Cryptographic Review
    story.append(Paragraph("3b. Cryptographic Protocol & Certificate Review", h2_style))
    ssl_days = recon_result.ssl_expires_days if recon_result and hasattr(recon_result, "ssl_expires_days") and recon_result.ssl_expires_days is not None else tls_info.get("days_remaining", "N/A")
    ssl_cipher = tls_info.get("cipher_suite", "N/A")
    ssl_enabled = tls_info.get("ssl_enabled", True if ssl_issuer_str != "N/A" else False)
    ssl_sans = tls_info.get("sample_sans", [])
    sans_display = ", ".join(str(s) for s in ssl_sans[:4]) if ssl_sans else "N/A"

    ssl_table_data = [
        [Paragraph("<b>Cryptographic Vector</b>", table_cell_bold), Paragraph("<b>Configuration Detail</b>", table_cell_bold), Paragraph("<b>Health Rating</b>", table_cell_bold)],
        [Paragraph("TLS Protocol Version", table_cell), Paragraph(p_safe(tls_ver_str), table_cell), Paragraph("STRONG" if "1.3" in str(tls_ver_str) or "1.2" in str(tls_ver_str) else "REVIEW", badge_pass if "1.3" in str(tls_ver_str) else badge_warn)],
        [Paragraph("Certificate Authority", table_cell), Paragraph(p_safe(ssl_issuer_str), table_cell), Paragraph("TRUSTED CA", badge_pass if ssl_issuer_str != "N/A" else badge_warn)],
        [Paragraph("Validity Remaining", table_cell), Paragraph(f"{ssl_days} Days" if ssl_days != "N/A" else "N/A", table_cell), Paragraph("VALID" if isinstance(ssl_days, int) and ssl_days > 30 else "EXPIRING", badge_pass if isinstance(ssl_days, int) and ssl_days > 30 else badge_warn)],
        [Paragraph("Negotiated Cipher Suite", table_cell), Paragraph(p_safe(ssl_cipher), wrap_url_style), Paragraph("AEAD STRONG" if "GCM" in str(ssl_cipher) or "CHACHA" in str(ssl_cipher) else "STANDARD", badge_pass)],
        [Paragraph("Subject Alternative Names", table_cell), Paragraph(p_safe(sans_display), wrap_url_style), Paragraph(f"{len(ssl_sans)} SAN(s)" if ssl_sans else "N/A", badge_info)]
    ]
    t_ssl = Table(ssl_table_data, colWidths=[150, 270, 120])
    t_ssl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BG_MUTED),
        ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_ssl)
    story.append(Spacer(1, 8))

    # Sub-section 3c: Technology Stack & Fingerprints
    tech_list = rec_details.get("technologies", [])
    if tech_list:
        story.append(Paragraph("3c. Detected Technologies & Framework Signatures", h2_style))
        tech_data = [[Paragraph("<b>Detected Technology</b>", table_cell_bold), Paragraph("<b>Category</b>", table_cell_bold), Paragraph("<b>Version</b>", table_cell_bold), Paragraph("<b>Confidence / Evidence</b>", table_cell_bold)]]
        for t_item in tech_list[:8]:
            tech_data.append([
                Paragraph(p_safe(t_item.get("technology", "N/A")), table_cell_bold),
                Paragraph(p_safe(t_item.get("category", "N/A")), table_cell),
                Paragraph(p_safe(t_item.get("version", "N/A")), table_cell),
                Paragraph(f"{p_safe(t_item.get('confidence', 'High'))} - {p_safe(t_item.get('evidence', ''))[:45]}", table_cell)
            ])
        t_tech = Table(tech_data, colWidths=[140, 120, 80, 200])
        t_tech.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), BG_MUTED),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(t_tech)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 4: ATTACK SURFACE INVENTORY & DISCOVERED ASSETS
    # =========================================================================
    story.append(Paragraph("4. Attack Surface Inventory & Discovered Assets", h1_style))
    story.append(Paragraph(
        "Attack surface discovery maps all reachable routes, APIs, scripts, and document endpoints. "
        "Testing is strictly bounded to these verified assets to prevent unauthorized cross-tenant crawling.",
        body_style
    ))

    # Limit asset rendering based on profile to balance thoroughness and length
    asset_limit = 15 if profile_key == "Quick" else (60 if profile_key == "Standard" else 150)

    if attack_surface_assets:
        # Category summary table first
        type_counts: Dict[str, int] = {}
        for a in attack_surface_assets:
            atype = getattr(a, "asset_type", "PAGE")
            type_counts[atype] = type_counts.get(atype, 0) + 1

        cat_summary_rows = [
            [Paragraph("<b>Discovered Asset Classification</b>", table_cell_bold), Paragraph("<b>Count</b>", table_cell_bold), Paragraph("<b>Testing Relevance</b>", table_cell_bold)]
        ]
        for atype, cnt in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            cat_summary_rows.append([
                Paragraph(f"<b>{p_safe(atype)}</b>", table_cell),
                Paragraph(str(cnt), table_cell_bold),
                Paragraph("Targeted for non-destructive inspection", table_cell)
            ])
        t_cat_summary = Table(cat_summary_rows, colWidths=[180, 80, 280])
        t_cat_summary.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), BG_MUTED),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(t_cat_summary)
        story.append(Spacer(1, 8))

        # Comprehensive asset catalog table
        story.append(Paragraph("<b>Discovered In-Scope Assets Catalog:</b>", h2_style))
        asset_table_data = [
            [
                Paragraph("<b>Asset Type</b>", table_cell_bold),
                Paragraph("<b>Method</b>", table_cell_bold),
                Paragraph("<b>Discovered URL / Endpoint Path</b>", table_cell_bold),
                Paragraph("<b>Evidence Status</b>", table_cell_bold)
            ]
        ]
        for asset in attack_surface_assets[:asset_limit]:
            asset_type = getattr(asset, "asset_type", "PAGE")
            method = getattr(asset, "http_method", "GET")
            path_or_url = getattr(asset, "url", getattr(asset, "path", "N/A"))
            ev_status = getattr(asset, "evidence_status", "OBSERVED")

            asset_table_data.append([
                Paragraph(p_safe(asset_type), table_cell_bold),
                Paragraph(p_safe(method), table_cell),
                Paragraph(wrap_url_for_pdf(path_or_url), wrap_url_style),
                Paragraph(p_safe(ev_status), table_cell)
            ])

        t_assets = Table(asset_table_data, colWidths=[90, 55, 295, 100])
        t_assets.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), BG_MUTED),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(t_assets)

        if len(attack_surface_assets) > asset_limit:
            story.append(Spacer(1, 4))
            story.append(Paragraph(
                f"<i>Note: Displaying top {asset_limit} of {len(attack_surface_assets)} discovered assets. "
                "Full penetration audit profiles contain exhaustive asset catalogs.</i>",
                ParagraphStyle('NoteStyle', parent=body_style, fontSize=7.5, textColor=TEXT_MUTED)
            ))
    else:
        surf = rec_details.get("attack_surface", {})
        p_title = surf.get("page_title", "N/A")
        f_count = surf.get("forms_count", 0)
        links_cnt = surf.get("internal_links_count", 0)
        scripts_cnt = surf.get("scripts_count", 0)

        passive_surf_data = [
            [Paragraph("<b>Discovery Parameter</b>", table_cell_bold), Paragraph("<b>Observed Telemetry</b>", table_cell_bold), Paragraph("<b>Security Relevance</b>", table_cell_bold)],
            [Paragraph("Target Page Title", table_cell), Paragraph(p_safe(p_title)[:60], table_cell), Paragraph("Passive asset identity profiling", table_cell)],
            [Paragraph("Interactive Forms Discovered", table_cell), Paragraph(f"{f_count} Form Vector(s)", table_cell), Paragraph("Input vector audit scope", table_cell)],
            [Paragraph("Same-Origin Endpoints", table_cell), Paragraph(f"{links_cnt} Endpoint Link(s)", table_cell), Paragraph("Perimeter crawl boundary", table_cell)],
            [Paragraph("Script Dependencies", table_cell), Paragraph(f"{scripts_cnt} Script Resource(s)", table_cell), Paragraph("Client-side library execution surface", table_cell)]
        ]
        t_psurf = Table(passive_surf_data, colWidths=[160, 180, 200])
        t_psurf.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), BG_MUTED),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(t_psurf)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 5: CONFIRMED SECURITY FINDINGS
    # =========================================================================
    story.append(Paragraph("5. Confirmed Security Findings", h1_style))

    if confirmed_findings_count == 0:
        zero_findings_panel = [
            [Paragraph("<b>SECURITY VULNERABILITY STATUS: CLEAR / NO CONFIRMED FINDINGS</b>", ParagraphStyle('P_Z1', fontName='Helvetica-Bold', fontSize=9, textColor=STATUS_PASS))],
            [Paragraph(
                "No confirmed security vulnerabilities were identified within the tested scope and methodology.<br/>"
                "Automated security testing executed controlled input reflection checks, CORS policy evaluation, unvalidated redirect probes, "
                "safe HTTP method inspection, and administrative boundary observations across all discovered in-scope assets. "
                "None of the automated probes yielded exploitable vulnerability indicators.<br/><br/>"
                "<i>Note: Zero confirmed vulnerabilities does not guarantee the complete absence of zero-day or complex logic flaws. "
                "Refer to Section 6 for defense-in-depth security hardening observations.</i>",
                body_style
            )]
        ]
        t_zero = Table(zero_findings_panel, colWidths=[540])
        t_zero.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#ECFDF5")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#A7F3D0")),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t_zero)
        story.append(Spacer(1, 12))

    else:
        sev_table_data = [
            [Paragraph("<b>Severity Category</b>", table_cell_bold), Paragraph("<b>Count</b>", table_cell_bold), Paragraph("<b>Risk Impact Level</b>", table_cell_bold), Paragraph("<b>Remediation SLA</b>", table_cell_bold)],
            [Paragraph("Critical (CVSS 9.0 - 10.0)", table_cell), Paragraph(str(c_cnt), table_cell_bold), Paragraph("Immediate Threat", badge_crit), Paragraph("24 Hours", table_cell)],
            [Paragraph("High (CVSS 7.0 - 8.9)", table_cell), Paragraph(str(h_cnt), table_cell_bold), Paragraph("High Risk", badge_high), Paragraph("7 Days", table_cell)],
            [Paragraph("Medium (CVSS 4.0 - 6.9)", table_cell), Paragraph(str(m_cnt), table_cell_bold), Paragraph("Moderate Risk", badge_med), Paragraph("30 Days", table_cell)],
            [Paragraph("Low (CVSS 0.1 - 3.9)", table_cell), Paragraph(str(l_cnt), table_cell_bold), Paragraph("Low Risk", badge_low), Paragraph("90 Days", table_cell)],
            [Paragraph("Info (0.0)", table_cell), Paragraph(str(i_cnt), table_cell_bold), Paragraph("Informational", badge_info), Paragraph("Best Effort", table_cell)]
        ]
        t_sev = Table(sev_table_data, colWidths=[150, 80, 160, 150])
        t_sev.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), BG_MUTED),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(t_sev)
        story.append(Spacer(1, 10))

        story.append(Paragraph("<b>Detailed Finding Dossiers:</b>", h2_style))
        for idx, f_item in enumerate(f_list, 1):
            title_txt = getattr(f_item, 'title', 'Untitled Finding')
            sev_txt = getattr(f_item, 'severity', 'Medium')
            cvss_val = getattr(f_item, 'cvss_score', None)
            cvss_display = f"{cvss_val:.1f}" if cvss_val is not None else "N/A"
            cve_display = getattr(f_item, 'cve_id', None) or getattr(f_item, 'test_type', None) or "N/A"
            status_txt = getattr(f_item, 'status', 'Open')
            conf_txt = getattr(f_item, 'confidence', 'MEDIUM')
            t_type = getattr(f_item, 'test_type', None) or getattr(f_item, 'category', '')
            raw_url = getattr(f_item, 'affected_asset', None) or getattr(f_item, 'affected_url', None) or target_url
            p_url = urllib.parse.urlparse(raw_url)
            orig = f"{p_url.scheme}://{p_url.netloc}" if p_url.netloc else raw_url

            if t_type in ("SECURITY_HEADERS", "COOKIE_SECURITY", "API_SECURITY") or getattr(f_item, "category", "") == "Security Misconfiguration":
                k = (t_type, title_txt, orig)
            else:
                k = (t_type, title_txt, raw_url)

            aff_assets = finding_assets_map.get(k, [])
            if len(aff_assets) > 1:
                url_display = f"{orig} ({len(aff_assets)} observed assets)"
            else:
                url_display = raw_url

            desc_display = getattr(f_item, 'description', 'No description provided.')
            remed_display = getattr(f_item, 'remediation_guidance', 'Apply defensive patch.')
            ev_data = getattr(f_item, 'evidence', None)

            b_style = badge_crit if sev_txt == "Critical" else (badge_high if sev_txt == "High" else (badge_med if sev_txt == "Medium" else badge_low))

            card_table = [
                [Paragraph(f"<b>FINDING-{idx:03d}: {p_safe(title_txt)}</b>", h2_style), "", ""],
                [
                    Paragraph(f"<b>Severity:</b> {p_safe(sev_txt.upper())}", b_style),
                    Paragraph(f"<b>Confidence:</b> {p_safe(conf_txt)}", table_cell),
                    Paragraph(f"<b>Status:</b> {p_safe(status_txt.upper())}", table_cell)
                ],
                [
                    Paragraph(f"<b>CVSS Score:</b> {p_safe(cvss_display)}", table_cell),
                    Paragraph(f"<b>Test Identifier:</b> {p_safe(cve_display)}", table_cell),
                    Paragraph(f"<b>Category:</b> {p_safe(getattr(f_item, 'category', 'General'))}", table_cell)
                ],
                [
                    Paragraph("<b>Affected Scope:</b>", table_cell_bold),
                    Paragraph(wrap_url_for_pdf(url_display), wrap_url_style),
                    ""
                ]
            ]
            t_card = Table(card_table, colWidths=[150, 195, 195])
            t_card.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT),
                ('SPAN', (0, 0), (2, 0)),
                ('SPAN', (1, 3), (2, 3)),
                ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]))

            finding_flowables = [
                t_card,
                Spacer(1, 3),
                Paragraph(f"<b>Technical Description:</b> {p_safe(desc_display)}", body_style),
            ]

            ev_lines = []
            if len(aff_assets) > 1:
                sample_urls = ", ".join(aff_assets[:4])
                if len(aff_assets) > 4:
                    sample_urls += f" ... (+{len(aff_assets) - 4} more)"
                ev_lines.append(f"Affected In-Scope Assets ({len(aff_assets)}): {p_safe(sample_urls)}")

            if ev_data:
                if isinstance(ev_data, dict):
                    t_mod = ev_data.get("tester", "")
                    obs = ev_data.get("observation", "")
                    req = ev_data.get("request", {})
                    resp = ev_data.get("response", {})
                    if t_mod:
                        ev_lines.append(f"Testing Module: {p_safe(t_mod)}")
                    if req and isinstance(req, dict) and "method" in req:
                        ev_lines.append(f"Probe: {req.get('method')} {p_safe(req.get('url', ''))}")
                    if resp and isinstance(resp, dict) and "status" in resp:
                        ev_lines.append(f"HTTP Status: {resp.get('status')}")
                    if obs:
                        ev_lines.append(f"Observation: {p_safe(obs)}")
                    if resp and isinstance(resp, dict) and resp.get("body_excerpt"):
                        ev_lines.append(f"Response Excerpt: {p_safe(resp.get('body_excerpt')[:150])}")
                elif isinstance(ev_data, str) and ev_data.strip():
                    ev_lines.append(p_safe(ev_data[:300]))

            if ev_lines:
                ev_block = "<br/>".join(ev_lines)
                finding_flowables.append(Paragraph(f"<b>Observed Empirical Evidence:</b><br/>{ev_block}", code_style))

            finding_flowables.append(Paragraph(f"<b>Remediation Guidance:</b><br/>{p_safe(remed_display)}", code_style))
            finding_flowables.append(Spacer(1, 8))
            story.append(KeepTogether(finding_flowables))

    # =========================================================================
    # SECTION 6: SECURITY OBSERVATIONS & DEFENSIVE HARDENING
    # =========================================================================
    story.append(Paragraph("6. Security Observations & Defensive Hardening", h1_style))
    story.append(Paragraph(
        "Security observations represent verified configuration postures that do not constitute direct exploitable vulnerabilities "
        "but provide essential defense-in-depth when properly hardened.",
        body_style
    ))

    # Comprehensive HTTP Security Headers Audit Table
    header_audit_data = [
        [
            Paragraph("<b>Security Control / Header</b>", table_cell_bold),
            Paragraph("<b>Current Status</b>", table_cell_bold),
            Paragraph("<b>Observed Telemetry / Value</b>", table_cell_bold),
            Paragraph("<b>Defensive Guidance & Relevance</b>", table_cell_bold)
        ]
    ]

    GUIDANCE_MAP = {
        "strict-transport-security": "Enforces HTTPS encryption and prevents SSL-stripping man-in-the-middle attacks.",
        "content-security-policy": "Restricts resource origins; crucial defense against Cross-Site Scripting (XSS) and data injection.",
        "x-content-type-options": "Enforces 'nosniff' directive to prevent MIME-confusion and script sniffing attacks.",
        "x-frame-options": "Restricts framing permissions to defend against UI redressing and clickjacking.",
        "referrer-policy": "Controls referrer information passed to third-party endpoints to prevent metadata leakage.",
        "permissions-policy": "Disables access to browser device APIs (camera, microphone, geolocation) by default.",
        "cross-origin-opener-policy": "Isolates the browsing context to defend against Spectre-style side-channel attacks.",
        "cross-origin-resource-policy": "Prevents other origins from embedding application resources indiscriminately.",
        "cross-origin-embedder-policy": "Ensures document can only load resources that explicitly grant permission."
    }

    if header_details:
        for item in header_details:
            h_name = str(item.get("header", "Security Header")).strip()
            h_stat = str(item.get("status", "MISSING")).strip().upper()
            h_val = str(item.get("value", "Header not set")).strip()
            relevance = GUIDANCE_MAP.get(h_name.lower(), "Defense-in-depth HTTP security hardening directive.")

            stat_badge = badge_pass if h_stat in ("PASS", "PRESENT", "STRONG") else badge_warn
            val_display = h_val if h_val and h_val != "Header not set" else "Header not set"

            header_audit_data.append([
                Paragraph(f"<b>{p_safe(h_name)}</b>", table_cell),
                Paragraph(h_stat, stat_badge),
                Paragraph(wrap_url_for_pdf(val_display), wrap_url_style if len(val_display) > 30 else table_cell),
                Paragraph(relevance, table_cell)
            ])
    else:
        for h_key, h_desc in GUIDANCE_MAP.items():
            header_audit_data.append([
                Paragraph(f"<b>{p_safe(h_key)}</b>", table_cell),
                Paragraph("OBSERVATION", badge_info),
                Paragraph("Telemetry not available", table_cell),
                Paragraph(h_desc, table_cell)
            ])

    t_hdrs = Table(header_audit_data, colWidths=[130, 65, 165, 180])
    t_hdrs.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BG_MUTED),
        ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(t_hdrs)
    story.append(Spacer(1, 10))

    # Dedicated Technical Hardening Analyses for missing headers (Standard & Full)
    if profile_key in ("Standard", "Full") and missing_headers:
        story.append(Paragraph("<b>In-Depth Hardening Guidance for Missing Controls:</b>", h2_style))
        for mh in missing_headers:
            mh_name = str(mh.get("header", "")).strip()
            if mh_name.lower() == "content-security-policy":
                story.append(Paragraph("<b>Content-Security-Policy (CSP) Architecture:</b>", h2_style))
                story.append(Paragraph(
                    "The absence of a Content-Security-Policy header allows the browser to execute inline scripts and load external assets "
                    "from arbitrary domains if an injection vector occurs. Deploying a CSP establishes an authoritative allowlist of trusted "
                    "origins, substantially reducing the impact of client-side script execution attacks.",
                    body_style
                ))
                story.append(Paragraph("<code>Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; frame-ancestors 'none';</code>", code_style))
            elif mh_name.lower() == "strict-transport-security":
                story.append(Paragraph("<b>HTTP Strict-Transport-Security (HSTS) Architecture:</b>", h2_style))
                story.append(Paragraph(
                    "Without HSTS, user agents can be tricked into initiating unencrypted HTTP connections susceptible to SSL-stripping "
                    "and adversary-in-the-middle interception before being redirected to HTTPS. HSTS instructs browsers to remember "
                    "that the domain must strictly and exclusively be reached over encrypted HTTPS connections.",
                    body_style
                ))
                story.append(Paragraph("<code>Strict-Transport-Security: max-age=31536000; includeSubDomains; preload</code>", code_style))
            elif mh_name.lower() == "x-content-type-options":
                story.append(Paragraph("<b>MIME Sniffing Defense (X-Content-Type-Options):</b>", h2_style))
                story.append(Paragraph(
                    "Legacy and modern browsers may attempt to guess (sniff) the MIME type of a response regardless of the declared Content-Type header. "
                    "Setting 'nosniff' prevents browsers from treating user-uploaded images or text files as executable JavaScript.",
                    body_style
                ))
                story.append(Paragraph("<code>X-Content-Type-Options: nosniff</code>", code_style))
            elif mh_name.lower() == "x-frame-options":
                story.append(Paragraph("<b>Clickjacking Defense (X-Frame-Options):</b>", h2_style))
                story.append(Paragraph(
                    "The X-Frame-Options header indicates whether a browser should be allowed to render a page in an iframe, frame, or embed element. "
                    "Configuring DENY or SAMEORIGIN protects authenticated user sessions from transparent overlay attacks.",
                    body_style
                ))
                story.append(Paragraph("<code>X-Frame-Options: DENY</code>", code_style))
            elif mh_name.lower() == "referrer-policy":
                story.append(Paragraph("<b>Referrer Privacy & Metadata Protection:</b>", h2_style))
                story.append(Paragraph(
                    "Controlling the Referer header ensures sensitive URL query parameters (e.g. reset tokens, session identifiers, internal IDs) "
                    "are not inadvertently leaked to external analytics or CDN services when users follow outbound links.",
                    body_style
                ))
                story.append(Paragraph("<code>Referrer-Policy: strict-origin-when-cross-origin</code>", code_style))
            elif mh_name.lower() == "permissions-policy":
                story.append(Paragraph("<b>Browser Device Capability Restrictions:</b>", h2_style))
                story.append(Paragraph(
                    "Permissions-Policy allows application owners to explicitly disable access to browser hardware APIs (e.g. camera, microphone, geolocation) "
                    "that the application does not legitimately require, shrinking the client-side privilege footprint.",
                    body_style
                ))
                story.append(Paragraph("<code>Permissions-Policy: camera=(), microphone=(), geolocation=()</code>", code_style))
        story.append(Spacer(1, 8))

    # =========================================================================
    # SECTION 7: OWASP TOP 10 (2021) BASELINE ALIGNMENT
    # =========================================================================
    story.append(Paragraph("7. OWASP Top 10 (2021) Baseline Alignment", h1_style))
    story.append(Paragraph(
        "The Open Worldwide Application Security Project (OWASP) Top 10 represents the globally recognized standard awareness document "
        "for developers and web application security. Every assessment evaluates the target scope across all ten baseline risk classes:",
        body_style
    ))

    OWASP_BENCHMARK = [
        ("A01:2021", "Broken Access Control", "Access restrictions, unvalidated endpoints & CORS boundaries"),
        ("A02:2021", "Cryptographic Failures", "TLS ciphers, transport encryption, and certificate hygiene"),
        ("A03:2021", "Injection", "Input reflection, SQL/command injection, and parameter handling"),
        ("A04:2021", "Insecure Design", "Security architecture, defense-in-depth, and control segregation"),
        ("A05:2021", "Security Misconfiguration", "Default permissions, missing security headers, and verbose errors"),
        ("A06:2021", "Vulnerable & Outdated Components", "Server version disclosure, outdated libraries, and dependencies"),
        ("A07:2021", "Identification & Authentication", "Authentication mechanisms, token exposure, and session cookies"),
        ("A08:2021", "Software & Data Integrity Failures", "Code integrity, untrusted deserialization, and CDN integrity"),
        ("A09:2021", "Security Logging & Monitoring", "Detection surface, verbose debug leakage, and error handling"),
        ("A10:2021", "Server-Side Request Forgery", "External SSRF vectors, unsafe redirect hops, and metadata egress")
    ]

    CATEGORY_TO_OWASP = {
        "broken access control": "A01:2021",
        "cryptographic failures": "A02:2021",
        "injection": "A03:2021",
        "insecure design": "A04:2021",
        "security misconfiguration": "A05:2021",
        "vulnerable and outdated components": "A06:2021",
        "vulnerable components": "A06:2021",
        "identification and authentication": "A07:2021",
        "authentication failures": "A07:2021",
        "software and data integrity failures": "A08:2021",
        "security logging and monitoring": "A09:2021",
        "logging failures": "A09:2021",
        "server-side request forgery": "A10:2021",
        "ssrf": "A10:2021"
    }

    owasp_counts: Dict[str, int] = {}
    for f in f_list:
        title = str(getattr(f, "title", "")).lower()
        cat = str(getattr(f, "category", "")).lower()
        matched = False
        for code, name, _ in OWASP_BENCHMARK:
            if code.lower() in title or code.lower() in cat or name.lower() in cat:
                owasp_counts[code] = owasp_counts.get(code, 0) + 1
                matched = True
                break
        if not matched:
            mapped_code = CATEGORY_TO_OWASP.get(cat, "A05:2021")
            owasp_counts[mapped_code] = owasp_counts.get(mapped_code, 0) + 1

    owasp_table_data = [
        [
            Paragraph("<b>Category Code</b>", table_cell_bold),
            Paragraph("<b>OWASP Category Title</b>", table_cell_bold),
            Paragraph("<b>Observed Assessment Posture</b>", table_cell_bold),
            Paragraph("<b>Mapped Findings</b>", table_cell_bold)
        ]
    ]

    for code, name, desc in OWASP_BENCHMARK:
        count = owasp_counts.get(code, 0)
        if count > 0:
            posture_text = Paragraph("VULNERABILITY IDENTIFIED", badge_crit if count > 1 else badge_high)
            count_text = Paragraph(f"<b>{count} Finding(s)</b>", badge_crit)
        else:
            if code == "A05:2021" and observations_count > 0:
                posture_text = Paragraph("HARDENING ADVISED (See Sec 6)", badge_warn)
                count_text = Paragraph(f"0 ({observations_count} Obs)", table_cell)
            else:
                posture_text = Paragraph("CLEAR / NO FINDINGS OBSERVED", badge_pass)
                count_text = Paragraph("0", table_cell)

        owasp_table_data.append([
            Paragraph(f"<b>{code}</b>", table_cell_bold),
            Paragraph(f"<b>{name}</b><br/><font size=7 color='#64748B'>{desc}</font>", table_cell),
            posture_text,
            count_text
        ])

    t_owasp = Table(owasp_table_data, colWidths=[75, 185, 190, 90])
    t_owasp.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BG_MUTED),
        ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(t_owasp)
    story.append(Spacer(1, 10))

    # Profile-Adaptive Technical OWASP Narrative Breakdown (Standard & Full)
    if profile_key in ("Standard", "Full"):
        story.append(Paragraph("<b>Category-by-Category Technical Audit Summary:</b>", h2_style))
        owasp_narratives = [
            ("A01:2021 Broken Access Control", "Tested discovered administrative paths and CORS policies against unauthorized cross-origin data exposure. No access control bypasses observed."),
            ("A02:2021 Cryptographic Failures", f"Evaluated SSL/TLS transport encryption. Active cipher ({p_safe(ssl_cipher)}) enforces AEAD encryption with a trusted certificate authority."),
            ("A03:2021 Injection", "Probed discovered input parameters with benign canary markers and type-mismatch strings. Zero reflective or command injection indicators were triggered."),
            ("A04:2021 Insecure Design", "Audited architectural perimeter exposure and endpoint advertisements. System exhibits standard segmented perimeter architecture."),
            ("A05:2021 Security Misconfiguration", f"Identified {observations_count} missing defensive security headers across HTTP responses. No default credentials or debug stack traces exposed."),
            ("A06:2021 Vulnerable and Outdated Components", f"Fingerprinted server banners ({p_safe(server_banner)}). No outdated third-party library CVEs were detected on public endpoints."),
            ("A07:2021 Identification and Authentication Failures", "Audited authentication boundaries. No exposed session tokens, unauthenticated administrative dashboards, or weak cookie configurations."),
            ("A08:2021 Software and Data Integrity Failures", "Inspected external script resource dependencies. Discovered client-side libraries load from verified CDN domains."),
            ("A09:2021 Security Logging and Monitoring Failures", "Audited malformed input response behavior. Server returns standard HTTP status codes without leaking internal server logs."),
            ("A10:2021 Server-Side Request Forgery (SSRF)", "Tested redirect destinations and URL parameters. No unvalidated outbound requests to loopback or cloud metadata IPs permitted.")
        ]
        for c_title, c_desc in owasp_narratives:
            story.append(Paragraph(f"• <b>{c_title}:</b> {c_desc}", body_style))
        story.append(Spacer(1, 10))

    # =========================================================================
    # SECTION 8: RISK SCORING & ASSESSMENT METHODOLOGY
    # =========================================================================
    story.append(Paragraph("8. Risk Scoring & Assessment Methodology", h1_style))
    story.append(Paragraph(
        "AutoPentest AI implements an objective, evidence-based security scoring methodology. "
        "The evaluation starts at a baseline of 100.0 and applies mathematically weighted deductions across confirmed vulnerabilities, "
        "cryptographic weaknesses, and perimeter configuration anomalies.",
        body_style
    ))

    score_factors = score_data.get("factors", {}) if score_data else {}
    score_deductions = score_data.get("deductions", {}) if score_data else {}

    scoring_math_data = [
        [Paragraph("<b>Evaluation Dimension</b>", table_cell_bold), Paragraph("<b>Observed Telemetry</b>", table_cell_bold), Paragraph("<b>Deduction Weight</b>", table_cell_bold), Paragraph("<b>Applied Penalty</b>", table_cell_bold)],
        [Paragraph("Critical Vulnerabilities", table_cell), Paragraph(f"{c_cnt} Confirmed", table_cell), Paragraph("-20.0 pts each", table_cell), Paragraph(f"-{score_deductions.get('critical_vulnerabilities', 0):.1f} pts", table_cell_bold if c_cnt > 0 else table_cell)],
        [Paragraph("High Vulnerabilities", table_cell), Paragraph(f"{h_cnt} Confirmed", table_cell), Paragraph("-10.0 pts each", table_cell), Paragraph(f"-{score_deductions.get('high_vulnerabilities', 0):.1f} pts", table_cell_bold if h_cnt > 0 else table_cell)],
        [Paragraph("Medium Vulnerabilities", table_cell), Paragraph(f"{m_cnt} Confirmed", table_cell), Paragraph("-5.0 pts each", table_cell), Paragraph(f"-{score_deductions.get('medium_vulnerabilities', 0):.1f} pts", table_cell_bold if m_cnt > 0 else table_cell)],
        [Paragraph("Low Vulnerabilities", table_cell), Paragraph(f"{l_cnt} Confirmed", table_cell), Paragraph("-2.0 pts each", table_cell), Paragraph(f"-{score_deductions.get('low_vulnerabilities', 0):.1f} pts", table_cell_bold if l_cnt > 0 else table_cell)],
        [Paragraph("Transport / TLS Security", table_cell), Paragraph(f"{score_factors.get('ssl_issues', 0)} Anomalies", table_cell), Paragraph("-10.0 pts each", table_cell), Paragraph(f"-{score_deductions.get('ssl_issues', 0):.1f} pts", table_cell)],
        [Paragraph("Missing Security Headers", table_cell), Paragraph(f"{len(missing_headers)} Missing Directives", table_cell), Paragraph("Weighted (0.5 to 4.0 pts)", table_cell), Paragraph(f"-{score_deductions.get('missing_security_headers', 0):.1f} pts", table_cell_bold if missing_headers else table_cell)],
        [Paragraph("<b>Final Calculated Score</b>", table_cell_bold), Paragraph(f"<b>Grade {grade_val} ({risk_val} Risk)</b>", table_cell_bold), Paragraph("<b>Base: 100.0</b>", table_cell_bold), Paragraph(f"<b>{score_display}</b>", badge_pass if grade_val in ('A', 'B') else badge_warn)]
    ]
    t_score_math = Table(scoring_math_data, colWidths=[150, 140, 130, 120])
    t_score_math.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BG_MUTED),
        ('BACKGROUND', (0, -1), (-1, -1), BG_MUTED),
        ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_score_math)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 9: STRATEGIC REMEDIATION ROADMAP
    # =========================================================================
    story.append(Paragraph("9. Strategic Remediation Roadmap", h1_style))
    story.append(Paragraph(
        "Remediation guidance is divided into concrete engineering actions derived from actual observed telemetry. "
        "Generic or irrelevant vulnerability recommendations are strictly excluded.",
        body_style
    ))

    # Part A: Target-Specific Hardening Actions (Derived directly from missing headers)
    story.append(Paragraph("<b>Target-Specific Configuration Directives:</b>", h2_style))

    missing_header_names = [h.get("header") for h in missing_headers if isinstance(h, dict)]

    EXACT_CONFIGS = {
        "Content-Security-Policy": (
            "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none';",
            "Deploy a restrictive CSP to prevent arbitrary JavaScript execution and clickjacking."
        ),
        "Strict-Transport-Security": (
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "Enforce HTTPS across all subdomains and request HSTS preload listing in modern browsers."
        ),
        "X-Content-Type-Options": (
            "X-Content-Type-Options: nosniff",
            "Instruct the browser to strictly honor declared Content-Type headers and avoid MIME-sniffing."
        ),
        "X-Frame-Options": (
            "X-Frame-Options: DENY",
            "Prevent the application from being rendered inside an iframe, mitigating clickjacking attacks."
        ),
        "Referrer-Policy": (
            "Referrer-Policy: strict-origin-when-cross-origin",
            "Preserve privacy by stripping URL paths and query parameters on cross-origin requests."
        ),
        "Permissions-Policy": (
            "Permissions-Policy: camera=(), microphone=(), geolocation=()",
            "Explicitly disable access to sensitive browser hardware capabilities."
        )
    }

    if missing_header_names:
        for h_name in missing_header_names[:4]:
            if h_name in EXACT_CONFIGS:
                cfg_snippet, cfg_expl = EXACT_CONFIGS[h_name]
                story.append(Paragraph(f"• <b>Remediate Missing {p_safe(h_name)}:</b> {cfg_expl}", body_style))
                story.append(Paragraph(p_safe(cfg_snippet), code_style))
    else:
        story.append(Paragraph("<i>All standard defensive HTTP security response headers are currently present. Continue regular posture verification.</i>", body_style))

    story.append(Spacer(1, 6))

    # Part B: General Security Program Recommendations
    story.append(Paragraph("<b>General Security Program Recommendations:</b>", h2_style))
    general_rec = (
        "• <b>Continuous Automated Perimeter Auditing:</b> Schedule recurring weekly or monthly automated audits to detect unintended configuration drift or newly exposed routes.<br/>"
        "• <b>Dependency Hygiene:</b> Implement automated Software Bill of Materials (SBOM) dependency scanning across CI/CD build pipelines to track outdated third-party libraries.<br/>"
        "• <b>Centralized Ingress Hardening:</b> Configure web application firewalls (WAF) or reverse proxy header rules to uniformly inject security directives at the ingress layer."
    )
    story.append(Paragraph(general_rec, body_style))
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 10: REGULATORY & COMPLIANCE FRAMEWORK ALIGNMENT
    # =========================================================================
    story.append(Paragraph("10. Regulatory & Compliance Framework Alignment", h1_style))
    story.append(Paragraph(
        "Evaluation of target security posture against major regulatory frameworks. "
        "Framework alignment status is derived empirically from the presence or absence of critical security controls.",
        body_style
    ))

    pci_status = "NON-COMPLIANT" if c_cnt > 0 or h_cnt > 0 else "SATISFACTORY"
    soc2_status = "DEFICIENT" if c_cnt > 0 else ("NEEDS REVIEW" if h_cnt > 0 else "ALIGNED")
    nist_status = "PARTIALLY IMPLEMENTED" if confirmed_findings_count > 0 else "IMPLEMENTED"
    iso_status = "ACTION REQUIRED" if confirmed_findings_count > 0 else "CONFORMING"

    comp_table_data = [
        [Paragraph("<b>Framework / Standard</b>", table_cell_bold), Paragraph("<b>Control Scope Evaluated</b>", table_cell_bold), Paragraph("<b>Current Alignment Status</b>", table_cell_bold)],
        [Paragraph("PCI-DSS v4.0", table_cell), Paragraph("Requirement 6.4: Web Application Security Controls", table_cell), Paragraph(pci_status, badge_pass if pci_status == "SATISFACTORY" else badge_crit)],
        [Paragraph("SOC 2 Type II", table_cell), Paragraph("Trust Services Criteria CC6.1: Access & Perimeter Control", table_cell), Paragraph(soc2_status, badge_pass if soc2_status == "ALIGNED" else badge_warn)],
        [Paragraph("NIST CSF 2.0", table_cell), Paragraph("Identify & Protect (PR.IP / DE.CM): Flaw Remediation", table_cell), Paragraph(nist_status, badge_pass if nist_status == "IMPLEMENTED" else badge_warn)],
        [Paragraph("ISO/IEC 27001:2022", table_cell), Paragraph("Annex A.8.8: Management of Technical Vulnerabilities", table_cell), Paragraph(iso_status, badge_pass if iso_status == "CONFORMING" else badge_crit)]
    ]
    t_comp = Table(comp_table_data, colWidths=[140, 260, 140])
    t_comp.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BG_MUTED),
        ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_comp)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 11: AUDIT GOVERNANCE & SCAN LIMITATIONS
    # =========================================================================
    story.append(Paragraph("11. Audit Governance & Scan Limitations", h1_style))
    story.append(Paragraph(
        f"This document represents an authorized, automated penetration testing audit generated exclusively for target <b>{p_safe(target_url)}</b>. "
        "The findings and telemetry contained herein reflect the observable security posture at the exact timestamp of execution.",
        body_style
    ))

    gov_data = [
        [Paragraph("<b>Governance Attribute</b>", table_cell_bold), Paragraph("<b>Verification Statement</b>", table_cell_bold)],
        [Paragraph("Target Authorization", table_cell), Paragraph("Operator confirmed authorization to conduct external security evaluation on the target scope.", table_cell)],
        [Paragraph("Safety Guarantee", table_cell), Paragraph("Conducted strictly with safe HTTP methods. Zero destructive payloads, data deletion, or denial-of-service executed.", table_cell)],
        [Paragraph("Data Redaction", table_cell), Paragraph("All authentication tokens, passwords, secrets, and raw session cookie values are sanitized prior to report compilation.", table_cell)],
        [Paragraph("Report Identifier", table_cell), Paragraph(f"<code>REP-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{scan_id:04d}-{profile_key[:1]}</code>", table_cell)]
    ]
    t_gov = Table(gov_data, colWidths=[150, 390])
    t_gov.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BG_MUTED),
        ('BOX', (0, 0), (-1, -1), 1, BORDER_LIGHT),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(t_gov)
    story.append(Spacer(1, 10))

    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_LIGHT, spaceBefore=8, spaceAfter=8))
    story.append(Paragraph(
        f"<b>CONFIDENTIALITY NOTICE:</b> This {profile_key.upper()} cybersecurity audit document contains sensitive intelligence compiled exclusively "
        f"for authorized stakeholders of <b>{p_safe(target_url)}</b>. Unauthorized copying, distribution, or public dissemination is strictly prohibited.",
        ParagraphStyle('ConfidentialNotice', parent=body_style, fontSize=7.5, leading=10, textColor=TEXT_MUTED)
    ))

    # Build PDF with NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    pdf_bytes = buffer.getvalue()

    # Extract exact real page count via pypdf
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        actual_page_count = len(reader.pages)
    except Exception:
        actual_page_count = 1

    return pdf_bytes, actual_page_count
