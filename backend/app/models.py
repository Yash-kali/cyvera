from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, ForeignKey, JSON, LargeBinary, Boolean
from sqlalchemy.orm import relationship
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    password_version = Column(Integer, default=1, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    scans = relationship("Scan", back_populates="owner", cascade="all, delete-orphan")
    recon_results = relationship("ReconResult", back_populates="owner", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="owner", cascade="all, delete-orphan")
    ai_explanations = relationship("AIExplanation", back_populates="owner", cascade="all, delete-orphan")
    chat_messages = relationship("ChatMessage", back_populates="owner", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="owner", cascade="all, delete-orphan")
    settings = relationship("UserSettings", back_populates="owner", uselist=False, cascade="all, delete-orphan")
    attack_surface_assets = relationship("AttackSurfaceAsset", back_populates="owner", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    report_id_str = Column(String(100), unique=True, nullable=False, index=True)
    report_type = Column(String(50), nullable=False, default="Standard")  # 'Quick', 'Standard', 'Full'
    title = Column(String(255), nullable=False)
    target_url = Column(String(2048), nullable=False)
    pages = Column(Integer, nullable=False, default=15)
    file_path = Column(String(1024), nullable=True)
    pdf_bytes = Column(LargeBinary, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    owner = relationship("User", back_populates="reports")
    scan = relationship("Scan")



class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = Column(String(100), nullable=False, default="default", index=True)
    sender = Column(String(20), nullable=False)  # 'user' or 'assistant'
    message = Column(Text, nullable=False)
    context = Column(JSON, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    owner = relationship("User", back_populates="chat_messages")



class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target_url = Column(String(2048), nullable=False)
    scan_type = Column(String(50), nullable=False)  # 'Quick', 'Standard', 'Full'
    status = Column(String(50), nullable=False, default="Pending")  # 'Pending', 'Running', 'Completed', 'Failed'
    security_score = Column(Float, nullable=True)
    security_grade = Column(String(10), nullable=True)
    risk_level = Column(String(50), nullable=True)
    score_details = Column(JSON, nullable=True)
    
    # Phase 7B Safety, Authorization & Worker Tracking Fields
    authorization_confirmed = Column(Boolean, default=False, nullable=False)
    authorization_timestamp = Column(DateTime(timezone=True), nullable=True)
    current_phase = Column(String(50), default="PENDING", nullable=False)
    current_scanner = Column(String(100), nullable=True)
    progress = Column(Integer, default=0, nullable=False)
    worker_id = Column(String(100), nullable=True)
    worker_started_at = Column(DateTime(timezone=True), nullable=True)
    last_heartbeat_at = Column(DateTime(timezone=True), nullable=True)
    cancel_requested = Column(Boolean, default=False, nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    failure_reason = Column(Text, nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    owner = relationship("User", back_populates="scans")
    recon = relationship("ReconResult", back_populates="scan", uselist=False)
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    attack_surface = relationship("AttackSurfaceAsset", back_populates="scan", cascade="all, delete-orphan")



class ReconResult(Base):
    __tablename__ = "recon_results"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    target_url = Column(String(2048), nullable=False)
    ip_address = Column(String(100), nullable=False)
    web_server = Column(String(255), nullable=False)
    ssl_issuer = Column(String(255), nullable=False)
    ssl_expires_days = Column(Integer, nullable=False)
    security_score = Column(Float, nullable=False)  # float to support fractional scores (e.g. 82.5)
    details = Column(JSON, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    owner = relationship("User", back_populates="recon_results")
    scan = relationship("Scan", back_populates="recon")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    asset_id = Column(Integer, ForeignKey("attack_surface_assets.id", ondelete="SET NULL"), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False, default="Security Misconfiguration")
    description = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False, index=True)
    confidence = Column(String(50), nullable=False, default="HIGH")
    cvss_score = Column(Float, nullable=True)
    cve_id = Column(String(100), nullable=True)
    affected_url = Column(String(2048), nullable=False)
    status = Column(String(50), nullable=False, default="Open")
    remediation_guidance = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=True)
    first_observed = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    last_observed = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    source = Column(String(100), nullable=False, default="Phase7E_SecurityTesting")
    test_type = Column(String(100), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    owner = relationship("User", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")
    asset = relationship("AttackSurfaceAsset")
    ai_explanation = relationship("AIExplanation", back_populates="finding", uselist=False, cascade="all, delete-orphan")


class AIExplanation(Base):
    __tablename__ = "ai_explanations"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    executive_summary = Column(Text, nullable=False)
    technical_description = Column(Text, nullable=False)
    business_impact = Column(Text, nullable=False)
    attack_scenario = Column(Text, nullable=False)
    remediation_guidance = Column(Text, nullable=False)
    secure_coding_recommendations = Column(Text, nullable=True)
    owasp_mapping = Column(String(100), nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


    owner = relationship("User", back_populates="ai_explanations")
    finding = relationship("Finding", back_populates="ai_explanation")


class UserSettings(Base):
    __tablename__ = "user_settings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    max_concurrency = Column(Integer, nullable=False, default=4)
    auto_patch_validation = Column(Boolean, nullable=False, default=True)
    db_backup_interval = Column(String(50), nullable=False, default="daily")
    email_notifications = Column(Boolean, nullable=False, default=True)
    scan_completion_alerts = Column(Boolean, nullable=False, default=True)
    critical_finding_alerts = Column(Boolean, nullable=False, default=True)
    weekly_digest = Column(Boolean, nullable=False, default=False)
    default_scan_profile = Column(String(50), nullable=False, default="Standard")
    auto_recon_enabled = Column(Boolean, nullable=False, default=True)
    two_factor_enabled = Column(Boolean, nullable=False, default=False)
    api_key = Column(String(128), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    owner = relationship("User", back_populates="settings")


class AttackSurfaceAsset(Base):
    __tablename__ = "attack_surface_assets"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_type = Column(String(50), nullable=False, index=True)  # PAGE, ENDPOINT, FORM, API, SCRIPT, RESOURCE, DOCUMENT, ROBOTS, SITEMAP, WEB_SOCKET, GRAPHQL, TECHNOLOGY, REDIRECT
    url = Column(String(2048), nullable=False)
    normalized_url = Column(String(2048), nullable=False, index=True)
    hostname = Column(String(255), nullable=False, index=True)
    path = Column(String(1024), nullable=False)
    query_parameters = Column(JSON, nullable=True)
    http_method = Column(String(20), nullable=False, default="GET")
    content_type = Column(String(100), nullable=True)
    status_code = Column(Integer, nullable=True)
    discovered_from = Column(String(50), nullable=False, default="HTML")  # HTML, JAVASCRIPT, ROBOTS, SITEMAP, OPENAPI, REDIRECT
    source_url = Column(String(2048), nullable=True)
    evidence = Column(JSON, nullable=False)
    confidence = Column(String(20), nullable=False, default="High")  # High, Medium, Low
    evidence_status = Column(String(20), nullable=False, default="OBSERVED")  # OBSERVED, INFERRED, VERIFIED
    in_scope = Column(Boolean, nullable=False, default=True)
    external = Column(Boolean, nullable=False, default=False)
    duplicate_key = Column(String(255), nullable=False, index=True)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    owner = relationship("User", back_populates="attack_surface_assets")
    scan = relationship("Scan", back_populates="attack_surface")

    def __repr__(self):
        return f"<AttackSurfaceAsset(id={self.id}, scan_id={self.scan_id}, type='{self.asset_type}', url='{self.url}')>"

