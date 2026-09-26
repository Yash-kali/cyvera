from datetime import datetime
from typing import Optional, Literal, Dict, Any, List
from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(..., min_length=6, max_length=100, description="User password (min 6 chars)")
    admin_invite_token: Optional[str] = Field(None, description="Administrative bootstrap/invite token for account provisioning")


class UserLogin(BaseModel):
    email_or_username: str = Field(..., description="User's email or username")
    password: str = Field(..., description="User password")


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    password_version: int = 1
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class TokenData(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    user_id: Optional[int] = None


# --- Phase 3 Scan Schemas ---

ScanTypeEnum = Literal["Quick", "Standard", "Full"]
ScanStatusEnum = Literal["Pending", "Running", "Cancelling", "Cancelled", "Completed", "Failed"]


class ScanCreate(BaseModel):
    target_url: str = Field(..., description="Target domain or endpoint URL")
    scan_type: str = Field("Standard", description="Scan intensity profile")
    authorization_confirmed: bool = Field(
        ...,
        description="Explicit legal attestation confirming operator authorization to test target"
    )

    @field_validator("authorization_confirmed")
    @classmethod
    def validate_authorization(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Target authorization must be explicitly confirmed before initiating a security assessment.")
        return v

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v_str = str(v).strip()
        if not v_str:
            raise ValueError("Target URL cannot be empty.")
        if not (v_str.startswith("http://") or v_str.startswith("https://")):
            v_str = "https://" + v_str
        if len(v_str) < 8 or ("." not in v_str and "127." not in v_str and "localhost" not in v_str):
            raise ValueError("Target URL must be a valid domain or endpoint")
        return v_str

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        v_lower = str(v).strip().lower()
        if "quick" in v_lower:
            return "Quick"
        elif "full" in v_lower:
            return "Full"
        return "Standard"


class ScanResponse(BaseModel):
    id: int
    user_id: int
    target_url: str
    scan_type: str
    status: str
    security_score: Optional[float] = None
    security_grade: Optional[str] = None
    risk_level: Optional[str] = None
    vulnerabilities_count: Optional[int] = None
    critical_count: Optional[int] = None
    authorization_confirmed: bool = False
    authorization_timestamp: Optional[datetime] = None
    current_phase: Optional[str] = None
    progress: Optional[int] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    failure_reason: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanProgressResponse(BaseModel):
    scan_id: int
    stage: str
    progress: int
    message: str
    status: str = "Running"
    timestamp: Optional[str] = None



# --- Phase 4 Asset Security & Recon Schemas ---

class ReconInspectRequest(BaseModel):
    target_url: str = Field(..., description="Target URL for asset posture inspection")
    scan_id: Optional[int] = Field(None, description="Optional associated scan task ID")

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v_str = str(v).strip()
        if not v_str:
            raise ValueError("Target URL cannot be empty.")
        if not (v_str.startswith("http://") or v_str.startswith("https://")):
            v_str = "https://" + v_str
        if len(v_str) < 8 or ("." not in v_str and "localhost" not in v_str):
            raise ValueError("Target URL must be a valid domain, IP address, or endpoint")
        return v_str



class ReconResultResponse(BaseModel):
    id: int
    user_id: int
    scan_id: Optional[int] = None
    target_url: str
    ip_address: str
    web_server: str
    ssl_issuer: str
    ssl_expires_days: int
    security_score: float  # float to support fractional scores (e.g. 82.5)
    details: Dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# --- Phase 5 Finding Schemas ---

SeverityEnum = Literal["Critical", "High", "Medium", "Low", "Info"]
FindingStatusEnum = Literal["Open", "In Review", "Confirmed", "Mitigated", "Resolved", "False Positive", "Accepted Risk"]


class FindingCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., description="Technical summary of vulnerability finding")
    severity: SeverityEnum = Field("Medium")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cve_id: Optional[str] = Field(None, max_length=100)
    affected_url: str = Field(..., description="Target URL or affected component")
    remediation_guidance: str = Field(..., description="Actionable fix or mitigation steps")
    scan_id: Optional[int] = None


class FindingStatusUpdate(BaseModel):
    status: FindingStatusEnum = Field(..., description="Updated triage status")


class FindingResponse(BaseModel):
    id: int
    user_id: int
    scan_id: Optional[int] = None
    asset_id: Optional[int] = None
    title: str
    category: Optional[str] = "Security Misconfiguration"
    description: str
    severity: str
    confidence: Optional[str] = "HIGH"
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    affected_url: str
    status: str
    remediation_guidance: str
    evidence: Optional[Dict[str, Any]] = None
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    source: Optional[str] = "Phase7E_SecurityTesting"
    test_type: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityTestingSummaryResponse(BaseModel):
    scan_id: int
    total_findings: int
    severity_breakdown: Dict[str, int]
    category_breakdown: Dict[str, int]
    tests_executed: List[str]
    total_requests: int
    budget_exhausted: bool
    verification_statuses: Dict[str, int]

    model_config = ConfigDict(from_attributes=True)


class SARIFImportPayload(BaseModel):
    sarif_data: Optional[Dict[str, Any]] = Field(None, description="Raw SARIF JSON report object")
    runs: Optional[List[Dict[str, Any]]] = Field(None, description="OASIS SARIF runs array")
    findings: Optional[List[Dict[str, Any]]] = Field(None, description="Pipeline findings array")
    tool_name: Optional[str] = Field(None, description="Security tool or scanner identifier")
    scan_id: Optional[int] = Field(None, description="Optional scan task ID to associate findings with")



# --- Phase 6 Risk Assessment & Analytics Schemas ---

class SeverityDistribution(BaseModel):
    Critical: int
    High: int
    Medium: int
    Low: int
    Info: int


class RiskSummaryResponse(BaseModel):
    security_score: float
    risk_score: float
    grade: str
    grade_color: str
    total_findings: int
    open_findings: int
    resolved_findings: int
    sla_compliance_rate: float
    severity_distribution: SeverityDistribution


class AssetRiskItem(BaseModel):
    target_url: str
    total_findings: int
    critical_count: int
    high_count: int
    asset_risk_score: float
    asset_security_score: float
    risk_rating: str


class ScanProfileDistribution(BaseModel):
    Quick: int = 0
    Standard: int = 0
    Full: int = 0


class OWASPDistributionItem(BaseModel):
    code: str
    name: str
    count: int


class TrendDataPoint(BaseModel):
    date: str
    findings: int = 0
    scans: int = 0
    risk_score: float = 0.0


class AnalyticsOverviewResponse(BaseModel):
    total_scans: int
    completed_scans: int
    running_scans: int
    failed_scans: int
    total_findings: int
    open_findings: int = 0
    resolved_findings: int = 0
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    security_score: float
    risk_score: float
    grade: str
    grade_color: str
    sla_compliance_rate: float
    severity_distribution: SeverityDistribution
    scan_profile_distribution: ScanProfileDistribution
    owasp_distribution: List[OWASPDistributionItem]
    trend_data: List[TrendDataPoint]
    asset_risks: List[AssetRiskItem]


# --- Phase 7 AI Vulnerability Explanation Schemas ---

class AIExplanationRequest(BaseModel):
    finding_id: int = Field(..., description="ID of the finding to generate AI explanation for")


class AIExplanationResponse(BaseModel):
    id: int
    user_id: int
    finding_id: int
    executive_summary: str
    technical_description: str
    business_impact: str
    attack_scenario: str
    remediation_guidance: str
    secure_coding_recommendations: Optional[str] = None
    owasp_mapping: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)



class ScoreFactors(BaseModel):
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    info_observations: int = 0
    ssl_issues: int = 0
    missing_security_headers: int = 0
    open_ports: int = 0

    model_config = ConfigDict(extra="allow")


class ScoreDeductions(BaseModel):
    critical_vulnerabilities: float = 0.0
    high_vulnerabilities: float = 0.0
    medium_vulnerabilities: float = 0.0
    low_vulnerabilities: float = 0.0
    ssl_issues: float = 0.0
    missing_security_headers: float = 0.0
    open_ports: float = 0.0

    model_config = ConfigDict(extra="allow")


class SecurityScoreResponse(BaseModel):
    score: float = Field(..., ge=0.0, le=100.0, description="Overall Security Score 0-100")
    grade: str = Field(..., description="Letter Security Grade A-F")
    risk_level: str = Field(..., description="Risk level (Low, Medium, High, Critical)")
    factors: ScoreFactors
    deductions: ScoreDeductions
    scan_id: int
    target_url: str

    model_config = ConfigDict(extra="allow")


# --- Phase 9 OWASP Top 10 Mapping Schemas ---

class OWASPCategoryGroup(BaseModel):
    code: str
    name: str
    category_key: str
    count: int
    findings: List[FindingResponse] = []


class OWASPFindingsResponse(BaseModel):
    scan_id: int
    total_findings: int
    categories: List[OWASPCategoryGroup]


class OWASPStatsResponse(BaseModel):
    scan_id: int
    total_mapped_findings: int
    category_counts: Dict[str, int]
    severity_breakdown: Dict[str, int]
    category_severity_matrix: Dict[str, Dict[str, int]]
    top_vulnerable_category: str


# --- Phase 10 AI Security Copilot Schemas ---

class ChatMessageCreate(BaseModel):
    message: str = Field(..., min_length=1, description="Operator user message or question")
    context: Optional[Dict[str, Any]] = Field(None, description="Optional active scope, finding, or route context")
    session_id: Optional[str] = Field("default", description="Optional session or thread identifier")


class ChatMessageResponse(BaseModel):
    id: int
    user_id: int
    session_id: str
    sender: str
    message: str
    context: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ChatResponse(BaseModel):
    reply: str = Field(..., description="AI Security Copilot response")
    user_message: str
    context: Optional[Dict[str, Any]] = None
    created_at: datetime
    history: List[ChatMessageResponse] = []


ReportProfileType = Literal["quick", "standard", "full", "Quick", "Standard", "Full"]

class ReportGeneratePayload(BaseModel):
    scan_profile: Optional[ReportProfileType] = Field("standard", description="Report profile: quick | standard | full")



class ReportResponse(BaseModel):
    id: int
    report_id_str: str
    report_type: str = "Standard"
    title: str
    target_url: str
    scan_id: Optional[int] = None
    pages: int = 15
    created_at: datetime
    download_url: str

    model_config = ConfigDict(from_attributes=True)


# --- Phase 5 Settings & Account Security Schemas ---

class UserSettingsResponse(BaseModel):
    id: int
    user_id: int
    max_concurrency: int = 4
    auto_patch_validation: bool = True
    db_backup_interval: str = "daily"
    email_notifications: bool = True
    scan_completion_alerts: bool = True
    critical_finding_alerts: bool = True
    weekly_digest: bool = False
    default_scan_profile: str = "Standard"
    auto_recon_enabled: bool = True
    two_factor_enabled: bool = False
    api_key: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserSettingsUpdate(BaseModel):
    max_concurrency: Optional[int] = Field(None, ge=1, le=16)
    auto_patch_validation: Optional[bool] = None
    db_backup_interval: Optional[Literal["daily", "weekly", "monthly"]] = None
    email_notifications: Optional[bool] = None
    scan_completion_alerts: Optional[bool] = None
    critical_finding_alerts: Optional[bool] = None
    weekly_digest: Optional[bool] = None
    default_scan_profile: Optional[Literal["Quick", "Standard", "Full"]] = None
    auto_recon_enabled: Optional[bool] = None
    two_factor_enabled: Optional[bool] = None


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(..., min_length=1, description="Existing user password")
    new_password: str = Field(..., min_length=6, max_length=100, description="New user password (min 6 chars)")
    confirm_password: str = Field(..., min_length=6, max_length=100, description="Confirm new password")

    @field_validator("confirm_password")
    @classmethod
    def validate_confirmation(cls, v: str, info) -> str:
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("New password and confirmation password do not match.")
        return v


class UserProfileUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None


class ApiKeyResponse(BaseModel):
    api_key: str
    created_at: datetime


# --- Phase 7D Attack Surface Schemas ---

class AttackSurfaceAssetResponse(BaseModel):
    id: int
    scan_id: int
    user_id: int
    asset_type: str
    url: str
    normalized_url: str
    hostname: str
    path: str
    query_parameters: Optional[List[str]] = None
    http_method: str = "GET"
    content_type: Optional[str] = None
    status_code: Optional[int] = None
    discovered_from: str = "HTML"
    source_url: Optional[str] = None
    evidence: Dict[str, Any]
    confidence: str = "High"
    evidence_status: str = "OBSERVED"
    in_scope: bool = True
    external: bool = False
    duplicate_key: str
    first_seen: datetime
    last_seen: datetime

    model_config = ConfigDict(from_attributes=True)


class AttackSurfaceSummaryResponse(BaseModel):
    scan_id: int
    total_assets: int
    in_scope_count: int
    external_count: int
    asset_types: Dict[str, int]
    evidence_statuses: Dict[str, int]
    discovered_from: Dict[str, int]
    crawl_stats: Dict[str, Any]






