from pathlib import Path
from typing import List
from pydantic import model_validator, Field, AliasChoices
from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_DIR = Path(__file__).resolve().parent.parent
_DEFAULT_SQLITE_PATH = (_BACKEND_DIR / "autopentest.db").as_posix()

# Known insecure placeholder values that must never be used in any environment.
_INSECURE_SECRET_DEFAULTS: set[str] = {
    "super-secret-cyvera-jwt-key-change-in-production",
    "super-secret-autopentest-ai-jwt-key-change-in-production",
    "changeme",
    "secret",
    "REPLACE_WITH_A_STRONG_RANDOM_SECRET_KEY",
    "",
}

# Known weak/default operator passwords that are acceptable in dev but blocked in production.
_WEAK_OPERATOR_PASSWORDS: set[str] = {
    "Yash@4050",
    "password",
    "Password1!",
    "Admin@123",
    "Change-Me-Now",
    "Choose-A-Strong-Password",
}


class Settings(BaseSettings):
    PROJECT_NAME: str = "Cyvera"
    ENVIRONMENT: str = "development"

    # JWT_SECRET_KEY must be provided via the JWT_SECRET_KEY or SECRET_KEY
    # environment variable or .env file.
    # No predictable or insecure hardcoded fallback is provided.
    # Generate a strong key with:
    #   python -c "import secrets; print(secrets.token_hex(48))"
    # Startup will fail with a clear configuration error if the key is absent
    # or set to an insecure placeholder.
    SECRET_KEY: str = Field(
        default="",
        validation_alias=AliasChoices("JWT_SECRET_KEY", "SECRET_KEY"),
        description="JWT secret key for signing authentication tokens",
    )

    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Database URL (SQLite default for seamless local development, PostgreSQL in prod)
    DATABASE_URL: str = f"sqlite+aiosqlite:///{_DEFAULT_SQLITE_PATH}"

    # CORS Settings
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://localhost",
    ]

    # Optional: Gemini API key for live AI analysis and copilot.
    # When not set the application falls back to the built-in expert rule engine.
    GEMINI_API_KEY: str = ""

    # Private Application Access & Registration Control
    ALLOW_PUBLIC_REGISTRATION: bool = False
    ADMIN_BOOTSTRAP_TOKEN: str = ""

    # Single Fixed Operator Account Configuration
    OPERATOR_USERNAME: str = "Yash"
    OPERATOR_EMAIL: str = "yaswanthtekpudi@gmail.com"
    OPERATOR_PASSWORD: str = ""

    # Phase 8: Production Hardening Settings
    # Disable OpenAPI docs (/docs, /redoc) in production environments
    DISABLE_API_DOCS: bool = False

    # Login rate limiting: max attempts per window per IP
    LOGIN_RATE_LIMIT_MAX_ATTEMPTS: int = 10
    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = 300  # 5-minute window

    # Structured logging: set to "json" for log aggregation tools (ELK, Loki)
    LOG_FORMAT: str = "text"  # "text" | "json"

    # SQLite WAL mode: improves concurrent read performance (ignored for PostgreSQL)
    SQLITE_WAL_MODE: bool = True

    # Stale scan recovery threshold in seconds
    STALE_SCAN_THRESHOLD_SECONDS: int = 60

    model_config = SettingsConfigDict(
        env_file=((_BACKEND_DIR / ".env").as_posix(), "backend/.env", ".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def JWT_SECRET_KEY(self) -> str:
        """Alias property to access secret key as JWT_SECRET_KEY."""
        return self.SECRET_KEY

    @model_validator(mode="after")
    def _validate_settings(self) -> "Settings":
        """
        Validate that a strong secret key has been configured.
        Refuses to start in any environment if JWT_SECRET_KEY / SECRET_KEY
        is missing, empty, or set to a known insecure placeholder.
        In production, also refuses to start with a known weak OPERATOR_PASSWORD.
        """
        val = (self.SECRET_KEY or "").strip()
        if not val or val in _INSECURE_SECRET_DEFAULTS:
            raise ValueError(
                "FATAL CONFIGURATION ERROR: JWT_SECRET_KEY (or SECRET_KEY) is missing "
                "or set to an insecure placeholder. An explicit secret must be provided "
                "via environment variables or a .env file.\n"
                "To generate a secure key, run:\n"
                "    python -c \"import secrets; print(secrets.token_hex(48))\"\n"
                "Then add it to your .env file:\n"
                "    JWT_SECRET_KEY=\"<generated-key>\""
            )

        # Production-only: block startup if OPERATOR_PASSWORD is a known weak default
        env = (self.ENVIRONMENT or "development").strip().lower()
        op_pass = (self.OPERATOR_PASSWORD or "").strip()
        if env == "production" and op_pass in _WEAK_OPERATOR_PASSWORDS:
            raise ValueError(
                "FATAL CONFIGURATION ERROR: OPERATOR_PASSWORD is set to a known "
                "weak or default value. In production, you must set a strong, unique "
                "OPERATOR_PASSWORD in your environment or .env file."
            )

        # In production, auto-enable docs disable if not explicitly configured
        if env == "production" and not self.DISABLE_API_DOCS:
            object.__setattr__(self, "DISABLE_API_DOCS", True)

        # Ensure SQLite URL is resolved deterministically to backend/autopentest.db
        if "sqlite" in self.DATABASE_URL and "./autopentest.db" in self.DATABASE_URL:
            self.DATABASE_URL = self.DATABASE_URL.replace("./autopentest.db", _DEFAULT_SQLITE_PATH)

        return self


settings = Settings()


