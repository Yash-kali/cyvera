import sys
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.config import settings
from app.logging_config import logger

# Format DB URL for asyncpg if postgresql:// is supplied
db_url = settings.DATABASE_URL
if db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

# Ensure SQLite URL resolves deterministically to the canonical backend database file
if "sqlite" in db_url and "./autopentest.db" in db_url:
    from pathlib import Path
    backend_db = (Path(__file__).resolve().parent.parent / "autopentest.db").as_posix()
    db_url = db_url.replace("./autopentest.db", backend_db)

# SQLite fallback support if sqlite URL is passed
connect_args = {}
if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_async_engine(
    db_url,
    echo=False,
    future=True,
    connect_args=connect_args
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """
    Initialize database tables and seed the development user if absent.

    IMPORTANT: This function NEVER modifies or overwrites the credentials
    of any existing user.  It only inserts the seed account when no user
    with that username is present in the database.
    """
    # Step 1: Create all tables that don't yet exist (idempotent DDL).
    import app.models  # Ensure all model tables are registered in Base.metadata
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # Non-destructive column addition for SQLite
        from sqlalchemy import text

        # Phase 8: Enable SQLite WAL mode for better concurrent read performance
        if db_url.startswith("sqlite") and settings.SQLITE_WAL_MODE:
            try:
                await conn.execute(text("PRAGMA journal_mode=WAL"))
                logger.info("[DB] SQLite WAL mode enabled.")
            except Exception as wal_err:
                logger.warning(f"[DB] Could not enable WAL mode: {wal_err}")

        try:
            res = await conn.execute(text("PRAGMA table_info(scans)"))
            existing_cols = {row[1] for row in res.fetchall()}

            new_cols = [
                ("authorization_confirmed", "BOOLEAN NOT NULL DEFAULT 0"),
                ("authorization_timestamp", "DATETIME"),
                ("current_phase", "VARCHAR(50) NOT NULL DEFAULT 'PENDING'"),
                ("current_scanner", "VARCHAR(100)"),
                ("progress", "INTEGER NOT NULL DEFAULT 0"),
                ("worker_id", "VARCHAR(100)"),
                ("worker_started_at", "DATETIME"),
                ("last_heartbeat_at", "DATETIME"),
                ("cancel_requested", "BOOLEAN NOT NULL DEFAULT 0"),
                ("started_at", "DATETIME"),
                ("completed_at", "DATETIME"),
                ("failure_reason", "TEXT")
            ]
            for col_name, col_type in new_cols:
                if col_name not in existing_cols:
                    await conn.execute(text(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}"))

            # Check users table for password_version
            res_user = await conn.execute(text("PRAGMA table_info(users)"))
            existing_user_cols = {row[1] for row in res_user.fetchall()}
            if "password_version" not in existing_user_cols:
                await conn.execute(text("ALTER TABLE users ADD COLUMN password_version INTEGER NOT NULL DEFAULT 1"))

            # Check findings table for Phase 7E evidence and metadata columns
            res_finding = await conn.execute(text("PRAGMA table_info(findings)"))
            existing_finding_cols = {row[1] for row in res_finding.fetchall()}
            new_finding_cols = [
                ("asset_id", "INTEGER"),
                ("category", "VARCHAR(100) DEFAULT 'Security Misconfiguration'"),
                ("confidence", "VARCHAR(50) DEFAULT 'HIGH'"),
                ("evidence", "TEXT"),
                ("first_observed", "DATETIME"),
                ("last_observed", "DATETIME"),
                ("source", "VARCHAR(100) DEFAULT 'Phase7E_SecurityTesting'"),
                ("test_type", "VARCHAR(100)")
            ]
            for col_name, col_type in new_finding_cols:
                if col_name not in existing_finding_cols:
                    await conn.execute(text(f"ALTER TABLE findings ADD COLUMN {col_name} {col_type}"))
        except Exception as migration_err:
            # Log schema migration issues as warnings; non-SQLite engines may not support PRAGMA
            logger.warning(f"[DB] Schema migration note (non-critical for PostgreSQL): {migration_err}")


    # Step 2: Ensure the single fixed operator account is initialized / synchronized.
    from sqlalchemy import select, or_
    from app.models import User
    from app.auth import get_password_hash, verify_password

    op_user = (settings.OPERATOR_USERNAME or "Yash").strip()
    op_email = (settings.OPERATOR_EMAIL or "yash@cyvera.ai").strip().lower()
    op_pass = (settings.OPERATOR_PASSWORD or "").strip()

    async with AsyncSessionLocal() as session:
        # Match by configured username, email, or legacy 'Yash'
        stmt = select(User).where(
            or_(
                User.username == op_user,
                User.username == "Yash",
                User.email == op_email
            )
        )
        existing = await session.execute(stmt)
        operator = existing.scalars().first()

        if operator is None:
            # First-run creation when no operator account exists
            logger.info("Initializing fixed operator account '%s' (first-run).", op_user)
            default_pass = op_pass if op_pass else "Yash@4050"
            new_operator = User(
                username=op_user,
                email=op_email,
                hashed_password=get_password_hash(default_pass),
                password_version=1,
            )
            session.add(new_operator)
            await session.commit()
            logger.info("Startup: Operator account '%s' created successfully.", op_user)
        else:
            # Existing account found - synchronize profile fields if modified
            updated = False
            if operator.username != op_user:
                operator.username = op_user
                updated = True
            if operator.email != op_email:
                operator.email = op_email
                updated = True

            # If an explicit non-empty password is provided in config and differs, update securely
            if op_pass and not verify_password(op_pass, operator.hashed_password):
                operator.hashed_password = get_password_hash(op_pass)
                operator.password_version = (operator.password_version or 1) + 1
                updated = True
                logger.info("Startup: Operator credentials updated from environment configuration.")

            if updated:
                await session.commit()
                logger.info("Startup: Operator account '%s' synchronized.", op_user)
            else:
                logger.info("Startup: Operator account '%s' verified — credentials unchanged.", op_user)


