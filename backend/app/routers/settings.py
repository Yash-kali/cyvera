import secrets
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db
from app.models import User, UserSettings
from app.schemas import (
    UserSettingsResponse,
    UserSettingsUpdate,
    ApiKeyResponse,
)
from app.auth import get_current_user

logger = logging.getLogger("autopentest.settings")

router = APIRouter(prefix="/api/v1/settings", tags=["User Settings & Preferences"])


@router.get("", response_model=UserSettingsResponse)
@router.get("/", response_model=UserSettingsResponse, include_in_schema=False)
async def get_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve authenticated user's settings and preferences.
    If no settings row exists yet, safe deterministic defaults are created dynamically
    without modifying user credentials or dropping state.
    """
    stmt = select(UserSettings).where(UserSettings.user_id == current_user.id)
    result = await db.execute(stmt)
    user_settings = result.scalars().first()

    if not user_settings:
        user_settings = UserSettings(
            user_id=current_user.id,
            max_concurrency=4,
            auto_patch_validation=True,
            db_backup_interval="daily",
            email_notifications=True,
            scan_completion_alerts=True,
            critical_finding_alerts=True,
            weekly_digest=False,
            default_scan_profile="Standard",
            auto_recon_enabled=True,
            two_factor_enabled=False,
            api_key=None
        )
        db.add(user_settings)
        await db.commit()
        await db.refresh(user_settings)
        logger.info("Initialized default settings for user %s", current_user.id)

    return user_settings


@router.patch("", response_model=UserSettingsResponse)
@router.patch("/", response_model=UserSettingsResponse, include_in_schema=False)
async def update_settings(
    settings_in: UserSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Partial update for authenticated user's settings.
    Updates only supplied fields without resetting unrelated preferences.
    Strictly isolated to current_user.id.
    """
    stmt = select(UserSettings).where(UserSettings.user_id == current_user.id)
    result = await db.execute(stmt)
    user_settings = result.scalars().first()

    if not user_settings:
        # Create default record before applying update
        user_settings = UserSettings(
            user_id=current_user.id,
            max_concurrency=4,
            auto_patch_validation=True,
            db_backup_interval="daily",
            email_notifications=True,
            scan_completion_alerts=True,
            critical_finding_alerts=True,
            weekly_digest=False,
            default_scan_profile="Standard",
            auto_recon_enabled=True,
            two_factor_enabled=False,
            api_key=None
        )
        db.add(user_settings)
        await db.commit()
        await db.refresh(user_settings)

    update_data = settings_in.model_dump(exclude_unset=True)
    if not update_data:
        return user_settings

    for field, value in update_data.items():
        setattr(user_settings, field, value)

    user_settings.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user_settings)

    logger.info("Updated settings for user %s: fields=%s", current_user.id, list(update_data.keys()))
    return user_settings


@router.post("/roll-api-key", response_model=ApiKeyResponse)
async def roll_api_key(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate and persist a new cryptographic API key for the authenticated user.
    """
    stmt = select(UserSettings).where(UserSettings.user_id == current_user.id)
    result = await db.execute(stmt)
    user_settings = result.scalars().first()

    if not user_settings:
        user_settings = UserSettings(user_id=current_user.id)
        db.add(user_settings)
        await db.commit()
        await db.refresh(user_settings)

    new_key = f"ap_live_{secrets.token_urlsafe(24)}"
    user_settings.api_key = new_key
    user_settings.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(user_settings)

    logger.info("Generated new API key for user %s", current_user.id)
    return ApiKeyResponse(api_key=new_key, created_at=user_settings.updated_at)
