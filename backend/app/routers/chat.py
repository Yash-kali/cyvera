from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.database import get_db
from app.models import User, ChatMessage
from app.schemas import ChatMessageCreate, ChatMessageResponse, ChatResponse
from app.auth import get_current_user
from app.services.chat_copilot import process_copilot_chat

router = APIRouter(prefix="/api/v1/chat", tags=["AI Security Copilot"])


@router.post("", response_model=ChatResponse, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=ChatResponse, status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def send_chat_message(
    payload: ChatMessageCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    POST /api/v1/chat
    Process operator query with AI Security Copilot (Google Gemini API).
    Saves user query and assistant response in conversation history.
    """
    session_id = payload.session_id or "default"

    # Save user message in DB
    user_msg_entry = ChatMessage(
        user_id=current_user.id,
        session_id=session_id,
        sender="user",
        message=payload.message,
        context=payload.context
    )
    db.add(user_msg_entry)
    await db.commit()
    await db.refresh(user_msg_entry)

    # Process AI Copilot response
    ai_reply = process_copilot_chat(
        user_message=payload.message,
        context=payload.context
    )

    # Save assistant reply in DB
    assistant_msg_entry = ChatMessage(
        user_id=current_user.id,
        session_id=session_id,
        sender="assistant",
        message=ai_reply,
        context=payload.context
    )
    db.add(assistant_msg_entry)
    await db.commit()
    await db.refresh(assistant_msg_entry)

    # Fetch recent conversation history
    stmt_hist = (
        select(ChatMessage)
        .where(ChatMessage.user_id == current_user.id, ChatMessage.session_id == session_id)
        .order_by(ChatMessage.created_at.asc())
        .limit(50)
    )
    res_hist = await db.execute(stmt_hist)
    history_records = res_hist.scalars().all()

    return ChatResponse(
        reply=ai_reply,
        user_message=payload.message,
        context=payload.context,
        created_at=assistant_msg_entry.created_at,
        history=[ChatMessageResponse.model_validate(h) for h in history_records]
    )


@router.get("/history", response_model=List[ChatMessageResponse])
async def get_chat_history(
    session_id: str = "default",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    GET /api/v1/chat/history
    Retrieves stored conversation history for authenticated user.
    """
    stmt = (
        select(ChatMessage)
        .where(ChatMessage.user_id == current_user.id, ChatMessage.session_id == session_id)
        .order_by(ChatMessage.created_at.asc())
    )
    result = await db.execute(stmt)
    records = result.scalars().all()
    return records
