from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import desc, select

from api.deps import get_current_user, require_csrf
from core.models import AlertRecipient, Setting
from core.schemas import (
    AlertRecipientCreate,
    AlertRecipientOut,
    EmailSettingsOut,
    EmailSettingsUpdate,
    ManualBlockRequest,
)


router = APIRouter(prefix="/api/v1", tags=["settings"])


@router.get("/settings/recipients", response_model=list[AlertRecipientOut])
async def list_recipients(request: Request, _=Depends(get_current_user)) -> list[AlertRecipient]:
    async with request.app.state.db.session_factory() as session:
        rows = await session.scalars(
            select(AlertRecipient).order_by(desc(AlertRecipient.created_at))
        )
        return rows.all()


@router.post("/settings/recipients", response_model=AlertRecipientOut, dependencies=[Depends(require_csrf)])
async def create_recipient(
    payload: AlertRecipientCreate,
    request: Request,
    _=Depends(get_current_user),
) -> AlertRecipient:
    async with request.app.state.db.session_factory() as session:
        existing = await session.scalar(select(AlertRecipient).where(AlertRecipient.email == payload.email))
        if existing:
            raise HTTPException(status_code=409, detail="Recipient already exists")
        recipient = AlertRecipient(**payload.model_dump())
        session.add(recipient)
        await session.commit()
        await session.refresh(recipient)
        return recipient


@router.delete("/settings/recipients/{recipient_id}", dependencies=[Depends(require_csrf)])
async def delete_recipient(
    recipient_id: int,
    request: Request,
    _=Depends(get_current_user),
) -> dict:
    async with request.app.state.db.session_factory() as session:
        recipient = await session.get(AlertRecipient, recipient_id)
        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient not found")
        await session.delete(recipient)
        await session.commit()
    return {"status": "deleted"}


@router.get("/settings/email", response_model=EmailSettingsOut)
async def get_email_settings(request: Request, _=Depends(get_current_user)) -> dict:
    async with request.app.state.db.session_factory() as session:
        rows = await session.scalars(select(Setting).where(Setting.key.like("smtp_%")))
        settings = {row.key: row.value for row in rows.all()}
    return {
        "host": settings.get("smtp_host", request.app.state.settings.smtp.host),
        "port": int(settings.get("smtp_port", request.app.state.settings.smtp.port)),
        "sender": settings.get("smtp_sender", request.app.state.settings.smtp.sender),
        "username": settings.get("smtp_username") or None,
        "use_tls": json.loads(settings.get("smtp_use_tls", "false")),
        "use_starttls": json.loads(settings.get("smtp_use_starttls", "false")),
    }


@router.put("/settings/email", dependencies=[Depends(require_csrf)])
async def update_email_settings(
    payload: EmailSettingsUpdate,
    request: Request,
    _=Depends(get_current_user),
) -> dict:
    async with request.app.state.db.session_factory() as session:
        for key, value in {
            "smtp_host": payload.host,
            "smtp_port": str(payload.port),
            "smtp_sender": payload.sender,
            "smtp_username": payload.username or "",
            "smtp_password": payload.password or "",
            "smtp_use_tls": json.dumps(payload.use_tls),
            "smtp_use_starttls": json.dumps(payload.use_starttls),
        }.items():
            row = await session.get(Setting, key)
            if row is None:
                session.add(Setting(key=key, value=value))
            else:
                row.value = value
        await session.commit()
    request.app.state.engine.emailer.smtp_settings.host = payload.host
    request.app.state.engine.emailer.smtp_settings.port = payload.port
    request.app.state.engine.emailer.smtp_settings.sender = payload.sender
    request.app.state.engine.emailer.smtp_settings.username = payload.username
    request.app.state.engine.emailer.smtp_settings.password = payload.password
    request.app.state.engine.emailer.smtp_settings.use_tls = payload.use_tls
    request.app.state.engine.emailer.smtp_settings.use_starttls = payload.use_starttls
    return {"status": "updated"}


@router.post("/blocks", dependencies=[Depends(require_csrf)])
async def manual_block(
    payload: ManualBlockRequest,
    request: Request,
    _=Depends(get_current_user),
) -> dict:
    action = await request.app.state.engine.ban_manager.manual_block(
        ip=payload.ip,
        reason=payload.reason,
        permanent=payload.permanent,
        duration_minutes=payload.duration_minutes,
    )
    return {"status": action}


@router.delete("/blocks/{ip}", dependencies=[Depends(require_csrf)])
async def unblock(
    ip: str,
    request: Request,
    _=Depends(get_current_user),
) -> dict:
    action = await request.app.state.engine.ban_manager.unblock(ip)
    return {"status": action}
