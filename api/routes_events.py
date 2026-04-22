from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, select

from api.deps import get_current_user
from core.metrics import collect_system_metrics
from core.models import BlockedIP, Event
from core.schemas import BlockedIPOut, EventOut, OverviewOut


router = APIRouter(prefix="/api/v1", tags=["events"])


@router.get("/overview", response_model=OverviewOut)
async def overview(request: Request, _=Depends(get_current_user)) -> dict:
    return await request.app.state.engine.overview()


@router.get("/events", response_model=list[EventOut])
async def list_events(
    request: Request,
    _=Depends(get_current_user),
    ip: str | None = None,
    domain: str | None = None,
    service: str | None = None,
    severity: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[Event]:
    async with request.app.state.db.session_factory() as session:
        query = select(Event).order_by(desc(Event.created_at)).limit(limit)
        if ip:
            query = query.where(Event.ip == ip)
        if domain:
            query = query.where(Event.domain == domain)
        if service:
            query = query.where(Event.service == service)
        if severity:
            query = query.where(Event.severity == severity)
        rows = await session.scalars(query)
        return rows.all()


@router.get("/blocks", response_model=list[BlockedIPOut])
async def list_blocks(request: Request, _=Depends(get_current_user)) -> list[BlockedIP]:
    async with request.app.state.db.session_factory() as session:
        rows = await session.scalars(
            select(BlockedIP).order_by(desc(BlockedIP.created_at)).limit(200)
        )
        return rows.all()


@router.get("/metrics")
async def metrics(request: Request, _=Depends(get_current_user)) -> dict:
    return collect_system_metrics()


@router.get("/events/stream")
async def event_stream(request: Request, _=Depends(get_current_user)) -> StreamingResponse:
    async def generator():
        async for message in request.app.state.event_bus.subscribe_events():
            yield f"data: {json.dumps(message.payload)}\n\n"

    return StreamingResponse(generator(), media_type="text/event-stream")


@router.get("/logs/stream")
async def log_stream(
    request: Request,
    _=Depends(get_current_user),
    source: str | None = None,
) -> StreamingResponse:
    async def generator():
        async for message in request.app.state.event_bus.subscribe_logs(source):
            yield f"data: {json.dumps(message.payload)}\n\n"

    return StreamingResponse(generator(), media_type="text/event-stream")


@router.get("/log-sources")
async def log_sources(request: Request, _=Depends(get_current_user)) -> dict:
    return request.app.state.settings.logs.all_patterns()
