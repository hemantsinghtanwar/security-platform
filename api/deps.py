from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from jose import JWTError
from sqlalchemy import select

from core.models import User
from core.security import decode_access_token


def get_engine(request: Request):
    return request.app.state.engine


def get_settings(request: Request):
    return request.app.state.settings


async def get_current_user(request: Request):
    settings = request.app.state.settings
    token = request.cookies.get("access_token")
    auth_header = request.headers.get("Authorization")
    if not token and auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        payload = decode_access_token(
            token,
            settings.api.jwt_secret,
            settings.api.jwt_algorithm,
        )
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    username = payload.get("sub")
    async with request.app.state.db.session_factory() as session:
        user = await session.scalar(select(User).where(User.username == username))
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user


async def require_csrf(request: Request, _: User = Depends(get_current_user)) -> None:
    cookie_token = request.cookies.get("csrf_token")
    header_token = request.headers.get("X-CSRF-Token")
    if not cookie_token or not header_token or cookie_token != header_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
