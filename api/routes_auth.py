from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select

from api.deps import get_current_user
from core.models import User
from core.schemas import LoginRequest, UserOut
from core.security import create_access_token, generate_csrf_token, verify_password


router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login")
async def login(payload: LoginRequest, request: Request, response: Response) -> dict:
    settings = request.app.state.settings
    async with request.app.state.db.session_factory() as session:
        user = await session.scalar(select(User).where(User.username == payload.username))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(
        subject=user.username,
        secret=settings.api.jwt_secret,
        algorithm=settings.api.jwt_algorithm,
        expires_minutes=settings.api.jwt_expire_minutes,
    )
    csrf_token = generate_csrf_token()
    response.set_cookie(
        "access_token",
        token,
        httponly=True,
        secure=settings.api.secure_cookies,
        samesite="strict",
        max_age=settings.api.jwt_expire_minutes * 60,
    )
    response.set_cookie(
        "csrf_token",
        csrf_token,
        httponly=False,
        secure=settings.api.secure_cookies,
        samesite="strict",
        max_age=settings.api.jwt_expire_minutes * 60,
    )
    return {"user": UserOut.model_validate(user), "csrf_token": csrf_token}


@router.post("/logout")
async def logout(response: Response) -> dict:
    response.delete_cookie("access_token")
    response.delete_cookie("csrf_token")
    return {"status": "ok"}


@router.get("/me", response_model=UserOut)
async def me(user=Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)
