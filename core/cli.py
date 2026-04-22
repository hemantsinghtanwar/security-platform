from __future__ import annotations

import argparse
import asyncio
import getpass

from sqlalchemy import select

from core.config import load_settings
from core.database import Database
from core.models import AlertRecipient, Base, User
from core.security import hash_password


async def init_db() -> None:
    settings = load_settings().data
    db = Database(settings.database.url)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with db.session_factory() as session:
        existing = await session.scalar(
            select(AlertRecipient).where(AlertRecipient.email == settings.admin_email)
        )
        if existing is None:
            session.add(AlertRecipient(email=settings.admin_email, name="Admin"))
            await session.commit()
    await db.dispose()


async def create_admin(username: str, password: str | None) -> None:
    settings = load_settings().data
    db = Database(settings.database.url)
    async with db.session_factory() as session:
        existing = await session.scalar(select(User).where(User.username == username))
        if existing:
            raise SystemExit(f"user {username!r} already exists")
        if not password:
            password = getpass.getpass("Admin password: ")
        session.add(User(username=username, password_hash=hash_password(password)))
        await session.commit()
    await db.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Security platform CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init-db")
    create_admin_parser = subparsers.add_parser("create-admin")
    create_admin_parser.add_argument("--username", required=True)
    create_admin_parser.add_argument("--password")

    args = parser.parse_args()
    if args.command == "init-db":
        asyncio.run(init_db())
    elif args.command == "create-admin":
        asyncio.run(create_admin(args.username, args.password))


if __name__ == "__main__":
    main()
