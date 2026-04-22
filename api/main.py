from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from api import routes_auth, routes_events, routes_settings
from core import models
from core.config import load_settings
from core.database import Database
from core.engine import SecurityEngine
from core.event_bus import EventBus


BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "dashboard" / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    loaded = load_settings()
    db = Database(loaded.data.database.url)
    bus = EventBus()
    engine = SecurityEngine(loaded.data, db, bus)
    app.state.settings = loaded.data
    app.state.db = db
    app.state.event_bus = bus
    app.state.engine = engine
    app.state.models = models
    await engine.start()
    try:
        yield
    finally:
        await engine.stop()
        await db.dispose()


app = FastAPI(title="WHM Security Platform", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "dashboard" / "static")), name="static")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes_auth.router)
app.include_router(routes_events.router)
app.include_router(routes_settings.router)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
