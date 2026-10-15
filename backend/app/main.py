"""FastAPI application factory.

Run locally:  uvicorn app.main:app --reload   (from the backend/ directory)
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.reviews import router as reviews_router
from app.config import Settings, load_project_config
from app.database import init_db, make_engine, make_session_factory


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    # Fail fast if the research configuration is missing or invalid.
    project_config = load_project_config(settings.project_config_path)
    engine = make_engine(settings.database_url)
    session_factory = make_session_factory(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db(engine)
        yield
        engine.dispose()

    app = FastAPI(title="Evidence-Based Security Code Review", version=project_config.project.version, lifespan=lifespan)
    app.state.settings = settings
    app.state.project_config = project_config
    app.state.engine = engine
    app.state.session_factory = session_factory

    @app.get("/health", tags=["meta"])
    def health():
        return {"status": "ok", "version": project_config.project.version}

    app.include_router(reviews_router)

    # Basic demonstration UI. API routes are registered first so they remain
    # available; the root mount serves frontend/index.html for local demos.
    frontend_dir = Path(__file__).resolve().parents[2] / "frontend"
    if frontend_dir.is_dir():
        app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

    return app


app = create_app()
