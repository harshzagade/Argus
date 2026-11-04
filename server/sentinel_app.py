"""Sentinel unified application.

Extends the Argus FastAPI app with:
  - Threat Intelligence Platform routes (/api/ti/v1/*)
  - A top-level health endpoint that reports all components

Run:
    uvicorn server.sentinel_app:app --host 0.0.0.0 --port 8000

Environment:
    ARGUS_API_KEY           shared API key for SIEM + TI (default: argus-dev-key)
    ARGUS_DB                SQLite path for SIEM data
    SENTINEL_TI_DB          SQLite path for TI data (default: ./sentinel-ti.db)
    SENTINEL_TI_URL         (optional) external TI URL; if set enrichment queries it
    SENTINEL_TI_FEED_INTERVAL  seconds between automatic feed refreshes (default: 3600)
    ANTHROPIC_API_KEY / OPENAI_API_KEY  optional LLM triage
    ABUSEIPDB_KEY / VT_KEY / GREYNOISE_KEY  optional external threat intel
"""
import os
import sys
from pathlib import Path

# Ensure the project root is in sys.path so `threatintel` package is importable
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

# ---- Import the Argus core app
from .app import app as argus_app

# ---- Import the TI platform (now importable as a proper package)
from threatintel.app import app as _ti_fastapi  # noqa: E402


# ---- Build the unified Sentinel app by combining both route sets
app = FastAPI(
    title="Sentinel — Unified Security Platform",
    version="1.0.0",
    description=(
        "Argus SIEM/XDR  +  SSH/HTTP Honeypot  +  Threat Intelligence Platform\n\n"
        "All components share one port (8000) and one API key."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
)


@app.get("/api/sentinel/health")
def sentinel_health():
    """Combined platform health check."""
    from .app import engine, playbooks
    from .db import now_iso
    return {
        "platform": "Sentinel",
        "version": "1.0.0",
        "components": {
            "siem": {
                "status": "ok",
                "rules": len(engine.rules),
                "playbooks": len(playbooks),
            },
            "threat_intel": {
                "status": "ok",
                "db": os.path.basename(os.environ.get("SENTINEL_TI_DB", "sentinel-ti.db")),
            },
            "honeypot": {
                "status": "configured",
                "note": "Start honeypot/honeypot_server.py separately on ports 2222/8080",
            },
        },
        "ts": now_iso(),
    }


# ---- Include all Argus routes (/api/v1/*, /ws/feed)
for route in argus_app.routes:
    # Skip the static dashboard mount — we add it ourselves at the end
    if hasattr(route, "name") and route.name == "dashboard":
        continue
    # Skip duplicate OpenAPI/docs routes
    if hasattr(route, "path") and route.path in ("/openapi.json", "/docs", "/redoc"):
        continue
    app.routes.append(route)

# Copy startup/shutdown handlers from argus_app
for handler in argus_app.router.on_startup:
    app.router.on_startup.append(handler)
for handler in argus_app.router.on_shutdown:
    app.router.on_shutdown.append(handler)

# ---- Include all TI routes (/api/ti/v1/*)
for route in _ti_fastapi.routes:
    if hasattr(route, "path") and route.path in ("/openapi.json", "/docs", "/redoc"):
        continue
    app.routes.append(route)

# Copy TI startup/shutdown
for handler in _ti_fastapi.router.on_startup:
    app.router.on_startup.append(handler)
for handler in _ti_fastapi.router.on_shutdown:
    app.router.on_shutdown.append(handler)

# ---- Serve the Sentinel dashboard at /
_dashboard_dir = _ROOT / "dashboard"
if _dashboard_dir.exists():
    app.mount("/", StaticFiles(directory=str(_dashboard_dir), html=True), name="dashboard")
