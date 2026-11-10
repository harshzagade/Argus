"""Deprecated entry point kept for compatibility.

Sentinel was renamed to Argus. This module simply re-exports the Argus
unified app so old commands (uvicorn server.sentinel_app:app) keep
working. New deployments should use server.argus_app.
"""
from .argus_app import app  # noqa: F401
