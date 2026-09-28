"""Air-gapped user interface subsystem for TraceCrypt.

Features:
- Self-contained, responsive local web UI (HTML5, Vanilla CSS, modern ES modules)
- Zero external CDN dependencies; self-hosted offline assets
- Distinct workspaces: Sender (packaging), Recipient (reading & attribution), Investigator (workbench), Validator (ledger)
"""

from __future__ import annotations

from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

__status__ = "IMPLEMENTED"
STATIC_DIR = Path(__file__).parent / "web"


def mount_ui(app: FastAPI) -> None:
    """Mount the air-gapped web UI onto the FastAPI application."""
    if not STATIC_DIR.exists():
        return

    # Mount static assets directory
    app.mount("/ui", StaticFiles(directory=str(STATIC_DIR), html=True), name="ui")

    # Serve index.html on root path
    @app.get("/", include_in_schema=False)
    async def serve_root():
        index_file = STATIC_DIR / "index.html"
        return FileResponse(str(index_file))
