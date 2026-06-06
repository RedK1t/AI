#!/usr/bin/env python3
"""
Report REST API

A small HTTP API, served alongside the scanner WebSocket (see api.py), that builds
a security report from the most recent scan's findings and serves it for preview
(HTML / Markdown) and download (DOCX / PDF / Markdown).
"""

import os
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from test import LAST_SCAN
from reports.report_service import build_report, LAST_REPORT, REPORTS_DIR

logger = logging.getLogger(__name__)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RESULTS_FILE = os.path.join(SCRIPT_DIR, "core", "scan_results.json")

app = FastAPI(title="RedKit AI Report API", version="1.0.0")

# Allow all origins (the front-end is served from a different port/host)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class GenerateReportRequest(BaseModel):
    # Optional override; defaults to the most recent scan's target
    target_url: str | None = None


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "report-api"}


@app.post("/api/generate-report")
def generate_report(payload: GenerateReportRequest | None = None):
    """
    Build a report from the latest scan results and return preview content +
    flags indicating which downloadable formats are available.
    """
    results_file = LAST_SCAN.get("results_file") or DEFAULT_RESULTS_FILE
    if not os.path.exists(results_file):
        return JSONResponse(
            status_code=404,
            content={"error": "No scan results found. Run a scan first."},
        )

    target_url = (payload.target_url if payload else None) or LAST_SCAN.get("target_url") or "Unknown"

    try:
        result = build_report(results_file, target_url=target_url)
    except Exception as e:
        logger.exception("Report generation failed")
        return JSONResponse(status_code=500, content={"error": f"Report generation failed: {e}"})

    available = result["downloads"]
    base = "/api/report/download"
    return {
        "target_url": target_url,
        "markdown_content": result["markdown_content"],
        "html_content": result["html_content"],
        "downloads": {
            "md": f"{base}?format=md" if available.get("md") else None,
            "docx": f"{base}?format=docx" if available.get("docx") else None,
            "pdf": f"{base}?format=pdf" if available.get("pdf") else None,
        },
    }


@app.get("/api/report/download")
def download_report(format: str = "docx"):
    """Download the most recently generated report in the requested format."""
    fmt = format.lower()
    media_types = {
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "pdf": "application/pdf",
        "md": "text/markdown",
    }
    if fmt not in media_types:
        return JSONResponse(status_code=400, content={"error": f"Unsupported format: {format}"})

    path = LAST_REPORT.get(fmt)
    if not path or not os.path.exists(path):
        return JSONResponse(
            status_code=404,
            content={"error": f"No '{fmt}' report available. Generate a report first."},
        )

    return FileResponse(path, media_type=media_types[fmt], filename=os.path.basename(path))
