#!/usr/bin/env python3
"""
Report REST API

A small HTTP API, served alongside the scanner WebSocket (see api.py), that builds
a security report from the most recent scan's findings and serves it for preview
(HTML / Markdown) and download (DOCX / PDF / Markdown).
"""

import os
import json
import uuid
import tempfile
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from test import LAST_SCAN
from reports.report_service import build_report, LAST_REPORT, REPORTS, REPORTS_DIR

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
    # Findings for the CURRENT user's CURRENT target, supplied by the authenticated
    # front-end (Supabase is the per-user source of truth). When present, the report
    # is built from THESE findings — never from the global last-scan — so a report
    # can't leak across accounts or linger after a target was deleted. An empty list
    # is meaningful ("scan ran, no vulnerabilities"); only None falls back to disk.
    vulnerabilities: list[dict] | None = None


# Maps a stored severity label to a representative rule score, since the report
# generator buckets severity from rule_analysis.score.
_SEVERITY_SCORE = {"CRITICAL": 3.5, "HIGH": 2.5, "MEDIUM": 1.5, "LOW": 0.5}


def _normalize_findings(raw: list[dict]) -> list[dict]:
    """
    Convert the front-end's display-shape findings (vuln_type/severity/parameter/
    payload/confidence/explanation/…) into the entry shape the report generator
    expects. Every supplied finding is a confirmed vulnerability.
    """
    normalized: list[dict] = []
    for v in raw or []:
        if not isinstance(v, dict):
            continue
        severity = str(v.get("severity") or "").upper()
        confidence = v.get("confidence") or 0
        if severity in _SEVERITY_SCORE:
            score = _SEVERITY_SCORE[severity]
        elif confidence >= 0.8:
            score = 2.5
        elif confidence >= 0.5:
            score = 1.5
        else:
            score = 0.5

        parameter = v.get("parameter")
        if isinstance(parameter, list):
            parameter = ", ".join(str(p) for p in parameter)

        normalized.append({
            "vuln_type": v.get("vuln_type"),
            "is_vulnerable": True,
            "attack_details": {
                "payload": v.get("payload", "N/A"),
                "parameter": parameter if parameter is not None else "Unknown",
                "category": v.get("category", ""),
                "url": v.get("url", ""),
                "method": v.get("method", ""),
            },
            "rule_analysis": {"score": score, "evidence": []},
            "ai_analysis": {
                "verdict": "yes",
                "confidence": confidence,
                "explanation": v.get("explanation", "Analysis not available."),
            },
            "severity_analysis": (
                {
                    "severity": severity,
                    "confidence": confidence,
                    "model_used": False,
                    "risk_factors": [],
                }
                if severity
                else None
            ),
        })
    return normalized


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "report-api"}


@app.post("/api/generate-report")
def generate_report(payload: GenerateReportRequest | None = None):
    """
    Build a report and return preview content + scoped download links.

    Preferred path: the client sends `vulnerabilities` for the current user's
    current target; we build a stateless report from those. Legacy fallback (no
    findings supplied): the most recent scan file on disk.
    """
    target_url = (
        (payload.target_url if payload else None)
        or LAST_SCAN.get("target_url")
        or "Unknown"
    )
    report_id = uuid.uuid4().hex
    findings = payload.vulnerabilities if payload else None

    try:
        if findings is not None:
            # Per-user, per-target findings → write to a temp file consumed only
            # by this request, then build the report from it.
            normalized = _normalize_findings(findings)
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    "w", suffix=".json", delete=False, encoding="utf-8"
                ) as tmp:
                    json.dump(normalized, tmp)
                    tmp_path = tmp.name
                result = build_report(
                    tmp_path, target_url=target_url, report_id=report_id
                )
            finally:
                if tmp_path:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
        else:
            # Legacy fallback: most recent scan file on disk.
            results_file = LAST_SCAN.get("results_file") or DEFAULT_RESULTS_FILE
            if not os.path.exists(results_file):
                return JSONResponse(
                    status_code=404,
                    content={"error": "No scan results found. Run a scan first."},
                )
            result = build_report(
                results_file, target_url=target_url, report_id=report_id
            )
    except Exception as e:
        logger.exception("Report generation failed")
        return JSONResponse(
            status_code=500, content={"error": f"Report generation failed: {e}"}
        )

    available = result["downloads"]
    base = "/api/report/download"

    def link(fmt: str) -> str | None:
        return f"{base}?format={fmt}&id={report_id}" if available.get(fmt) else None

    return {
        "target_url": target_url,
        "report_id": report_id,
        "markdown_content": result["markdown_content"],
        "html_content": result["html_content"],
        "downloads": {"md": link("md"), "docx": link("docx"), "pdf": link("pdf")},
    }


@app.get("/api/report/download")
def download_report(format: str = "docx", id: str | None = None):
    """
    Download a generated report in the requested format. `id` selects the exact
    report produced by a generate call (so concurrent users get their own report);
    without it we fall back to the most recently generated one.
    """
    fmt = format.lower()
    media_types = {
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "pdf": "application/pdf",
        "md": "text/markdown",
    }
    if fmt not in media_types:
        return JSONResponse(status_code=400, content={"error": f"Unsupported format: {format}"})

    record = REPORTS.get(id) if id else None
    path = (record or LAST_REPORT).get(fmt)
    if not path or not os.path.exists(path):
        return JSONResponse(
            status_code=404,
            content={"error": f"No '{fmt}' report available. Generate a report first."},
        )

    return FileResponse(path, media_type=media_types[fmt], filename=os.path.basename(path))
