"""
Report service: turns a completed scan's results (scan_results.json) into a
security report in multiple formats (Markdown, styled HTML, DOCX, PDF).

Reuses SingleVulnReportGenerator for the DOCX + Markdown content, renders the
Markdown to a styled HTML document for in-app preview, and (best-effort) renders
that HTML to PDF via WeasyPrint.
"""

import os
from datetime import datetime

import markdown as md_lib

from reports.report_generator import SingleVulnReportGenerator

# AI/ project root, then the reports/ output directory
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(SCRIPT_DIR, "reports")

# Artifact paths of the most recently generated report, read by the download endpoint
LAST_REPORT = {"md": None, "docx": None, "pdf": None, "html": None}

# Styled HTML wrapper for the rendered Markdown (palette mirrors the RedKit report theme)
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Assessment Report</title>
<style>
  :root {{ color-scheme: light; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.6; color: #1f2937; background: #ffffff;
    max-width: 900px; margin: 0 auto; padding: 32px;
  }}
  h1 {{ color: #b91c1c; border-bottom: 3px solid #b91c1c; padding-bottom: 8px; }}
  h2 {{ color: #991b1b; margin-top: 28px; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; }}
  h3 {{ color: #374151; margin-top: 20px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
  th, td {{ border: 1px solid #e5e7eb; padding: 8px 12px; text-align: left; vertical-align: top; }}
  th {{ background: #f9fafb; color: #111827; }}
  tr:nth-child(even) td {{ background: #fafafa; }}
  code, pre {{ font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; }}
  pre {{ background: #0b1020; color: #e5e7eb; padding: 12px; border-radius: 6px; overflow-x: auto; }}
  code {{ background: #f3f4f6; padding: 2px 5px; border-radius: 4px; }}
  pre code {{ background: transparent; padding: 0; }}
  hr {{ border: none; border-top: 1px solid #e5e7eb; margin: 24px 0; }}
  blockquote {{ border-left: 4px solid #b91c1c; margin: 16px 0; padding: 4px 16px; color: #4b5563; background: #fef2f2; }}
</style>
</head>
<body>
{content}
</body>
</html>"""


def _markdown_to_html(md_text: str) -> str:
    """Render report Markdown to a styled, standalone HTML document."""
    body = md_lib.markdown(md_text, extensions=["tables", "fenced_code", "sane_lists"])
    return HTML_TEMPLATE.format(content=body)


def build_report(scan_results_path: str, target_url: str = "Unknown") -> dict:
    """
    Build a report from the given scan results file.

    Returns:
        {
          "markdown_content": str,
          "html_content": str,
          "downloads": {"md": bool, "docx": bool, "pdf": bool}
        }
    The actual files are tracked in LAST_REPORT for the download endpoint.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    generator = SingleVulnReportGenerator(scan_results_path, target_url=target_url)

    # Markdown (generate_markdown writes a file and returns its path)
    md_path = generator.generate_markdown(output_dir=REPORTS_DIR)
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()

    # DOCX (pass an absolute path so it lands in REPORTS_DIR regardless of CWD)
    docx_path = os.path.join(REPORTS_DIR, f"security_report_{timestamp}.docx")
    try:
        docx_path = generator.generate_docx(output_path=docx_path)
    except Exception as e:
        print(f"[report] DOCX generation failed: {e}")
        docx_path = None

    # HTML (rendered from the Markdown, styled for preview)
    html = _markdown_to_html(md_text)
    html_path = os.path.join(REPORTS_DIR, f"report_{timestamp}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # PDF (best-effort; requires WeasyPrint native libraries to be installed)
    pdf_path = None
    try:
        from weasyprint import HTML as WeasyHTML
        pdf_path = os.path.join(REPORTS_DIR, f"report_{timestamp}.pdf")
        WeasyHTML(string=html).write_pdf(pdf_path)
    except Exception as e:
        print(f"[report] PDF generation skipped/failed: {e}")
        pdf_path = None

    LAST_REPORT.update({"md": md_path, "docx": docx_path, "pdf": pdf_path, "html": html_path})

    return {
        "markdown_content": md_text,
        "html_content": html,
        "downloads": {
            "md": md_path is not None and os.path.exists(md_path),
            "docx": docx_path is not None and os.path.exists(docx_path),
            "pdf": pdf_path is not None and os.path.exists(pdf_path),
        },
    }
