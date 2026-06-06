# RedKit AI Scanner — API Documentation

The AI service provides two co-located APIs, started together by `api.py`:

| API | Protocol | Default port | Purpose |
|---|---|---|---|
| **Scanner** | WebSocket | `3006` (`API_PORT`) | Real-time SQL Injection + Reflected XSS scanning |
| **Report** | REST/HTTP | `3007` (`REPORT_API_PORT`) | Build & download a report from the latest scan |

Both run in the same process (`python api.py`). If the report API's optional dependencies are missing, the scanner still starts and a warning is logged.

## Configuration

Environment variables (see `template.env`):

| Variable | Default | Description |
|---|---|---|
| `API_PORT` | `8765` (compose uses `3006`) | Scanner WebSocket port |
| `API_HOST` | `0.0.0.0` | Bind host for both servers |
| `REPORT_API_PORT` | `3007` | Report REST API port |
| `COHERE_API_KEY` | — | LLM used to confirm findings |
| `GEMINI_API_KEY` | — | Optional secondary key |

## Running

```bash
pip install -r requirements.txt   # includes fastapi, uvicorn, markdown, weasyprint, python-docx
python api.py
# Scanner:  ws://0.0.0.0:3006
# Report:   http://0.0.0.0:3007
```

PDF reports require WeasyPrint's native libraries (installed in the Docker image:
`libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libcairo2 shared-mime-info`). If they're
absent, PDF is skipped while HTML/Markdown/DOCX still work.

---

# 1. Scanner WebSocket API (port 3006)

Connect to `ws://<host>:3006`. On connect the server sends:

```json
{ "type": "connected", "client_id": "<uuid>", "message": "Connected to Vulnerability Scanner API (SQLi + XSS)" }
```

## Starting a scan — `start_scan`

There are **two modes**:

### A) Full raw request (recommended — tests body params & any method)

Send the captured HTTP request verbatim. This lets the scanner test **POST/PUT/PATCH body
parameters**, GET/DELETE query parameters, JSON bodies, and replays captured headers
(cookies/authorization) so authenticated endpoints stay authenticated.

```json
{
  "type": "start_scan",
  "raw_request": "POST /login.php HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: sid=abc\r\n\r\nuname=admin&pass=secret",
  "url": "https://example.com/login.php"
}
```

- `raw_request` (string, required for this mode): the full raw HTTP request (request line + headers + blank line + body).
- `url` (string, optional but recommended): the absolute URL, used to resolve scheme/host reliably (the raw request line often carries only a path).

**Body handling:**
- `Content-Type: application/x-www-form-urlencoded` → body parsed into params and sent as a form body.
- `Content-Type: application/json` (or a JSON-looking body) → keys parsed into params and sent as a JSON body.
- Parameter placement follows the method: body methods (POST/PUT/PATCH) test **body** params; other methods test **query** params. (A request mixing query + body params tests the method-appropriate set.)

### B) URL only (recon / legacy)

```json
{ "type": "start_scan", "url": "http://example.com/listproducts.php?cat=1" }
```

The scanner parses URL query params and fetches the page to discover `<form>` inputs, then tests them.

> One of `raw_request` or `url` is required; otherwise an `error` is returned.

## Other client messages

| Message | Shape | Effect |
|---|---|---|
| `ping` | `{ "type": "ping" }` | Server replies `{ "type": "pong", ... }` |
| `watch_scan` | `{ "type": "watch_scan", "scan_id": "<id>" }` | Subscribe to another in-flight scan |
| `list_scans` | `{ "type": "list_scans" }` | Returns active scans |

## Server → client message stream

During a scan the server streams these message types:

**`scan_start`**
```json
{ "type": "scan_start", "scan_id": "<uuid>", "target_url": "<url>", "timestamp": "<iso>" }
```

**`progress`** — one per payload tested
```json
{ "type": "progress", "url": "<endpoint>", "current": 12, "total": 240, "timestamp": "<iso>" }
```

**`vulnerability_found`** — emitted immediately when a finding is confirmed (covers **both** SQLi and XSS via `vuln_type`)
```json
{
  "type": "vulnerability_found",
  "vulnerability": {
    "vuln_type": "sql_injection" | "reflected_xss",
    "parameter": "<name>" | ["p1", "p2"],
    "payload": "<injected string>",
    "url": "<target url>",
    "method": "GET" | "POST" | "PUT" | "PATCH" | "...",
    "confidence": 0.0,
    "explanation": "<LLM explanation>",
    "raw_request": "<reconstructed HTTP request>",
    "raw_response": "<HTTP response snippet>",
    "timestamp": "<iso>"
  }
}
```

**`endpoint_transition`**
```json
{ "type": "endpoint_transition", "completed_url": "<url>", "next_url": "<url>|null", "timestamp": "<iso>" }
```

**`scan_complete`** — terminal
```json
{
  "type": "scan_complete",
  "scan_id": "<uuid>",
  "result": {
    "success": true,
    "total_endpoints": 1,
    "total_vulnerabilities": 2,
    "sqli_vulnerabilities": 1,
    "xss_vulnerabilities": 1,
    "results_file": "<path to scan_results.json>"
  },
  "total_vulnerabilities": 2,
  "vulnerabilities": [ /* all vulnerability objects from this scan */ ],
  "timestamp": "<iso>"
}
```

**`error`**
```json
{ "type": "error", "error": "<message>", "timestamp": "<iso>" }
```

After each scan, results are written to `core/scan_results.json` and recorded as the
"latest scan" for the report API.

---

# 2. Report REST API (port 3007)

Builds a security report **from the most recent scan's findings** (no manual data entry).
Base URL: `http://<host>:3007`. CORS allows all origins.

### `GET /api/health`
```json
{ "status": "ok", "service": "report-api" }
```

### `POST /api/generate-report`
Generates the report from the latest `scan_results.json` and returns preview content plus
download links for each available format.

Request body (optional):
```json
{ "target_url": "https://example.com" }
```
- `target_url` (optional): overrides the report's target label; defaults to the last scan's target.

Response `200`:
```json
{
  "target_url": "https://example.com",
  "markdown_content": "# Vulnerability Assessment Report\n...",
  "html_content": "<!DOCTYPE html>... styled report ...",
  "downloads": {
    "md":   "/api/report/download?format=md",
    "docx": "/api/report/download?format=docx",
    "pdf":  "/api/report/download?format=pdf"
  }
}
```
- `html_content` is the Markdown report rendered to a styled, standalone HTML document (used for in-app preview).
- A `downloads.*` value is `null` if that format could not be produced (e.g. `pdf` when WeasyPrint native libs are missing).
- `404` if no scan has been run yet; `500` on generation failure.

### `GET /api/report/download?format=docx|pdf|md`
Returns the most recently generated report file (`FileResponse`).
- `format` (default `docx`): one of `docx`, `pdf`, `md`.
- `400` for an unsupported format; `404` if no report has been generated yet.

---

## End-to-end flow (front-end)

1. **Interceptor** → right-click a captured request → **Do Quick Scan**. The front-end sends the
   full `raw_request` (+ `url`) over the scanner WebSocket; for history rows without a loaded body
   it falls back to a URL-only scan.
2. **/AiScanner** streams `progress` / `vulnerability_found` and renders results (SQLi & XSS).
3. **Generate Report** → **/AiReport** calls `POST /api/generate-report`, previews `html_content`,
   and offers **DOCX / PDF / Markdown** downloads via `/api/report/download`.
