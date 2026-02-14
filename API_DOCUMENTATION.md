# SQL Injection Scanner WebSocket API

A real-time WebSocket API for SQL injection vulnerability scanning. The scanner discovers forms and inputs on web pages and tests them for SQL injection vulnerabilities, reporting findings as they are discovered.

## Features

- **Real-time Results**: Get vulnerability findings instantly as they're discovered
- **Smart Testing**: Stops testing a parameter once a vulnerability is found and moves to the next
- **Form Discovery**: Automatically extracts forms and inputs from target URLs
- **Multi-Payload Testing**: Tests various SQL injection payloads with different encoding modes
- **AI-Powered Analysis**: Uses rule-based analysis and LLM for vulnerability confirmation

## Installation

```bash
pip install python-dotenv websockets
```

## Configuration

Create or edit the `.env` file in the project root:

```env
API_PORT=8765
API_HOST=0.0.0.0
GEMINI_API_KEY=your_gemini_api_key
COHERE_API_KEY=your_cohere_api_key
```

## Running the API

```bash
python api.py
```

The server will start on `ws://0.0.0.0:8765` (or the port specified in `.env`).

## WebSocket Connection

Connect to the WebSocket endpoint:

```javascript
const ws = new WebSocket('ws://localhost:8765');
```

---

## Message Protocol

All messages are JSON-encoded. Below are the message flows grouped by functionality.

### 1. Connection Flow

**When you connect to the server:**

**→ Client connects to:** `ws://localhost:8765`

**← Server sends:** `connected`

```json
{
  "type": "connected",
  "client_id": "uuid",
  "message": "Connected to SQL Injection Scanner API"
}
```

---

### 2. Start Scan Flow

**To initiate a new SQL injection scan:**

**→ Client sends:** `start_scan`

```json
{
  "type": "start_scan",
  "url": "http://example.com/login"
}
```

**← Server responds:** `scan_start`

```json
{
  "type": "scan_start",
  "scan_id": "uuid",
  "target_url": "http://example.com/login",
  "timestamp": "2024-01-15T10:30:00"
}
```

**← Server sends multiple:** `progress` (during scanning)

```json
{
  "type": "progress",
  "message": "   [POST] uid = ' OR '1'='1...",
  "current": 15,
  "total": 162,
  "timestamp": "2024-01-15T10:30:05"
}
```

**← Server sends (if vulnerability found):** `vulnerability_found`

```json
{
  "type": "vulnerability_found",
  "vulnerability": {
    "parameter": "username",
    "payload": "' OR '1'='1",
    "url": "http://example.com/login",
    "method": "POST",
    "confidence": 0.95,
    "explanation": "SQL injection confirmed via boolean-based blind injection",
    "timestamp": "2024-01-15T10:30:15"
  }
}
```

**← Server sends (when complete):** `scan_complete`

```json
{
  "type": "scan_complete",
  "scan_id": "uuid",
  "result": {
    "success": true,
    "total_endpoints": 3,
    "total_vulnerabilities": 2,
    "results_file": "core/scan_results.json"
  },
  "total_vulnerabilities": 2,
  "vulnerabilities": [
    {
      "parameter": "username",
      "payload": "' OR '1'='1",
      "confidence": 0.95
    }
  ],
  "timestamp": "2024-01-15T10:35:00"
}
```

---

### 3. Watch Scan Flow

**To watch an existing scan in progress:**

**→ Client sends:** `watch_scan`

```json
{
  "type": "watch_scan",
  "scan_id": "uuid-of-scan"
}
```

**← Server responds (if scan exists):** `watching_scan`

```json
{
  "type": "watching_scan",
  "scan_id": "uuid-of-scan",
  "timestamp": "2024-01-15T10:30:00"
}
```

**← Server responds (if scan not found):** `error`

```json
{
  "type": "error",
  "error": "Scan uuid-of-scan not found",
  "timestamp": "2024-01-15T10:30:00"
}
```

---

### 4. List Active Scans Flow

**To get all currently running scans:**

**→ Client sends:** `list_scans`

```json
{
  "type": "list_scans"
}
```

**← Server responds:** `scans_list`

```json
{
  "type": "scans_list",
  "scans": [
    {
      "scan_id": "scan-uuid-1",
      "target_url": "http://example.com/login",
      "start_time": "2024-01-15T10:30:00"
    }
  ],
  "timestamp": "2024-01-15T10:30:00"
}
```

---

### 5. Keep-Alive Flow

**To check if the connection is alive:**

**→ Client sends:** `ping`

```json
{
  "type": "ping"
}
```

**← Server responds:** `pong`

```json
{
  "type": "pong",
  "timestamp": "2024-01-15T10:30:00"
}
```

---

### 6. Error Handling Flow

**Server sends error messages when something goes wrong:**

**← Server sends:** `error`

**Missing URL parameter:**
```json
{
  "type": "error",
  "error": "Missing 'url' parameter",
  "timestamp": "2024-01-15T10:30:00"
}
```

**Invalid JSON:**
```json
{
  "type": "error",
  "error": "Invalid JSON message",
  "timestamp": "2024-01-15T10:30:00"
}
```

**Unknown message type:**
```json
{
  "type": "error",
  "error": "Unknown message type: invalid_type",
  "timestamp": "2024-01-15T10:30:00"
}
```

**Scan error:**
```json
{
  "type": "error",
  "scan_id": "uuid",
  "error": "Error description here",
  "timestamp": "2024-01-15T10:30:00"
}
```

---

## Example Usage

### JavaScript Client Example

```javascript
const ws = new WebSocket('ws://localhost:8765');

ws.onopen = () => {
  console.log('Connected to SQL Injection Scanner API');
  
  // Start a scan
  ws.send(JSON.stringify({
    type: 'start_scan',
    url: 'http://altoro.testfire.net/login.jsp'
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  switch (data.type) {
    case 'connected':
      console.log('Client ID:', data.client_id);
      break;
      
    case 'progress':
      console.log(`Progress: ${data.current}/${data.total} - ${data.message}`);
      break;
      
    case 'vulnerability_found':
      console.log('⚠️ VULNERABILITY FOUND!');
      console.log('Parameter:', data.vulnerability.parameter);
      console.log('Payload:', data.vulnerability.payload);
      console.log('Confidence:', data.vulnerability.confidence);
      break;
      
    case 'scan_complete':
      console.log('✅ Scan Complete');
      console.log('Total Vulnerabilities:', data.total_vulnerabilities);
      break;
      
    case 'error':
      console.error('Error:', data.error);
      break;
  }
};

ws.onerror = (error) => {
  console.error('WebSocket Error:', error);
};

ws.onclose = () => {
  console.log('Disconnected from server');
};
```

### Python Client Example

```python
import asyncio
import json
import websockets

async def scan():
    uri = "ws://localhost:8765"
    async with websockets.connect(uri) as ws:
        # Start scan
        await ws.send(json.dumps({
            "type": "start_scan",
            "url": "http://altoro.testfire.net/login.jsp"
        }))
        
        async for message in ws:
            data = json.loads(message)
            
            if data["type"] == "progress":
                current = data.get("current", "?")
                total = data.get("total", "?")
                print(f"Progress: {current}/{total} - {data['message']}")
                
            elif data["type"] == "vulnerability_found":
                vuln = data["vulnerability"]
                print(f"VULNERABILITY: {vuln['parameter']} - {vuln['payload']}")
                
            elif data["type"] == "scan_complete":
                print(f"Scan complete. Total: {data['total_vulnerabilities']}")
                break

asyncio.run(scan())
```

---

## How It Works

### Scanning Flow

1. **URL Parsing**: The scanner fetches the target URL and extracts all forms and inputs
2. **Endpoint Discovery**: Identifies all testable endpoints (GET/POST parameters, form fields)
3. **Baseline Request**: Makes a baseline request to understand normal behavior
4. **Payload Generation**: Generates SQL injection test cases using various payloads and encoding modes
5. **Vulnerability Testing**:
   - Sends each payload to the target
   - Analyzes responses using rule-based detection
   - If score >= 3.0, uses AI to confirm vulnerability
   - **On vulnerability found**: Immediately stops testing further payloads for that parameter and moves to the next
6. **Results Export**: Saves all results to `core/scan_results.json`

### Smart Parameter Testing

The scanner tracks which parameters have been found vulnerable and skips testing them with additional payloads:

```
Testing parameter: username
  - Payload 1: ' OR '1'='1 → VULNERABLE!
  → Stop testing username, move to next parameter
```

This significantly reduces testing time while maintaining thorough coverage.

---

## Port Configuration

The API port is configured via the `.env` file:

```env
API_PORT=8765
API_HOST=0.0.0.0
```

Default: `8765`

---

## Error Reference

| Error | Description | When It Occurs |
|-------|-------------|----------------|
| `Missing 'url' parameter` | No URL provided in start_scan request | When `start_scan` message lacks `url` field |
| `Invalid JSON message` | Client sent malformed JSON | When message cannot be parsed as JSON |
| `Unknown message type` | Unrecognized message type | When `type` field doesn't match known types |
| `Scan {id} not found` | Attempted to watch non-existent scan | When `watch_scan` references invalid scan_id |

---

## Notes

- The scanner requires internet access to:
  - Fetch target web pages
  - Make test requests to targets
  - Call AI APIs (Gemini/Cohere) for advanced analysis
- Some targets may block automated requests (CAPTCHA, WAF, etc.)
- Always get permission before scanning websites you don't own
