# Process Guard API Documentation

REST API for Process Guard monitoring and control.

## Base URL

```
http://127.0.0.1:8080/api
```

## Authentication

Optional API token via `Authorization` header:

```http
Authorization: Bearer your-api-token-here
```

Configure token in `config.toml`:

```toml
[api]
auth_token = "your-secret-token"
```

## Endpoints

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "version": "0.3.0",
  "uptime": 3600
}
```

### GET /processes

List all monitored processes.

**Query Parameters:**
- `suspicious` (bool) - Only suspicious processes
- `limit` (int) - Max results (default: 100)
- `offset` (int) - Pagination offset

**Response:**
```json
{
  "processes": [
    {
      "pid": 1234,
      "name": "explorer.exe",
      "parent_pid": 1000,
      "create_time": 1699123456,
      "image_base": "0x7ff6c2340000",
      "entry_point": "0x7ff6c2341000",
      "risk_score": 0.0,
      "status": "CLEAN"
    }
  ],
  "total": 150,
  "suspicious": 2
}
```

### GET /processes/{pid}

Get specific process details.

**Response:**
```json
{
  "pid": 1234,
  "name": "explorer.exe",
  "parent_pid": 1000,
  "create_time": 1699123456,
  "image_base": "0x7ff6c2340000",
  "entry_point": "0x7ff6c2341000",
  "risk_score": 0.0,
  "status": "CLEAN",
  "detections": [],
  "memory_regions": [
    {
      "base": "0x7ff6c2340000",
      "size": 1048576,
      "protection": "PAGE_EXECUTE_READ",
      "type": "IMAGE"
    }
  ]
}
```

### POST /scan/{pid}

Scan specific process for injections.

**Request Body:** (optional)
```json
{
  "techniques": ["ProcessHollowing", "ThreadHijacking", "ProcessDoppelganging"],
  "deep_scan": true
}
```

**Response:**
```json
{
  "pid": 1234,
  "scan_time": "2023-11-06T12:00:00Z",
  "detections": [
    {
      "technique": "ProcessDoppelgänging",
      "confidence": 0.92,
      "details": "TxF transaction pattern detected",
      "timestamp": 1699123456
    }
  ],
  "risk_score": 0.92,
  "status": "MALICIOUS"
}
```

### GET /detections

Get all detection events.

**Query Parameters:**
- `since` (int) - Unix timestamp
- `limit` (int) - Max results
- `technique` (string) - Filter by technique
- `min_confidence` (float) - Minimum confidence threshold

**Response:**
```json
{
  "detections": [
    {
      "id": "det_001",
      "pid": 1234,
      "process_name": "malware.exe",
      "technique": "ProcessDoppelgänging",
      "confidence": 0.92,
      "details": "TxF transaction pattern detected",
      "timestamp": 1699123456,
      "action_taken": "TERMINATED"
    }
  ],
  "total": 50
}
```

### DELETE /processes/{pid}

Terminate malicious process.

**Request Body:** (optional)
```json
{
  "force": true,
  "reason": "Process Doppelgänging detected"
}
```

**Response:**
```json
{
  "pid": 1234,
  "terminated": true,
  "timestamp": 1699123456
}
```

### GET /stats

Get system statistics.

**Query Parameters:**
- `hours` (int) - Time range in hours (default: 24)

**Response:**
```json
{
  "timeframe": {
    "start": 1699123456,
    "end": 1699209856,
    "hours": 24
  },
  "totals": {
    "detections": 15,
    "processes_scanned": 1250,
    "processes_terminated": 3,
    "false_positives": 1
  },
  "techniques": {
    "ProcessDoppelgänging": {
      "count": 8,
      "percentage": 53.3,
      "avg_confidence": 0.91
    },
    "ProcessHollowing": {
      "count": 5,
      "percentage": 33.3,
      "avg_confidence": 0.94
    },
    "ThreadHijacking": {
      "count": 2,
      "percentage": 13.3,
      "avg_confidence": 0.87
    }
  },
  "performance": {
    "detection_latency_ms": 0.8,
    "memory_usage_mb": 48,
    "cpu_usage_percent": 1.8,
    "false_positive_rate": 0.08,
    "events_per_second": 15000
  }
}
```

### POST /config

Update configuration.

**Request Body:**
```json
{
  "monitoring": {
    "interval_ms": 100,
    "enable_txf": true
  },
  "detection": {
    "confidence_threshold": 0.9
  }
}
```

**Response:**
```json
{
  "updated": true,
  "restart_required": false
}
```

### GET /config

Get current configuration.

**Response:**
```json
{
  "monitoring": {
    "interval_ms": 100,
    "enable_etw": true,
    "enable_ml": true,
    "enable_txf": true,
    "whitelist": ["explorer.exe"],
    "blacklist": [],
    "auto_kill": false
  },
  "detection": {
    "confidence_threshold": 0.8,
    "ml_threshold": 0.9,
    "techniques": ["ProcessHollowing", "ProcessDoppelganging"],
    "false_positive_reduction": true
  }
}
```

### GET /txf/transactions

Get active TxF transactions.

**Response:**
```json
{
  "transactions": [
    {
      "handle": "0x1234",
      "guid": "550e8400-e29b-41d4-a716-446655440000",
      "create_time": 1699123456,
      "state": "ACTIVE",
      "files": [
        {
          "path": "C:\\temp\\malware.exe",
          "operation": "CreateTransacted",
          "pe_written": true,
          "section_created": false
        }
      ],
      "suspicious": false
    }
  ],
  "total": 5,
  "suspicious": 1
}
```

### POST /whitelist

Add process to whitelist.

**Request Body:**
```json
{
  "process_name": "legitimate.exe",
  "reason": "Known good application"
}
```

**Response:**
```json
{
  "added": true,
  "process_name": "legitimate.exe"
}
```

### DELETE /whitelist/{name}

Remove process from whitelist.

**Response:**
```json
{
  "removed": true,
  "process_name": "legitimate.exe"
}
```

## Websocket API

Real-time events via WebSocket at `/ws`.

### Connection

```javascript
const ws = new WebSocket('ws://127.0.0.1:8080/ws');
```

### Event Types

#### Detection Event
```json
{
  "type": "detection",
  "data": {
    "pid": 1234,
    "technique": "ProcessDoppelgänging",
    "confidence": 0.92,
    "timestamp": 1699123456
  }
}
```

#### Process Event
```json
{
  "type": "process",
  "action": "created",
  "data": {
    "pid": 1234,
    "name": "notepad.exe",
    "parent_pid": 1000
  }
}
```

#### Stats Update
```json
{
  "type": "stats",
  "data": {
    "detections_today": 15,
    "cpu_usage": 1.8,
    "memory_usage": 48
  }
}
```

## Error Responses

All errors follow consistent format:

```json
{
  "error": {
    "code": "PROCESS_NOT_FOUND",
    "message": "Process with PID 1234 not found",
    "details": {
      "pid": 1234
    }
  }
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `PROCESS_NOT_FOUND` | Process doesn't exist |
| `ACCESS_DENIED` | Insufficient privileges |
| `INVALID_REQUEST` | Malformed request |
| `RATE_LIMITED` | Too many requests |
| `CONFIG_ERROR` | Configuration invalid |
| `INTERNAL_ERROR` | Server error |

## Rate Limiting

Default limits (configurable):
- 100 requests per minute per IP
- 10 scan requests per minute per IP
- 5 terminate requests per minute per IP

Rate limit headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1699123456
```

## Examples

### JavaScript Client

```javascript
class ProcessGuardClient {
  constructor(baseUrl, token) {
    this.baseUrl = baseUrl;
    this.token = token;
  }

  async getProcesses() {
    const response = await fetch(`${this.baseUrl}/processes`, {
      headers: {
        'Authorization': `Bearer ${this.token}`
      }
    });
    return response.json();
  }

  async scanProcess(pid) {
    const response = await fetch(`${this.baseUrl}/scan/${pid}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json'
      }
    });
    return response.json();
  }

  async killProcess(pid) {
    const response = await fetch(`${this.baseUrl}/processes/${pid}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${this.token}`
      }
    });
    return response.json();
  }
}

const client = new ProcessGuardClient('http://127.0.0.1:8080/api', 'your-token');
```

### Python Client

```python
import requests

class ProcessGuardClient:
    def __init__(self, base_url, token=None):
        self.base_url = base_url
        self.headers = {}
        if token:
            self.headers['Authorization'] = f'Bearer {token}'

    def get_processes(self):
        response = requests.get(f'{self.base_url}/processes',
                              headers=self.headers)
        return response.json()

    def scan_process(self, pid):
        response = requests.post(f'{self.base_url}/scan/{pid}',
                               headers=self.headers)
        return response.json()

    def kill_process(self, pid):
        response = requests.delete(f'{self.base_url}/processes/{pid}',
                                 headers=self.headers)
        return response.json()

client = ProcessGuardClient('http://127.0.0.1:8080/api', 'your-token')
```

### PowerShell Client

```powershell
$BaseUrl = "http://127.0.0.1:8080/api"
$Token = "your-token"
$Headers = @{ "Authorization" = "Bearer $Token" }

# Get processes
$Processes = Invoke-RestMethod -Uri "$BaseUrl/processes" -Headers $Headers

# Scan process
$ScanResult = Invoke-RestMethod -Uri "$BaseUrl/scan/1234" -Method Post -Headers $Headers

# Kill process
$KillResult = Invoke-RestMethod -Uri "$BaseUrl/processes/1234" -Method Delete -Headers $Headers
```