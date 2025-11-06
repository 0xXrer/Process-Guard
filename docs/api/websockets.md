# WebSocket API

Real-time event streaming and monitoring through WebSocket connections.

## 🔌 Connection

### Endpoint
```
ws://127.0.0.1:8080/ws
```

### Authentication
```javascript
// Connect with API token
const ws = new WebSocket('ws://127.0.0.1:8080/ws', [], {
    headers: {
        'Authorization': 'Bearer your-api-token'
    }
});
```

### Connection Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `filter` | string | Event filter expression |
| `buffer_size` | integer | Client buffer size (default: 1000) |
| `compression` | boolean | Enable compression (default: true) |
| `heartbeat` | integer | Heartbeat interval in seconds (default: 30) |

### Example Connection
```javascript
const wsUrl = new URL('ws://127.0.0.1:8080/ws');
wsUrl.searchParams.set('filter', 'detection.confidence > 0.8');
wsUrl.searchParams.set('buffer_size', '500');

const ws = new WebSocket(wsUrl.toString());
```

## 📡 Event Types

### Detection Events

#### Direct Syscall Detection
```json
{
  "type": "detection",
  "timestamp": "2023-11-06T12:00:00.123Z",
  "event_id": "det_syscall_001",
  "data": {
    "technique": "DirectSyscalls",
    "pid": 1234,
    "process_name": "malware.exe",
    "confidence": 0.89,
    "pattern_matched": "syswhispers_template",
    "syscall_address": "0x401000",
    "stack_frames": [
      {
        "address": "0x401000",
        "module": "malware.exe",
        "offset": "0x1000"
      }
    ],
    "threat_level": "HIGH",
    "details": "SysWhispers2 pattern detected bypassing ntdll"
  }
}
```

#### Heaven's Gate Detection
```json
{
  "type": "detection",
  "timestamp": "2023-11-06T12:01:30.456Z",
  "event_id": "det_wow64_002",
  "data": {
    "technique": "HeavensGate",
    "pid": 5678,
    "process_name": "injector32.exe",
    "confidence": 0.94,
    "transition": {
      "from_cs": "0x23",
      "to_cs": "0x33",
      "from_address": "0x401050",
      "to_address": "0x7FF800001000"
    },
    "x64_code_detected": true,
    "threat_level": "CRITICAL",
    "details": "WoW64 process executing x64 shellcode"
  }
}
```

#### Process Doppelgänging Detection
```json
{
  "type": "detection",
  "timestamp": "2023-11-06T12:02:15.789Z",
  "event_id": "det_txf_003",
  "data": {
    "technique": "ProcessDoppelganging",
    "pid": 9012,
    "process_name": "svchost.exe",
    "confidence": 0.92,
    "transaction_id": "550e8400-e29b-41d4-a716-446655440000",
    "file_operations": [
      {
        "path": "C:\\temp\\malware.exe",
        "operation": "CreateTransacted",
        "pe_written": true
      }
    ],
    "threat_level": "HIGH",
    "details": "TxF transaction with PE creation and rollback"
  }
}
```

### Process Events

#### Process Creation
```json
{
  "type": "process",
  "action": "created",
  "timestamp": "2023-11-06T12:03:00.000Z",
  "data": {
    "pid": 3456,
    "parent_pid": 1000,
    "name": "notepad.exe",
    "path": "C:\\Windows\\System32\\notepad.exe",
    "command_line": "notepad.exe document.txt",
    "create_time": 1699276980,
    "user": "DOMAIN\\user",
    "integrity_level": "Medium",
    "risk_score": 0.1
  }
}
```

#### Process Termination
```json
{
  "type": "process",
  "action": "terminated",
  "timestamp": "2023-11-06T12:04:00.000Z",
  "data": {
    "pid": 1234,
    "name": "malware.exe",
    "exit_code": 1337,
    "termination_reason": "killed_by_process_guard",
    "detection_count": 3,
    "final_risk_score": 0.95,
    "uptime_seconds": 120
  }
}
```

### System Events

#### Statistics Update
```json
{
  "type": "statistics",
  "timestamp": "2023-11-06T12:05:00.000Z",
  "data": {
    "period": "last_minute",
    "detections": {
      "total": 15,
      "by_technique": {
        "DirectSyscalls": 8,
        "HeavensGate": 4,
        "ProcessDoppelganging": 3
      },
      "high_confidence": 12,
      "false_positives": 0
    },
    "performance": {
      "detection_latency_ms": 0.6,
      "cpu_usage_percent": 2.1,
      "memory_usage_mb": 52,
      "events_per_second": 18500
    },
    "processes": {
      "total": 127,
      "suspicious": 3,
      "terminated": 1
    }
  }
}
```

#### Configuration Change
```json
{
  "type": "config",
  "action": "updated",
  "timestamp": "2023-11-06T12:06:00.000Z",
  "data": {
    "changed_settings": [
      "detection.confidence_threshold",
      "monitoring.interval_ms"
    ],
    "old_values": {
      "detection.confidence_threshold": 0.8,
      "monitoring.interval_ms": 100
    },
    "new_values": {
      "detection.confidence_threshold": 0.9,
      "monitoring.interval_ms": 50
    },
    "updated_by": "admin",
    "restart_required": false
  }
}
```

### Alert Events

#### Critical Alert
```json
{
  "type": "alert",
  "severity": "critical",
  "timestamp": "2023-11-06T12:07:00.000Z",
  "data": {
    "alert_id": "alert_001",
    "title": "Multiple injection techniques detected",
    "description": "Process 1234 (malware.exe) detected using multiple advanced evasion techniques",
    "affected_processes": [1234, 5678],
    "techniques_detected": ["DirectSyscalls", "HeavensGate"],
    "recommended_actions": [
      "immediate_termination",
      "memory_dump",
      "network_isolation"
    ],
    "confidence": 0.98,
    "risk_score": 0.95
  }
}
```

## 🎛️ Event Filtering

### Filter Syntax
```javascript
// Confidence threshold
filter: "detection.confidence > 0.8"

// Specific techniques
filter: "detection.technique in ['DirectSyscalls', 'HeavensGate']"

// Process names
filter: "process.name matches 'malware.*'"

// Threat levels
filter: "detection.threat_level == 'CRITICAL'"

// Time-based filtering
filter: "timestamp > '2023-11-06T12:00:00Z'"

// Complex expressions
filter: "(detection.confidence > 0.9) AND (process.risk_score > 0.8)"
```

### Subscription Examples
```javascript
// Subscribe to high-confidence detections only
const ws = new WebSocket('ws://127.0.0.1:8080/ws?filter=detection.confidence>0.9');

// Subscribe to specific process events
const processWs = new WebSocket('ws://127.0.0.1:8080/ws?filter=type==process');

// Subscribe to critical alerts
const alertWs = new WebSocket('ws://127.0.0.1:8080/ws?filter=type==alert AND severity==critical');
```

## 💻 Client Examples

### JavaScript/Node.js Client
```javascript
class ProcessGuardWebSocket {
    constructor(url, token, filters = {}) {
        this.url = new URL(url);
        this.token = token;

        // Add filters as query parameters
        Object.entries(filters).forEach(([key, value]) => {
            this.url.searchParams.set(key, value);
        });

        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000;
    }

    connect() {
        this.ws = new WebSocket(this.url.toString(), [], {
            headers: {
                'Authorization': `Bearer ${this.token}`
            }
        });

        this.ws.on('open', () => {
            console.log('Connected to Process Guard WebSocket');
            this.reconnectAttempts = 0;
        });

        this.ws.on('message', (data) => {
            try {
                const event = JSON.parse(data);
                this.handleEvent(event);
            } catch (error) {
                console.error('Failed to parse event:', error);
            }
        });

        this.ws.on('close', (code, reason) => {
            console.log(`WebSocket closed: ${code} - ${reason}`);
            this.reconnect();
        });

        this.ws.on('error', (error) => {
            console.error('WebSocket error:', error);
        });
    }

    handleEvent(event) {
        switch (event.type) {
            case 'detection':
                this.onDetection(event);
                break;
            case 'process':
                this.onProcess(event);
                break;
            case 'statistics':
                this.onStatistics(event);
                break;
            case 'alert':
                this.onAlert(event);
                break;
            default:
                console.log('Unknown event type:', event.type);
        }
    }

    onDetection(event) {
        console.log(`Detection: ${event.data.technique} in ${event.data.process_name} (confidence: ${event.data.confidence})`);

        if (event.data.confidence > 0.9) {
            this.sendAlert(event);
        }
    }

    onProcess(event) {
        console.log(`Process ${event.action}: ${event.data.name} (PID: ${event.data.pid})`);
    }

    onStatistics(event) {
        console.log(`Stats: ${event.data.detections.total} detections in last minute`);
    }

    onAlert(event) {
        console.error(`ALERT [${event.severity}]: ${event.data.title}`);
        // Send to SIEM, email, etc.
    }

    sendAlert(detection) {
        // Integration with alerting systems
        fetch('/api/alerts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(detection)
        });
    }

    reconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

            console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);

            setTimeout(() => {
                this.connect();
            }, delay);
        } else {
            console.error('Max reconnection attempts reached');
        }
    }

    close() {
        if (this.ws) {
            this.ws.close();
        }
    }
}

// Usage
const pgWs = new ProcessGuardWebSocket(
    'ws://127.0.0.1:8080/ws',
    'your-api-token',
    { filter: 'detection.confidence > 0.8' }
);

pgWs.connect();
```

### Python Client
```python
import asyncio
import websockets
import json
import logging
from urllib.parse import urlencode

class ProcessGuardWebSocket:
    def __init__(self, url, token, filters=None):
        self.url = url
        self.token = token
        self.filters = filters or {}
        self.ws = None
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 5

    async def connect(self):
        # Build URL with filters
        query_params = urlencode(self.filters)
        full_url = f"{self.url}?{query_params}" if query_params else self.url

        headers = {
            'Authorization': f'Bearer {self.token}'
        }

        try:
            self.ws = await websockets.connect(full_url, extra_headers=headers)
            logging.info("Connected to Process Guard WebSocket")
            self.reconnect_attempts = 0

            await self.listen()

        except Exception as e:
            logging.error(f"Connection failed: {e}")
            await self.reconnect()

    async def listen(self):
        try:
            async for message in self.ws:
                try:
                    event = json.loads(message)
                    await self.handle_event(event)
                except json.JSONDecodeError as e:
                    logging.error(f"Failed to parse event: {e}")

        except websockets.exceptions.ConnectionClosed:
            logging.warning("WebSocket connection closed")
            await self.reconnect()

        except Exception as e:
            logging.error(f"Listen error: {e}")

    async def handle_event(self, event):
        event_type = event.get('type')

        if event_type == 'detection':
            await self.on_detection(event)
        elif event_type == 'process':
            await self.on_process(event)
        elif event_type == 'statistics':
            await self.on_statistics(event)
        elif event_type == 'alert':
            await self.on_alert(event)
        else:
            logging.info(f"Unknown event type: {event_type}")

    async def on_detection(self, event):
        data = event['data']
        logging.info(f"Detection: {data['technique']} in {data['process_name']} "
                    f"(confidence: {data['confidence']})")

        if data['confidence'] > 0.9:
            await self.send_alert(event)

    async def on_process(self, event):
        data = event['data']
        logging.info(f"Process {event['action']}: {data['name']} (PID: {data['pid']})")

    async def on_statistics(self, event):
        data = event['data']
        logging.info(f"Stats: {data['detections']['total']} detections in last minute")

    async def on_alert(self, event):
        data = event['data']
        logging.critical(f"ALERT [{event['severity']}]: {data['title']}")

    async def send_alert(self, detection):
        # Integration with alerting systems
        pass

    async def reconnect(self):
        if self.reconnect_attempts < self.max_reconnect_attempts:
            self.reconnect_attempts += 1
            delay = 2 ** (self.reconnect_attempts - 1)

            logging.info(f"Reconnecting in {delay}s (attempt {self.reconnect_attempts})")
            await asyncio.sleep(delay)

            await self.connect()
        else:
            logging.error("Max reconnection attempts reached")

# Usage
async def main():
    pg_ws = ProcessGuardWebSocket(
        'ws://127.0.0.1:8080/ws',
        'your-api-token',
        {'filter': 'detection.confidence > 0.8'}
    )

    await pg_ws.connect()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
```

### PowerShell Client
```powershell
# PowerShell WebSocket client using ClientWebSocket
Add-Type -AssemblyName System.Net.WebSockets
Add-Type -AssemblyName System.Threading

function Connect-ProcessGuardWebSocket {
    param(
        [string]$Uri = "ws://127.0.0.1:8080/ws",
        [string]$Token,
        [hashtable]$Filters = @{}
    )

    # Build URI with filters
    $UriBuilder = [System.UriBuilder]$Uri
    if ($Filters.Count -gt 0) {
        $QueryParams = ($Filters.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&"
        $UriBuilder.Query = $QueryParams
    }

    $WebSocket = [System.Net.WebSockets.ClientWebSocket]::new()

    # Add authorization header
    if ($Token) {
        $WebSocket.Options.SetRequestHeader("Authorization", "Bearer $Token")
    }

    try {
        # Connect
        $ConnectTask = $WebSocket.ConnectAsync($UriBuilder.Uri, [System.Threading.CancellationToken]::None)
        $ConnectTask.Wait()

        Write-Host "Connected to Process Guard WebSocket"

        # Listen for messages
        $Buffer = [System.Byte[]]::new(4096)
        $ArraySegment = [System.ArraySegment[System.Byte]]::new($Buffer)

        while ($WebSocket.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
            $ReceiveTask = $WebSocket.ReceiveAsync($ArraySegment, [System.Threading.CancellationToken]::None)
            $ReceiveTask.Wait()

            $Result = $ReceiveTask.Result
            $Message = [System.Text.Encoding]::UTF8.GetString($Buffer, 0, $Result.Count)

            # Parse and handle event
            $Event = $Message | ConvertFrom-Json
            Handle-ProcessGuardEvent -Event $Event
        }
    }
    catch {
        Write-Error "WebSocket error: $_"
    }
    finally {
        $WebSocket.Dispose()
    }
}

function Handle-ProcessGuardEvent {
    param($Event)

    switch ($Event.type) {
        "detection" {
            $Data = $Event.data
            Write-Host "Detection: $($Data.technique) in $($Data.process_name) (confidence: $($Data.confidence))"

            if ($Data.confidence -gt 0.9) {
                Write-Warning "High confidence detection - alerting!"
                # Send alert
            }
        }
        "process" {
            $Data = $Event.data
            Write-Host "Process $($Event.action): $($Data.name) (PID: $($Data.pid))"
        }
        "alert" {
            $Data = $Event.data
            Write-Error "ALERT [$($Event.severity)]: $($Data.title)"
        }
        default {
            Write-Host "Unknown event: $($Event.type)"
        }
    }
}

# Usage
$Filters = @{
    "filter" = "detection.confidence > 0.8"
}

Connect-ProcessGuardWebSocket -Uri "ws://127.0.0.1:8080/ws" -Token "your-api-token" -Filters $Filters
```

## 🔧 Configuration

### Server-side Configuration
```toml
[websocket]
enabled = true
bind_address = "127.0.0.1"
port = 8080
max_connections = 1000
buffer_size = 4096
compression = true
heartbeat_interval = 30

[websocket.filters]
max_complexity = 100
timeout_ms = 1000
default_buffer_size = 1000

[websocket.rate_limiting]
enabled = true
max_messages_per_minute = 1000
max_connections_per_ip = 10
```

### Client Configuration
```javascript
const config = {
    url: 'ws://127.0.0.1:8080/ws',
    token: 'your-api-token',
    options: {
        reconnect: true,
        maxReconnectAttempts: 5,
        reconnectDelay: 1000,
        compression: true,
        heartbeat: true
    },
    filters: {
        confidence_threshold: 0.8,
        techniques: ['DirectSyscalls', 'HeavensGate'],
        threat_levels: ['HIGH', 'CRITICAL']
    }
};
```

## 🚨 Error Handling

### Connection Errors
```json
{
  "type": "error",
  "code": "WS_CONNECTION_FAILED",
  "message": "Failed to establish WebSocket connection",
  "details": {
    "reason": "Authentication failed",
    "retry_after": 5000
  }
}
```

### Filter Errors
```json
{
  "type": "error",
  "code": "WS_FILTER_INVALID",
  "message": "Invalid filter expression",
  "details": {
    "expression": "detection.confidence >> 0.8",
    "position": 20,
    "expected": "comparison operator"
  }
}
```

### Rate Limit Errors
```json
{
  "type": "error",
  "code": "WS_RATE_LIMITED",
  "message": "Rate limit exceeded",
  "details": {
    "limit": 1000,
    "window": "1 minute",
    "retry_after": 60
  }
}
```

---

## 📚 Related Documentation

- [REST API](./README.md) - HTTP API endpoints
- [Authentication](./auth.md) - API authentication methods
- [Client Libraries](../clients/README.md) - Ready-to-use client libraries
- [Integration Examples](../examples/websocket-integration.md) - Real-world integration examples