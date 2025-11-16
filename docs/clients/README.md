# Client Libraries

Client libraries for Process Guard REST API integration.

## 📚 Available Libraries

Process Guard provides client libraries for popular programming languages to simplify integration with the REST API and WebSocket events.

### Status

| Language | Status | Package | Documentation |
|----------|--------|---------|---------------|
| **JavaScript** | 📝 Planned | - | [Guide](./javascript.md) |
| **Python** | 📝 Planned | - | [Guide](./python.md) |
| **PowerShell** | 📝 Planned | - | [Guide](./powershell.md) |
| **C#** | 📝 Planned | - | [Guide](./csharp.md) |

**Legend**: ✅ Available | 🔄 In Progress | 📝 Planned

## 🚀 Quick Start (REST API)

Until official client libraries are available, you can interact with the Process Guard API using standard HTTP clients:

### JavaScript (Node.js)

```javascript
const axios = require('axios');

const client = axios.create({
  baseURL: 'http://localhost:8080/api',
  headers: {
    'Authorization': 'Bearer YOUR_AUTH_TOKEN',
    'Content-Type': 'application/json'
  }
});

// Get suspicious processes
async function getSuspiciousProcesses() {
  const response = await client.get('/processes?suspicious=true');
  return response.data;
}

// Scan for direct syscalls
async function scanSyscalls() {
  const response = await client.post('/syscalls/scan', {
    scan_type: 'deep'
  });
  return response.data;
}

// Monitor WoW64 activity
async function monitorWow64() {
  const response = await client.get('/wow64?transitions_only=true');
  return response.data;
}
```

### Python

```python
import requests

class ProcessGuardClient:
    def __init__(self, base_url='http://localhost:8080/api', token=None):
        self.base_url = base_url
        self.session = requests.Session()
        if token:
            self.session.headers['Authorization'] = f'Bearer {token}'

    def get_suspicious_processes(self):
        response = self.session.get(f'{self.base_url}/processes?suspicious=true')
        response.raise_for_status()
        return response.json()

    def scan_syscalls(self, scan_type='deep'):
        response = self.session.post(
            f'{self.base_url}/syscalls/scan',
            json={'scan_type': scan_type}
        )
        response.raise_for_status()
        return response.json()

    def monitor_wow64(self, transitions_only=True):
        params = {'transitions_only': str(transitions_only).lower()}
        response = self.session.get(f'{self.base_url}/wow64', params=params)
        response.raise_for_status()
        return response.json()

# Usage
client = ProcessGuardClient(token='YOUR_AUTH_TOKEN')
processes = client.get_suspicious_processes()
```

### PowerShell

```powershell
# Configuration
$BaseUrl = "http://localhost:8080/api"
$Token = "YOUR_AUTH_TOKEN"
$Headers = @{
    "Authorization" = "Bearer $Token"
    "Content-Type" = "application/json"
}

# Get suspicious processes
function Get-SuspiciousProcesses {
    $uri = "$BaseUrl/processes?suspicious=true"
    Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get
}

# Scan for direct syscalls
function Invoke-SyscallScan {
    param([string]$ScanType = "deep")

    $uri = "$BaseUrl/syscalls/scan"
    $body = @{ scan_type = $ScanType } | ConvertTo-Json
    Invoke-RestMethod -Uri $uri -Headers $Headers -Method Post -Body $body
}

# Monitor WoW64 activity
function Get-Wow64Activity {
    param([bool]$TransitionsOnly = $true)

    $uri = "$BaseUrl/wow64?transitions_only=$($TransitionsOnly.ToString().ToLower())"
    Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get
}

# Usage
$processes = Get-SuspiciousProcesses
$syscalls = Invoke-SyscallScan -ScanType "deep"
$wow64 = Get-Wow64Activity
```

### C#

```csharp
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Tasks;

public class ProcessGuardClient : IDisposable
{
    private readonly HttpClient _httpClient;

    public ProcessGuardClient(string baseUrl = "http://localhost:8080/api", string token = null)
    {
        _httpClient = new HttpClient { BaseAddress = new Uri(baseUrl) };

        if (!string.IsNullOrEmpty(token))
        {
            _httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", token);
        }
    }

    public async Task<JsonDocument> GetSuspiciousProcessesAsync()
    {
        var response = await _httpClient.GetAsync("/processes?suspicious=true");
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(content);
    }

    public async Task<JsonDocument> ScanSyscallsAsync(string scanType = "deep")
    {
        var content = new StringContent(
            JsonSerializer.Serialize(new { scan_type = scanType }),
            System.Text.Encoding.UTF8,
            "application/json"
        );

        var response = await _httpClient.PostAsync("/syscalls/scan", content);
        response.EnsureSuccessStatusCode();

        var responseContent = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(responseContent);
    }

    public async Task<JsonDocument> MonitorWow64Async(bool transitionsOnly = true)
    {
        var response = await _httpClient.GetAsync(
            $"/wow64?transitions_only={transitionsOnly.ToString().ToLower()}"
        );
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(content);
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
    }
}

// Usage
using var client = new ProcessGuardClient(token: "YOUR_AUTH_TOKEN");
var processes = await client.GetSuspiciousProcessesAsync();
var syscalls = await client.ScanSyscallsAsync("deep");
var wow64 = await client.MonitorWow64Async(true);
```

## 🔌 WebSocket Integration

### JavaScript WebSocket Client

```javascript
const WebSocket = require('ws');

const ws = new WebSocket('ws://localhost:8080/ws', {
  headers: {
    'Authorization': 'Bearer YOUR_AUTH_TOKEN'
  }
});

ws.on('open', () => {
  console.log('Connected to Process Guard');

  // Subscribe to detection events
  ws.send(JSON.stringify({
    type: 'subscribe',
    events: ['detection', 'syscall', 'wow64']
  }));
});

ws.on('message', (data) => {
  const event = JSON.parse(data);
  console.log('Event received:', event);

  if (event.type === 'detection') {
    console.log('Detection alert:', event.data);
  }
});

ws.on('error', (error) => {
  console.error('WebSocket error:', error);
});
```

### Python WebSocket Client

```python
import websocket
import json

def on_message(ws, message):
    event = json.loads(message)
    print(f'Event received: {event}')

    if event['type'] == 'detection':
        print(f'Detection alert: {event["data"]}')

def on_open(ws):
    print('Connected to Process Guard')
    ws.send(json.dumps({
        'type': 'subscribe',
        'events': ['detection', 'syscall', 'wow64']
    }))

ws = websocket.WebSocketApp(
    'ws://localhost:8080/ws',
    header={'Authorization': 'Bearer YOUR_AUTH_TOKEN'},
    on_message=on_message,
    on_open=on_open
)

ws.run_forever()
```

## 📖 API Reference

For detailed API documentation, see:
- [REST API Overview](../api/README.md)
- [WebSocket API](../api/websockets.md)
- [API Endpoints](../api/processes.md)

## 🤝 Contributing

Interested in developing an official client library? See our [Contributing Guide](../development/contributing.md).

### Client Library Requirements

Official client libraries should:
- ✅ Support all REST API endpoints
- ✅ Support WebSocket event streaming
- ✅ Include comprehensive error handling
- ✅ Provide TypeScript definitions (for JS)
- ✅ Include unit tests (>80% coverage)
- ✅ Follow language-specific best practices
- ✅ Include usage examples
- ✅ Support async/await patterns

## 📞 Support

- 🐛 **Issues**: https://github.com/xrer/process-guard/issues
- 💬 **Discussions**: https://github.com/xrer/process-guard/discussions
- 📖 **Documentation**: [../README.md](../README.md)

---

**Status**: Documentation stub - Official client libraries planned for future releases
**Last Updated**: 2025-11-16
