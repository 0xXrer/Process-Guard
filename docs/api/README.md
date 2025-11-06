# Process Guard REST API

REST API для мониторинга и управления Process Guard.

## 📋 API Overview

### Base URL
```
http://127.0.0.1:8080/api
```

### Content Type
```
Content-Type: application/json
Accept: application/json
```

### Rate Limiting
- 100 requests/minute per IP
- 10 scan requests/minute per IP
- 5 terminate requests/minute per IP

## 🔐 Authentication

Optional API token via `Authorization` header:

```http
Authorization: Bearer your-api-token-here
```

Configure in `config.toml`:
```toml
[api]
auth_token = "your-secret-token"
```

## 📚 API Sections

### Core Endpoints
- [**Health & Status**](./health.md) - System health checks
- [**Processes**](./processes.md) - Process monitoring and management
- [**Detections**](./detections.md) - Detection events and history
- [**Configuration**](./config.md) - Runtime configuration

### Detection-Specific APIs
- [**Syscalls**](./syscalls.md) - Direct syscall monitoring
- [**WoW64**](./wow64.md) - Heaven's Gate detection
- [**TxF**](./txf.md) - Transaction file monitoring

### Management APIs
- [**Whitelist**](./whitelist.md) - Process whitelist management
- [**Statistics**](./stats.md) - System statistics and metrics

### Real-time APIs
- [**WebSockets**](./websockets.md) - Real-time event streaming

## 🚀 Quick Start

### Basic Health Check
```bash
curl http://127.0.0.1:8080/api/health
```

### List Processes
```bash
curl -H "Authorization: Bearer your-token" \
     http://127.0.0.1:8080/api/processes
```

### Scan Process
```bash
curl -X POST \
     -H "Authorization: Bearer your-token" \
     -H "Content-Type: application/json" \
     -d '{"deep_scan": true}' \
     http://127.0.0.1:8080/api/scan/1234
```

## 📊 Response Format

### Success Response
```json
{
  "data": {
    // response data
  },
  "meta": {
    "timestamp": 1699123456,
    "request_id": "req_001",
    "processing_time_ms": 15
  }
}
```

### Error Response
```json
{
  "error": {
    "code": "PROCESS_NOT_FOUND",
    "message": "Process with PID 1234 not found",
    "details": {
      "pid": 1234
    }
  },
  "meta": {
    "timestamp": 1699123456,
    "request_id": "req_001"
  }
}
```

## 🔧 Common Headers

### Request Headers
```http
Authorization: Bearer your-token
Content-Type: application/json
Accept: application/json
User-Agent: YourApp/1.0
X-Request-ID: unique-request-id
```

### Response Headers
```http
Content-Type: application/json
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1699123456
X-Request-ID: unique-request-id
```

## 📱 Client Libraries

- [JavaScript/Node.js](../clients/javascript.md)
- [Python](../clients/python.md)
- [PowerShell](../clients/powershell.md)
- [C#](../clients/csharp.md)

## 🐛 Error Handling

See [Error Handling Guide](./errors.md) for detailed error codes and handling strategies.

## 🔍 Testing API

Use the included Postman collection or curl examples in each endpoint documentation.