# Error Handling

Complete guide to Process Guard API error handling, codes, and recovery strategies.

## 📋 Error Response Format

### Standard Error Response
All Process Guard API errors follow a consistent format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error description",
    "details": {
      "additional_context": "value",
      "suggested_action": "retry_with_authentication"
    },
    "timestamp": "2023-11-06T12:00:00.123Z",
    "request_id": "req_001",
    "documentation_url": "https://docs.process-guard.dev/api/errors#ERROR_CODE"
  },
  "meta": {
    "api_version": "v1",
    "response_time_ms": 15
  }
}
```

### Error Object Properties
| Property | Type | Description |
|----------|------|-------------|
| `code` | string | Machine-readable error identifier |
| `message` | string | Human-readable error description |
| `details` | object | Additional context and information |
| `timestamp` | string | ISO 8601 timestamp of the error |
| `request_id` | string | Unique identifier for tracing |
| `documentation_url` | string | Link to specific error documentation |

## 🚨 HTTP Status Codes

### Success Codes
| Code | Status | Description |
|------|--------|-------------|
| 200 | OK | Request successful |
| 201 | Created | Resource created successfully |
| 202 | Accepted | Request accepted for processing |
| 204 | No Content | Request successful, no content to return |

### Client Error Codes
| Code | Status | Description |
|------|--------|-------------|
| 400 | Bad Request | Invalid request format or parameters |
| 401 | Unauthorized | Authentication required or failed |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource does not exist |
| 409 | Conflict | Resource conflict (e.g., already exists) |
| 422 | Unprocessable Entity | Valid format, invalid data |
| 429 | Too Many Requests | Rate limit exceeded |

### Server Error Codes
| Code | Status | Description |
|------|--------|-------------|
| 500 | Internal Server Error | Unexpected server error |
| 502 | Bad Gateway | Upstream service error |
| 503 | Service Unavailable | Service temporarily unavailable |
| 504 | Gateway Timeout | Upstream service timeout |

## 🔤 Error Codes Reference

### Authentication Errors (AUTH_*)

#### AUTH_TOKEN_MISSING
```json
{
  "error": {
    "code": "AUTH_TOKEN_MISSING",
    "message": "Authentication token is required",
    "details": {
      "header_name": "Authorization",
      "expected_format": "Bearer <token>"
    }
  }
}
```

#### AUTH_TOKEN_INVALID
```json
{
  "error": {
    "code": "AUTH_TOKEN_INVALID",
    "message": "Invalid authentication token",
    "details": {
      "token_format": "malformed",
      "suggested_action": "regenerate_token"
    }
  }
}
```

#### AUTH_TOKEN_EXPIRED
```json
{
  "error": {
    "code": "AUTH_TOKEN_EXPIRED",
    "message": "Authentication token has expired",
    "details": {
      "expired_at": "2023-11-06T10:00:00Z",
      "suggested_action": "refresh_token"
    }
  }
}
```

#### AUTH_INSUFFICIENT_PRIVILEGES
```json
{
  "error": {
    "code": "AUTH_INSUFFICIENT_PRIVILEGES",
    "message": "Insufficient privileges for this operation",
    "details": {
      "required_privilege": "SeDebugPrivilege",
      "current_privileges": ["SeShutdownPrivilege"],
      "suggested_action": "run_as_administrator"
    }
  }
}
```

### Process Errors (PROCESS_*)

#### PROCESS_NOT_FOUND
```json
{
  "error": {
    "code": "PROCESS_NOT_FOUND",
    "message": "Process with specified PID not found",
    "details": {
      "pid": 1234,
      "possible_reasons": [
        "process_terminated",
        "permission_denied",
        "invalid_pid"
      ]
    }
  }
}
```

#### PROCESS_ACCESS_DENIED
```json
{
  "error": {
    "code": "PROCESS_ACCESS_DENIED",
    "message": "Access denied to process",
    "details": {
      "pid": 1234,
      "process_name": "system_process.exe",
      "required_privilege": "SeDebugPrivilege",
      "suggested_action": "run_with_elevated_privileges"
    }
  }
}
```

#### PROCESS_SCAN_IN_PROGRESS
```json
{
  "error": {
    "code": "PROCESS_SCAN_IN_PROGRESS",
    "message": "Process is already being scanned",
    "details": {
      "pid": 1234,
      "scan_id": "scan_001",
      "started_at": "2023-11-06T12:00:00Z",
      "estimated_completion": "2023-11-06T12:00:30Z"
    }
  }
}
```

#### PROCESS_TERMINATION_FAILED
```json
{
  "error": {
    "code": "PROCESS_TERMINATION_FAILED",
    "message": "Failed to terminate process",
    "details": {
      "pid": 1234,
      "reason": "protected_process",
      "suggested_actions": [
        "use_force_flag",
        "terminate_via_service"
      ]
    }
  }
}
```

### Detection Errors (DETECTION_*)

#### DETECTION_ENGINE_UNAVAILABLE
```json
{
  "error": {
    "code": "DETECTION_ENGINE_UNAVAILABLE",
    "message": "Detection engine is not available",
    "details": {
      "engine": "syscall_monitor",
      "status": "initializing",
      "retry_after": 5000
    }
  }
}
```

#### DETECTION_TIMEOUT
```json
{
  "error": {
    "code": "DETECTION_TIMEOUT",
    "message": "Detection operation timed out",
    "details": {
      "timeout_seconds": 30,
      "partial_results": true,
      "suggested_action": "increase_timeout_or_retry"
    }
  }
}
```

#### DETECTION_INVALID_TECHNIQUE
```json
{
  "error": {
    "code": "DETECTION_INVALID_TECHNIQUE",
    "message": "Invalid detection technique specified",
    "details": {
      "technique": "InvalidTechnique",
      "valid_techniques": [
        "ProcessHollowing",
        "DirectSyscalls",
        "HeavensGate",
        "ProcessDoppelganging"
      ]
    }
  }
}
```

### Configuration Errors (CONFIG_*)

#### CONFIG_INVALID_FORMAT
```json
{
  "error": {
    "code": "CONFIG_INVALID_FORMAT",
    "message": "Configuration format is invalid",
    "details": {
      "format_expected": "TOML",
      "parse_error": "Invalid syntax at line 15",
      "suggested_action": "validate_configuration_file"
    }
  }
}
```

#### CONFIG_VALUE_OUT_OF_RANGE
```json
{
  "error": {
    "code": "CONFIG_VALUE_OUT_OF_RANGE",
    "message": "Configuration value is out of valid range",
    "details": {
      "parameter": "detection.confidence_threshold",
      "value": 1.5,
      "valid_range": "0.0 to 1.0"
    }
  }
}
```

### Rate Limiting Errors (RATE_*)

#### RATE_LIMIT_EXCEEDED
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "API rate limit exceeded",
    "details": {
      "limit": 100,
      "window": "1 minute",
      "current_usage": 150,
      "reset_time": "2023-11-06T12:01:00Z",
      "retry_after": 45
    }
  }
}
```

### Resource Errors (RESOURCE_*)

#### RESOURCE_EXHAUSTED
```json
{
  "error": {
    "code": "RESOURCE_EXHAUSTED",
    "message": "System resources exhausted",
    "details": {
      "resource_type": "memory",
      "current_usage": "95%",
      "suggested_action": "reduce_scan_frequency"
    }
  }
}
```

#### RESOURCE_LOCKED
```json
{
  "error": {
    "code": "RESOURCE_LOCKED",
    "message": "Resource is currently locked",
    "details": {
      "resource_id": "process_1234",
      "locked_by": "scan_operation",
      "estimated_unlock": "2023-11-06T12:00:30Z"
    }
  }
}
```

### System Errors (SYSTEM_*)

#### SYSTEM_ETW_UNAVAILABLE
```json
{
  "error": {
    "code": "SYSTEM_ETW_UNAVAILABLE",
    "message": "ETW (Event Tracing for Windows) is not available",
    "details": {
      "reason": "etw_service_disabled",
      "suggested_actions": [
        "enable_etw_service",
        "run_without_etw"
      ]
    }
  }
}
```

#### SYSTEM_DRIVER_NOT_LOADED
```json
{
  "error": {
    "code": "SYSTEM_DRIVER_NOT_LOADED",
    "message": "Required kernel driver is not loaded",
    "details": {
      "driver_name": "ProcessGuardDriver.sys",
      "suggested_action": "install_and_load_driver"
    }
  }
}
```

## 🛠️ Error Recovery Strategies

### Automatic Retry Logic
```javascript
class ProcessGuardClient {
    async makeRequest(endpoint, options = {}) {
        const maxRetries = 3;
        const baseDelay = 1000;

        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                const response = await fetch(endpoint, options);

                if (response.ok) {
                    return await response.json();
                }

                const errorData = await response.json();
                const shouldRetry = this.shouldRetry(errorData.error.code, attempt);

                if (!shouldRetry) {
                    throw new Error(`API Error: ${errorData.error.message}`);
                }

                const delay = this.calculateDelay(errorData.error, attempt, baseDelay);
                await this.sleep(delay);

            } catch (error) {
                if (attempt === maxRetries) {
                    throw error;
                }
            }
        }
    }

    shouldRetry(errorCode, attempt) {
        const retryableErrors = [
            'RATE_LIMIT_EXCEEDED',
            'RESOURCE_EXHAUSTED',
            'DETECTION_TIMEOUT',
            'SYSTEM_ETW_UNAVAILABLE'
        ];

        return retryableErrors.includes(errorCode) && attempt < 3;
    }

    calculateDelay(error, attempt, baseDelay) {
        // Use retry_after if provided
        if (error.details?.retry_after) {
            return error.details.retry_after * 1000;
        }

        // Exponential backoff
        return baseDelay * Math.pow(2, attempt - 1);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}
```

### Error-Specific Handling
```javascript
class ErrorHandler {
    static handle(error) {
        switch (error.code) {
            case 'AUTH_TOKEN_EXPIRED':
                return this.handleTokenExpired(error);

            case 'PROCESS_NOT_FOUND':
                return this.handleProcessNotFound(error);

            case 'RATE_LIMIT_EXCEEDED':
                return this.handleRateLimit(error);

            case 'DETECTION_ENGINE_UNAVAILABLE':
                return this.handleEngineUnavailable(error);

            default:
                return this.handleGenericError(error);
        }
    }

    static async handleTokenExpired(error) {
        console.log('Token expired, refreshing...');
        const newToken = await this.refreshToken();
        return { retry: true, newToken };
    }

    static handleProcessNotFound(error) {
        console.log(`Process ${error.details.pid} not found`);
        return { retry: false, skipProcess: true };
    }

    static handleRateLimit(error) {
        const delay = error.details.retry_after * 1000;
        console.log(`Rate limited, waiting ${delay}ms`);
        return { retry: true, delay };
    }

    static handleEngineUnavailable(error) {
        console.log(`Engine ${error.details.engine} unavailable`);
        return {
            retry: true,
            delay: error.details.retry_after || 5000,
            fallback: true
        };
    }

    static handleGenericError(error) {
        console.error('Unhandled error:', error.message);
        return { retry: false, escalate: true };
    }
}
```

### Python Error Handling
```python
import asyncio
import logging
from typing import Dict, Any, Optional

class ProcessGuardAPIError(Exception):
    def __init__(self, code: str, message: str, details: Dict[str, Any] = None):
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(f"{code}: {message}")

class ProcessGuardClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url
        self.token = token
        self.session = None

    async def make_request(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        max_retries = 3
        base_delay = 1.0

        for attempt in range(1, max_retries + 1):
            try:
                response = await self.session.request(
                    method=kwargs.get('method', 'GET'),
                    url=f"{self.base_url}/{endpoint}",
                    headers={'Authorization': f'Bearer {self.token}'},
                    **kwargs
                )

                if response.status < 400:
                    return await response.json()

                error_data = await response.json()
                error = ProcessGuardAPIError(
                    code=error_data['error']['code'],
                    message=error_data['error']['message'],
                    details=error_data['error'].get('details', {})
                )

                if not self.should_retry(error.code, attempt):
                    raise error

                delay = self.calculate_delay(error, attempt, base_delay)
                logging.warning(f"Request failed, retrying in {delay}s: {error.message}")
                await asyncio.sleep(delay)

            except ProcessGuardAPIError:
                raise
            except Exception as e:
                if attempt == max_retries:
                    raise ProcessGuardAPIError('CLIENT_ERROR', str(e))

    def should_retry(self, error_code: str, attempt: int) -> bool:
        retryable_errors = {
            'RATE_LIMIT_EXCEEDED',
            'RESOURCE_EXHAUSTED',
            'DETECTION_TIMEOUT',
            'SYSTEM_ETW_UNAVAILABLE'
        }
        return error_code in retryable_errors and attempt < 3

    def calculate_delay(self, error: ProcessGuardAPIError, attempt: int, base_delay: float) -> float:
        if 'retry_after' in error.details:
            return float(error.details['retry_after'])
        return base_delay * (2 ** (attempt - 1))
```

### PowerShell Error Handling
```powershell
function Invoke-ProcessGuardAPI {
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [object]$Body = $null,
        [int]$MaxRetries = 3
    )

    $BaseUri = "http://127.0.0.1:8080/api"
    $Uri = "$BaseUri/$Endpoint"

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            $Response = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -Body ($Body | ConvertTo-Json) -ContentType "application/json"
            return $Response
        }
        catch {
            $ErrorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
            $ErrorCode = $ErrorDetails.error.code

            if (-not (Test-ShouldRetry -ErrorCode $ErrorCode -Attempt $attempt)) {
                throw "API Error [$ErrorCode]: $($ErrorDetails.error.message)"
            }

            $Delay = Get-RetryDelay -ErrorDetails $ErrorDetails -Attempt $attempt
            Write-Warning "Request failed, retrying in $Delay seconds: $($ErrorDetails.error.message)"
            Start-Sleep -Seconds $Delay
        }
    }

    throw "Max retries exceeded"
}

function Test-ShouldRetry {
    param([string]$ErrorCode, [int]$Attempt)

    $RetryableErrors = @(
        "RATE_LIMIT_EXCEEDED",
        "RESOURCE_EXHAUSTED",
        "DETECTION_TIMEOUT",
        "SYSTEM_ETW_UNAVAILABLE"
    )

    return ($ErrorCode -in $RetryableErrors) -and ($Attempt -lt 3)
}

function Get-RetryDelay {
    param($ErrorDetails, [int]$Attempt)

    if ($ErrorDetails.error.details.retry_after) {
        return [int]$ErrorDetails.error.details.retry_after
    }

    return [Math]::Pow(2, $Attempt - 1)
}
```

## 📊 Error Monitoring

### Error Metrics
Track these metrics for error monitoring:

- **Error rate by endpoint**
- **Error rate by error code**
- **Average retry attempts**
- **Error resolution time**
- **Client error vs server error ratio**

### Logging Recommendations
```json
{
  "timestamp": "2023-11-06T12:00:00.123Z",
  "level": "ERROR",
  "request_id": "req_001",
  "client_ip": "192.168.1.100",
  "endpoint": "/api/processes/1234",
  "method": "DELETE",
  "error_code": "PROCESS_ACCESS_DENIED",
  "error_message": "Access denied to process",
  "response_time_ms": 150,
  "user_agent": "ProcessGuardClient/1.0"
}
```

## 🔧 Debugging Tips

### Enable Verbose Error Details
```bash
# Enable detailed error responses
process-guard config set api.verbose_errors true

# Include stack traces in development
process-guard config set api.include_stack_traces true
```

### Request Tracing
```bash
# Enable request tracing
curl -H "X-Trace: true" -H "Authorization: Bearer token" \
     http://127.0.0.1:8080/api/processes
```

### Error Reproduction
```bash
# Get detailed error information
curl -v -H "Authorization: Bearer invalid-token" \
     http://127.0.0.1:8080/api/processes

# Check server logs
process-guard logs --level error --since 1h
```

---

## 📚 Related Documentation

- [API Authentication](./auth.md) - Authentication and authorization
- [Rate Limiting](./rate-limiting.md) - API rate limiting details
- [Client Libraries](../clients/README.md) - Pre-built error handling
- [Monitoring Guide](../ops/monitoring.md) - Error monitoring setup