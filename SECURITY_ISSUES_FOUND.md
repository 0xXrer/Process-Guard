# Security Issues Found - 2025-11-16

## 🚨 Critical Issues

### 1. **API Authentication Missing** (CRITICAL)
**File**: `src/api.rs`
**Lines**: All endpoints (49-58)

**Issue**: The API has NO authentication mechanism whatsoever. Any attacker on the network can:
- List all processes
- Terminate processes (line 137-157)
- View detections
- Manipulate process whitelist

**Impact**: Remote attackers can kill critical system processes, view sensitive detection data, and disable security monitoring.

**Recommendation**:
```rust
// Add authentication middleware
use axum::middleware;
use axum::http::Request;

async fn auth_middleware(
    req: Request<Body>,
    next: Next<Body>,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(token) if verify_token(token) => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED)
    }
}

// Apply to router
Router::new()
    .layer(middleware::from_fn(auth_middleware))
    .route("/api/processes", get(list_processes))
    // ...
```

### 2. **No Rate Limiting** (HIGH)
**File**: `src/api.rs`
**Lines**: All endpoints

**Issue**: API endpoints have no rate limiting, allowing:
- DoS attacks by flooding requests
- Brute force attacks on future auth
- Resource exhaustion

**Recommendation**: Add tower-governor or similar rate limiting middleware.

### 3. **Process Termination Without Authorization** (CRITICAL)
**File**: `src/api.rs`
**Lines**: 131-174

**Issue**: The `/api/process/:pid/action` endpoint allows ANYONE to terminate ANY process without:
- Authentication
- Authorization checks
- PID validation
- Logging/auditing

**Impact**: Attacker can kill system processes, causing system instability or DoS.

**Recommendation**:
```rust
// Add PID validation
fn is_safe_to_terminate(pid: u32) -> bool {
    // Don't allow terminating system processes
    const PROTECTED_PIDS: &[u32] = &[0, 4, 8]; // System, csrss, etc.
    !PROTECTED_PIDS.contains(&pid)
}

// Add authorization check
if !is_safe_to_terminate(pid) {
    return Json(ApiResponse {
        success: false,
        error: Some("Cannot terminate protected process".to_string()),
        data: None,
    });
}

// Add audit logging
audit_log(&format!("Process {} terminated by {}", pid, user));
```

### 4. **Unsafe Code Without Safety Documentation** (HIGH)
**File**: `src/api.rs`
**Lines**: 138-156

**Issue**: Unsafe block lacks:
- Safety documentation (SAFETY comments)
- Proper error handling
- Input validation (PID could be 0 or invalid)

**Current Code**:
```rust
unsafe {
    use windows::Win32::System::Threading::*;
    if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
        let _ = TerminateProcess(handle, 1);  // Ignoring result!
        let _ = CloseHandle(handle);           // Ignoring result!
```

**Recommendation**:
```rust
// SAFETY: We're calling Win32 APIs with validated input.
// - pid is validated to be non-zero and not a protected process
// - We properly close the handle even on error
// - We check the return value of TerminateProcess
unsafe {
    use windows::Win32::System::Threading::*;

    // Validate PID before unsafe operations
    if pid == 0 {
        return Json(ApiResponse {
            success: false,
            error: Some("Invalid PID".to_string()),
            data: None,
        });
    }

    match OpenProcess(PROCESS_TERMINATE, false, pid) {
        Ok(handle) => {
            let result = TerminateProcess(handle, 1);
            let _ = CloseHandle(handle); // Always close handle

            if result.is_ok() {
                Json(ApiResponse {
                    success: true,
                    data: Some("Process terminated".to_string()),
                    error: None,
                })
            } else {
                Json(ApiResponse {
                    success: false,
                    error: Some("Failed to terminate process".to_string()),
                    data: None,
                })
            }
        },
        Err(_) => {
            Json(ApiResponse {
                success: false,
                error: Some("Failed to open process".to_string()),
                data: None,
            })
        }
    }
}
```

### 5. **No Input Validation** (MEDIUM)
**File**: `src/api.rs`
**Lines**: 94-96, 131-134

**Issue**:
- PID parameter not validated (could be 0, could be out of range)
- Action parameter only checked against string match, allowing case variations
- No JSON schema validation

**Recommendation**: Add input validation with proper error messages.

### 6. **Information Disclosure** (MEDIUM)
**File**: `src/api.rs`
**Lines**: 191-194

**Issue**: The `uptime_seconds` calculation uses `UNIX_EPOCH` instead of actual process start time, potentially leaking system information.

**Recommendation**: Track actual guard start time instead.

### 7. **No TLS/HTTPS Enforcement** (HIGH)
**File**: `src/api.rs`

**Issue**: API runs over HTTP without TLS, exposing:
- Authentication tokens (when added)
- Process information
- Detection data
- Control commands

**Recommendation**: Add TLS support with proper certificate validation.

### 8. **No CORS Protection** (MEDIUM)
**File**: `src/api.rs`

**Issue**: No CORS headers configured, allowing cross-site requests from malicious websites.

**Recommendation**: Add tower-http CORS middleware with strict origin controls.

## ⚠️ Medium Issues

### 9. **Error Messages Too Detailed** (LOW-MEDIUM)
**File**: `src/api.rs`
**Lines**: Various

**Issue**: Error messages like "Process not found" could be used for process enumeration attacks.

**Recommendation**: Use generic error messages externally, detailed logging internally.

### 10. **No Request Size Limits** (MEDIUM)
**File**: `src/api.rs`

**Issue**: No limits on request body size, allowing memory exhaustion attacks.

**Recommendation**: Add DefaultBodyLimit middleware.

## 📊 Summary

| Severity | Count | Fixed |
|----------|-------|-------|
| Critical | 3     | ❌ 0  |
| High     | 3     | ❌ 0  |
| Medium   | 4     | ❌ 0  |
| Total    | 10    | ❌ 0  |

## 🔧 Recommended Immediate Actions

1. ✅ **Add Authentication** - Block unauthenticated access
2. ✅ **Add Rate Limiting** - Prevent DoS attacks
3. ✅ **Add Authorization** - Restrict dangerous operations
4. ✅ **Add TLS Support** - Encrypt communications
5. ✅ **Add Input Validation** - Prevent injection attacks
6. ✅ **Add Audit Logging** - Track all API actions
7. ✅ **Document Unsafe Code** - Add SAFETY comments
8. ✅ **Add CORS Protection** - Prevent cross-site attacks

## 📚 Dependencies Security

**Recommendation**: Install and run:
```bash
cargo install cargo-audit
cargo audit

cargo install cargo-deny
cargo deny check advisories
```

## 📝 Notes

- This is a security research tool that requires admin privileges
- Running without authentication is EXTREMELY dangerous
- The documented security features in SECURITY.md are NOT actually implemented in the code
- Current state is NOT production-ready from a security perspective

---

**Audit Date**: 2025-11-16
**Auditor**: Claude AI Security Review
**Severity Scale**: Critical > High > Medium > Low
