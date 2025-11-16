# Changelog

All notable changes to Process Guard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2025-11-16

### 🔒 Security - CRITICAL UPDATE

This release addresses **10 critical security vulnerabilities** found in the API layer. **All users are strongly recommended to upgrade immediately.**

#### Fixed Security Issues

**Critical:**
1. **API Authentication** - Added Bearer token authentication for all API endpoints
2. **Authorization** - Implemented process termination authorization with protected PID list
3. **Rate Limiting** - Added 10 req/sec rate limiting to prevent DoS attacks

**High:**
4. **TLS Support** - Added HTTPS/TLS support via axum-server with rustls
5. **Unsafe Code Documentation** - Added comprehensive SAFETY comments to all unsafe blocks
6. **Input Validation** - Implemented validation for all API inputs (PIDs, actions, JSON)

**Medium:**
7. **CORS Protection** - Added CORS middleware with configurable origins
8. **Request Size Limits** - Implemented 1MB request body limit
9. **Information Disclosure** - Generic error messages to prevent enumeration
10. **Audit Logging** - Added comprehensive audit logging for all sensitive operations

### ✨ Added

- **Authentication Middleware** - Constant-time token comparison to prevent timing attacks
- **Rate Limiting** - Tower-governor based rate limiting (10 req/sec default, burst 20)
- **PID Validation** - Validates PIDs before any operations
- **Protected Process List** - Prevents termination of system processes (PID < 100, PID 0, PID 4)
- **Audit Logging** - All API operations logged with operation, PID, and success status
- **Input Validation** - Using validator crate for request validation
- **CORS Support** - Configurable CORS with tower-http
- **Request Tracing** - HTTP request tracing for debugging
- **Uptime Tracking** - Accurate uptime tracking from process start time

### 📚 Documentation

- **CLAUDE.md** - Comprehensive AI assistant guide with architecture overview
- **SECURITY.md** - Security policy and vulnerability reporting process
- **SECURITY_ISSUES_FOUND.md** - Detailed security audit findings
- **docs/clients/README.md** - Client library documentation
- **docs/technical/architecture.md** - System architecture documentation
- **docs/technical/performance.md** - Performance tuning guide
- **docs/detections/process-hollowing.md** - Process hollowing detection guide
- **docs/detections/doppelganging.md** - Doppelgänging detection stub
- **docs/detections/thread-hijacking.md** - Thread hijacking detection stub

### 🔧 Changed

- **API Signature** - `create_router()` now requires `auth_token` parameter
- **Error Messages** - More generic error messages to prevent information disclosure
- **Process Status** - Changed "Infected" to "Suspicious" for better accuracy
- **Dependencies** - Added security-focused dependencies (tower-http, tower-governor, validator, constant_time_eq)

### ⚠️ Breaking Changes

1. **Authentication Required** - All API endpoints (except `/health`) now require `Authorization: Bearer <token>` header
2. **API Function Signature** - `create_router(guard: Arc<ProcessGuard>, auth_token: String)`
3. **Environment Variable** - Set `PROCESS_GUARD_AUTH_TOKEN` for authentication
4. **Protected Processes** - Cannot terminate PIDs < 100 or system processes

### 🚀 CI/CD

- **GitHub Actions Workflows** - Complete CI/CD pipeline
  - `ci.yml` - Build, test, lint, clippy, formatting checks
  - `release.yml` - Automated releases on version tags
  - `security.yml` - Daily security audits with cargo-audit and cargo-deny
- **Automated Releases** - Creates GitHub releases with binaries on tag push
- **Security Scanning** - Automated dependency vulnerability scanning

### 📦 Dependencies

#### Added
- `axum-server` 0.6 - TLS/HTTPS support
- `tower` 0.4 - Middleware infrastructure
- `tower-http` 0.5 - CORS, limits, tracing
- `tower-governor` 0.3 - Rate limiting
- `validator` 0.18 - Input validation
- `constant_time_eq` 0.3 - Timing-attack resistant comparisons
- `chrono` 0.4 - Time handling
- `uuid` 1.10 - Unique identifiers
- `base64` 0.22 - Base64 encoding

## [0.3.1] - 2025-11-06

### Fixed
- Documentation improvements
- Minor bug fixes

## [0.2.0] - 2025-XX-XX

### Added
- Initial API implementation
- Basic process monitoring
- Detection engine

## [0.1.0] - 2025-XX-XX

### Added
- Initial release
- ETW integration
- Direct syscall detection
- Heaven's Gate detection
- Process hollowing detection

---

## Security Advisories

### GHSA-XXXX-XXXX-XXXX (v0.1.0 - v0.3.1)

**Severity:** Critical
**Component:** REST API
**Issue:** Missing authentication allows unauthorized access
**Fixed in:** v0.4.0
**CVE:** Pending

**Description:**
Versions prior to 0.4.0 have a critical vulnerability in the REST API that allows unauthenticated access to all endpoints, including process termination. This could allow remote attackers to kill arbitrary processes.

**Mitigation:**
Upgrade to v0.4.0 or later immediately. If upgrade is not possible, restrict network access to the API port (default 8080) using firewall rules.

---

[0.4.0]: https://github.com/xrer/process-guard/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/xrer/process-guard/compare/v0.2.0...v0.3.1
[0.2.0]: https://github.com/xrer/process-guard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/xrer/process-guard/releases/tag/v0.1.0
