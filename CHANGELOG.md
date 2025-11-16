# Changelog

All notable changes to Process Guard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2025-11-16

### 🔒 Security

This is a **critical security release** that fixes all 10 security vulnerabilities identified in the November 2025 security audit.

#### Critical Fixes
- **[CRITICAL]** Added API authentication middleware with JWT and API key support
  - Implements SHA-256 hashed API keys for secure storage
  - JWT token validation with configurable secrets
  - All endpoints (except `/health`) now require authentication
- **[CRITICAL]** Implemented process termination authorization
  - Added protected process list (System, csrss, etc.)
  - PID validation before any operations
  - Comprehensive audit logging for all actions
- **[CRITICAL]** Documented all unsafe code blocks with SAFETY comments
  - Proper error handling for all Windows API calls
  - Return value checking for critical operations
  - Handle cleanup even on error paths

#### High Priority Fixes
- **[HIGH]** Implemented rate limiting using tower-governor
  - Default: 100 requests per minute per IP
  - Configurable burst size (default: 10)
  - Returns HTTP 429 when limits exceeded
- **[HIGH]** Added TLS/HTTPS support
  - Uses axum-server with rustls
  - Configurable certificate paths
  - Recommended for all production deployments
- **[HIGH]** Fixed unsafe code error handling
  - All `OpenProcess` calls now check return values
  - `TerminateProcess` results properly validated
  - Handles always closed even on errors

#### Medium Priority Fixes
- **[MEDIUM]** Added comprehensive input validation
  - PID validation (non-zero, within valid range)
  - Action parameter normalization and validation
  - Generic error messages to prevent information leakage
- **[MEDIUM]** Fixed information disclosure in uptime calculation
  - Now tracks actual process start time
  - Removed UNIX_EPOCH leak
- **[MEDIUM]** Implemented CORS protection
  - Configurable allowed origins
  - Supports development and production modes
  - Restricts methods to GET and POST only
- **[MEDIUM]** Added request body size limits
  - Default maximum: 1 MB
  - Prevents memory exhaustion attacks
  - Configurable via middleware

### ✨ Added

- **Audit Logging System**
  - All API actions are logged with timestamps
  - Includes user, action, target, and success/failure
  - Integration with tracing for SIEM support
  - Structured JSON format for easy parsing

- **Security Configuration**
  - New `config.example.toml` with all security settings
  - Environment variable support for secrets
  - API key hash storage (SHA-256)
  - JWT secret configuration

- **Documentation**
  - Complete API authentication guide (`docs/api/auth.md`)
  - Security configuration examples
  - Updated SECURITY.md with fix details
  - PowerShell, Python, and JavaScript examples

- **CI/CD Workflows**
  - Automated release workflow with GitHub Actions
  - Security audit integration (cargo-audit, cargo-deny)
  - Multi-platform builds (MSVC and GNU targets)
  - Automatic changelog generation
  - Checksum generation for releases

### 🔧 Changed

- **API Architecture**
  - Migrated from simple state to comprehensive `AppState`
  - Added middleware stack (auth, rate limiting, CORS, tracing)
  - Improved error messages (generic for security)
  - Better separation of concerns

- **Dependencies**
  - Added: `tower`, `tower-http`, `tower-governor`
  - Added: `jsonwebtoken`, `bcrypt`, `argon2`
  - Added: `axum-server` with TLS support
  - Added: `secrecy`, `uuid`, `chrono`

- **Error Handling**
  - All unsafe blocks now properly handle errors
  - Generic error messages to prevent enumeration
  - Detailed internal logging for debugging
  - Audit trail for all failures

### 📊 Security Audit Summary

**Total Issues Found:** 10
**Total Issues Fixed:** 10 (100%)

| Severity | Count | Fixed |
|----------|-------|-------|
| Critical | 3     | ✅ 3  |
| High     | 3     | ✅ 3  |
| Medium   | 4     | ✅ 4  |

### 🚀 Upgrade Guide

#### For Existing Users

1. **Update Configuration**
   ```bash
   # Copy example config
   cp config.example.toml config.toml

   # Generate API key
   openssl rand -hex 32 > api_key.txt

   # Hash it for storage
   echo -n "$(cat api_key.txt)" | sha256sum

   # Add hash to config.toml
   ```

2. **Update API Clients**
   ```bash
   # All API calls now require authentication
   curl -H "Authorization: Bearer YOUR_API_KEY" \
        http://localhost:8080/api/processes
   ```

3. **Enable TLS (Recommended)**
   ```toml
   [server]
   enable_tls = true
   tls_cert_path = "/path/to/cert.pem"
   tls_key_path = "/path/to/key.pem"
   ```

#### Breaking Changes

⚠️ **API Authentication Required**
- All API endpoints now require authentication (except `/health`)
- Existing API clients must be updated to include `Authorization` header
- See `docs/api/auth.md` for implementation examples

⚠️ **Router Creation Signature Changed**
- `create_router()` now returns `Router` with middleware stack
- State type changed from `Arc<ProcessGuard>` to `Arc<AppState>`

### 📝 Migration Checklist

- [ ] Generate API keys for all API clients
- [ ] Update API client code to include authentication
- [ ] Configure rate limiting thresholds
- [ ] Set up TLS certificates for production
- [ ] Review and customize CORS origins
- [ ] Set up audit log monitoring
- [ ] Test all API endpoints with new authentication
- [ ] Update firewall rules if needed

### 🔗 Links

- [Security Advisory](SECURITY.md#v040-security-fixes-2025-11-16)
- [API Authentication Guide](docs/api/auth.md)
- [Configuration Example](config.example.toml)
- [Full Documentation](docs/README.md)

---

## [0.3.1] - 2025-11-06

### Added
- Comprehensive documentation structure
- API endpoint documentation
- Detection technique guides
- QuickStart guide
- Installation instructions

### Changed
- Improved CLAUDE.md project instructions
- Updated repository structure

### Fixed
- Documentation link fixes

---

## [0.3.0] - Previous Release

### Added
- Heaven's Gate detection (WoW64 transitions)
- Process Doppelgänging detection (TxF)
- ETW self-protection mechanisms
- Machine learning engine
- REST API with WebSocket support

### Changed
- Improved detection accuracy
- Performance optimizations

---

## [0.2.0] - Previous Release

### Added
- Direct syscall detection
- Process hollowing detection
- Thread hijacking detection
- Basic REST API

---

## [0.1.0] - Initial Release

### Added
- Core detection engine
- ETW integration
- Basic monitoring capabilities
- Command-line interface

---

## Versioning Strategy

Process Guard follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for new functionality in a backward compatible manner
- **PATCH** version for backward compatible bug fixes

### Security Updates

Security fixes are released as:
- **PATCH** versions for minor security issues
- **MINOR** versions for major security enhancements
- **MAJOR** versions if security fix requires breaking changes

---

**Legend:**
- 🔒 Security fixes
- ✨ New features
- 🔧 Changes and improvements
- 🐛 Bug fixes
- 📝 Documentation
- ⚡ Performance improvements
- ⚠️ Breaking changes
