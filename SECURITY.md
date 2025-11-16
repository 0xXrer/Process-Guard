# Security Policy

## 🔒 Security Overview

Process Guard is a security research and defensive security tool designed to detect and prevent process injection attacks on Windows systems. We take security seriously and appreciate the security community's efforts to responsibly disclose vulnerabilities.

## 🛡️ Supported Versions

We provide security updates for the following versions:

| Version | Supported          | End of Support |
| ------- | ------------------ | -------------- |
| 0.3.x   | ✅ Yes (Current)   | N/A            |
| 0.2.x   | ⚠️ Limited         | 2025-12-31     |
| 0.1.x   | ❌ No              | 2025-06-30     |
| < 0.1   | ❌ No              | Ended          |

**Note**: We recommend always using the latest stable release for the best security posture and feature set.

## 🚨 Reporting a Vulnerability

### How to Report

If you discover a security vulnerability in Process Guard, please report it responsibly:

1. **DO NOT** open a public GitHub issue for security vulnerabilities
2. **DO NOT** disclose the vulnerability publicly until it has been addressed
3. **DO** email security details to: **security@process-guard.dev** (or create a GitHub Security Advisory)

### What to Include

Please provide the following information in your report:

- **Description**: Detailed description of the vulnerability
- **Impact**: Potential security impact and affected versions
- **Reproduction**: Step-by-step instructions to reproduce the issue
- **Proof of Concept**: Code, screenshots, or other evidence (if available)
- **Suggested Fix**: Your recommendation for fixing the issue (optional)
- **Disclosure Timeline**: Your preferred disclosure timeline

### Example Report Template

```markdown
## Vulnerability Report

**Reporter**: [Your Name / Handle]
**Date**: [YYYY-MM-DD]
**Affected Version(s)**: [e.g., 0.3.1, all versions]

### Description
[Detailed description of the vulnerability]

### Impact
- **Severity**: [Critical/High/Medium/Low]
- **Attack Vector**: [Local/Network/Physical]
- **Privileges Required**: [None/Low/High]
- **User Interaction**: [None/Required]

### Reproduction Steps
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Proof of Concept
[Code, commands, or screenshots]

### Suggested Fix
[Your recommendations]
```

## 📋 Security Response Process

### Our Commitment

When you report a vulnerability, we commit to:

1. **Acknowledge** your report within **48 hours**
2. **Provide an initial assessment** within **5 business days**
3. **Keep you updated** on the progress of the fix
4. **Credit you** in the security advisory (if desired)
5. **Coordinate disclosure** timing with you

### Response Timeline

| Stage | Timeline | Description |
|-------|----------|-------------|
| **Acknowledgment** | 48 hours | We confirm receipt of your report |
| **Triage** | 5 days | We assess severity and impact |
| **Investigation** | 1-2 weeks | We investigate and develop a fix |
| **Patch Development** | 2-4 weeks | We implement and test the fix |
| **Release** | 4-6 weeks | We release the patched version |
| **Public Disclosure** | 7 days after release | We publish security advisory |

**Note**: Timeline may vary based on severity and complexity of the vulnerability.

## 🔐 Security Best Practices

### For Users

When deploying Process Guard:

#### 1. **Principle of Least Privilege**
```toml
# config.toml - Use minimal required privileges
[security]
drop_privileges_after_init = true
required_privileges = ["SeDebugPrivilege"]  # Only what's needed
```

#### 2. **API Security**
```toml
# config.toml - Secure API configuration
[api]
enabled = true
port = 8080
auth_required = true
auth_token = "CHANGE_THIS_TO_STRONG_RANDOM_TOKEN"  # Use strong tokens!
rate_limit_requests_per_minute = 100
tls_enabled = true  # Enable TLS in production
tls_cert = "path/to/cert.pem"
tls_key = "path/to/key.pem"
```

#### 3. **Network Security**
```toml
# config.toml - Restrict API access
[api.access_control]
allowed_ips = ["127.0.0.1", "10.0.0.0/8"]  # Whitelist IPs
deny_by_default = true
```

#### 4. **Logging Security**
```toml
# config.toml - Secure logging
[logging]
level = "info"  # Don't use "debug" in production
sanitize_sensitive_data = true  # Remove tokens, passwords
log_to_file = true
log_file = "C:\\ProgramData\\ProcessGuard\\logs\\guard.log"
max_log_size_mb = 100
```

#### 5. **Update Regularly**
```bash
# Check for updates weekly
cargo install process-guard --force

# Or download latest release
# https://github.com/xrer/process-guard/releases/latest
```

### For Developers

When contributing to Process Guard:

#### 1. **Input Validation**
```rust
// GOOD - Validate all inputs
fn scan_process(pid: u32) -> Result<Detection, Error> {
    if pid == 0 || pid > u32::MAX {
        return Err(Error::InvalidPid(pid));
    }
    // ... safe to proceed
}

// BAD - No validation
fn scan_process(pid: u32) -> Detection {
    unsafe { /* assumes pid is valid */ }
}
```

#### 2. **Safe FFI Calls**
```rust
// GOOD - Error handling and safety checks
unsafe fn read_process_memory(handle: HANDLE, addr: usize) -> Result<Vec<u8>, Error> {
    if handle.is_null() {
        return Err(Error::InvalidHandle);
    }
    // ... proper error handling
}

// BAD - No safety checks
unsafe fn read_process_memory(handle: HANDLE, addr: usize) -> Vec<u8> {
    // ... unchecked unsafe operations
}
```

#### 3. **Secure Secret Handling**
```rust
// GOOD - Constant-time comparison
use subtle::ConstantTimeEq;

fn verify_token(provided: &str, expected: &str) -> bool {
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

// BAD - Timing attack vulnerable
fn verify_token(provided: &str, expected: &str) -> bool {
    provided == expected  // Timing oracle!
}
```

#### 4. **Avoid Information Disclosure**
```rust
// GOOD - Generic error messages
return Err(Error::AuthenticationFailed);

// BAD - Leaks information
return Err(Error::InvalidToken("Expected: abc123, Got: xyz789"));
```

#### 5. **Run Security Checks**
```bash
# Before committing
cargo clippy -- -D warnings
cargo audit
cargo deny check advisories
cargo test --all-features

# Periodic security scans
cargo outdated
cargo geiger  # Detect unsafe code usage
```

## 🔍 Known Security Considerations

### 1. **Elevated Privileges Required**

**Issue**: Process Guard requires Administrator privileges and SeDebugPrivilege.

**Risk**: If compromised, attacker gains elevated access.

**Mitigation**:
- Run Process Guard in isolated environment
- Use Windows Defender Application Control (WDAC)
- Monitor Process Guard's own process integrity
- Enable code signing verification

### 2. **ETW Event Processing**

**Issue**: Processing untrusted kernel events could lead to parsing vulnerabilities.

**Mitigation**:
- All ETW data is validated before processing
- Events are processed in isolated context
- Buffer overflow protections enabled
- Fuzz testing on ETW parsers

### 3. **REST API Exposure**

**Issue**: API endpoints could be targeted for abuse or DoS attacks.

**Mitigation**:
- Authentication required by default
- Rate limiting implemented
- Input validation on all endpoints
- TLS/HTTPS support
- IP whitelisting available

### 4. **Memory Safety**

**Issue**: Unsafe Rust code used for Windows API interaction.

**Mitigation**:
- Minimal use of `unsafe` blocks
- All unsafe code documented with safety invariants
- Extensive testing of unsafe sections
- Memory sanitizers in CI/CD

### 5. **False Positive Handling**

**Issue**: Detection engine might flag legitimate processes.

**Mitigation**:
- Confidence thresholds adjustable
- Machine learning adapts to environment
- Whitelist/blacklist support
- Detailed logging for investigation

## 🚀 Security Features

Process Guard includes the following security features:

### ✅ Built-in Protections

1. **Self-Integrity Monitoring**
   - Detects tampering with own process
   - Validates code signatures
   - Monitors ETW callback integrity

2. **Defense in Depth**
   - Multiple detection layers
   - Redundant validation
   - Fail-secure defaults

3. **Secure by Default**
   - Authentication enabled by default
   - Minimal privileges requested
   - Safe configuration defaults

4. **Audit Logging**
   - All security events logged
   - Tamper-evident logging
   - SIEM integration support

5. **Cryptographic Security**
   - Constant-time comparisons for secrets
   - Secure random number generation
   - TLS support for API

## 📊 Security Audit History

| Date | Type | Findings | Status |
|------|------|----------|--------|
| 2025-11-16 | Internal Review | Documentation gaps identified | ✅ Fixed |
| 2025-11-06 | Code Audit | No critical issues | ✅ Passed |
| Future | External Audit | Planned | 📅 Scheduled |

## 🎖️ Security Hall of Fame

We recognize security researchers who have responsibly disclosed vulnerabilities:

| Researcher | Vulnerability | Severity | Date |
|------------|---------------|----------|------|
| *Your name could be here* | - | - | - |

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [Windows Security Best Practices](https://docs.microsoft.com/en-us/windows/security/)

## 📞 Contact

- **Security Email**: security@process-guard.dev
- **General Issues**: https://github.com/xrer/process-guard/issues
- **Security Advisories**: https://github.com/xrer/process-guard/security/advisories

## 📄 Responsible Disclosure Policy

We follow responsible disclosure principles:

1. **Coordination**: We work with reporters to coordinate disclosure
2. **Credit**: We credit researchers in advisories (if desired)
3. **Transparency**: We publish advisories after fixes are released
4. **No Legal Action**: We won't pursue legal action against good-faith researchers

### Safe Harbor

We consider the following activities as authorized security research:

- ✅ Testing against your own installations
- ✅ Responsible vulnerability disclosure
- ✅ Following this security policy
- ✅ Making good faith effort to avoid harm

We consider the following activities as **NOT** authorized:

- ❌ Attacking production systems without authorization
- ❌ Accessing data that isn't yours
- ❌ Social engineering or phishing
- ❌ Denial of service attacks
- ❌ Physical attacks against facilities or personnel

---

**Last Updated**: 2025-11-16
**Version**: 1.0
**Contact**: security@process-guard.dev
