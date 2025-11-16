# Process Guard - Claude AI Assistant Guide

This document provides comprehensive guidance for Claude AI when working with the Process Guard codebase.

## 🎯 Project Overview

**Process Guard** is an advanced Windows process injection detection and prevention framework with real-time monitoring capabilities. It's designed for security researchers, SOC analysts, and developers building security monitoring solutions.

### Core Purpose
- Detect and prevent process injection attacks on Windows systems
- Monitor syscalls, WoW64 transitions, and memory manipulations
- Provide real-time alerts through REST API and WebSocket interfaces
- Offer machine learning-based behavioral analysis

### Technology Stack
- **Language**: Rust (stable)
- **Platform**: Windows (ETW, WoW64, kernel integration)
- **API**: REST API with WebSocket support
- **ML Engine**: Custom anomaly detection

## 📁 Project Structure

```
Process-Guard/
├── src/                    # Rust source code
│   ├── main.rs            # Entry point and CLI
│   ├── lib.rs             # Library exports
│   ├── detector.rs        # Core detection engine
│   ├── etw.rs             # Event Tracing for Windows integration
│   ├── etw_protection.rs  # ETW self-protection mechanisms
│   ├── heavens_gate.rs    # WoW64 Heaven's Gate detection
│   ├── ml.rs              # Machine learning engine
│   ├── txf.rs             # Transactional NTFS monitoring
│   ├── cli.rs             # CLI interface
│   └── kernel_driver.rs   # Kernel driver interface
├── docs/                  # Documentation
│   ├── api/              # API documentation
│   ├── detections/       # Detection technique guides
│   ├── development/      # Development guides
│   └── ops/              # Operations & configuration
├── tests/                # Integration tests
├── benches/              # Performance benchmarks
├── examples/             # Usage examples
└── public/               # Public assets

```

## 🔍 Detection Techniques

Process Guard implements the following detection techniques:

### ✅ Fully Implemented
1. **Direct Syscalls** (`src/detector.rs`) - Detects SysWhispers and inline syscalls
2. **Heaven's Gate** (`src/heavens_gate.rs`) - WoW64 x32→x64 transitions
3. **Process Hollowing** - Memory region analysis for code injection
4. **Process Doppelgänging** (`src/txf.rs`) - TxF transaction monitoring
5. **Thread Hijacking** - Thread context monitoring
6. **ETW Patching Protection** (`src/etw_protection.rs`) - Self-protection
7. **Module Stomping** - Module integrity verification

### 🔄 Planned/In Progress
- Fiber Injection detection
- AMSI Bypass detection
- Callback-based injection detection

## 📚 Documentation Structure

### Complete Documentation
- ✅ `docs/api/README.md` - API overview
- ✅ `docs/api/websockets.md` - WebSocket events
- ✅ `docs/api/errors.md` - Error handling
- ✅ `docs/api/processes.md` - Process endpoints
- ✅ `docs/api/syscalls.md` - Syscall monitoring
- ✅ `docs/api/wow64.md` - WoW64 monitoring
- ✅ `docs/detections/README.md` - Detection overview
- ✅ `docs/detections/direct-syscalls.md` - Direct syscall detection
- ✅ `docs/detections/heavens-gate.md` - Heaven's Gate detection
- ✅ `docs/development/build.md` - Build instructions
- ✅ `docs/development/contributing.md` - Contribution guide
- ✅ `docs/quickstart.md` - Quick start guide
- ✅ `docs/installation.md` - Installation guide
- ✅ `docs/ops/config.md` - Configuration guide

### Missing Documentation (Stubs Needed)
The following documentation is referenced but doesn't exist yet:

#### Technical Documentation
- `docs/technical/architecture.md` - System architecture
- `docs/technical/etw.md` - ETW integration details
- `docs/technical/txf.md` - TxF monitoring
- `docs/technical/ml.md` - ML engine details
- `docs/technical/performance.md` - Performance optimization

#### API Documentation
- `docs/api/auth.md` - Authentication
- `docs/api/endpoints.md` - Complete endpoint reference

#### Detection Documentation
- `docs/detections/process-hollowing.md`
- `docs/detections/doppelganging.md`
- `docs/detections/thread-hijacking.md`
- `docs/detections/etw-patching.md`
- `docs/detections/module-stomping.md`
- `docs/detections/fiber-injection.md`
- `docs/detections/amsi-bypass.md`
- `docs/detections/callback-injection.md`
- `docs/detections/first-detection.md`
- `docs/detections/custom-rules.md`

#### Client Libraries
- `docs/clients/README.md`
- `docs/clients/javascript.md`
- `docs/clients/python.md`
- `docs/clients/powershell.md`
- `docs/clients/csharp.md`

#### Operations
- `docs/ops/logging.md`
- `docs/ops/metrics.md`
- `docs/ops/alerts.md`
- `docs/ops/troubleshooting.md`
- `docs/ops/false-positives.md`
- `docs/ops/performance-issues.md`
- `docs/ops/detection-gaps.md`

#### Development
- `docs/development/testing.md`
- `docs/development/benchmarks.md`
- `docs/first-steps.md`

## 🔒 Security Considerations

### Important Security Notes

1. **This is a Security Research Tool**
   - Process Guard is designed for legitimate security research, threat detection, and defensive security
   - It should only be used in authorized environments
   - Never use for malicious purposes or unauthorized system monitoring

2. **Privileged Access Required**
   - Requires Administrator/SYSTEM privileges
   - Uses SeDebugPrivilege for process memory access
   - Accesses kernel-level ETW events

3. **Self-Protection**
   - Implements ETW patching protection
   - Monitors own process integrity
   - Validates code signatures

4. **API Security**
   - Token-based authentication required
   - Rate limiting to prevent DoS
   - Input validation on all endpoints
   - No sensitive data in logs

### Code Security Best Practices

When modifying the codebase:
- ✅ Always validate user input
- ✅ Use Rust's type system for memory safety
- ✅ Avoid unsafe blocks unless absolutely necessary
- ✅ Document all unsafe code with safety invariants
- ✅ Run security audits: `cargo audit`
- ✅ Check for vulnerabilities: `cargo deny check`
- ✅ Use constant-time comparisons for secrets
- ✅ Never log sensitive information
- ✅ Implement proper error handling (no panics in production)

## 🛠️ Development Workflow

### Building
```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test --all-features

# Run benchmarks
cargo bench

# Security audit
cargo audit
```

### Testing
```bash
# Unit tests
cargo test --lib

# Integration tests
cargo test --test integration_tests

# Specific module tests
cargo test detector
cargo test etw
```

### Code Quality
```bash
# Format code
cargo fmt

# Lint code
cargo clippy -- -D warnings

# Check for security issues
cargo audit

# Generate documentation
cargo doc --open
```

## 🚨 Common Issues & Solutions

### Issue: Missing Documentation Links
**Problem**: Many documentation files are referenced but don't exist
**Solution**: This has been identified and stub files are being created

### Issue: ETW Access Denied
**Problem**: Cannot initialize ETW session
**Solution**: Ensure running with Administrator privileges and SeDebugPrivilege

### Issue: High CPU Usage
**Problem**: Detection engine consuming excessive CPU
**Solution**: Adjust `monitoring.interval_ms` in config and reduce enabled techniques

### Issue: False Positives
**Problem**: Legitimate processes being flagged
**Solution**: Adjust `detection.confidence_threshold` and add process whitelist

## 📊 Performance Metrics

Target performance characteristics:
- **Detection Latency**: < 1ms average
- **Memory Usage**: < 60MB runtime
- **CPU Usage**: < 3% background monitoring
- **Event Processing**: > 15,000 events/sec
- **False Positive Rate**: < 0.1%

## 🔗 Important Links

- **Repository**: https://github.com/xrer/process-guard
- **Issues**: https://github.com/xrer/process-guard/issues
- **Releases**: https://github.com/xrer/process-guard/releases
- **Documentation**: `/docs/README.md`

## 💡 Tips for Claude AI

### When Reviewing Code
1. Check for unsafe Rust blocks and verify safety invariants
2. Ensure Windows API calls are properly error-handled
3. Validate that ETW callbacks don't panic
4. Verify privilege checks before sensitive operations
5. Ensure API endpoints validate all input

### When Adding Features
1. Add corresponding tests in `tests/`
2. Update relevant documentation in `docs/`
3. Add benchmarks if performance-critical
4. Update `CHANGELOG.md` with changes
5. Ensure backward compatibility with API

### When Fixing Bugs
1. Add a test that reproduces the bug
2. Fix the issue
3. Verify the test passes
4. Check for similar issues in related code
5. Update documentation if behavior changed

### When Writing Documentation
1. Include practical code examples
2. Document Windows-specific behavior
3. Note privilege requirements
4. Add performance implications
5. Link to related documentation

## 🎓 Learning Resources

### Windows Internals
- Process injection techniques (MITRE ATT&CK T1055)
- ETW (Event Tracing for Windows) architecture
- WoW64 subsystem and Heaven's Gate technique
- Transactional NTFS (TxF) API

### Rust Security
- Unsafe code guidelines
- Memory safety in FFI
- Error handling best practices
- Windows API bindings (winapi crate)

## 📝 Version Information

- **Current Version**: 0.3.1
- **Minimum Rust Version**: 1.70.0
- **Target Platform**: Windows 10/11 (x64)
- **API Version**: 1.0

---

**Last Updated**: 2025-11-16
**Maintained By**: Process Guard Team
**For**: Claude AI Assistant
