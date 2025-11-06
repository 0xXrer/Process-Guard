# Quick Start Guide

Get Process Guard up and running in 10 minutes.

## 🚀 Installation

### Prerequisites
- Windows 10/11 or Windows Server 2019+
- Administrator privileges
- Rust 1.70+ (for building from source)

### Option 1: Pre-built Binaries (Recommended)
```bash
# Download latest release
curl -LO https://github.com/xrer/process-guard/releases/latest/download/process-guard-windows-x64.zip

# Extract and install
unzip process-guard-windows-x64.zip
cd process-guard
```

### Option 2: Build from Source
```bash
# Clone repository
git clone https://github.com/xrer/process-guard.git
cd process-guard

# Build release binary
cargo build --release

# Binary will be at target/release/process-guard.exe
```

## ⚡ Basic Setup

### 1. Initial Configuration
Create basic configuration file:

```bash
# Create config directory
mkdir %USERPROFILE%\.config\process-guard

# Generate default config
process-guard config init
```

This creates `config.toml`:
```toml
[monitoring]
interval_ms = 100
auto_terminate = false

[detection]
enabled_techniques = [
    "ProcessHollowing",
    "ProcessDoppelganging",
    "DirectSyscalls",
    "HeavensGate"
]
confidence_threshold = 0.8

[api]
enabled = true
port = 8080
```

### 2. Test Installation
```bash
# Check version and help
process-guard --version
process-guard --help

# Verify privileges (must be Administrator)
process-guard check-privileges
```

## 🛡️ First Detection

### Start Monitoring
```bash
# Start basic monitoring (run as Administrator)
process-guard monitor

# Or with specific techniques
process-guard monitor --syscalls --wow64 --verbose
```

You should see output like:
```
[INFO] Process Guard v0.3.1 starting...
[INFO] ETW session initialized
[INFO] Detection engines loaded: 4
[INFO] Monitoring 127 processes
[INFO] API server listening on http://127.0.0.1:8080
[INFO] Ready for threat detection
```

### Test Detection
Open another terminal and create a test scenario:

```bash
# Scan current processes
process-guard list --suspicious

# Scan specific process
process-guard scan 1234

# Check statistics
process-guard stats
```

### Verify API Access
```bash
# Test REST API
curl http://127.0.0.1:8080/api/health

# List processes via API
curl http://127.0.0.1:8080/api/processes
```

## 📊 Monitoring Dashboard

### Real-time Statistics
```bash
# Live dashboard
process-guard stats --realtime

# Export current stats
process-guard stats --export stats.csv
```

### Web Interface (Optional)
If API is enabled, open browser to:
```
http://127.0.0.1:8080/dashboard
```

## 🔧 Common Commands

### Process Management
```bash
# List all processes with risk scores
process-guard list --detailed

# Scan suspicious processes only
process-guard list --suspicious | xargs -I {} process-guard scan {}

# Terminate malicious process
process-guard kill 1234 --reason "Direct syscalls detected"
```

### Detection Control
```bash
# Enable specific detection
process-guard config set detection.syscall_monitoring true

# Set confidence threshold
process-guard config set detection.confidence_threshold 0.9

# Restart monitoring with new config
process-guard monitor --reload
```

### Export & Analysis
```bash
# Export YARA rules
process-guard export yara --output detection-rules.yar

# Export detection events
process-guard export json --since "2025-11-06" --output events.json

# Generate report
process-guard report --format pdf --output security-report.pdf
```

## 🎯 Configuration Examples

### High Security Environment
```toml
[detection]
confidence_threshold = 0.7
auto_terminate = true
create_memory_dumps = true

[monitoring]
interval_ms = 50
deep_memory_analysis = true
```

### Production Environment
```toml
[detection]
confidence_threshold = 0.85
auto_terminate = false

[monitoring]
interval_ms = 200
performance_mode = true

[logging]
level = "warn"
file = "C:\\Logs\\process-guard.log"
```

### Development Environment
```toml
[detection]
confidence_threshold = 0.9
auto_terminate = false

[monitoring]
interval_ms = 500
whitelist = [
    "devenv.exe",
    "cargo.exe",
    "rust-analyzer.exe"
]

[logging]
level = "debug"
console = true
```

## 🚨 First Response

When Process Guard detects a threat:

### 1. Review Alert
```bash
# Check recent detections
process-guard detections --since 1h

# Get detailed information
process-guard scan 1234 --detailed --output scan-1234.json
```

### 2. Investigate Process
```bash
# Analyze process tree
process-guard tree 1234

# Check network connections
process-guard network 1234

# Memory analysis
process-guard memory 1234 --dump
```

### 3. Take Action
```bash
# Isolate process (stop network access)
process-guard isolate 1234

# Create forensic dump
process-guard dump 1234 --full --output forensic-1234.dmp

# Terminate if confirmed malicious
process-guard kill 1234 --force
```

## 🔍 Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Verify running as Administrator
whoami /groups | findstr "S-1-5-32-544"

# Enable SeDebugPrivilege
process-guard privileges --enable SeDebugPrivilege
```

#### ETW Session Failed
```bash
# Check existing ETW sessions
logman query -ets

# Stop conflicting sessions
process-guard etw --stop-all --force
```

#### High CPU Usage
```bash
# Check performance impact
process-guard benchmark --quick

# Enable performance mode
process-guard config set monitoring.performance_mode true
```

#### False Positives
```bash
# Add to whitelist
process-guard whitelist add "legitimate-app.exe"

# Adjust confidence threshold
process-guard config set detection.confidence_threshold 0.9

# Review detection rules
process-guard rules --list --verbose
```

## 📚 Next Steps

### Learn More
- [**API Integration**](./api/README.md) - Integrate with SIEM/SOAR
- [**Detection Deep Dive**](./detections/README.md) - Understand detection techniques
- [**Performance Tuning**](./technical/performance.md) - Optimize for your environment
- [**Advanced Configuration**](./ops/config.md) - Detailed configuration options

### Get Help
- [**Documentation**](./README.md) - Complete documentation
- [**Troubleshooting**](./ops/troubleshooting.md) - Common issues and solutions
- [**Community**](https://github.com/xrer/process-guard/discussions) - Ask questions
- [**Issues**](https://github.com/xrer/process-guard/issues) - Report bugs

## ⚠️ Important Notes

### Security Considerations
- Always run as Administrator/SYSTEM for full functionality
- Monitor own process integrity to prevent tampering
- Use strong API authentication in production environments
- Regularly update detection rules and patterns

### Performance Guidelines
- Start with default settings, then tune based on environment
- Monitor CPU/memory usage during initial deployment
- Use performance mode for high-throughput environments
- Consider whitelisting known-good applications

### Legal & Compliance
- Ensure monitoring complies with local privacy laws
- Document detection capabilities for compliance audits
- Maintain logs for forensic analysis requirements
- Review data retention policies

---

**🎉 Congratulations!** Process Guard is now protecting your system. Check the [full documentation](./README.md) for advanced features and configuration options.