# Installation Guide

Complete installation instructions for Process Guard across different environments.

## 📋 System Requirements

### Minimum Requirements
- **OS**: Windows 10 (1809) or Windows Server 2019
- **RAM**: 4GB available memory
- **CPU**: x64 processor with 2+ cores
- **Storage**: 500MB free disk space
- **Privileges**: Administrator/SYSTEM account

### Recommended Requirements
- **OS**: Windows 11 or Windows Server 2022
- **RAM**: 8GB+ available memory
- **CPU**: x64 processor with 4+ cores
- **Storage**: 2GB free disk space (for logs and dumps)
- **Network**: Unrestricted access for updates

### Supported Architectures
- ✅ **x64 (AMD64)** - Primary supported platform
- ❌ **ARM64** - Not currently supported
- ❌ **x86 (32-bit)** - Legacy architecture not supported

## 🚀 Installation Methods

### Method 1: Pre-built Binaries (Recommended)

#### Download Latest Release
```powershell
# Using PowerShell
$LatestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/xrer/process-guard/releases/latest"
$DownloadUrl = $LatestRelease.assets | Where-Object { $_.name -like "*windows-x64.zip" } | Select-Object -ExpandProperty browser_download_url
Invoke-WebRequest -Uri $DownloadUrl -OutFile "process-guard-latest.zip"

# Extract
Expand-Archive -Path "process-guard-latest.zip" -DestinationPath "C:\Program Files\ProcessGuard"
```

#### Using Curl
```bash
# Download
curl -LO https://github.com/xrer/process-guard/releases/latest/download/process-guard-windows-x64.zip

# Extract
unzip process-guard-windows-x64.zip -d "C:\Program Files\ProcessGuard"
```

#### Manual Installation
1. Visit [GitHub Releases](https://github.com/xrer/process-guard/releases)
2. Download `process-guard-windows-x64.zip`
3. Extract to `C:\Program Files\ProcessGuard`
4. Add to PATH (optional)

### Method 2: Package Managers

#### Chocolatey
```powershell
# Install Chocolatey if not present
Set-ExecutionPolicy Bypass -Scope Process -Force
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install Process Guard
choco install process-guard
```

#### Winget (Windows Package Manager)
```powershell
# Install via winget
winget install xrer.ProcessGuard

# Verify installation
winget list process-guard
```

#### Scoop
```powershell
# Add bucket
scoop bucket add process-guard https://github.com/xrer/scoop-process-guard.git

# Install
scoop install process-guard
```

### Method 3: Build from Source

#### Prerequisites
```powershell
# Install Rust
Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile "rustup-init.exe"
.\rustup-init.exe -y
refreshenv

# Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/vs/features/cplusplus/

# Install Windows SDK
# Download from: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
```

#### Build Process
```powershell
# Clone repository
git clone https://github.com/xrer/process-guard.git
cd process-guard

# Install dependencies
rustup component add clippy rustfmt
cargo install cargo-tarpaulin

# Build release
cargo build --release

# Run tests
cargo test --all-features

# Binary location
# target\release\process-guard.exe
```

#### Development Build
```powershell
# Debug build for development
cargo build

# With additional debugging
cargo build --features debug-symbols

# Binary location
# target\debug\process-guard.exe
```

## ⚙️ Post-Installation Setup

### 1. Path Configuration
```powershell
# Add to system PATH
$ProcessGuardPath = "C:\Program Files\ProcessGuard"
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
[Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$ProcessGuardPath", "Machine")

# Verify
refreshenv
process-guard --version
```

### 2. Service Installation (Optional)
```powershell
# Install as Windows Service
process-guard service install --start-type automatic

# Configure service
process-guard service config --config-file "C:\ProgramData\ProcessGuard\config.toml"

# Start service
process-guard service start

# Check status
process-guard service status
```

### 3. Configuration Directory
```powershell
# Create configuration directory
New-Item -ItemType Directory -Path "C:\ProgramData\ProcessGuard" -Force

# Generate default configuration
process-guard config init --system-wide

# Edit configuration
notepad "C:\ProgramData\ProcessGuard\config.toml"
```

### 4. Privilege Setup
```powershell
# Grant SeDebugPrivilege (if needed)
process-guard privileges --grant SeDebugPrivilege

# Verify privileges
process-guard privileges --check
```

## 🐳 Container Deployment

### Docker Support
```dockerfile
# Windows Server Core base image
FROM mcr.microsoft.com/windows/servercore:ltsc2022

# Copy Process Guard binary
COPY process-guard.exe C:\ProcessGuard\
COPY config.toml C:\ProcessGuard\

# Set working directory
WORKDIR C:\ProcessGuard

# Expose API port
EXPOSE 8080

# Run as service
CMD ["process-guard.exe", "monitor", "--api"]
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: process-guard
  namespace: security
spec:
  selector:
    matchLabels:
      app: process-guard
  template:
    metadata:
      labels:
        app: process-guard
    spec:
      nodeSelector:
        kubernetes.io/os: windows
      containers:
      - name: process-guard
        image: process-guard:latest
        securityContext:
          windowsOptions:
            runAsUserName: "SYSTEM"
        ports:
        - containerPort: 8080
          name: api
        volumeMounts:
        - name: config
          mountPath: C:\ProcessGuard\config.toml
          subPath: config.toml
        - name: logs
          mountPath: C:\Logs
      volumes:
      - name: config
        configMap:
          name: process-guard-config
      - name: logs
        hostPath:
          path: C:\Logs\ProcessGuard
```

## 🔧 Configuration Management

### Configuration File Locations

#### User Configuration
```
%USERPROFILE%\.config\process-guard\config.toml
```

#### System-wide Configuration
```
C:\ProgramData\ProcessGuard\config.toml
```

#### Service Configuration
```
C:\Program Files\ProcessGuard\config.toml
```

### Configuration Priority
1. Command-line arguments (highest priority)
2. Environment variables
3. User configuration file
4. System-wide configuration file
5. Default values (lowest priority)

### Basic Configuration
```toml
[monitoring]
interval_ms = 100
enabled = true
auto_start = true

[detection]
enabled_techniques = ["all"]
confidence_threshold = 0.8
auto_terminate = false

[api]
enabled = true
port = 8080
bind_address = "127.0.0.1"

[logging]
level = "info"
file = "C:\\Logs\\ProcessGuard\\process-guard.log"
max_size_mb = 100
rotate_count = 5
```

## 🛡️ Security Hardening

### File Permissions
```powershell
# Secure installation directory
icacls "C:\Program Files\ProcessGuard" /grant:r "Administrators:F" /grant:r "SYSTEM:F" /remove:g "Users" /T

# Secure configuration files
icacls "C:\ProgramData\ProcessGuard" /grant:r "Administrators:F" /grant:r "SYSTEM:F" /remove:g "Users" /T

# Secure log directory
icacls "C:\Logs\ProcessGuard" /grant:r "Administrators:F" /grant:r "SYSTEM:F" /T
```

### Windows Defender Exclusions
```powershell
# Add Windows Defender exclusions
Add-MpPreference -ExclusionProcess "process-guard.exe"
Add-MpPreference -ExclusionPath "C:\Program Files\ProcessGuard"
Add-MpPreference -ExclusionPath "C:\ProgramData\ProcessGuard"
```

### Firewall Configuration
```powershell
# Allow API access (if needed)
New-NetFirewallRule -DisplayName "Process Guard API" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow

# Allow ETW access (usually not needed)
New-NetFirewallRule -DisplayName "Process Guard ETW" -Direction Inbound -Protocol TCP -LocalPort 0-65535 -Action Allow -Profile Domain,Private
```

## 🔍 Verification & Testing

### Installation Verification
```powershell
# Check version
process-guard --version

# Verify installation
process-guard check --installation

# Test basic functionality
process-guard test --quick

# Validate configuration
process-guard config validate
```

### Functionality Tests
```powershell
# Test detection engines
process-guard test detection --all

# Test API endpoints
process-guard test api --endpoint all

# Test ETW integration
process-guard test etw --session-count 1

# Performance benchmark
process-guard benchmark --quick
```

### Health Check
```powershell
# System health
process-guard health --system

# Process Guard health
process-guard health --self

# Configuration health
process-guard health --config

# API health
curl http://127.0.0.1:8080/api/health
```

## 📊 Monitoring Installation

### Event Logs
Process Guard writes to Windows Event Log:
- **Application Log**: General events and errors
- **Security Log**: Detection events and alerts
- **System Log**: Service and driver events

### Log Files
```powershell
# Main log file
Get-Content "C:\Logs\ProcessGuard\process-guard.log" -Tail 50

# Detection events
Get-Content "C:\Logs\ProcessGuard\detections.log" -Tail 20

# API access log
Get-Content "C:\Logs\ProcessGuard\api.log" -Tail 30
```

### Performance Counters
```powershell
# View performance counters
Get-Counter "\Process Guard\Detection Latency"
Get-Counter "\Process Guard\Memory Usage"
Get-Counter "\Process Guard\CPU Usage"
```

## 🚨 Troubleshooting Installation

### Common Issues

#### Issue: Access Denied
```powershell
# Solution: Run as Administrator
Start-Process powershell -Verb RunAs
```

#### Issue: Missing Dependencies
```powershell
# Solution: Install Visual C++ Redistributable
Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "vc_redist.x64.exe"
.\vc_redist.x64.exe /quiet
```

#### Issue: ETW Session Conflicts
```powershell
# Solution: Stop conflicting sessions
logman stop "NT Kernel Logger" -ets
process-guard etw --reset-sessions
```

#### Issue: Antivirus False Positive
```powershell
# Solution: Add exclusions
Add-MpPreference -ExclusionProcess "process-guard.exe"
```

### Diagnostic Commands
```powershell
# Collect diagnostic information
process-guard diagnostics --collect --output diagnostics.zip

# Check system compatibility
process-guard system-check --detailed

# Validate installation integrity
process-guard verify --installation --checksums
```

## 🔄 Updates & Maintenance

### Automatic Updates
```toml
[updates]
enabled = true
check_interval = "daily"
auto_install = false
backup_config = true
```

### Manual Updates
```powershell
# Check for updates
process-guard update --check

# Download and install
process-guard update --install

# Rollback if needed
process-guard update --rollback
```

### Maintenance Tasks
```powershell
# Clean old logs
process-guard maintenance --clean-logs --older-than 30d

# Compact database
process-guard maintenance --compact-db

# Update detection rules
process-guard update --rules-only

# Verify installation integrity
process-guard verify --full
```

---

## 🎯 Next Steps

After successful installation:

1. **[Quick Start Guide](./quickstart.md)** - Get up and running quickly
2. **[Configuration Guide](./ops/config.md)** - Detailed configuration options
3. **[API Documentation](./api/README.md)** - Integrate with existing systems
4. **[Detection Guide](./detections/README.md)** - Understand detection capabilities

Need help? Check our [Troubleshooting Guide](./ops/troubleshooting.md) or [open an issue](https://github.com/xrer/process-guard/issues).