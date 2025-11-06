# Configuration Guide

Complete configuration reference for Process Guard with examples and best practices.

## 📋 Configuration Overview

Process Guard uses TOML configuration files with a hierarchical structure. Configuration can be provided through:

1. **Command-line arguments** (highest priority)
2. **Environment variables**
3. **Configuration files** (user, system, default)
4. **Built-in defaults** (lowest priority)

## 📁 Configuration File Locations

### File Priority (highest to lowest)
1. `--config path/to/config.toml` (command line)
2. `%USERPROFILE%\.config\process-guard\config.toml` (user)
3. `C:\ProgramData\ProcessGuard\config.toml` (system)
4. Built-in defaults

### Creating Configuration
```bash
# Generate default configuration
process-guard config init

# Generate system-wide configuration
process-guard config init --system-wide

# Validate existing configuration
process-guard config validate

# Show effective configuration
process-guard config show
```

## ⚙️ Configuration Reference

### Basic Configuration
```toml
# config.toml - Basic example
[monitoring]
enabled = true
interval_ms = 100
auto_start = true

[detection]
enabled_techniques = ["ProcessHollowing", "DirectSyscalls", "HeavensGate"]
confidence_threshold = 0.8
auto_terminate = false

[api]
enabled = true
port = 8080
bind_address = "127.0.0.1"

[logging]
level = "info"
file = "./process-guard.log"
```

### Complete Configuration
```toml
# config.toml - Complete example with all options

# =============================================================================
# MONITORING SETTINGS
# =============================================================================
[monitoring]
# Enable/disable monitoring
enabled = true

# Scan interval in milliseconds
interval_ms = 100

# Auto-start monitoring on service startup
auto_start = true

# Enable deep memory analysis (higher resource usage)
deep_memory_analysis = false

# Performance mode (reduced accuracy, better performance)
performance_mode = false

# Maximum concurrent scans
max_concurrent_scans = 10

# Process scan timeout in seconds
scan_timeout_seconds = 30

# Whitelist of processes to ignore
whitelist = [
    "explorer.exe",
    "winlogon.exe",
    "csrss.exe",
    "dwm.exe"
]

# Blacklist of processes to always flag as suspicious
blacklist = [
    "known-malware.exe"
]

# Monitor process tree changes
monitor_process_tree = true

# Monitor file system changes
monitor_filesystem = true

# Monitor network connections
monitor_network = true

# Monitor registry changes
monitor_registry = false

# =============================================================================
# DETECTION SETTINGS
# =============================================================================
[detection]
# List of enabled detection techniques
enabled_techniques = [
    "ProcessHollowing",
    "ProcessDoppelganging",
    "DirectSyscalls",
    "HeavensGate",
    "ThreadHijacking",
    "EtwPatching",
    "ModuleStomping"
]

# Global confidence threshold (0.0 - 1.0)
confidence_threshold = 0.8

# Auto-terminate processes above this confidence
auto_terminate = false
auto_terminate_threshold = 0.95

# Create memory dumps for high-confidence detections
create_memory_dumps = false
memory_dump_threshold = 0.9
memory_dump_directory = "./dumps"

# Maximum detections to store in memory
max_detections_cached = 10000

# Detection timeout per technique (milliseconds)
technique_timeout_ms = 5000

# Enable false positive reduction algorithms
false_positive_reduction = true

# Minimum time between detections for same process (seconds)
detection_cooldown_seconds = 10

# =============================================================================
# TECHNIQUE-SPECIFIC SETTINGS
# =============================================================================

# Direct Syscalls Detection
[detection.direct_syscalls]
enabled = true
stack_trace_validation = true
pattern_matching = true
etw_integration = true
confidence_boost = 0.1

# Heaven's Gate Detection
[detection.heavens_gate]
enabled = true
monitor_wow64_only = true
detect_far_jumps = true
track_x64_regions = true
cs_segment_monitoring = true

# Process Doppelgänging Detection
[detection.process_doppelganging]
enabled = true
monitor_txf_transactions = true
pe_validation = true
rollback_detection = true

# ETW Patching Detection
[detection.etw_patching]
enabled = true
self_integrity_checks = true
callback_validation = true
hash_verification = true

# =============================================================================
# ETW (EVENT TRACING FOR WINDOWS) SETTINGS
# =============================================================================
[etw]
# Enable ETW monitoring
enabled = true

# ETW session name
session_name = "ProcessGuardETW"

# Buffer size in KB
buffer_size_kb = 1024

# Number of buffers
buffer_count = 20

# Flush timer in seconds
flush_timer_seconds = 1

# Enable kernel events
enable_kernel_events = true

# Enable process events
enable_process_events = true

# Enable thread events
enable_thread_events = true

# Enable image load events
enable_image_events = true

# Enable file I/O events
enable_file_events = false

# Enable registry events
enable_registry_events = false

# Enable network events
enable_network_events = false

# =============================================================================
# MACHINE LEARNING SETTINGS
# =============================================================================
[ml]
# Enable ML-based anomaly detection
enabled = true

# ML model file path
model_path = "./models/anomaly_detection.onnx"

# Anomaly detection threshold
anomaly_threshold = 0.9

# Feature extraction settings
[ml.features]
process_behavior = true
memory_patterns = true
api_call_sequences = true
network_behavior = false

# Model update settings
[ml.updates]
auto_update = true
update_interval_hours = 24
update_server = "https://models.process-guard.dev"

# =============================================================================
# API SETTINGS
# =============================================================================
[api]
# Enable REST API server
enabled = true

# Bind address
bind_address = "127.0.0.1"

# Port number
port = 8080

# Enable HTTPS
tls_enabled = false
tls_cert_file = "./certs/server.crt"
tls_key_file = "./certs/server.key"

# API authentication
auth_enabled = true
auth_token = "your-secure-api-token-here"

# CORS settings
cors_enabled = true
cors_origins = ["http://localhost:3000", "https://dashboard.company.com"]

# Rate limiting
[api.rate_limiting]
enabled = true
requests_per_minute = 100
scan_requests_per_minute = 10
terminate_requests_per_minute = 5

# WebSocket settings
[api.websocket]
enabled = true
max_connections = 1000
buffer_size = 4096
compression = true
heartbeat_interval_seconds = 30

# =============================================================================
# LOGGING SETTINGS
# =============================================================================
[logging]
# Log level: trace, debug, info, warn, error
level = "info"

# Log to file
file_enabled = true
file_path = "./logs/process-guard.log"

# Log to console
console_enabled = true
console_colors = true

# Log to Windows Event Log
eventlog_enabled = true
eventlog_source = "ProcessGuard"

# Log to syslog (if available)
syslog_enabled = false
syslog_server = "192.168.1.100:514"

# Log rotation
[logging.rotation]
max_size_mb = 100
max_files = 10
compress = true

# Log formatting
[logging.format]
timestamp_format = "iso8601"  # iso8601, rfc3339, custom
include_thread_id = false
include_module_path = true

# Detection-specific logging
[logging.detections]
enabled = true
file_path = "./logs/detections.log"
format = "json"  # json, text, csv
include_stack_traces = true

# =============================================================================
# PERFORMANCE SETTINGS
# =============================================================================
[performance]
# Maximum memory usage in MB
max_memory_mb = 512

# CPU usage limit as percentage
cpu_limit_percent = 25.0

# I/O priority (1=low, 2=normal, 3=high)
io_priority = 2

# Thread pool size (0 = auto)
thread_pool_size = 0

# Cache settings
[performance.cache]
detection_cache_size = 10000
process_cache_size = 5000
pattern_cache_size = 1000
cache_ttl_seconds = 300

# Memory management
[performance.memory]
gc_interval_seconds = 60
max_heap_size_mb = 256
pre_allocate_buffers = true

# =============================================================================
# SECURITY SETTINGS
# =============================================================================
[security]
# Enable self-protection
self_protection_enabled = true

# Monitor own process integrity
self_integrity_checks = true

# Secure configuration file permissions
secure_config_permissions = true

# Encrypt sensitive data at rest
encrypt_sensitive_data = true
encryption_key_file = "./keys/master.key"

# Digital signature verification
[security.signatures]
verify_loaded_modules = true
trust_microsoft_signed = true
trust_store_path = "cert:\\LocalMachine\\TrustedPublisher"

# =============================================================================
# ALERTING & NOTIFICATIONS
# =============================================================================
[alerts]
# Enable alerting system
enabled = true

# Alert thresholds
critical_threshold = 0.95
high_threshold = 0.85
medium_threshold = 0.7

# Email notifications
[alerts.email]
enabled = false
smtp_server = "smtp.company.com"
smtp_port = 587
smtp_username = "alerts@company.com"
smtp_password = "password"
from_address = "process-guard@company.com"
to_addresses = ["security-team@company.com"]

# Webhook notifications
[alerts.webhook]
enabled = true
url = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
timeout_seconds = 10
retry_attempts = 3

# Windows Event Log alerts
[alerts.eventlog]
enabled = true
event_source = "ProcessGuard"
critical_event_id = 1001
high_event_id = 1002

# =============================================================================
# INTEGRATION SETTINGS
# =============================================================================

# SIEM Integration
[siem]
enabled = false
type = "splunk"  # splunk, elastic, qradar, sentinel
endpoint = "https://splunk.company.com:8088/services/collector"
token = "your-hec-token"
index = "security"

# EDR Integration
[edr]
enabled = false
type = "defender"  # defender, crowdstrike, sentinelone
api_endpoint = "https://api.securitycenter.microsoft.com"
tenant_id = "your-tenant-id"
client_id = "your-client-id"
client_secret = "your-client-secret"

# Threat Intelligence
[threat_intel]
enabled = false
providers = ["virustotal", "openioc"]
api_keys = { virustotal = "your-vt-api-key" }
cache_duration_hours = 24

# =============================================================================
# DEVELOPMENT & DEBUGGING
# =============================================================================
[development]
# Enable development mode (more verbose logging, relaxed security)
enabled = false

# Enable profiling
profiling_enabled = false
profile_output_path = "./profiles"

# Enable metrics collection
metrics_enabled = true
metrics_bind_address = "127.0.0.1:9090"

# Testing configuration
[development.testing]
create_test_processes = false
test_data_directory = "./test-data"
mock_detections = false

# =============================================================================
# SERVICE SETTINGS (Windows Service Mode)
# =============================================================================
[service]
# Service name
name = "ProcessGuard"

# Service display name
display_name = "Process Guard Security Service"

# Service description
description = "Advanced process injection detection and prevention"

# Service start type (auto, manual, disabled)
start_type = "auto"

# Service account (LocalSystem, NetworkService, or custom)
account = "LocalSystem"

# Service dependencies
dependencies = ["EventLog", "RpcSs"]

# Recovery actions
[service.recovery]
reset_period_seconds = 86400  # 24 hours
restart_service_delay_ms = 60000  # 1 minute
run_program_delay_ms = 120000  # 2 minutes
restart_attempts = 3
```

## 🌍 Environment Variables

Override configuration with environment variables:

### Monitoring
```bash
PROCESS_GUARD_MONITORING_ENABLED=true
PROCESS_GUARD_MONITORING_INTERVAL_MS=50
PROCESS_GUARD_MONITORING_PERFORMANCE_MODE=true
```

### Detection
```bash
PROCESS_GUARD_DETECTION_CONFIDENCE_THRESHOLD=0.9
PROCESS_GUARD_DETECTION_AUTO_TERMINATE=false
PROCESS_GUARD_DETECTION_ENABLED_TECHNIQUES=DirectSyscalls,HeavensGate
```

### API
```bash
PROCESS_GUARD_API_ENABLED=true
PROCESS_GUARD_API_PORT=8080
PROCESS_GUARD_API_AUTH_TOKEN=your-secure-token
```

### Logging
```bash
PROCESS_GUARD_LOGGING_LEVEL=debug
PROCESS_GUARD_LOGGING_FILE_PATH=./debug.log
```

## 🎯 Configuration Profiles

### High Security Environment
```toml
[monitoring]
interval_ms = 50
deep_memory_analysis = true

[detection]
confidence_threshold = 0.7
auto_terminate = true
auto_terminate_threshold = 0.9
create_memory_dumps = true

[logging]
level = "debug"
detections.enabled = true

[security]
self_protection_enabled = true
verify_loaded_modules = true
```

### Production Environment
```toml
[monitoring]
interval_ms = 200
performance_mode = true

[detection]
confidence_threshold = 0.85
auto_terminate = false
false_positive_reduction = true

[performance]
max_memory_mb = 256
cpu_limit_percent = 10.0

[logging]
level = "warn"
rotation.max_size_mb = 50
```

### Development Environment
```toml
[monitoring]
interval_ms = 500
whitelist = ["devenv.exe", "cargo.exe", "rust-analyzer.exe"]

[detection]
confidence_threshold = 0.9
auto_terminate = false

[logging]
level = "debug"
console_enabled = true
console_colors = true

[development]
enabled = true
profiling_enabled = true
metrics_enabled = true
```

### Minimal Resource Environment
```toml
[monitoring]
interval_ms = 1000
performance_mode = true
max_concurrent_scans = 2

[detection]
enabled_techniques = ["ProcessHollowing"]
confidence_threshold = 0.9

[performance]
max_memory_mb = 128
cpu_limit_percent = 5.0

[ml]
enabled = false

[api]
enabled = false
```

## 🔧 Configuration Management

### Command Line Tools
```bash
# Show current configuration
process-guard config show

# Show specific section
process-guard config show detection

# Validate configuration
process-guard config validate config.toml

# Set configuration value
process-guard config set detection.confidence_threshold 0.9

# Get configuration value
process-guard config get api.port

# Reset to defaults
process-guard config reset

# Generate configuration template
process-guard config template > config.toml
```

### Programmatic Configuration
```rust
use process_guard::Config;

// Load from file
let config = Config::from_file("config.toml")?;

// Load from environment
let config = Config::from_env()?;

// Programmatic configuration
let config = Config::builder()
    .monitoring_interval(100)
    .detection_threshold(0.8)
    .api_enabled(true)
    .api_port(8080)
    .build()?;

// Merge configurations
let config = Config::from_file("base.toml")?
    .merge_env()?
    .merge_file("override.toml")?;
```

## 🔒 Security Best Practices

### File Permissions
```powershell
# Secure configuration directory
icacls "C:\ProgramData\ProcessGuard" /grant:r "Administrators:F" /grant:r "SYSTEM:F" /remove:g "Users" /T

# Secure configuration file
icacls "C:\ProgramData\ProcessGuard\config.toml" /grant:r "Administrators:F" /grant:r "SYSTEM:R" /remove:g "Users"
```

### Sensitive Data
```toml
# Use environment variables for secrets
[api]
auth_token = "${PROCESS_GUARD_API_TOKEN}"

[alerts.email]
smtp_password = "${SMTP_PASSWORD}"

[siem]
token = "${SIEM_TOKEN}"
```

### Configuration Validation
```toml
[security]
# Enable configuration file integrity checking
secure_config_permissions = true

# Verify configuration signature (if signed)
verify_config_signature = true
config_signature_file = "./config.toml.sig"
```

## 📊 Configuration Monitoring

### Configuration Changes
Process Guard logs all configuration changes:

```json
{
  "timestamp": "2023-11-06T12:00:00Z",
  "level": "INFO",
  "event": "config_changed",
  "changes": [
    {
      "key": "detection.confidence_threshold",
      "old_value": 0.8,
      "new_value": 0.9,
      "source": "api"
    }
  ],
  "user": "admin",
  "source_ip": "192.168.1.100"
}
```

### Configuration Drift Detection
```bash
# Check for configuration drift
process-guard config drift --baseline baseline-config.toml

# Report configuration status
process-guard config status --format json
```

## 🚨 Troubleshooting

### Common Issues

#### Invalid Configuration Format
```bash
# Error: Failed to parse configuration file
# Solution: Validate TOML syntax
process-guard config validate config.toml
```

#### Permission Denied
```bash
# Error: Permission denied reading config file
# Solution: Check file permissions
icacls config.toml
```

#### Invalid Values
```bash
# Error: Confidence threshold out of range
# Solution: Check value constraints
process-guard config check --strict
```

### Debugging Configuration
```bash
# Show effective configuration with sources
process-guard config show --verbose --sources

# Test configuration without applying
process-guard config test config.toml

# Show configuration schema
process-guard config schema
```

---

## 📚 Related Documentation

- [Installation Guide](../installation.md) - Initial setup and installation
- [Quick Start](../quickstart.md) - Getting started quickly
- [API Reference](../api/README.md) - API configuration options
- [Security Guide](./security.md) - Security configuration best practices