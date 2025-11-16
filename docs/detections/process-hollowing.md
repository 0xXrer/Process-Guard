# Process Hollowing Detection

Detection and prevention of process hollowing injection techniques.

## 📋 Overview

Process hollowing is a sophisticated code injection technique where an attacker:
1. Creates a legitimate process in suspended state
2. Unmaps the legitimate code from memory
3. Writes malicious code into the hollowed process
4. Resumes the process to execute malicious code

**MITRE ATT&CK**: T1055.012 - Process Injection: Process Hollowing

## 🔍 Detection Methods

Process Guard detects process hollowing through multiple techniques:

### 1. Memory Region Analysis
- Compares memory regions with disk image
- Identifies unmapped original sections
- Detects mismatches in PE headers

### 2. Entry Point Verification
- Checks if entry point matches disk image
- Validates section characteristics
- Monitors for suspicious entry point changes

### 3. Suspended Process Monitoring
- Tracks processes created in suspended state
- Monitors for memory writes before resume
- Detects anomalous resume timing

## 🚨 Detection Indicators

Process Guard flags the following as suspicious:

- ✅ Process created with `CREATE_SUSPENDED` flag
- ✅ Memory unmapping via `NtUnmapViewOfSection`
- ✅ Large memory writes to remote process
- ✅ Entry point differs from disk image
- ✅ Modified PE headers in memory
- ✅ Executable sections with wrong protections

## 📊 Detection Example

```
[ALERT] Process Hollowing Detected
PID: 4892
Process: svchost.exe
Confidence: 95%

Indicators:
  ✓ Created in suspended state
  ✓ Original sections unmapped
  ✓ Entry point modified: 0x401000 → 0x7FF800001000
  ✓ PE header mismatch detected
  ✓ Suspicious resume after 250ms

Recommendation: Terminate and investigate
```

## 🔧 Configuration

```toml
[detection.process_hollowing]
enabled = true
check_entry_point = true
check_pe_headers = true
monitor_suspended_processes = true
confidence_threshold = 0.85
```

## 📚 Related Techniques

- [Process Doppelgänging](./doppelganging.md) - TxF-based injection
- [Thread Hijacking](./thread-hijacking.md) - Alternative injection method
- [Direct Syscalls](./direct-syscalls.md) - May be used together

---

**Status**: Implemented ✅
**Last Updated**: 2025-11-16
