# 📚 Documentation Navigation

Quick access to all Process Guard documentation.

## 🎯 I want to...

### 🚀 Get Started
| Goal | Document | Time |
|------|----------|------|
| Install and run | [Installation Guide](./installation.md) | 5 min |
| First detection | [Quick Start](./quickstart.md) | 10 min |
| Basic configuration | [Configuration Guide](./ops/config.md) | 15 min |

### 🔧 Integrate API
| Goal | Document | Time |
|------|----------|------|
| Understand API | [API Overview](./api/README.md) | 5 min |
| Manage processes | [Processes API](./api/processes.md) | 10 min |
| Monitor syscalls | [Syscalls API](./api/syscalls.md) | 15 min |
| Track WoW64 | [WoW64 API](./api/wow64.md) | 15 min |

### 🛡️ Understand Detections
| Goal | Document | Time |
|------|----------|------|
| Detection overview | [Detection Matrix](./detections/README.md) | 10 min |
| Direct syscalls | [Direct Syscalls](./detections/direct-syscalls.md) | 20 min |
| Heaven's Gate | [Heaven's Gate](./detections/heavens-gate.md) | 20 min |
| Process Doppelgänging | [Doppelgänging](./detections/doppelganging.md) | 25 min |

### 💻 Build Clients
| Goal | Document | Time |
|------|----------|------|
| JavaScript client | [JS Client](./clients/javascript.md) | 15 min |
| Python integration | [Python Client](./clients/python.md) | 15 min |
| PowerShell scripts | [PowerShell](./clients/powershell.md) | 10 min |
| C# application | [C# Client](./clients/csharp.md) | 20 min |

### 🔬 Deep Technical
| Goal | Document | Time |
|------|----------|------|
| System architecture | [Architecture](./technical/architecture.md) | 30 min |
| ETW integration | [ETW Details](./technical/etw.md) | 25 min |
| ML engine | [Machine Learning](./technical/ml.md) | 20 min |
| Performance tuning | [Performance](./technical/performance.md) | 30 min |

### 🛠️ Develop & Contribute
| Goal | Document | Time |
|------|----------|------|
| Build from source | [Build Guide](./development/build.md) | 15 min |
| Run tests | [Testing Guide](./development/testing.md) | 10 min |
| Contribute code | [Contributing Guide](./development/contributing.md) | 20 min |
| Benchmark performance | [Benchmarking](./development/benchmarks.md) | 20 min |

### 📊 Operations
| Goal | Document | Time |
|------|----------|------|
| Configure logging | [Logging Setup](./ops/logging.md) | 10 min |
| Setup metrics | [Metrics & Monitoring](./ops/metrics.md) | 15 min |
| Configure alerts | [Alerting](./ops/alerts.md) | 15 min |
| Troubleshoot issues | [Troubleshooting](./ops/troubleshooting.md) | varies |

## 🎭 By Role

### 🛡️ Security Analyst
**Start here**: [Detection Overview](./detections/README.md)

Key documents:
1. [Direct Syscalls Detection](./detections/direct-syscalls.md)
2. [Heaven's Gate Detection](./detections/heavens-gate.md)
3. [API Reference](./api/README.md)
4. [Troubleshooting](./ops/troubleshooting.md)

### 💻 Developer/Integrator
**Start here**: [API Overview](./api/README.md)

Key documents:
1. [Client Libraries](./clients/javascript.md)
2. [WebSocket API](./api/websockets.md)
3. [Error Handling](./api/errors.md)
4. [Build Guide](./development/build.md)

### 🔧 System Administrator
**Start here**: [Installation Guide](./installation.md)

Key documents:
1. [Configuration](./ops/config.md)
2. [Logging](./ops/logging.md)
3. [Metrics](./ops/metrics.md)
4. [Performance Tuning](./technical/performance.md)

### 🧪 Security Researcher
**Start here**: [Technical Architecture](./technical/architecture.md)

Key documents:
1. [ETW Integration](./technical/etw.md)
2. [Detection Techniques](./detections/README.md)
3. [Contributing](./development/contributing.md)
4. [Advanced Configurations](./ops/config.md)

## 📱 By Platform

### 🪟 Windows
- [Installation on Windows](./installation.md#windows)
- [Windows-specific Config](./ops/config.md#windows)
- [ETW on Windows](./technical/etw.md)
- [PowerShell Client](./clients/powershell.md)

### 🐧 Linux (Analysis VM)
- [Linux Installation](./installation.md#linux)
- [Cross-platform Analysis](./technical/cross-platform.md)
- [Python Client](./clients/python.md)

### ☁️ Cloud Deployment
- [Docker Deployment](./ops/docker.md)
- [Kubernetes](./ops/kubernetes.md)
- [Cloud Metrics](./ops/cloud-metrics.md)

## 🔍 By Detection Type

### Direct Syscalls
- [Direct Syscalls Detection](./detections/direct-syscalls.md)
- [Syscalls API](./api/syscalls.md)
- [SysWhispers Analysis](./detections/syswhispers.md)

### Heaven's Gate
- [Heaven's Gate Detection](./detections/heavens-gate.md)
- [WoW64 API](./api/wow64.md)
- [x86/x64 Transitions](./technical/wow64.md)

### Process Techniques
- [Process Hollowing](./detections/process-hollowing.md)
- [Process Doppelgänging](./detections/doppelganging.md)
- [Thread Hijacking](./detections/thread-hijacking.md)

## 🚨 Emergency Responses

### 🔥 Active Incident
1. [Emergency Response](./ops/incident-response.md)
2. [Isolate Processes](./api/processes.md#delete-processes)
3. [Memory Dumps](./ops/memory-dumps.md)
4. [Forensic Analysis](./ops/forensics.md)

### 💥 System Issues
1. [Troubleshooting Guide](./ops/troubleshooting.md)
2. [Performance Issues](./ops/performance-issues.md)
3. [Log Analysis](./ops/log-analysis.md)
4. [Recovery Procedures](./ops/recovery.md)

### 🐛 False Positives
1. [False Positive Analysis](./ops/false-positives.md)
2. [Whitelist Management](./api/whitelist.md)
3. [Tuning Detection](./ops/tuning.md)

## 📞 Support & Community

### 💬 Getting Help
- [Community Discord](https://discord.gg/process-guard)
- [GitHub Discussions](https://github.com/user/process-guard/discussions)
- [Stack Overflow Tag](https://stackoverflow.com/questions/tagged/process-guard)

### 🐛 Report Issues
- [Bug Reports](https://github.com/user/process-guard/issues/new?template=bug_report.md)
- [Feature Requests](https://github.com/user/process-guard/issues/new?template=feature_request.md)
- [Security Issues](./security.md#reporting)

### 📖 External Resources
- [MITRE ATT&CK Mapping](./reference/mitre-attack.md)
- [Related Research Papers](./reference/papers.md)
- [Malware Analysis Tools](./reference/tools.md)

---

**💡 Tip**: Use Ctrl+F (Cmd+F on Mac) to search this page for specific topics!