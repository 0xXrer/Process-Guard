# Thread Hijacking Detection

Detection of thread context manipulation for code execution.

## 📋 Overview

Thread hijacking redirects existing thread execution to malicious code.

**MITRE ATT&CK**: T1055.003 - Process Injection: Thread Execution Hijacking

## 🔍 Detection Methods

- Monitor `SetThreadContext` API calls
- Validate instruction pointer changes
- Track suspicious context modifications

## 📚 Related Techniques

- [Process Hollowing](./process-hollowing.md)
- [Heaven's Gate](./heavens-gate.md)

---

**Last Updated**: 2025-11-16
