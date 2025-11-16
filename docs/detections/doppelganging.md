# Process Doppelgänging Detection

Detection of Process Doppelgänging via Transactional NTFS (TxF).

## 📋 Overview

Process Doppelgänging exploits Windows Transactional NTFS to execute malicious code:
1. Create file transaction
2. Write malicious code to transacted file
3. Create process from transacted file
4. Rollback transaction (removes evidence)

**MITRE ATT&CK**: T1055.013 - Process Injection: Process Doppelgänging

## 🔍 Detection Status

✅ **Implemented** - See `src/txf.rs` for implementation details

## 📚 Related Techniques

- [Process Hollowing](./process-hollowing.md)
- [Direct Syscalls](./direct-syscalls.md)

---

**Last Updated**: 2025-11-16
