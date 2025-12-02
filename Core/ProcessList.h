#pragma once

#include <ntddk.h>

namespace ProcessGuard {

class AutoLock {
public:
    enum class Mode {
        Shared,
        Exclusive
    };

    AutoLock(ERESOURCE* resource, Mode mode)
        : m_resource(resource), m_mode(mode) {
        if (m_mode == Mode::Shared) {
            ExEnterCriticalRegionAndAcquireResourceShared(m_resource);
        } else {
            ExEnterCriticalRegionAndAcquireResourceExclusive(m_resource);
        }
    }

    ~AutoLock() {
        ExReleaseResourceAndLeaveCriticalRegion(m_resource);
    }

    AutoLock(const AutoLock&) = delete;
    AutoLock& operator=(const AutoLock&) = delete;

private:
    ERESOURCE* m_resource;
    Mode m_mode;
};

struct ProcessEntry {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
};

struct WhitelistEntry {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
};

class ProcessList {
public:
    ProcessList();
    ~ProcessList();

    NTSTATUS Initialize();
    void Destroy();

    NTSTATUS AddProcess(HANDLE pid);
    NTSTATUS RemoveProcess(HANDLE pid);
    bool IsProcessProtected(HANDLE pid);
    void ClearAll();

    NTSTATUS AddWhitelist(HANDLE pid);
    NTSTATUS RemoveWhitelist(HANDLE pid);
    bool IsProcessWhitelisted(HANDLE pid);
    bool IsProcessWhitelistedByName(const char* processName);
    void ClearWhitelist();
    void InitializeSystemWhitelist();

private:
    LIST_ENTRY m_listHead;
    LIST_ENTRY m_whitelistHead;
    ERESOURCE m_lock;
    bool m_initialized;

    static constexpr size_t MAX_SYSTEM_NAMES = 16;
    char m_systemProcessNames[MAX_SYSTEM_NAMES][16];
    size_t m_systemNameCount;

    ProcessEntry* FindEntry(HANDLE pid);
    WhitelistEntry* FindWhitelistEntry(HANDLE pid);
};

}
