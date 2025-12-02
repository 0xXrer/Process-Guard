#include "ProcessList.h"
#include "Globals.h"

namespace ProcessGuard {

ProcessList::ProcessList() : m_initialized(false) {
    InitializeListHead(&m_listHead);
    InitializeListHead(&m_whitelistHead);
}

ProcessList::~ProcessList() {
    if (m_initialized) {
        Destroy();
    }
}

NTSTATUS ProcessList::Initialize() {
    if (m_initialized) {
        return STATUS_SUCCESS;
    }

    NTSTATUS status = ExInitializeResourceLite(&m_lock);
    if (!NT_SUCCESS(status)) {
        LogError("Failed to initialize ERESOURCE: 0x%08X", status);
        return status;
    }

    m_initialized = true;
    LogInfo("ProcessList initialized");
    return STATUS_SUCCESS;
}

void ProcessList::Destroy() {
    if (!m_initialized) {
        return;
    }

    ClearAll();
    ClearWhitelist();
    ExDeleteResourceLite(&m_lock);
    m_initialized = false;
    LogInfo("ProcessList destroyed");
}

NTSTATUS ProcessList::AddProcess(HANDLE pid) {
    if (!m_initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    AutoLock lock(&m_lock, AutoLock::Mode::Exclusive);

    if (FindEntry(pid)) {
        return STATUS_OBJECT_NAME_COLLISION;
    }

    ProcessEntry* entry = static_cast<ProcessEntry*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ProcessEntry), PROCESS_GUARD_TAG)
    );

    if (!entry) {
        LogError("Failed to allocate ProcessEntry for PID %llu", (ULONG_PTR)pid);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->ProcessId = pid;
    InsertTailList(&m_listHead, &entry->ListEntry);

    LogInfo("Added PID %llu to protection list", (ULONG_PTR)pid);
    return STATUS_SUCCESS;
}

NTSTATUS ProcessList::RemoveProcess(HANDLE pid) {
    if (!m_initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    AutoLock lock(&m_lock, AutoLock::Mode::Exclusive);

    ProcessEntry* entry = FindEntry(pid);
    if (!entry) {
        return STATUS_NOT_FOUND;
    }

    RemoveEntryList(&entry->ListEntry);
    ExFreePoolWithTag(entry, PROCESS_GUARD_TAG);

    LogInfo("Removed PID %llu from protection list", (ULONG_PTR)pid);
    return STATUS_SUCCESS;
}

bool ProcessList::IsProcessProtected(HANDLE pid) {
    if (!m_initialized) {
        return false;
    }

    AutoLock lock(&m_lock, AutoLock::Mode::Shared);
    return FindEntry(pid) != nullptr;
}

void ProcessList::ClearAll() {
    if (!m_initialized) {
        return;
    }

    AutoLock lock(&m_lock, AutoLock::Mode::Exclusive);

    while (!IsListEmpty(&m_listHead)) {
        LIST_ENTRY* entry = RemoveHeadList(&m_listHead);
        ProcessEntry* processEntry = CONTAINING_RECORD(entry, ProcessEntry, ListEntry);
        ExFreePoolWithTag(processEntry, PROCESS_GUARD_TAG);
    }

    LogInfo("Cleared all protected processes");
}

ProcessEntry* ProcessList::FindEntry(HANDLE pid) {
    for (LIST_ENTRY* entry = m_listHead.Flink; entry != &m_listHead; entry = entry->Flink) {
        ProcessEntry* processEntry = CONTAINING_RECORD(entry, ProcessEntry, ListEntry);
        if (processEntry->ProcessId == pid) {
            return processEntry;
        }
    }
    return nullptr;
}

NTSTATUS ProcessList::AddWhitelist(HANDLE pid) {
    if (!m_initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    AutoLock lock(&m_lock, AutoLock::Mode::Exclusive);

    if (FindWhitelistEntry(pid)) {
        return STATUS_OBJECT_NAME_COLLISION;
    }

    WhitelistEntry* entry = static_cast<WhitelistEntry*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(WhitelistEntry), PROCESS_GUARD_WHITELIST_TAG)
    );

    if (!entry) {
        LogError("Failed to allocate WhitelistEntry for PID %llu", (ULONG_PTR)pid);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->ProcessId = pid;
    InsertTailList(&m_whitelistHead, &entry->ListEntry);

    LogInfo("Added PID %llu to whitelist", (ULONG_PTR)pid);
    return STATUS_SUCCESS;
}

NTSTATUS ProcessList::RemoveWhitelist(HANDLE pid) {
    if (!m_initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    AutoLock lock(&m_lock, AutoLock::Mode::Exclusive);

    WhitelistEntry* entry = FindWhitelistEntry(pid);
    if (!entry) {
        return STATUS_NOT_FOUND;
    }

    RemoveEntryList(&entry->ListEntry);
    ExFreePoolWithTag(entry, PROCESS_GUARD_WHITELIST_TAG);

    LogInfo("Removed PID %llu from whitelist", (ULONG_PTR)pid);
    return STATUS_SUCCESS;
}

bool ProcessList::IsProcessWhitelisted(HANDLE pid) {
    if (!m_initialized) {
        return false;
    }

    AutoLock lock(&m_lock, AutoLock::Mode::Shared);
    return FindWhitelistEntry(pid) != nullptr;
}

void ProcessList::ClearWhitelist() {
    if (!m_initialized) {
        return;
    }

    AutoLock lock(&m_lock, AutoLock::Mode::Exclusive);

    while (!IsListEmpty(&m_whitelistHead)) {
        LIST_ENTRY* entry = RemoveHeadList(&m_whitelistHead);
        WhitelistEntry* whitelistEntry = CONTAINING_RECORD(entry, WhitelistEntry, ListEntry);
        ExFreePoolWithTag(whitelistEntry, PROCESS_GUARD_WHITELIST_TAG);
    }

    LogInfo("Cleared whitelist");
}

WhitelistEntry* ProcessList::FindWhitelistEntry(HANDLE pid) {
    for (LIST_ENTRY* entry = m_whitelistHead.Flink; entry != &m_whitelistHead; entry = entry->Flink) {
        WhitelistEntry* whitelistEntry = CONTAINING_RECORD(entry, WhitelistEntry, ListEntry);
        if (whitelistEntry->ProcessId == pid) {
            return whitelistEntry;
        }
    }
    return nullptr;
}

}
