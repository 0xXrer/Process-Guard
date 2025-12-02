#include "ProcessCreationCallback.h"
#include "ProcessList.h"
#include "Globals.h"

namespace ProcessGuard {

ProcessCreationCallback* ProcessCreationCallback::s_instance = nullptr;

ProcessCreationCallback::ProcessCreationCallback(ProcessList* processList)
    : m_processList(processList), m_registered(false), m_autoProtectEnabled(false) {
}

ProcessCreationCallback::~ProcessCreationCallback() {
    if (m_registered) {
        UnregisterCallback();
    }
}

NTSTATUS ProcessCreationCallback::RegisterCallback() {
    if (m_registered) {
        return STATUS_SUCCESS;
    }

    s_instance = this;

    NTSTATUS status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        LogError("PsSetCreateProcessNotifyRoutine failed: 0x%08X", status);
        s_instance = nullptr;
        return status;
    }

    m_registered = true;
    LogInfo("Process creation callback registered successfully");
    return STATUS_SUCCESS;
}

void ProcessCreationCallback::UnregisterCallback() {
    if (!m_registered) {
        return;
    }

    PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);
    m_registered = false;
    s_instance = nullptr;
    LogInfo("Process creation callback unregistered");
}

void ProcessCreationCallback::ProcessNotifyCallback(
    HANDLE parentId,
    HANDLE processId,
    BOOLEAN create
) {
    UNREFERENCED_PARAMETER(parentId);

    if (!s_instance || !s_instance->m_processList) {
        return;
    }

    if (create) {
        if (s_instance->m_autoProtectEnabled) {
            s_instance->m_processList->AddProcess(processId);
            LogInfo("Auto-protected new process PID %llu", (ULONG_PTR)processId);
        }
    } else {
        s_instance->m_processList->RemoveProcess(processId);
    }
}

}
