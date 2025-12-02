#pragma once

#include <ntddk.h>

namespace ProcessGuard {

class ProcessList;

class ProcessCreationCallback {
public:
    ProcessCreationCallback(ProcessList* processList);
    ~ProcessCreationCallback();

    NTSTATUS RegisterCallback();
    void UnregisterCallback();

    void SetAutoProtectEnabled(bool enabled) { m_autoProtectEnabled = enabled; }
    bool IsAutoProtectEnabled() const { return m_autoProtectEnabled; }

private:
    ProcessList* m_processList;
    bool m_registered;
    bool m_autoProtectEnabled;

    static void ProcessNotifyCallback(
        HANDLE parentId,
        HANDLE processId,
        BOOLEAN create
    );

    static ProcessCreationCallback* s_instance;
};

}
