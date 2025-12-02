#pragma once

#include <ntddk.h>

namespace ProcessGuard {

class ProcessList;

class CallbackManager {
public:
    CallbackManager(ProcessList* processList);
    ~CallbackManager();

    NTSTATUS RegisterCallbacks();
    void UnregisterCallbacks();

private:
    ProcessList* m_processList;
    PVOID m_processCallbackHandle;
    PVOID m_threadCallbackHandle;
    bool m_registered;

    static OB_PREOP_CALLBACK_STATUS PreOperationCallback(
        PVOID registrationContext,
        POB_PRE_OPERATION_INFORMATION operationInformation
    );

    static OB_PREOP_CALLBACK_STATUS ThreadPreOperationCallback(
        PVOID registrationContext,
        POB_PRE_OPERATION_INFORMATION operationInformation
    );
};

}
