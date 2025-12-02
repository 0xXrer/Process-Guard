#include "Callbacks.h"
#include "ProcessList.h"
#include "Globals.h"

namespace ProcessGuard {

CallbackManager::CallbackManager(ProcessList* processList)
    : m_processList(processList), m_processCallbackHandle(nullptr),
      m_threadCallbackHandle(nullptr), m_registered(false) {
}

CallbackManager::~CallbackManager() {
    if (m_registered) {
        UnregisterCallbacks();
    }
}

NTSTATUS CallbackManager::RegisterCallbacks() {
    if (m_registered) {
        return STATUS_SUCCESS;
    }

    OB_OPERATION_REGISTRATION operationRegistrations[2] = {};

    operationRegistrations[0].ObjectType = PsProcessType;
    operationRegistrations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistrations[0].PreOperation = PreOperationCallback;
    operationRegistrations[0].PostOperation = nullptr;

    operationRegistrations[1].ObjectType = PsThreadType;
    operationRegistrations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistrations[1].PreOperation = ThreadPreOperationCallback;
    operationRegistrations[1].PostOperation = nullptr;

    OB_CALLBACK_REGISTRATION callbackRegistration = {};
    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 2;
    callbackRegistration.RegistrationContext = this;

    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"385200");
    callbackRegistration.Altitude = altitude;
    callbackRegistration.OperationRegistration = operationRegistrations;

    NTSTATUS status = ObRegisterCallbacks(&callbackRegistration, &m_processCallbackHandle);
    if (!NT_SUCCESS(status)) {
        LogError("ObRegisterCallbacks failed: 0x%08X", status);
        return status;
    }

    m_registered = true;
    LogInfo("ObCallbacks registered successfully (Process + Thread)");
    return STATUS_SUCCESS;
}

void CallbackManager::UnregisterCallbacks() {
    if (!m_registered) {
        return;
    }

    if (m_processCallbackHandle) {
        ObUnRegisterCallbacks(m_processCallbackHandle);
        m_processCallbackHandle = nullptr;
    }

    m_registered = false;
    LogInfo("ObCallbacks unregistered");
}

OB_PREOP_CALLBACK_STATUS CallbackManager::PreOperationCallback(
    PVOID registrationContext,
    POB_PRE_OPERATION_INFORMATION operationInformation
) {
    if (!registrationContext || !operationInformation) {
        return OB_PREOP_SUCCESS;
    }

    if (operationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    if (operationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    CallbackManager* manager = static_cast<CallbackManager*>(registrationContext);
    if (!manager->m_processList) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS targetProcess = static_cast<PEPROCESS>(operationInformation->Object);
    HANDLE targetPid = PsGetProcessId(targetProcess);

    if (!manager->m_processList->IsProcessProtected(targetPid)) {
        return OB_PREOP_SUCCESS;
    }

    HANDLE callerPid = PsGetCurrentProcessId();
    if (manager->m_processList->IsProcessWhitelisted(callerPid)) {
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK dangerousAccess = 0;

    if (g_state.ProtectionFlags & PG_FLAG_PROTECT_TERMINATE) {
        dangerousAccess |= PROCESS_TERMINATE;
    }
    if (g_state.ProtectionFlags & PG_FLAG_PROTECT_VM_WRITE) {
        dangerousAccess |= PROCESS_VM_WRITE;
    }
    if (g_state.ProtectionFlags & PG_FLAG_PROTECT_VM_OP) {
        dangerousAccess |= PROCESS_VM_OPERATION;
    }
    if (g_state.ProtectionFlags & PG_FLAG_PROTECT_VM_READ) {
        dangerousAccess |= PROCESS_VM_READ;
    }
    if (g_state.ProtectionFlags & PG_FLAG_PROTECT_THREADS) {
        dangerousAccess |= PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME;
    }

    if (operationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        if (operationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & dangerousAccess) {
            operationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~dangerousAccess;
            LogInfo("Blocked access to PID %llu from PID %llu (CREATE)", (ULONG_PTR)targetPid, (ULONG_PTR)callerPid);
        }
    } else if (operationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        if (operationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & dangerousAccess) {
            operationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~dangerousAccess;
            LogInfo("Blocked access to PID %llu from PID %llu (DUPLICATE)", (ULONG_PTR)targetPid, (ULONG_PTR)callerPid);
        }
    }

    return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS CallbackManager::ThreadPreOperationCallback(
    PVOID registrationContext,
    POB_PRE_OPERATION_INFORMATION operationInformation
) {
    if (!registrationContext || !operationInformation) {
        return OB_PREOP_SUCCESS;
    }

    if (operationInformation->ObjectType != *PsThreadType) {
        return OB_PREOP_SUCCESS;
    }

    if (operationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    CallbackManager* manager = static_cast<CallbackManager*>(registrationContext);
    if (!manager->m_processList) {
        return OB_PREOP_SUCCESS;
    }

    PETHREAD targetThread = static_cast<PETHREAD>(operationInformation->Object);
    PEPROCESS targetProcess = PsGetThreadProcess(targetThread);
    HANDLE targetPid = PsGetProcessId(targetProcess);

    if (!manager->m_processList->IsProcessProtected(targetPid)) {
        return OB_PREOP_SUCCESS;
    }

    HANDLE callerPid = PsGetCurrentProcessId();
    if (manager->m_processList->IsProcessWhitelisted(callerPid)) {
        return OB_PREOP_SUCCESS;
    }

    if (!(g_state.ProtectionFlags & PG_FLAG_PROTECT_THREADS)) {
        return OB_PREOP_SUCCESS;
    }

    const ACCESS_MASK dangerousThreadAccess =
        THREAD_TERMINATE |
        THREAD_SUSPEND_RESUME |
        THREAD_SET_CONTEXT |
        THREAD_SET_THREAD_TOKEN;

    if (operationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        if (operationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & dangerousThreadAccess) {
            operationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~dangerousThreadAccess;
            LogInfo("Blocked thread access to protected process PID %llu from PID %llu", (ULONG_PTR)targetPid, (ULONG_PTR)callerPid);
        }
    } else if (operationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        if (operationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & dangerousThreadAccess) {
            operationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~dangerousThreadAccess;
            LogInfo("Blocked thread dup access to protected process PID %llu from PID %llu", (ULONG_PTR)targetPid, (ULONG_PTR)callerPid);
        }
    }

    return OB_PREOP_SUCCESS;
}

}
