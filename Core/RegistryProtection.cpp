#include "RegistryProtection.h"
#include "Globals.h"

namespace ProcessGuard {

RegistryProtection::RegistryProtection() : m_registered(false) {
    m_cookie.QuadPart = 0;
}

RegistryProtection::~RegistryProtection() {
    if (m_registered) {
        UnregisterCallback();
    }
}

NTSTATUS RegistryProtection::RegisterCallback() {
    if (m_registered) {
        return STATUS_SUCCESS;
    }

    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"385201");

    NTSTATUS status = CmRegisterCallbackEx(
        RegistryCallback,
        &altitude,
        GetCurrentThread(),
        this,
        &m_cookie,
        nullptr
    );

    if (!NT_SUCCESS(status)) {
        LogError("CmRegisterCallbackEx failed: 0x%08X", status);
        return status;
    }

    m_registered = true;
    LogInfo("Registry callback registered successfully");
    return STATUS_SUCCESS;
}

void RegistryProtection::UnregisterCallback() {
    if (!m_registered) {
        return;
    }

    CmUnRegisterCallback(m_cookie);
    m_registered = false;
    LogInfo("Registry callback unregistered");
}

bool RegistryProtection::IsProtectedKey(PUNICODE_STRING registryPath) {
    if (!registryPath || !registryPath->Buffer) {
        return false;
    }

    const wchar_t* protectedKeys[] = {
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\ProcessGuard",
        L"System\\CurrentControlSet\\Services\\ProcessGuard",
        L"ProcessGuard"
    };

    for (size_t i = 0; i < sizeof(protectedKeys) / sizeof(protectedKeys[0]); i++) {
        if (wcsstr(registryPath->Buffer, protectedKeys[i]) != nullptr) {
            return true;
        }
    }

    return false;
}

NTSTATUS RegistryProtection::RegistryCallback(
    PVOID callbackContext,
    PVOID argument1,
    PVOID argument2
) {
    UNREFERENCED_PARAMETER(callbackContext);

    if (!argument1 || !argument2) {
        return STATUS_SUCCESS;
    }

    REG_NOTIFY_CLASS notifyClass = static_cast<REG_NOTIFY_CLASS>(reinterpret_cast<ULONG_PTR>(argument1));

    RegistryProtection* prot = static_cast<RegistryProtection*>(callbackContext);
    if (!prot) {
        return STATUS_SUCCESS;
    }

    switch (notifyClass) {
        case RegNtPreDeleteKey:
        case RegNtPreDeleteValueKey:
        case RegNtPreSetValueKey: {
            PREG_DELETE_KEY_INFORMATION deleteInfo = static_cast<PREG_DELETE_KEY_INFORMATION>(argument2);
            if (deleteInfo && deleteInfo->CompleteName) {
                if (prot->IsProtectedKey(deleteInfo->CompleteName)) {
                    LogWarning("Blocked registry operation on protected key");
                    return STATUS_ACCESS_DENIED;
                }
            }
            break;
        }

        default:
            break;
    }

    return STATUS_SUCCESS;
}

}
