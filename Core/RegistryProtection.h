#pragma once

#include <ntddk.h>

namespace ProcessGuard {

class RegistryProtection {
public:
    RegistryProtection();
    ~RegistryProtection();

    NTSTATUS RegisterCallback();
    void UnregisterCallback();

private:
    LARGE_INTEGER m_cookie;
    bool m_registered;

    static NTSTATUS RegistryCallback(
        PVOID callbackContext,
        PVOID argument1,
        PVOID argument2
    );

    bool IsProtectedKey(PUNICODE_STRING registryPath);
};

}
