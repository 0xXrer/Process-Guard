#pragma once

#include <ntddk.h>

#define PROCESS_GUARD_TAG 'GrdP'
#define PROCESS_GUARD_WHITELIST_TAG 'WhtL'

#define LogInfo(format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[ProcessGuard] INFO: " format "\n", ##__VA_ARGS__)

#define LogWarning(format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "[ProcessGuard] WARN: " format "\n", ##__VA_ARGS__)

#define LogError(format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ProcessGuard] ERROR: " format "\n", ##__VA_ARGS__)

namespace ProcessGuard {

struct GlobalState {
    bool UnloadAllowed;
    bool SelfDefenseEnabled;
    bool AutoProtectNewProcesses;
    HANDLE ControllerPid;
    unsigned int ProtectionFlags;
};

extern GlobalState g_state;

}
