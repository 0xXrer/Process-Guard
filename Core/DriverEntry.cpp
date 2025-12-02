#include <ntddk.h>
#include "ProcessList.h"
#include "Callbacks.h"
#include "RegistryProtection.h"
#include "ProcessCreationCallback.h"
#include "Globals.h"
#include "../Shared/Common.h"

namespace ProcessGuard {
    ProcessList g_processList;
    CallbackManager* g_callbackManager = nullptr;
    RegistryProtection* g_registryProtection = nullptr;
    ProcessCreationCallback* g_processCreationCallback = nullptr;
    PDEVICE_OBJECT g_deviceObject = nullptr;
    GlobalState g_state = { false, false, false, nullptr, PG_FLAG_DEFAULT };
}

using namespace ProcessGuard;

NTSTATUS OnDeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp);
void DriverUnload(PDRIVER_OBJECT driverObject);
bool IsCallerAuthorized();

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);

    LogInfo("ProcessGuard driver loading...");

    NTSTATUS status = g_processList.Initialize();
    if (!NT_SUCCESS(status)) {
        LogError("Failed to initialize ProcessList: 0x%08X", status);
        return status;
    }

    g_processList.InitializeSystemWhitelist();

    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\ProcessGuard");
    status = IoCreateDevice(
        driverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_deviceObject
    );

    if (!NT_SUCCESS(status)) {
        LogError("IoCreateDevice failed: 0x%08X", status);
        g_processList.Destroy();
        return status;
    }

    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\ProcessGuard");
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        LogError("IoCreateSymbolicLink failed: 0x%08X", status);
        IoDeleteDevice(g_deviceObject);
        g_processList.Destroy();
        return status;
    }

    g_callbackManager = new (NonPagedPool, PROCESS_GUARD_TAG) CallbackManager(&g_processList);
    if (!g_callbackManager) {
        LogError("Failed to allocate CallbackManager");
        IoDeleteSymbolicLink(&symbolicLink);
        IoDeleteDevice(g_deviceObject);
        g_processList.Destroy();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = g_callbackManager->RegisterCallbacks();
    if (!NT_SUCCESS(status)) {
        LogError("Failed to register callbacks: 0x%08X", status);
        delete g_callbackManager;
        g_callbackManager = nullptr;
        IoDeleteSymbolicLink(&symbolicLink);
        IoDeleteDevice(g_deviceObject);
        g_processList.Destroy();
        return status;
    }

    g_registryProtection = new (NonPagedPool, PROCESS_GUARD_TAG) RegistryProtection();
    if (!g_registryProtection) {
        LogWarning("Failed to allocate RegistryProtection, continuing without registry protection");
    } else {
        status = g_registryProtection->RegisterCallback();
        if (!NT_SUCCESS(status)) {
            LogWarning("Failed to register registry callback: 0x%08X, continuing without registry protection", status);
            delete g_registryProtection;
            g_registryProtection = nullptr;
        }
    }

    g_processCreationCallback = new (NonPagedPool, PROCESS_GUARD_TAG) ProcessCreationCallback(&g_processList);
    if (!g_processCreationCallback) {
        LogWarning("Failed to allocate ProcessCreationCallback, continuing without process tracking");
    } else {
        status = g_processCreationCallback->RegisterCallback();
        if (!NT_SUCCESS(status)) {
            LogWarning("Failed to register process creation callback: 0x%08X, continuing without process tracking", status);
            delete g_processCreationCallback;
            g_processCreationCallback = nullptr;
        }
    }

    driverObject->MajorFunction[IRP_MJ_CREATE] = [](PDEVICE_OBJECT, PIRP irp) -> NTSTATUS {
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    };

    driverObject->MajorFunction[IRP_MJ_CLOSE] = [](PDEVICE_OBJECT, PIRP irp) -> NTSTATUS {
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    };

    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnDeviceControl;
    driverObject->DriverUnload = DriverUnload;

    LogInfo("ProcessGuard driver loaded successfully");
    return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT driverObject) {
    UNREFERENCED_PARAMETER(driverObject);

    if (!g_state.UnloadAllowed) {
        LogWarning("Unload blocked by self-defense mechanism");
        return;
    }

    LogInfo("ProcessGuard driver unloading...");

    if (g_processCreationCallback) {
        g_processCreationCallback->UnregisterCallback();
        delete g_processCreationCallback;
        g_processCreationCallback = nullptr;
    }

    if (g_registryProtection) {
        g_registryProtection->UnregisterCallback();
        delete g_registryProtection;
        g_registryProtection = nullptr;
    }

    if (g_callbackManager) {
        g_callbackManager->UnregisterCallbacks();
        delete g_callbackManager;
        g_callbackManager = nullptr;
    }

    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\ProcessGuard");
    IoDeleteSymbolicLink(&symbolicLink);

    if (g_deviceObject) {
        IoDeleteDevice(g_deviceObject);
        g_deviceObject = nullptr;
    }

    g_processList.Destroy();

    LogInfo("ProcessGuard driver unloaded");
}

bool IsCallerAuthorized() {
    SECURITY_SUBJECT_CONTEXT subjectContext = {};
    SeCaptureSubjectContext(&subjectContext);

    bool hasPrivilege = false;
    LUID seLoadDriverPrivilege = { SE_LOAD_DRIVER_PRIVILEGE, 0 };

    hasPrivilege = SePrivilegeCheck(&seLoadDriverPrivilege, &subjectContext, UserMode);

    SeReleaseSubjectContext(&subjectContext);

    if (hasPrivilege) {
        return true;
    }

    PACCESS_TOKEN token = PsReferencePrimaryToken(PsGetCurrentProcess());
    if (!token) {
        return false;
    }

    UCHAR tokenUserBuffer[sizeof(TOKEN_USER) + 128];
    PTOKEN_USER tokenUser = reinterpret_cast<PTOKEN_USER>(tokenUserBuffer);
    ULONG returnLength = 0;

    NTSTATUS status = SeQueryInformationToken(
        token,
        TokenUser,
        reinterpret_cast<PVOID*>(&tokenUser)
    );

    PsDereferencePrimaryToken(token);

    if (!NT_SUCCESS(status)) {
        return false;
    }

    PSID adminSid = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    status = RtlAllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminSid
    );

    if (!NT_SUCCESS(status)) {
        return false;
    }

    BOOLEAN isAdmin = RtlEqualSid(tokenUser->User.Sid, adminSid);
    RtlFreeSid(adminSid);

    return isAdmin != FALSE;
}

NTSTATUS OnDeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;

    if (!IsCallerAuthorized()) {
        LogError("Unauthorized IOCTL attempt");
        status = STATUS_ACCESS_DENIED;
        goto Complete;
    }

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_PG_ADD_PID: {
            if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(HANDLE)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                break;
            }

            HANDLE pid = *static_cast<HANDLE*>(irp->AssociatedIrp.SystemBuffer);
            status = g_processList.AddProcess(pid);
            break;
        }

        case IOCTL_PG_REMOVE_PID: {
            if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(HANDLE)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                break;
            }

            HANDLE pid = *static_cast<HANDLE*>(irp->AssociatedIrp.SystemBuffer);
            status = g_processList.RemoveProcess(pid);
            break;
        }

        case IOCTL_PG_CLEAR_ALL: {
            g_processList.ClearAll();
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_PG_ENABLE_SELF_DEFENSE: {
            g_state.SelfDefenseEnabled = true;
            g_state.ControllerPid = PsGetCurrentProcessId();
            status = g_processList.AddProcess(g_state.ControllerPid);
            if (NT_SUCCESS(status)) {
                LogInfo("Self-defense enabled for PID %llu", (ULONG_PTR)g_state.ControllerPid);
            }
            break;
        }

        case IOCTL_PG_DISABLE_SELF_DEFENSE: {
            if (g_state.SelfDefenseEnabled && g_state.ControllerPid) {
                g_processList.RemoveProcess(g_state.ControllerPid);
            }
            g_state.SelfDefenseEnabled = false;
            g_state.ControllerPid = nullptr;
            LogInfo("Self-defense disabled");
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_PG_ALLOW_UNLOAD: {
            g_state.UnloadAllowed = true;
            LogInfo("Unload allowed");
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_PG_ADD_WHITELIST: {
            if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(HANDLE)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                break;
            }

            HANDLE pid = *static_cast<HANDLE*>(irp->AssociatedIrp.SystemBuffer);
            status = g_processList.AddWhitelist(pid);
            break;
        }

        case IOCTL_PG_SET_FLAGS: {
            if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(unsigned int)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                break;
            }

            unsigned int flags = *static_cast<unsigned int*>(irp->AssociatedIrp.SystemBuffer);
            g_state.ProtectionFlags = flags;
            LogInfo("Protection flags updated to 0x%08X", flags);
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_PG_GET_FLAGS: {
            if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(unsigned int)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                break;
            }

            *static_cast<unsigned int*>(irp->AssociatedIrp.SystemBuffer) = g_state.ProtectionFlags;
            information = sizeof(unsigned int);
            status = STATUS_SUCCESS;
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

Complete:
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
