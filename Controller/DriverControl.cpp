#include "DriverControl.h"
#include "../Shared/Common.h"
#include <sstream>

DriverControl::DriverControl()
    : m_scManager(nullptr), m_deviceHandle(INVALID_HANDLE_VALUE) {
    m_scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!m_scManager) {
        SetLastError(L"Failed to open Service Control Manager");
    }
}

DriverControl::~DriverControl() {
    CloseDevice();
    if (m_scManager) {
        CloseServiceHandle(m_scManager);
    }
}

bool DriverControl::InstallDriver(const std::wstring& driverPath, const std::wstring& serviceName) {
    if (!m_scManager) {
        SetLastError(L"SCM not available");
        return false;
    }

    SC_HANDLE service = CreateServiceW(
        m_scManager,
        serviceName.c_str(),
        serviceName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        driverPath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );

    if (!service) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            SetLastError(L"Service already exists");
            return true;
        }
        std::wstringstream ss;
        ss << L"CreateService failed with error " << error;
        SetLastError(ss.str());
        return false;
    }

    CloseServiceHandle(service);
    return true;
}

bool DriverControl::StartDriver(const std::wstring& serviceName) {
    if (!m_scManager) {
        SetLastError(L"SCM not available");
        return false;
    }

    SC_HANDLE service = OpenServiceW(m_scManager, serviceName.c_str(), SERVICE_ALL_ACCESS);
    if (!service) {
        std::wstringstream ss;
        ss << L"OpenService failed with error " << GetLastError();
        SetLastError(ss.str());
        return false;
    }

    BOOL result = StartServiceW(service, 0, nullptr);
    DWORD error = GetLastError();
    CloseServiceHandle(service);

    if (!result) {
        if (error == ERROR_SERVICE_ALREADY_RUNNING) {
            SetLastError(L"Service already running");
            return true;
        }
        std::wstringstream ss;
        ss << L"StartService failed with error " << error;
        SetLastError(ss.str());
        return false;
    }

    return true;
}

bool DriverControl::StopDriver(const std::wstring& serviceName) {
    if (!m_scManager) {
        SetLastError(L"SCM not available");
        return false;
    }

    SC_HANDLE service = OpenServiceW(m_scManager, serviceName.c_str(), SERVICE_ALL_ACCESS);
    if (!service) {
        std::wstringstream ss;
        ss << L"OpenService failed with error " << GetLastError();
        SetLastError(ss.str());
        return false;
    }

    SERVICE_STATUS status = {};
    BOOL result = ControlService(service, SERVICE_CONTROL_STOP, &status);
    DWORD error = GetLastError();
    CloseServiceHandle(service);

    if (!result) {
        if (error == ERROR_SERVICE_NOT_ACTIVE) {
            SetLastError(L"Service not running");
            return true;
        }
        std::wstringstream ss;
        ss << L"ControlService failed with error " << error;
        SetLastError(ss.str());
        return false;
    }

    return true;
}

bool DriverControl::UninstallDriver(const std::wstring& serviceName) {
    if (!m_scManager) {
        SetLastError(L"SCM not available");
        return false;
    }

    SC_HANDLE service = OpenServiceW(m_scManager, serviceName.c_str(), SERVICE_ALL_ACCESS);
    if (!service) {
        std::wstringstream ss;
        ss << L"OpenService failed with error " << GetLastError();
        SetLastError(ss.str());
        return false;
    }

    BOOL result = DeleteService(service);
    DWORD error = GetLastError();
    CloseServiceHandle(service);

    if (!result) {
        std::wstringstream ss;
        ss << L"DeleteService failed with error " << error;
        SetLastError(ss.str());
        return false;
    }

    return true;
}

bool DriverControl::OpenDevice(const std::wstring& devicePath) {
    if (m_deviceHandle != INVALID_HANDLE_VALUE) {
        CloseDevice();
    }

    m_deviceHandle = CreateFileW(
        devicePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (m_deviceHandle == INVALID_HANDLE_VALUE) {
        std::wstringstream ss;
        ss << L"CreateFile failed with error " << GetLastError();
        SetLastError(ss.str());
        return false;
    }

    return true;
}

void DriverControl::CloseDevice() {
    if (m_deviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_deviceHandle);
        m_deviceHandle = INVALID_HANDLE_VALUE;
    }
}

bool DriverControl::ProtectPid(DWORD pid) {
    HANDLE pidHandle = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
    return SendIoctl(IOCTL_PG_ADD_PID, &pidHandle, sizeof(pidHandle));
}

bool DriverControl::UnprotectPid(DWORD pid) {
    HANDLE pidHandle = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
    return SendIoctl(IOCTL_PG_REMOVE_PID, &pidHandle, sizeof(pidHandle));
}

bool DriverControl::ClearAll() {
    return SendIoctl(IOCTL_PG_CLEAR_ALL, nullptr, 0);
}

bool DriverControl::EnableSelfDefense() {
    return SendIoctl(IOCTL_PG_ENABLE_SELF_DEFENSE, nullptr, 0);
}

bool DriverControl::DisableSelfDefense() {
    return SendIoctl(IOCTL_PG_DISABLE_SELF_DEFENSE, nullptr, 0);
}

bool DriverControl::AllowUnload() {
    return SendIoctl(IOCTL_PG_ALLOW_UNLOAD, nullptr, 0);
}

bool DriverControl::AddWhitelist(DWORD pid) {
    HANDLE pidHandle = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
    return SendIoctl(IOCTL_PG_ADD_WHITELIST, &pidHandle, sizeof(pidHandle));
}

bool DriverControl::SetProtectionFlags(DWORD flags) {
    return SendIoctl(IOCTL_PG_SET_FLAGS, &flags, sizeof(flags));
}

bool DriverControl::GetProtectionFlags(DWORD& flags) {
    if (m_deviceHandle == INVALID_HANDLE_VALUE) {
        SetLastError(L"Device not opened");
        return false;
    }

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        m_deviceHandle,
        IOCTL_PG_GET_FLAGS,
        nullptr,
        0,
        &flags,
        sizeof(flags),
        &bytesReturned,
        nullptr
    );

    if (!result) {
        std::wstringstream ss;
        ss << L"DeviceIoControl failed with error " << GetLastError();
        SetLastError(ss.str());
        return false;
    }

    return true;
}

bool DriverControl::SendIoctl(DWORD ioctlCode, void* inputBuffer, DWORD inputSize) {
    if (m_deviceHandle == INVALID_HANDLE_VALUE) {
        SetLastError(L"Device not opened");
        return false;
    }

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        m_deviceHandle,
        ioctlCode,
        inputBuffer,
        inputSize,
        nullptr,
        0,
        &bytesReturned,
        nullptr
    );

    if (!result) {
        std::wstringstream ss;
        ss << L"DeviceIoControl failed with error " << GetLastError();
        SetLastError(ss.str());
        return false;
    }

    return true;
}

void DriverControl::SetLastError(const std::wstring& message) {
    m_lastError = message;
}

std::wstring DriverControl::GetLastErrorMessage() const {
    return m_lastError;
}
