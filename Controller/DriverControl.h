#pragma once

#include <Windows.h>
#include <string>

class DriverControl {
public:
    DriverControl();
    ~DriverControl();

    bool InstallDriver(const std::wstring& driverPath, const std::wstring& serviceName);
    bool StartDriver(const std::wstring& serviceName);
    bool StopDriver(const std::wstring& serviceName);
    bool UninstallDriver(const std::wstring& serviceName);

    bool OpenDevice(const std::wstring& devicePath);
    void CloseDevice();

    bool ProtectPid(DWORD pid);
    bool UnprotectPid(DWORD pid);
    bool ClearAll();

    bool EnableSelfDefense();
    bool DisableSelfDefense();
    bool AllowUnload();
    bool AddWhitelist(DWORD pid);
    bool SetProtectionFlags(DWORD flags);
    bool GetProtectionFlags(DWORD& flags);

    std::wstring GetLastErrorMessage() const;

private:
    SC_HANDLE m_scManager;
    HANDLE m_deviceHandle;
    std::wstring m_lastError;

    bool SendIoctl(DWORD ioctlCode, void* inputBuffer, DWORD inputSize);
    void SetLastError(const std::wstring& message);
};
