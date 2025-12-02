#include "DriverControl.h"
#include <iostream>
#include <string>
#include <vector>

void PrintUsage() {
    std::wcout << L"ProcessGuard Controller v2.0\n\n";
    std::wcout << L"Usage:\n";
    std::wcout << L"  pgctl install <path_to_sys>    - Install driver\n";
    std::wcout << L"  pgctl start                     - Start driver\n";
    std::wcout << L"  pgctl protect <PID>             - Protect process\n";
    std::wcout << L"  pgctl unprotect <PID>           - Unprotect process\n";
    std::wcout << L"  pgctl whitelist <PID>           - Add process to whitelist\n";
    std::wcout << L"  pgctl clear                     - Clear all protections\n";
    std::wcout << L"  pgctl selfdefense on            - Enable self-defense\n";
    std::wcout << L"  pgctl selfdefense off           - Disable self-defense\n";
    std::wcout << L"  pgctl setflags <flags>          - Set protection flags (hex)\n";
    std::wcout << L"  pgctl getflags                  - Get current protection flags\n";
    std::wcout << L"  pgctl stop                      - Stop driver (requires allowunload)\n";
    std::wcout << L"  pgctl allowunload               - Allow driver unload\n";
    std::wcout << L"  pgctl uninstall                 - Uninstall driver\n";
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::wstring command = argv[1];
    DriverControl control;

    const std::wstring serviceName = L"ProcessGuard";
    const std::wstring devicePath = L"\\\\.\\ProcessGuard";

    if (command == L"install") {
        if (argc < 3) {
            std::wcerr << L"Error: Missing driver path\n";
            return 1;
        }

        std::wstring driverPath = argv[2];
        if (control.InstallDriver(driverPath, serviceName)) {
            std::wcout << L"Driver installed successfully\n";
            return 0;
        } else {
            std::wcerr << L"Failed to install driver: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }
    }
    else if (command == L"start") {
        if (control.StartDriver(serviceName)) {
            std::wcout << L"Driver started successfully\n";
            return 0;
        } else {
            std::wcerr << L"Failed to start driver: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }
    }
    else if (command == L"protect") {
        if (argc < 3) {
            std::wcerr << L"Error: Missing PID\n";
            return 1;
        }

        DWORD pid = static_cast<DWORD>(_wtoi(argv[2]));
        if (pid == 0) {
            std::wcerr << L"Error: Invalid PID\n";
            return 1;
        }

        if (!control.OpenDevice(devicePath)) {
            std::wcerr << L"Failed to open device: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }

        if (control.ProtectPid(pid)) {
            std::wcout << L"PID " << pid << L" protected successfully\n";
            return 0;
        } else {
            std::wcerr << L"Failed to protect PID: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }
    }
    else if (command == L"unprotect") {
        if (argc < 3) {
            std::wcerr << L"Error: Missing PID\n";
            return 1;
        }

        DWORD pid = static_cast<DWORD>(_wtoi(argv[2]));
        if (pid == 0) {
            std::wcerr << L"Error: Invalid PID\n";
            return 1;
        }

        if (!control.OpenDevice(devicePath)) {
            std::wcerr << L"Failed to open device: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }

        if (control.UnprotectPid(pid)) {
            std::wcout << L"PID " << pid << L" unprotected successfully\n";
            return 0;
        } else {
            std::wcerr << L"Failed to unprotect PID: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }
    }
    else if (command == L"clear") {
        if (!control.OpenDevice(devicePath)) {
            std::wcerr << L"Failed to open device: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }

        if (control.ClearAll()) {
            std::wcout << L"All protections cleared successfully\n";
            return 0;
        } else {
            std::wcerr << L"Failed to clear protections: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }
    }
    else if (command == L"stop") {
        if (control.StopDriver(serviceName)) {
            std::wcout << L"Driver stopped successfully\n";
            return 0;
        } else {
            std::wcerr << L"Failed to stop driver: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }
    }
    else if (command == L"whitelist") {
        if (argc < 3) {
            std::wcerr << L"Error: Missing PID\n";
            return 1;
        }

        DWORD pid = static_cast<DWORD>(_wtoi(argv[2]));
        if (pid == 0) {
            std::wcerr << L"Error: Invalid PID\n";
            return 1;
        }

        if (!control.OpenDevice(devicePath)) {
            std::wcerr << L"Failed to open device: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }

        if (control.AddWhitelist(pid)) {
            std::wcout << L"PID " << pid << L" added to whitelist\n";
            return 0;
        } else {
            std::wcerr << L"Failed to add to whitelist: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }
    }
    else if (command == L"selfdefense") {
        if (argc < 3) {
            std::wcerr << L"Error: Missing on/off parameter\n";
            return 1;
        }

        std::wstring mode = argv[2];

        if (!control.OpenDevice(devicePath)) {
            std::wcerr << L"Failed to open device: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }

        if (mode == L"on") {
            if (control.EnableSelfDefense()) {
                std::wcout << L"Self-defense enabled\n";
                return 0;
            } else {
                std::wcerr << L"Failed to enable self-defense: " << control.GetLastErrorMessage() << L"\n";
                return 1;
            }
        } else if (mode == L"off") {
            if (control.DisableSelfDefense()) {
                std::wcout << L"Self-defense disabled\n";
                return 0;
            } else {
                std::wcerr << L"Failed to disable self-defense: " << control.GetLastErrorMessage() << L"\n";
                return 1;
            }
        } else {
            std::wcerr << L"Error: Invalid parameter. Use 'on' or 'off'\n";
            return 1;
        }
    }
    else if (command == L"allowunload") {
        if (!control.OpenDevice(devicePath)) {
            std::wcerr << L"Failed to open device: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }

        if (control.AllowUnload()) {
            std::wcout << L"Driver unload allowed\n";
            return 0;
        } else {
            std::wcerr << L"Failed to allow unload: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }
    }
    else if (command == L"setflags") {
        if (argc < 3) {
            std::wcerr << L"Error: Missing flags value\n";
            return 1;
        }

        DWORD flags = static_cast<DWORD>(wcstoul(argv[2], nullptr, 16));

        if (!control.OpenDevice(devicePath)) {
            std::wcerr << L"Failed to open device: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }

        if (control.SetProtectionFlags(flags)) {
            std::wcout << L"Protection flags set to 0x" << std::hex << flags << std::dec << L"\n";
            return 0;
        } else {
            std::wcerr << L"Failed to set flags: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }
    }
    else if (command == L"getflags") {
        if (!control.OpenDevice(devicePath)) {
            std::wcerr << L"Failed to open device: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }

        DWORD flags = 0;
        if (control.GetProtectionFlags(flags)) {
            std::wcout << L"Current protection flags: 0x" << std::hex << flags << std::dec << L"\n";
            return 0;
        } else {
            std::wcerr << L"Failed to get flags: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }
    }
    else if (command == L"uninstall") {
        if (control.UninstallDriver(serviceName)) {
            std::wcout << L"Driver uninstalled successfully\n";
            return 0;
        } else {
            std::wcerr << L"Failed to uninstall driver: " << control.GetLastErrorMessage() << L"\n";
            return 1;
        }
    }
    else {
        std::wcerr << L"Unknown command: " << command << L"\n\n";
        PrintUsage();
        return 1;
    }

    return 0;
}
