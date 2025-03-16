# Process Stacking Injection

## 🛠 About the Technique
**Process Stacking Injection** is an advanced code injection technique that distributes shellcode across multiple processes. Unlike traditional injection methods, this approach **fragments the payload**, making detection more challenging for security tools.

### 🔹 Key Features:
- **Shellcode Fragmentation** → The payload is divided into multiple processes.
- **Reassembly in Target Process** → The fragments are reconstructed in memory before execution.
- **Execution via Hardware Breakpoints** → Ensures the payload runs only when triggered.
- **Stack Spoofing** → Manipulates the stack pointer to appear as a legitimate function call.

---

## 🚀 Improvements Implemented
### ✅ **Memory Management & Debugging**
- **Improved Memory Allocation Verification** → Ensures memory is properly allocated before writing shellcode.
- **Detailed Debug Messages** → Enhanced error reporting using `GetLastError()` to pinpoint failures.
- **Prevention of Invalid Memory Writes** → Added checks to avoid writing outside allocated memory.

### ✅ **Execution & Evasion Enhancements**
- **Hardware Breakpoints** → The shellcode only executes when the breakpoint is triggered.
- **Stack Spoofing Optimization** → Prevents crashes by properly adjusting the stack pointer (`RSP`).
- **Delayed Execution** → The payload is only executed after all fragments have been injected.

### ✅ **Stealth & Detection Avoidance**
- **No Direct `VirtualAllocEx` Calls for Execution** → Uses indirect memory mapping techniques.
- **Reduces Use of Common API Calls** → Avoids standard `CreateRemoteThread` and uses `NtCreateThreadEx` instead.
- **Memory Dump Verification** → Ensures the shellcode is written correctly before execution.

---

## 🔮 Future Enhancements
1️⃣ **Syscall Only Execution** → Implement direct syscalls to bypass API hooking by EDRs.  
2️⃣ **Memory Encryption & Decryption** → XOR/RC4 encryption to hide payload before execution.  
3️⃣ **Thread Hijacking for Covert Execution** → Inject into existing threads instead of creating new ones.  
4️⃣ **Process Doppelgänging** → Execute payloads in ghosted processes without touching disk.  
5️⃣ **ETW (Event Tracing for Windows) Bypass** → Disable telemetry tracking for enhanced stealth.  
