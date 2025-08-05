# go-native-syscall

## available api

### winapi

- `func UnhookNtdll() error`
- `func DirectSyscall(functionName string, args ...uintptr) (uintptr, error)`
- `func DirectSyscallByHash(functionHash uint32, args ...uintptr) (uintptr, error)`
- `func GetCurrentProcessHandle() uintptr`
- `func GetCurrentThreadHandle() uintptr`
- `func GetCurrentProcessId() uintptr`
- `func GetSyscallNumber(functionName string) uint16`
- `func GetFunctionHash(functionName string) uint32`
- `func GetSyscallWithValidation(functionName string) (uint16, bool, error)`
- `func GuessSyscallNumber(functionName string) uint16`
- `func PrewarmSyscallCache() error`
- `func GetSyscallCacheSize() int`
- `func GetSyscallCacheStats() map[string]interface{}`
- `func SelfDel()`
- `func StringToUTF16(s string) *uint16`
- `func NtAllocateVirtualMemory(...) (uintptr, error)`
- `func NtWriteVirtualMemory(...) (uintptr, error)`
- `func NtReadVirtualMemory(...) (uintptr, error)`
- `func NtProtectVirtualMemory(...) (uintptr, error)`
- `func NtCreateThreadEx(...) (uintptr, error)`
- `func NtOpenProcess(...) (uintptr, error)`
- `func NtClose(handle uintptr) (uintptr, error)`
- `func NtQuerySystemInformation(...) (uintptr, error)`
- `func NtQueryInformationProcess(...) (uintptr, error)`
- `func NtSetInformationProcess(...) (uintptr, error)`
- `func NtCreateFile(...) (uintptr, error)`
- `func NtWriteFile(...) (uintptr, error)`
- `func NtReadFile(...) (uintptr, error)`
- `func NtTerminateProcess(...) (uintptr, error)`
- `func NtSuspendProcess(processHandle uintptr) (uintptr, error)`
- `func NtResumeProcess(processHandle uintptr) (uintptr, error)`
- `func NtCreateProcess(...) (uintptr, error)`
- `func NtCreateThread(...) (uintptr, error)`
- `func NtOpenThread(...) (uintptr, error)`
- `func NtSuspendThread(...) (uintptr, error)`
- `func NtResumeThread(...) (uintptr, error)`
- `func NtTerminateThread(...) (uintptr, error)`
- `func NtCreateSection(...) (uintptr, error)`
- `func NtMapViewOfSection(...) (uintptr, error)`
- `func NtUnmapViewOfSection(...) (uintptr, error)`
- `func NtFreeVirtualMemory(...) (uintptr, error)`
- `func NtQueryVirtualMemory(...) (uintptr, error)`
- `func NtCreateKey(...) (uintptr, error)`
- `func NtOpenKey(...) (uintptr, error)`
- `func NtDeleteKey(keyHandle uintptr) (uintptr, error)`
- `func NtSetValueKey(...) (uintptr, error)`
- `func NtQueryValueKey(...) (uintptr, error)`
- `func NtDeleteValueKey(...) (uintptr, error)`
- `func NtOpenProcessToken(...) (uintptr, error)`
- `func NtOpenThreadToken(...) (uintptr, error)`
- `func NtQueryInformationToken(...) (uintptr, error)`
- `func NtSetInformationToken(...) (uintptr, error)`
- `func NtAdjustPrivilegesToken(...) (uintptr, error)`
- `func NtDuplicateObject(...) (uintptr, error)`
- `func NtQueryObject(...) (uintptr, error)`
- `func NtSetSystemInformation(...) (uintptr, error)`
- `func NtQuerySystemTime(systemTime *uint64) (uintptr, error)`
- `func NtSetSystemTime(...) (uintptr, error)`
- `func NtCreateEvent(...) (uintptr, error)`
- `func NtOpenEvent(...) (uintptr, error)`
- `func NtSetEvent(...) (uintptr, error)`
- `func NtResetEvent(...) (uintptr, error)`
- `func NtWaitForSingleObject(...) (uintptr, error)`
- `func NtWaitForMultipleObjects(...) (uintptr, error)`
- `func NtDeleteFile(objectAttributes uintptr) (uintptr, error)`
- `func NtQueryDirectoryFile(...) (uintptr, error)`
- `func NtQueryInformationFile(...) (uintptr, error)`
- `func NtSetInformationFile(...) (uintptr, error)`
- `func NtDeviceIoControlFile(...) (uintptr, error)`
- `func NtRemoveIoCompletion(...) (uintptr, error)`
- `func NtReleaseSemaphore(...) (uintptr, error)`
- `func NtReplyWaitReceivePort(...) (uintptr, error)`
- `func NtReplyPort(...) (uintptr, error)`
- `func NtSetInformationThread(...) (uintptr, error)`
- `func NtQueryInformationThread(...) (uintptr, error)`
- `func NtFlushInstructionCache(...) (uintptr, error)`
- `func NtSetEventBoostPriority(eventHandle uintptr) (uintptr, error)`
- `func NtQueryPerformanceCounter(...) (uintptr, error)`
- `func NtOpenThreadTokenEx(...) (uintptr, error)`
- `func NtOpenProcessTokenEx(...) (uintptr, error)`
- `func DumpAllSyscalls() ([]SyscallInfo, error)`
- `func DumpAllNtdllFunctions() ([]FunctionInfo, error)`
- `func PrewarmNtdllCache() error`
- `func GetNtdllCacheSize() int`
- `func GetNtdllCacheStats() map[string]interface{}`
- `func ClearNtdllCache()`
- `func DumpAllSyscallsWithFiles() ([]SyscallInfo, error)`
- `func NtInjectSelfShellcode(shellcode []byte) error`
- `func NtInjectRemote(processHandle uintptr, payload []byte) error`

### winapi_indirect

- `func IndirectSyscall(functionName string, args ...uintptr) (uintptr, error)`
- `func IndirectSyscallByHash(functionHash uint32, args ...uintptr) (uintptr, error)`
- `func SelfDelIndirect()`
- `func NtInjectSelfShellcodeIndirect(shellcode []byte) error`
- `func OriginalNtInjectSelfShellcodeIndirect(payload []byte) error`
- `func NtInjectRemoteIndirect(processHandle uintptr, payload []byte) error`
- *(Provides indirect-call versions of all Nt* functions, e.g., `NtAllocateVirtualMemoryIndirect`)*

### winapi_privesc

- `func ScanPrivilegeEscalationVectors() (*PrivEscMap, error)`
- `func ScanWeakPermissions() ([]WeakPermission, error)`
- `func FindPrivilegedProcesses() ([]ProcessInfo, error)`
- `func ImpersonateAndExecute(targetProcess ProcessInfo, shellcode []byte) error`

### winapi_exp

- `func ExploitBinaryPlanting(vectors []EscalationVector, options ExploitOptions) []ExploitResult`
- `func ExploitServiceReplacement(vectors []EscalationVector, options ExploitOptions) []ExploitResult`
- `func ExploitTaskScheduler(vectors []EscalationVector, options ExploitOptions) []ExploitResult`
- `func ExploitVectors(vectors []EscalationVector, options ExploitOptions) *ExploitSession`
- `func AutoExploit(escMap *PrivEscMap, payload []byte, testMode bool) *ExploitSession`
- `func GetExploitableVectors(escMap *PrivEscMap) []EscalationVector`

### patches

- `func PatchAMSI() error`
- `func PatchETW() error`
- `func PatchDbgUiRemoteBreakin() error`
- `func PatchNtTraceEvent() error`
- `func PatchNtSystemDebugControl() error`
- `func ApplyAllPatches() (successful []string, failed map[string]error)`
- `func ApplyCriticalPatches() (successful []string, failed map[string]error)`
- `func CreateRunKey() error`

### pkg/obf

- `func GetHash(input string) uint32`
- `func GetHashW(input *uint16) uint32`
- `func GetWString(s string) *uint16`

### pkg/syscall

- `func HashSyscall(functionHash uint32, args ...uintptr) (r1, r2 uintptr, err error)`
- `func HashIndirectSyscall(functionHash uint32, args ...uintptr) (r1, r2 uintptr, err error)`

### pkg/syscallresolve

- `func GetSyscallNumber(functionHash uint32) uint16`
- `func GetSyscallWithValidation(functionHash uint32) (uint16, bool, error)`
- `func GuessSyscallNumber(functionHash uint32) uint16`
- `func GetFunctionAddress(moduleBase uintptr, functionHash uint32) uintptr`
- `func GetModuleBase(moduleHash uint32) uintptr`
- `func PrewarmSyscallCache() error`
- `func GetSyscallCacheSize() int`

### pkg/unhook

- `func UnhookNtdll() error`

### constants

- provides various windows constants for memory, process/thread access, files, tokens, and other objects. also includes core data structures like `unicode_string`, `object_attributes`, and `process_basic_information`.

## technical details

this project provides a comprehensive toolkit for low-level windows interaction in go, focusing on direct and indirect syscall execution. it dynamically resolves syscall numbers by parsing ntdll.dll from memory, using djb2 hashing for function name obfuscation. this method avoids reliance on the standard library and makes it resilient to api hooking by user-mode edr solutions. the library includes functionality for memory operations, process and thread manipulation, token impersonation, and registry modification. it also features defensive capabilities such as amsi and etw patching, along with offensive modules for discovering and exploiting privilege escalation vectors like binary planting, service replacement, and task hijacking. the design emphasizes performance and operational security, with features like syscall caching, function pre-warming, and robust error handling.

