package winapi

import "unsafe"

// Common Windows constants for direct syscalls

// Memory allocation types
const (
	MEM_COMMIT      = 0x1000
	MEM_RESERVE     = 0x2000
	MEM_DECOMMIT    = 0x4000
	MEM_RELEASE     = 0x8000
	MEM_FREE        = 0x10000
	MEM_PRIVATE     = 0x20000
	MEM_MAPPED      = 0x40000
	MEM_RESET       = 0x80000
	MEM_TOP_DOWN    = 0x100000
	MEM_WRITE_WATCH = 0x200000
	MEM_PHYSICAL    = 0x400000
	MEM_LARGE_PAGES = 0x20000000
)

// Memory protection constants
const (
	PAGE_NOACCESS          = 0x01
	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_WRITECOPY         = 0x08
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80
	PAGE_GUARD             = 0x100
	PAGE_NOCACHE           = 0x200
	PAGE_WRITECOMBINE      = 0x400
)

// Process access rights
const (
	PROCESS_TERMINATE                 = 0x0001
	PROCESS_CREATE_THREAD             = 0x0002
	PROCESS_SET_SESSIONID             = 0x0004
	PROCESS_VM_OPERATION              = 0x0008
	PROCESS_VM_READ                   = 0x0010
	PROCESS_VM_WRITE                  = 0x0020
	PROCESS_DUP_HANDLE                = 0x0040
	PROCESS_CREATE_PROCESS            = 0x0080
	PROCESS_SET_QUOTA                 = 0x0100
	PROCESS_SET_INFORMATION           = 0x0200
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_SUSPEND_RESUME            = 0x0800
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_ALL_ACCESS                = 0x000F0000 | 0x00100000 | 0xFFFF
)

// Thread access rights
const (
	THREAD_TERMINATE                = 0x0001
	THREAD_SUSPEND_RESUME           = 0x0002
	THREAD_GET_CONTEXT              = 0x0008
	THREAD_SET_CONTEXT              = 0x0010
	THREAD_SET_INFORMATION          = 0x0020
	THREAD_QUERY_INFORMATION        = 0x0040
	THREAD_SET_THREAD_TOKEN         = 0x0080
	THREAD_IMPERSONATE              = 0x0100
	THREAD_DIRECT_IMPERSONATION     = 0x0200
	THREAD_SET_LIMITED_INFORMATION  = 0x0400
	THREAD_QUERY_LIMITED_INFORMATION = 0x0800
	THREAD_ALL_ACCESS               = 0x000F0000 | 0x00100000 | 0xFFFF
)

// Generic access rights
const (
	DELETE                   = 0x00010000
	READ_CONTROL            = 0x00020000
	WRITE_DAC               = 0x00040000
	WRITE_OWNER             = 0x00080000
	SYNCHRONIZE             = 0x00100000
	STANDARD_RIGHTS_REQUIRED = 0x000F0000
	STANDARD_RIGHTS_READ    = READ_CONTROL
	STANDARD_RIGHTS_WRITE   = READ_CONTROL
	STANDARD_RIGHTS_EXECUTE = READ_CONTROL
	STANDARD_RIGHTS_ALL     = 0x001F0000
	SPECIFIC_RIGHTS_ALL     = 0x0000FFFF
	ACCESS_SYSTEM_SECURITY  = 0x01000000
	MAXIMUM_ALLOWED         = 0x02000000
	GENERIC_READ            = 0x80000000
	GENERIC_WRITE           = 0x40000000
	GENERIC_EXECUTE         = 0x20000000
	GENERIC_ALL             = 0x10000000
)

// File access rights
const (
	FILE_READ_DATA            = 0x0001
	FILE_LIST_DIRECTORY       = 0x0001
	FILE_WRITE_DATA           = 0x0002
	FILE_ADD_FILE             = 0x0002
	FILE_APPEND_DATA          = 0x0004
	FILE_ADD_SUBDIRECTORY     = 0x0004
	FILE_CREATE_PIPE_INSTANCE = 0x0004
	FILE_READ_EA              = 0x0008
	FILE_WRITE_EA             = 0x0010
	FILE_EXECUTE              = 0x0020
	FILE_TRAVERSE             = 0x0020
	FILE_DELETE_CHILD         = 0x0040
	FILE_READ_ATTRIBUTES      = 0x0080
	FILE_WRITE_ATTRIBUTES     = 0x0100
	FILE_ALL_ACCESS           = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF
	FILE_GENERIC_READ         = STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE
	FILE_GENERIC_WRITE        = STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE
	FILE_GENERIC_EXECUTE      = STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE
)

// File share access
const (
	FILE_SHARE_READ   = 0x00000001
	FILE_SHARE_WRITE  = 0x00000002
	FILE_SHARE_DELETE = 0x00000004
)

// File creation disposition
const (
	FILE_SUPERSEDE    = 0x00000000
	FILE_OPEN         = 0x00000001
	FILE_CREATE       = 0x00000002
	FILE_OPEN_IF      = 0x00000003
	FILE_OVERWRITE    = 0x00000004
	FILE_OVERWRITE_IF = 0x00000005
)

// File creation options
const (
	FILE_DIRECTORY_FILE            = 0x00000001
	FILE_WRITE_THROUGH             = 0x00000002
	FILE_SEQUENTIAL_ONLY           = 0x00000004
	FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008
	FILE_SYNCHRONOUS_IO_ALERT      = 0x00000010
	FILE_SYNCHRONOUS_IO_NONALERT   = 0x00000020
	FILE_NON_DIRECTORY_FILE        = 0x00000040
	FILE_CREATE_TREE_CONNECTION    = 0x00000080
	FILE_COMPLETE_IF_OPLOCKED      = 0x00000100
	FILE_NO_EA_KNOWLEDGE           = 0x00000200
	FILE_OPEN_FOR_RECOVERY         = 0x00000400
	FILE_RANDOM_ACCESS             = 0x00000800
	FILE_DELETE_ON_CLOSE           = 0x00001000
	FILE_OPEN_BY_FILE_ID           = 0x00002000
	FILE_OPEN_FOR_BACKUP_INTENT    = 0x00004000
	FILE_NO_COMPRESSION            = 0x00008000
	FILE_RESERVE_OPFILTER          = 0x00100000
	FILE_OPEN_REPARSE_POINT        = 0x00200000
	FILE_OPEN_NO_RECALL            = 0x00400000
	FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000
)

// File attributes
const (
	FILE_ATTRIBUTE_READONLY              = 0x00000001
	FILE_ATTRIBUTE_HIDDEN                = 0x00000002
	FILE_ATTRIBUTE_SYSTEM                = 0x00000004
	FILE_ATTRIBUTE_DIRECTORY             = 0x00000010
	FILE_ATTRIBUTE_ARCHIVE               = 0x00000020
	FILE_ATTRIBUTE_DEVICE                = 0x00000040
	FILE_ATTRIBUTE_NORMAL                = 0x00000080
	FILE_ATTRIBUTE_TEMPORARY             = 0x00000100
	FILE_ATTRIBUTE_SPARSE_FILE           = 0x00000200
	FILE_ATTRIBUTE_REPARSE_POINT         = 0x00000400
	FILE_ATTRIBUTE_COMPRESSED            = 0x00000800
	FILE_ATTRIBUTE_OFFLINE               = 0x00001000
	FILE_ATTRIBUTE_NOT_CONTENT_INDEXED   = 0x00002000
	FILE_ATTRIBUTE_ENCRYPTED             = 0x00004000
	FILE_ATTRIBUTE_INTEGRITY_STREAM      = 0x00008000
	FILE_ATTRIBUTE_VIRTUAL               = 0x00010000
	FILE_ATTRIBUTE_NO_SCRUB_DATA         = 0x00020000
	FILE_ATTRIBUTE_RECALL_ON_OPEN        = 0x00040000
	FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
)

// System information classes
const (
	SystemBasicInformation                = 0
	SystemProcessorInformation            = 1
	SystemPerformanceInformation          = 2
	SystemTimeOfDayInformation            = 3
	SystemPathInformation                 = 4
	SystemProcessInformation              = 5
	SystemCallCountInformation            = 6
	SystemDeviceInformation               = 7
	SystemProcessorPerformanceInformation = 8
	SystemFlagsInformation                = 9
	SystemCallTimeInformation             = 10
	SystemModuleInformation               = 11
)

// Process information classes
const (
	ProcessBasicInformation                  = 0
	ProcessQuotaLimits                       = 1
	ProcessIoCounters                        = 2
	ProcessVmCounters                        = 3
	ProcessTimes                             = 4
	ProcessBasePriority                      = 5
	ProcessRaisePriority                     = 6
	ProcessDebugPort                         = 7
	ProcessExceptionPort                     = 8
	ProcessAccessToken                       = 9
	ProcessLdtInformation                    = 10
	ProcessLdtSize                           = 11
	ProcessDefaultHardErrorMode              = 12
	ProcessIoPortHandlers                    = 13
	ProcessPooledUsageAndLimits              = 14
	ProcessWorkingSetWatch                   = 15
	ProcessUserModeIOPL                      = 16
	ProcessEnableAlignmentFaultFixup         = 17
	ProcessPriorityClass                     = 18
	ProcessWx86Information                   = 19
	ProcessHandleCount                       = 20
	ProcessAffinityMask                      = 21
	ProcessPriorityBoost                     = 22
	ProcessDeviceMap                         = 23
	ProcessSessionInformation                = 24
	ProcessForegroundInformation             = 25
	ProcessWow64Information                  = 26
	ProcessImageFileName                     = 27
	ProcessLUIDDeviceMapsEnabled             = 28
	ProcessBreakOnTermination                = 29
	ProcessDebugObjectHandle                 = 30
	ProcessDebugFlags                        = 31
	ProcessHandleTracing                     = 32
	ProcessIoPriority                        = 33
	ProcessExecuteFlags                      = 34
	ProcessResourceManagement                = 35
	ProcessCookie                            = 36
	ProcessImageInformation                  = 37
	ProcessCycleTime                         = 38
	ProcessPagePriority                      = 39
	ProcessInstrumentationCallback           = 40
	ProcessThreadStackAllocation             = 41
	ProcessWorkingSetWatchEx                 = 42
	ProcessImageFileNameWin32                = 43
	ProcessImageFileMapping                  = 44
	ProcessAffinityUpdateMode                = 45
	ProcessMemoryAllocationMode              = 46
	ProcessGroupInformation                  = 47
	ProcessTokenVirtualizationEnabled       = 48
	ProcessConsoleHostProcess                = 49
	ProcessWindowInformation                 = 50
)

// NTSTATUS codes
const (
	STATUS_SUCCESS                = 0x00000000
	STATUS_BUFFER_OVERFLOW        = 0x80000005
	STATUS_INFO_LENGTH_MISMATCH   = 0xC0000004
	STATUS_ACCESS_VIOLATION       = 0xC0000005
	STATUS_INVALID_HANDLE         = 0xC0000008
	STATUS_INVALID_PARAMETER      = 0xC000000D
	STATUS_NO_MEMORY              = 0xC0000017
	STATUS_ACCESS_DENIED          = 0xC0000022
	STATUS_BUFFER_TOO_SMALL       = 0xC0000023
	STATUS_OBJECT_TYPE_MISMATCH   = 0xC0000024
	STATUS_OBJECT_NAME_INVALID    = 0xC0000033
	STATUS_OBJECT_PATH_SYNTAX_BAD = 0xC000003B
	STATUS_INVALID_PAGE_PROTECTION = 0xC0000045
	STATUS_MUTANT_NOT_OWNED       = 0xC0000046
	STATUS_SEMAPHORE_LIMIT_EXCEEDED = 0xC0000047
	STATUS_PORT_ALREADY_SET       = 0xC0000048
	STATUS_SECTION_NOT_EXTENDED   = 0xC0000087
	STATUS_INVALID_VIEW_SIZE      = 0xC000001F
	STATUS_ALREADY_COMMITTED      = 0xC0000021
	STATUS_TIMEOUT                = 0xC0000102
)

// Wait constants
const (
	INFINITE = 0xFFFFFFFF
	
	// Wait result constants
	WAIT_OBJECT_0  = 0x00000000
	WAIT_ABANDONED = 0x00000080
	WAIT_TIMEOUT   = 0x00000102
	WAIT_FAILED    = 0xFFFFFFFF
	
	// Timeout values (in 100ns units)
	// Negative values indicate relative timeouts
	TIMEOUT_10_SECONDS = uint64(0xFFFFFFFF9502F900) // -100,000,000 as uint64 (10 seconds relative)
)

// Thread creation flags
const (
	THREAD_CREATE_FLAGS_CREATE_SUSPENDED = 0x00000001
	THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH = 0x00000002
	THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER = 0x00000004
	THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR = 0x00000010
	THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET = 0x00000020
	THREAD_CREATE_FLAGS_INITIAL_THREAD = 0x00000080
)

// Windows API Structures
// These structures are used for direct syscalls and process enumeration

// UNICODE_STRING represents a Unicode string in Windows
type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// ANSI_STRING represents an ANSI string in Windows
type ANSI_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *byte
}

// CLIENT_ID represents a process and thread identifier pair
type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

// OBJECT_ATTRIBUTES structure for object creation/opening
type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *UNICODE_STRING
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// SYSTEM_PROCESS_INFORMATION structure for NtQuerySystemInformation
type SYSTEM_PROCESS_INFORMATION struct {
	NextEntryOffset              uint32
	NumberOfThreads              uint32
	WorkingSetPrivateSize        int64
	HardFaultCount               uint32
	NumberOfThreadsHighWatermark uint32
	CycleTime                    uint64
	CreateTime                   int64
	UserTime                     int64
	KernelTime                   int64
	ImageName                    UNICODE_STRING
	BasePriority                 int32
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
	HandleCount                  uint32
	SessionId                    uint32
	UniqueProcessKey             uintptr
	PeakVirtualSize              uintptr
	VirtualSize                  uintptr
	PageFaultCount               uint32
	PeakWorkingSetSize           uintptr
	WorkingSetSize               uintptr
	QuotaPeakPagedPoolUsage      uintptr
	QuotaPagedPoolUsage          uintptr
	QuotaPeakNonPagedPoolUsage   uintptr
	QuotaNonPagedPoolUsage       uintptr
	PagefileUsage                uintptr
	PeakPagefileUsage            uintptr
	PrivatePageCount             uintptr
	ReadOperationCount           int64
	WriteOperationCount          int64
	OtherOperationCount          int64
	ReadTransferCount            int64
	WriteTransferCount           int64
	OtherTransferCount           int64
}

// PROCESS_BASIC_INFORMATION structure for NtQueryInformationProcess
type PROCESS_BASIC_INFORMATION struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
}

// Token access rights
const (
	TOKEN_ASSIGN_PRIMARY    = 0x0001
	TOKEN_DUPLICATE        = 0x0002
	TOKEN_IMPERSONATE      = 0x0004
	TOKEN_QUERY           = 0x0008
	TOKEN_QUERY_SOURCE    = 0x0010
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_ADJUST_GROUPS    = 0x0040
	TOKEN_ADJUST_DEFAULT   = 0x0080
	TOKEN_ADJUST_SESSIONID = 0x0100
	TOKEN_ALL_ACCESS       = STANDARD_RIGHTS_REQUIRED |
		TOKEN_ASSIGN_PRIMARY |
		TOKEN_DUPLICATE |
		TOKEN_IMPERSONATE |
		TOKEN_QUERY |
		TOKEN_QUERY_SOURCE |
		TOKEN_ADJUST_PRIVILEGES |
		TOKEN_ADJUST_GROUPS |
		TOKEN_ADJUST_DEFAULT |
		TOKEN_ADJUST_SESSIONID
)

// Additional NTSTATUS codes for token operations
const (
	STATUS_NO_TOKEN = 0xC000007C
)

// Pseudo-handle constants
const (
	CURRENT_PROCESS = ^uintptr(0) // 0xFFFFFFFFFFFFFFFF
	CURRENT_THREAD  = ^uintptr(1) // 0xFFFFFFFFFFFFFFFE
)

// Section access rights
const (
	SECTION_QUERY                = 0x0001
	SECTION_MAP_WRITE            = 0x0002
	SECTION_MAP_READ             = 0x0004
	SECTION_MAP_EXECUTE          = 0x0008
	SECTION_EXTEND_SIZE          = 0x0010
	SECTION_MAP_EXECUTE_EXPLICIT = 0x0020
	SECTION_ALL_ACCESS           = STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE
)

// Section allocation attributes
const (
	SEC_BASED     = 0x00200000
	SEC_NO_CHANGE = 0x00400000
	SEC_FILE      = 0x00800000
	SEC_IMAGE     = 0x01000000
	SEC_PROTECTED_IMAGE = 0x02000000
	SEC_RESERVE   = 0x04000000
	SEC_COMMIT    = 0x08000000
	SEC_NOCACHE   = 0x10000000
	SEC_WRITECOMBINE = 0x40000000
	SEC_LARGE_PAGES  = 0x80000000
)

// Section inherit disposition
const (
	ViewShare  = 1
	ViewUnmap  = 2
)

// Object attributes flags
const (
	OBJ_INHERIT                    = 0x00000002
	OBJ_PERMANENT                  = 0x00000010
	OBJ_EXCLUSIVE                  = 0x00000020
	OBJ_CASE_INSENSITIVE          = 0x00000040
	OBJ_OPENIF                    = 0x00000080
	OBJ_OPENLINK                  = 0x00000100
	OBJ_KERNEL_HANDLE             = 0x00000200
	OBJ_FORCE_ACCESS_CHECK        = 0x00000400
	OBJ_VALID_ATTRIBUTES          = 0x000007F2
)

// File information classes for NtSetInformationFile
const (
	FileDirectoryInformation          = 1
	FileFullDirectoryInformation      = 2
	FileBothDirectoryInformation      = 3
	FileBasicInformation             = 4
	FileStandardInformation          = 5
	FileInternalInformation          = 6
	FileEaInformation                = 7
	FileAccessInformation            = 8
	FileNameInformation              = 9
	FileRenameInformation            = 10
	FileLinkInformation              = 11
	FileNamesInformation             = 12
	FileDispositionInformation       = 13
	FilePositionInformation          = 14
	FileFullEaInformation            = 15
	FileModeInformation              = 16
	FileAlignmentInformation         = 17
	FileAllInformation               = 18
	FileAllocationInformation        = 19
	FileEndOfFileInformation         = 20
	FileAlternateNameInformation     = 21
	FileStreamInformation            = 22
	FilePipeInformation              = 23
	FilePipeLocalInformation         = 24
	FilePipeRemoteInformation        = 25
	FileMailslotQueryInformation     = 26
	FileMailslotSetInformation       = 27
	FileCompressionInformation       = 28
	FileObjectIdInformation          = 29
	FileCompletionInformation        = 30
	FileMoveClusterInformation       = 31
	FileQuotaInformation             = 32
	FileReparsePointInformation      = 33
	FileNetworkOpenInformation       = 34
	FileAttributeTagInformation      = 35
	FileTrackingInformation          = 36
	FileIdBothDirectoryInformation   = 37
	FileIdFullDirectoryInformation   = 38
	FileValidDataLengthInformation   = 39
	FileShortNameInformation         = 40
)

// IO_STATUS_BLOCK structure for I/O operations
type IO_STATUS_BLOCK struct {
	Status      uintptr
	Information uintptr
}

// FILE_RENAME_INFO structure for file renaming
type FILE_RENAME_INFO struct {
	ReplaceIfExists uint8
	RootDirectory   uintptr
	FileNameLength  uint32
	FileName        [1]uint16 // Variable length array
}

// FILE_DISPOSITION_INFO structure for file deletion
type FILE_DISPOSITION_INFO struct {
	DeleteFile uint8
}

// NewUnicodeString creates a UNICODE_STRING from a UTF-16 string pointer
func NewUnicodeString(s *uint16) UNICODE_STRING {
	if s == nil {
		return UNICODE_STRING{}
	}
	
	// Calculate length by finding null terminator
	length := uint16(0)
	ptr := s
	for *ptr != 0 {
		length++
		ptr = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 2))
	}
	
	return UNICODE_STRING{
		Length:        length * 2, // Length in bytes
		MaximumLength: (length + 1) * 2, // Include null terminator
		Buffer:        s,
	}
}

// Thread information classes
const (
	ThreadBasicInformation = iota
	ThreadTimes
	ThreadPriority
	ThreadBasePriority
	ThreadAffinityMask
	ThreadImpersonationToken
	ThreadDescriptorTableEntry
	ThreadEnableAlignmentFaultFixup
	ThreadEventPair
	ThreadQuerySetWin32StartAddress
	ThreadZeroTlsCell
	ThreadPerformanceCount
	ThreadAmILastThread
	ThreadIdealProcessor
	ThreadPriorityBoost
	ThreadSetTlsArrayAddress
	ThreadIsIoPending
	ThreadHideFromDebugger
)

// Token information classes  
const (
	TokenUser = iota + 1
	TokenGroups
	TokenPrivileges
	TokenOwner
	TokenPrimaryGroup
	TokenDefaultDacl
	TokenSource
	TokenType
	TokenImpersonationLevel
	TokenStatistics
	TokenRestrictedSids
	TokenSessionId
	TokenGroupsAndPrivileges
	TokenSessionReference
	TokenSandBoxInert
	TokenAuditPolicy
	TokenOrigin
)

// Privilege constants (LUID values)
const (
	SE_CREATE_TOKEN_PRIVILEGE            = 2
	SE_ASSIGNPRIMARYTOKEN_PRIVILEGE      = 3
	SE_LOCK_MEMORY_PRIVILEGE             = 4
	SE_INCREASE_QUOTA_PRIVILEGE          = 5
	SE_MACHINE_ACCOUNT_PRIVILEGE         = 6
	SE_TCB_PRIVILEGE                     = 7
	SE_SECURITY_PRIVILEGE                = 8
	SE_TAKE_OWNERSHIP_PRIVILEGE          = 9
	SE_LOAD_DRIVER_PRIVILEGE             = 10
	SE_SYSTEM_PROFILE_PRIVILEGE          = 11
	SE_SYSTEMTIME_PRIVILEGE              = 12
	SE_PROF_SINGLE_PROCESS_PRIVILEGE     = 13
	SE_INC_BASE_PRIORITY_PRIVILEGE       = 14
	SE_CREATE_PAGEFILE_PRIVILEGE         = 15
	SE_CREATE_PERMANENT_PRIVILEGE        = 16
	SE_BACKUP_PRIVILEGE                  = 17
	SE_RESTORE_PRIVILEGE                 = 18
	SE_SHUTDOWN_PRIVILEGE                = 19
	SE_DEBUG_PRIVILEGE                   = 20
	SE_AUDIT_PRIVILEGE                   = 21
	SE_SYSTEM_ENVIRONMENT_PRIVILEGE      = 22
	SE_CHANGE_NOTIFY_PRIVILEGE           = 23
	SE_REMOTE_SHUTDOWN_PRIVILEGE         = 24
)

// Registry constants
const (
	KEY_ALL_ACCESS          = 0xF003F
	REG_OPTION_NON_VOLATILE = 0
	REG_SZ                  = 1
)

// LUID structure for privileges
type LUID struct {
	LowPart  uint32
	HighPart int32
}

// LUID_AND_ATTRIBUTES structure
type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

// TOKEN_PRIVILEGES structure
type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES // Variable length array
} 