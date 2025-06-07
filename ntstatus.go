package winapi

import "fmt"

func FormatNTStatus(status uintptr) string {
	statusCode := uint32(status)
	
	// Map of common NTSTATUS codes to their descriptions
	statusDescriptions := map[uint32]string{
		STATUS_SUCCESS:                     "STATUS_SUCCESS",
		STATUS_BUFFER_OVERFLOW:             "STATUS_BUFFER_OVERFLOW", 
		STATUS_INFO_LENGTH_MISMATCH:        "STATUS_INFO_LENGTH_MISMATCH",
		STATUS_INVALID_HANDLE:              "STATUS_INVALID_HANDLE",
		STATUS_INVALID_PARAMETER:           "STATUS_INVALID_PARAMETER",
		STATUS_NO_MEMORY:                   "STATUS_NO_MEMORY",
		STATUS_ACCESS_DENIED:               "STATUS_ACCESS_DENIED",
		STATUS_BUFFER_TOO_SMALL:            "STATUS_BUFFER_TOO_SMALL",
		STATUS_OBJECT_TYPE_MISMATCH:        "STATUS_OBJECT_TYPE_MISMATCH",
		STATUS_INVALID_PAGE_PROTECTION:     "STATUS_INVALID_PAGE_PROTECTION",
		STATUS_MUTANT_NOT_OWNED:            "STATUS_MUTANT_NOT_OWNED",
		STATUS_SEMAPHORE_LIMIT_EXCEEDED:    "STATUS_SEMAPHORE_LIMIT_EXCEEDED",
		STATUS_PORT_ALREADY_SET:            "STATUS_PORT_ALREADY_SET",
		STATUS_SECTION_NOT_EXTENDED:        "STATUS_SECTION_NOT_EXTENDED",
		STATUS_INVALID_VIEW_SIZE:           "STATUS_INVALID_VIEW_SIZE",
		STATUS_ALREADY_COMMITTED:           "STATUS_ALREADY_COMMITTED",
		0xC000001C:                         "STATUS_INVALID_PARAMETER_1", // Common additional status
		0xC0000005:                         "STATUS_ACCESS_VIOLATION",
		0xC0000010:                         "STATUS_INVALID_DEVICE_REQUEST",
		0xC0000013:                         "STATUS_NO_SUCH_DEVICE",
		0xC0000034:                         "STATUS_OBJECT_NAME_NOT_FOUND",
		0xC0000035:                         "STATUS_OBJECT_NAME_COLLISION",
		0xC000003A:                         "STATUS_OBJECT_PATH_NOT_FOUND",
		0xC0000041:                         "STATUS_DELETE_PENDING",
		0xC0000043:                         "STATUS_SHARING_VIOLATION",
		0xC000004B:                         "STATUS_THREAD_IS_TERMINATING",
		0xC0000061:                         "STATUS_PRIVILEGE_NOT_HELD",
		0xC0000070:                         "STATUS_INVALID_DEVICE_STATE",
		0xC0000072:                         "STATUS_INVALID_IMAGE_FORMAT",
		0xC000007C:                         "STATUS_INVALID_IMAGE_NOT_MZ",
		0xC000007D:                         "STATUS_INVALID_IMAGE_PROTECT",
		0xC0000102:                         "STATUS_TIMEOUT",
		0xC0000120:                         "STATUS_CANCELLED",
		0xC0000135:                         "STATUS_DLL_NOT_FOUND",
		0xC0000139:                         "STATUS_ENTRYPOINT_NOT_FOUND",
		0xC000013A:                         "STATUS_CONTROL_C_EXIT",
		0xC0000142:                         "STATUS_DLL_INIT_FAILED",
		0xC0000225:                         "STATUS_NOT_FOUND",
	}
	
	if description, exists := statusDescriptions[statusCode]; exists {
		return fmt.Sprintf("0x%08X (%s)", statusCode, description)
	}
	

	severity := (statusCode >> 30) & 0x3
	var severityStr string
	switch severity {
	case 0:
		severityStr = "SUCCESS"
	case 1:
		severityStr = "INFORMATIONAL" 
	case 2:
		severityStr = "WARNING"
	case 3:
		severityStr = "ERROR"
	default:
		severityStr = "UNKNOWN"
	}
	
	return fmt.Sprintf("0x%08X (Unknown %s status)", statusCode, severityStr)
}

// IsNTStatusSuccess checks if an NTSTATUS code indicates success
func IsNTStatusSuccess(status uintptr) bool {
	return status == STATUS_SUCCESS
}

// IsNTStatusError checks if an NTSTATUS code indicates an error
func IsNTStatusError(status uintptr) bool {
	return (status >> 30) == 3 // Severity bits = 11 (error)
}

// IsNTStatusWarning checks if an NTSTATUS code indicates a warning
func IsNTStatusWarning(status uintptr) bool {
	return (status >> 30) == 2 // Severity bits = 10 (warning)
}