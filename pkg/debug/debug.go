// Package debug provides shared debug logging functionality for go-native-syscall
package debug

import (
	"fmt"
	"os"
	"strings"
)

var (
	// debugEnabled controls whether debug output is printed
	debugEnabled bool
)

func init() {
	// Check environment variables for debug mode
	debugVars := []string{
		"WINAPI_DEBUG",
		"SYSCALLRESOLVE_DEBUG", 
		"SYSCALL_DEBUG",
		"DEBUG",
	}
	
	for _, envVar := range debugVars {
		if debug := os.Getenv(envVar); debug != "" {
			if strings.ToLower(debug) == "true" || debug == "1" {
				debugEnabled = true
				break
			}
		}
	}
}

// SetDebugMode enables or disables debug logging programmatically
func SetDebugMode(enabled bool) {
	debugEnabled = enabled
}

// IsDebugEnabled returns whether debug mode is currently enabled
func IsDebugEnabled() bool {
	return debugEnabled
}

// Printf prints debug messages only when debug mode is enabled
func Printf(format string, args ...interface{}) {
	if debugEnabled {
		fmt.Printf("[DEBUG] "+format, args...)
	}
}

// Println prints debug messages only when debug mode is enabled
func Println(args ...interface{}) {
	if debugEnabled {
		fmt.Print("[DEBUG] ")
		fmt.Println(args...)
	}
}

// Printfln prints debug messages with a specific prefix only when debug mode is enabled
func Printfln(prefix, format string, args ...interface{}) {
	if debugEnabled {
		fmt.Printf("[DEBUG %s] "+format, append([]interface{}{prefix}, args...)...)
	}
} 