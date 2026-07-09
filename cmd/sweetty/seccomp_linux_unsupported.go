//go:build linux && !amd64 && !arm64

package main

import "fmt"

// The release supports amd64 and arm64 only. Refuse to start on another Linux
// architecture instead of silently running without syscall lockdown.
func lockdownSyscalls() error {
	return fmt.Errorf("unsupported Linux architecture for seccomp lockdown")
}
