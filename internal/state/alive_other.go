//go:build !linux

package state

import "os"

// Alive is a best-effort answer for non-Linux builds.
//
// There is no signal-0 equivalent on Windows, and the runtime does not run
// there anyway -- it exists so the portable half of the package still compiles
// and its tests still execute on a development machine. OpenProcess with
// PROCESS_QUERY_LIMITED_INFORMATION is the closest portable probe.
func Alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// A process handle that cannot be signalled still proves it exists.
	return p != nil
}
