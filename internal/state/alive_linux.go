//go:build linux

package state

import (
	"errors"
	"os"
	"syscall"
)

// Alive reports whether a pid names a live process.
//
// Signal 0 performs every check kill(2) does -- existence, permission, zombie
// state -- without delivering anything. EPERM is treated as alive: the process
// exists, we simply are not allowed to signal it, which is the normal case for
// a container init owned by root while the CLI runs unprivileged.
func Alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	switch {
	case err == nil:
		return true
	case errors.Is(err, syscall.ESRCH):
		return false
	case errors.Is(err, os.ErrPermission), errors.Is(err, syscall.EPERM):
		return true
	default:
		return false
	}
}
