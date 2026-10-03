//go:build linux

// Package linuxutil provides the raw syscall layer that Go's stdlib omits or
// fails to export on linux/amd64.
//
// Everything here talks directly to the kernel through the vDSO-less syscall
// interface. This is the layer where the "clever low-level configuration"
// described in the README actually happens.
package linuxutil

// Go's syscall package omits several constants that a container runtime
// fundamentally requires on linux/amd64. Specifically:
//
//	SYS_SETNS              - defined for arm/riscv64/s390x/etc, absent on amd64
//	PR_SET_NO_NEW_PRIVS    - defined on arm64/mips/etc, absent on amd64
//	PR_SET_CHILD_SUBREAPER - same
//	MS_NOSYMFOLLOW         - never exported
//	CLONE_NEWCGROUP        - never exported
//
// We define them here from the Linux uapi headers rather than importing
// golang.org/x/sys, which would add a dependency for ~30 lines.

// Syscall numbers from arch/x86/entry/syscalls/*.sys (x86_64 table).
const (
	// sysSetns is `setns(2)`. Verified against the x86_64 syscall table:
	// SYS_FANOTIFY_MARK=301, SYS_PRLIMIT64=302, ... SYS_SETNS=308.
	//
	// syscall.SYS_SETNS is absent from zsysnum_linux_amd64.go.
	sysSetns = 308

	// sysPrctl is `prctl(2)`.
	sysPrctl = 157
)

// prctl(2) option numbers from include/linux/prctl.h.
const (
	prSetChildSubreaper = 0x24 // 36
	prSetNoNewPrivs     = 0x26 // 38
	prSetPdeathsig      = 0x01 // 1
	prSetDumpable       = 0x04 // 4
)

// mount(2) flags from include/uapi/linux/mount.h.
const (
	// MS_NOSYMFOLLOW is defined upstream as 0x400 but has never been exported
	// by the Go standard library. Using it on the kernel we support is safe
	// because unknown mount flags are ignored by older kernels.
	msNoSymFollow = 0x400
)

// clone(2) namespace flags from include/uapi/linux/sched.h.
//
// CLONE_NEWNS/NEWPID/NEWNET/NEWUTS/NEWIPC ARE exported by the syscall package
// and are re-used from there; CLONE_NEWCGROUP is not exported by Go at all.
const (
	cloneNewCgroup = 0x02000000
	cloneNewUser   = 0x10000000
)

// Namespace inode numbers as reported in /proc/<pid>/ns/*.
type NsType uint

const (
	NSCgroup NsType = iota
	NSIPC
	NSMount
	NSNet
	NSUser
	NSUts
	NSPid
)

var nsNames = map[NsType]string{
	NSCgroup: "cgroup",
	NSIPC:    "ipc",
	NSMount:  "mnt",
	NSNet:    "net",
	NSUser:   "user",
	NSUts:    "uts",
	NSPid:    "pid",
}

func (n NsType) String() string {
	if s, ok := nsNames[n]; ok {
		return s
	}
	return "unknown"
}
