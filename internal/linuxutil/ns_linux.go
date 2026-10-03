//go:build linux

package linuxutil

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------------------
// setns(2)
//
//   int setns(int fd, int nstype);
//
// setns reassociates the calling thread with the namespace referred to by the
// open file descriptor fd. This is how `docker exec` and `nsenter` join an
// existing container: the target namespaces are opened out of /proc/<pid>/ns
// and entered one at a time.
//
// Unlike unshare(2), setns takes effect for the *calling thread only*. A
// multithreaded Go process must therefore lock the OS thread for the duration,
// or other threads will silently remain in the old namespaces.
// ---------------------------------------------------------------------------

// Setns joins the namespace referred to by fd. nstype may be 0 when the fd is
// known to be unambiguous (e.g. a cgroup namespace fd).
//
// The caller must hold runtime.LockOSThread(). See EnterNamespaces.
func Setns(fd int, nstype NsType) error {
	_, _, errno := syscall.RawSyscall(sysSetns, uintptr(fd), uintptr(nstype), 0)
	if errno != 0 {
		return fmt.Errorf("setns(%s): %w", nstype, errno)
	}
	return nil
}

// OpenNamespace opens /proc/<pid>/ns/<name> for a namespace kind.
func OpenNamespace(pid int, nstype NsType) (*os.File, error) {
	path := fmt.Sprintf("/proc/%d/ns/%s", pid, nstype)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return f, nil
}

// ---------------------------------------------------------------------------
// prctl(2)
//
//   int prctl(int option, unsigned long arg2, ...);
//
// PR_SET_NO_NEW_PRIVS is the single most important hardening flag a container
// runtime can set. It makes the kernel refuse to grant the process any
// privilege it did not already have via file capabilities, so an execve() of a
// setuid binary inside the container cannot silently regain root. Without it,
// setuid-root binaries inside the image are an instant container escape.
// ---------------------------------------------------------------------------

// prctl(2) is declared as
//
//	int prctl(int option, unsigned long arg2, unsigned long arg3,
//	          unsigned long arg4, unsigned long arg5);
//
// which is six words including the option, so it needs RawSyscall6 rather than
// the three-argument RawSyscall. Only arg2 is meaningful for the PR_SET_*
// options used here; the remainder must still be passed as zero.
func prctl(option int, arg2, arg3, arg4, arg5 uintptr) error {
	_, _, errno := syscall.RawSyscall6(sysPrctl,
		uintptr(option), arg2, arg3, arg4, arg5, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// SetNoNewPrivs sets PR_SET_NO_NEW_PRIVS on the calling thread. It is
// inherited across execve and cannot be unset, which is what makes it useful.
func SetNoNewPrivs() error {
	if err := prctl(prSetNoNewPrivs, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}
	return nil
}

// SetChildSubreaper marks the process as a subreaper. Orphaned descendants
// whose real parent has died get reparented to the nearest subreaper instead of
// to PID 1 of the host. A container runtime sets this so that it, not the
// host init, is responsible for reaping every process inside a container.
func SetChildSubreaper() error {
	if err := prctl(prSetChildSubreaper, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_CHILD_SUBREAPER): %w", err)
	}
	return nil
}

// SetPdeathsig sets the signal delivered to this process when its parent dies.
// Used so an orphaned init shim tears its container down rather than leaking.
func SetPdeathsig(sig syscall.Signal) error {
	if err := prctl(prSetPdeathsig, uintptr(sig), 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_PDEATHSIG): %w", err)
	}
	return nil
}

// SetNonDumpable clears PR_SET_DUMPABLE so that only a suitably privileged
// process can ptrace this one, and so core dumps do not leak container secrets.
func SetNonDumpable() error {
	if err := prctl(prSetDumpable, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE=0): %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// pivot_root(2)
//
//   int pivot_root(const char *new_root, const char *put_old);
//
// pivot_root atomically replaces the process's root mount with new_root and
// moves the old root to put_old *inside* the new root. Unlike chroot(2) it
// cannot be undone, and it does not leave the old root reachable, because the
// old root ends up underneath the new one.
//
// The kernel imposes two rules that are the source of most implementation bugs:
//
//  1. new_root and put_old must be directories in *different* mount
//     namespaces-as-far-as-the-kernel-is-concerned -- i.e. put_old must not be
//     underneath new_root.
//  2. The current root must not be on a shared mount, otherwise the pivot would
//     propagate back out to the host. Hence the mandatory
//     mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) first.
//
// After a successful pivot_root the old root is still mounted and still
// contains the cwd. The caller must chdir(".") to escape it, or it will appear
// to be inside the deleted tree.
// ---------------------------------------------------------------------------

// PivotRoot moves the process root to newRoot, placing the old root at putOld.
func PivotRoot(newRoot, putOld string) error {
	n, err := syscall.BytePtrFromString(newRoot)
	if err != nil {
		return fmt.Errorf("pivot_root new_root %q: %w", newRoot, err)
	}
	o, err := syscall.BytePtrFromString(putOld)
	if err != nil {
		return fmt.Errorf("pivot_root put_old %q: %w", putOld, err)
	}
	_, _, errno := syscall.RawSyscall(syscall.SYS_PIVOT_ROOT,
		uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(o)), 0)
	if errno != 0 {
		return fmt.Errorf("pivot_root(%q, %q): %w", newRoot, putOld, errno)
	}
	return nil
}

// ---------------------------------------------------------------------------
// mount(2) helpers
// ---------------------------------------------------------------------------

// MakePrivateRecursively detaches the whole subtree rooted at path from the
// host's mount propagation. Without this, every mount performed inside the
// container would be visible to -- and could escape through -- the host.
func MakePrivateRecursively(path string) error {
	if err := syscall.Mount("", path, "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("mount(%s, MS_REC|MS_PRIVATE): %w", path, err)
	}
	return nil
}

// BindMount performs a recursive bind mount of source onto target.
func BindMount(source, target string, readonly bool) error {
	if err := syscall.Mount(source, target, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind mount %s -> %s: %w", source, target, err)
	}
	if !readonly {
		return nil
	}
	// A read-only bind requires a second MS_REMOUNT call; MS_RDONLY is ignored
	// on the initial MS_BIND. It must also be repeated for every existing
	// submount, hence MS_REC.
	if err := syscall.Mount("", target, "",
		syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("remount %s read-only: %w", target, err)
	}
	return nil
}

// MountProc mounts a fresh procfs at target. It must be mounted *after* the
// PID namespace is entered, otherwise /proc would expose the host's processes --
// the original CVE-2019-5736 family of bugs in essence.
func MountProc(target string) error {
	if err := syscall.Mount("proc", target, "proc", msNoSymFollow, ""); err != nil {
		return fmt.Errorf("mount proc on %s: %w", target, err)
	}
	return nil
}

// MountSysfs mounts sysfs. Note that sysfs is not namespace-aware for net, so a
// fresh mount is still required inside a new network namespace.
func MountSysfs(target string, readonly bool) error {
	flags := uintptr(msNoSymFollow)
	if readonly {
		flags |= syscall.MS_RDONLY
	}
	if err := syscall.Mount("sysfs", target, "sysfs", flags, ""); err != nil {
		return fmt.Errorf("mount sysfs on %s: %w", target, err)
	}
	return nil
}

// MountTmpfs mounts a tmpfs at target.
func MountTmpfs(target string, sizeBytes int64, mode uint32) error {
	data := fmt.Sprintf("size=%d,mode=%o", sizeBytes, mode)
	if err := syscall.Mount("tmpfs", target, "tmpfs", 0, data); err != nil {
		return fmt.Errorf("mount tmpfs on %s: %w", target, err)
	}
	return nil
}

// Unmount detaches target. MNT_DETACH is used so the unmount never fails with
// EBUSY merely because something holds a reference; the mount disappears once
// the last reference goes away.
func Unmount(target string, detach bool) error {
	flags := 0
	if detach {
		flags = MntDetach
	}
	if err := syscall.Unmount(target, flags); err != nil {
		return fmt.Errorf("unmount %s: %w", target, err)
	}
	return nil
}

// MntDetach is lazy unmount; exported by the syscall package as MNT_DETACH.
const MntDetach = 0x2
