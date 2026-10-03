//go:build linux

package initseq

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"kernelz/internal/cgroup"
	"kernelz/internal/linuxutil"
	"kernelz/internal/netns"
	"kernelz/internal/spec"
)

// Linux is the Backend that actually performs the syscalls.
//
// One Linux value serves both roles. The supervisor calls Clone and Wait; the
// freshly exec'd child calls the setup methods and finally Exec. Which role a
// given process is in is decided by which methods get called, not by a flag,
// because the two processes are genuinely different: a process is born into a
// PID namespace and cannot enter one afterwards.
type Linux struct {
	// InitBinary is the kz-init helper exec'd as the container's first process.
	InitBinary string
	// Root is the host root, needed to resolve the init binary before pivot_root.
	Root string

	// Child is the pid of the container's init process, valid in the supervisor.
	Child int
	// CG manages this container's cgroup, created by the supervisor.
	CG *cgroup.Manager
	// Net holds any host-side network objects created for the container.
	Net *netns.Handle

	// started is the moment Clone completed, for exit-duration reporting.
	started time.Time

	// StateDir is where the supervisor records container state.
	StateDir string
}

var _ Backend = (*Linux)(nil)

// New builds a Linux backend rooted at the host rootfs.
func New(initBinary, stateDir string) *Linux {
	return &Linux{
		InitBinary: initBinary,
		Root:       "/",
		StateDir:   stateDir,
	}
}

// ---------------------------------------------------------------------------
// Supervisor side
// ---------------------------------------------------------------------------

// Clone creates the container's init process with every requested namespace and
// execs kz-init inside it.
//
// The namespace flags are passed to the kernel by clone(2) itself via
// SysProcAttr.Unshareflags, not by calling unshare(2) afterwards. That is
// deliberate and is the only correct approach for the PID namespace: unshare
// affects only processes forked *after* the call, so unsharing in the parent and
// then forking would leave the parent in the old PID namespace and the child in
// the new one -- which is not the same thing as a container, where the child
// must be PID 1 of a brand new namespace.
//
// Pdeathsig is set so that if the supervisor dies, the container is killed
// rather than becoming an orphan nobody reaps.
func (l *Linux) Clone(s *spec.Spec) error {
	if s == nil {
		return errors.New("clone: nil spec")
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("clone: locate kz-init: %w", err)
	}
	init := l.InitBinary
	if init == "" {
		init = filepath.Join(filepath.Dir(self), "kz-init")
	}
	if _, err := os.Stat(init); err != nil {
		return fmt.Errorf("clone: kz-init not found at %s: %w", init, err)
	}

	attrs, err := procAttr(s)
	if err != nil {
		return err
	}

	cmd := exec.Command(init)
	cmd.SysProcAttr = attrs
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// The child is PID 1 in its namespace: it must never be killed by a
	// terminal hangup, and it must ignore the default SIGPIPE disposition
	// Go would otherwise install.
	cmd.Env = append(os.Environ(), "KZ_CONTAINER_ID="+s.ID)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("clone: start kz-init: %w", err)
	}
	l.Child = cmd.Process.Pid
	l.started = time.Now()

	// The exec.Cmd would normally be waited on, but the process is no longer our
	// child in the usual sense: it is PID 1 of its namespace and will outlive
	// this bookkeeping. Release the handle without reaping.
	go func() { _ = cmd.Wait() }()

	return nil
}

// procAttr builds the SysProcAttr for the clone, translating the spec's
// namespace list into clone(2) flags.
func procAttr(s *spec.Spec) (*syscall.SysProcAttr, error) {
	var flags uintptr
	for _, n := range s.Namespaces {
		switch n {
		case spec.NSMount:
			flags |= syscall.CLONE_NEWNS
		case spec.NSPID:
			flags |= syscall.CLONE_NEWPID
		case spec.NSNet:
			flags |= syscall.CLONE_NEWNET
		case spec.NSUts:
			flags |= syscall.CLONE_NEWUTS
		case spec.NSIPC:
			flags |= syscall.CLONE_NEWIPC
		case spec.NSCgroup:
			flags |= linuxutil.CloneNewCgroup
		case spec.NSUser:
			// Deliberately unsupported. A user namespace needs uid_map and
			// gid_map written from the *parent* after the child is created,
			// with setgroups disabled first, and Go's SysProcAttr cannot
			// express that sequence. Failing loudly is safer than half-doing it.
			return nil, fmt.Errorf(
				"clone: user namespaces are not implemented; refusing to start a container that would not be isolated as requested")
		default:
			return nil, fmt.Errorf("clone: unknown namespace %q", n)
		}
	}
	if flags&syscall.CLONE_NEWPID == 0 {
		return nil, errors.New("clone: refusing to start a container without a PID namespace")
	}
	if flags&syscall.CLONE_NEWNS == 0 {
		return nil, errors.New("clone: refusing to start a container without a mount namespace")
	}

	return &syscall.SysProcAttr{
		Unshareflags: flags,
		// If the supervisor dies, the kernel kills the container init rather
		// than leaving it running with no one to reap its children.
		Pdeathsig: syscall.SIGKILL,
		// The container must not inherit the supervisor's controlling terminal
		// or process group; it is its own session leader.
		Setsid: false,
		// Allocate a fresh pid for the process group so signals sent to the
		// container do not hit the shell that launched it.
		Setpgid: true,
		Pgid:    0,
	}, nil
}

// Wait blocks until the container's init exits and reports how it died.
//
// As a subreaper the supervisor inherits any process in the container whose
// parent died first, so it must reap those too -- otherwise they accumulate as
// zombies and the pid table fills up.
func (l *Linux) Wait() (ExitInfo, error) {
	if l.Child == 0 {
		return ExitInfo{}, errors.New("wait: no container process")
	}

	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(l.Child, &ws, 0, nil)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue // a signal arrived; keep waiting
			}
			return ExitInfo{}, fmt.Errorf("wait4(%d): %w", l.Child, err)
		}
		if pid != l.Child {
			continue
		}

		info := ExitInfo{}
		if ws.Signaled() {
			info.Signal = ws.Signal().String()
			// Report the conventional 128+signal shell encoding.
			info.ExitCode = 128 + int(ws.Signal())
		} else {
			info.ExitCode = ws.ExitStatus()
		}
		if !l.started.IsZero() {
			info.Duration = time.Since(l.started).Nanoseconds()
		}
		return info, nil
	}
}

// ---------------------------------------------------------------------------
// Child side
// ---------------------------------------------------------------------------

// SetupNetns configures networking for the container.
//
// When the container has its own network namespace this must run in the parent:
// the child, already inside that namespace, can no longer reach the host's, so
// the veth peer has to be moved across from outside.
func (l *Linux) SetupNetns(bridge string) error {
	if l.Child != 0 {
		h, err := netns.Attach(l.Child, bridge)
		if err != nil {
			return err
		}
		l.Net = h
		return nil
	}
	// Inside the container's own namespace, bring loopback up.
	return netns.EnableLoopback()
}

// TeardownNetns removes the host-side halves of the container's network.
func (l *Linux) TeardownNetns(bridge string) error {
	if l.Net != nil {
		return l.Net.Teardown()
	}
	return nil
}

func (l *Linux) Sethostname(name string) error {
	if err := linuxutil.Sethostname(name); err != nil {
		return err
	}
	return nil
}

func (l *Linux) MakePrivate(path string) error {
	return linuxutil.MakePrivateRecursively(path)
}

func (l *Linux) Mount(m spec.Mount, flags []string) error {
	opts := strings.Join(flags, ",")
	ro := m.ReadOnly || hasFlag(flags, "ro")

	switch m.Type {
	case "bind":
		return linuxutil.BindMount(m.Source, m.Destination, ro)
	case "proc":
		return linuxutil.MountProc(m.Destination)
	case "sysfs":
		return linuxutil.MountSysfs(m.Destination, ro)
	case "tmpfs":
		size, mode := parseTmpfs(flags)
		if err := linuxutil.MountTmpfs(m.Destination, size, mode); err != nil {
			return err
		}
		// tmpfs is mounted rw; honour a read-only request by remounting.
		if ro {
			return linuxutil.RemountReadOnly(m.Destination)
		}
		return nil
	case "overlay":
		// The overlay case is driven by the plan's Values (lowerdirs), which the
		// generic Mount signature does not carry, so the options arrive here as
		// a list and are joined into the mount(2) data field.
		if len(flags) == 0 {
			return errors.New("mount: overlay requires lowerdir options")
		}
		return linuxutil.MountOverlay(m.Destination, strings.Join(flags, ","), ro)
	default:
		return linuxutil.MountFilesystem(m.Type, m.Destination, opts, ro)
	}
}

func (l *Linux) BindMount(source, target string, ro bool) error {
	return linuxutil.BindMount(source, target, ro)
}

func (l *Linux) PivotRoot(newRoot, putOld string) error {
	// The kernel requires put_old to exist inside new_root and the current root
	// to be non-shared. Both are prerequisites, and checking them here turns a
	// bare EINVAL into a message that says what to fix.
	if err := linuxutil.PivotRoot(newRoot, putOld); err != nil {
		return fmt.Errorf("%w (put_old must be a directory inside the new root, and / must not be a shared mount)", err)
	}
	return nil
}

func (l *Linux) Chdir(path string) error {
	return os.Chdir(path)
}

func (l *Linux) Umount(path string, lazy bool) error {
	return linuxutil.Unmount(path, lazy)
}

func (l *Linux) RemountReadOnly(path string) error {
	return linuxutil.RemountReadOnly(path)
}

func (l *Linux) WriteCgroup(controller, file, value string) error {
	if l.CG == nil {
		m, err := cgroup.New(controller)
		if err != nil {
			return err
		}
		l.CG = m
	}
	// oom_score_adj lives in /proc/<pid>/, not in the cgroup filesystem.
	if controller == "proc" {
		return cgroup.WriteProcAttr(l.Child, file, value)
	}
	return l.CG.Write(controller, file, value)
}

func (l *Linux) SetGroups(gids []string) error {
	// syscall.Setgroups takes []int on Linux, not []uint32.
	g := make([]int, 0, len(gids))
	for _, s := range gids {
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return fmt.Errorf("setgroups: bad gid %q: %w", s, err)
		}
		g = append(g, int(v))
	}
	// An empty list clears the supplementary set, which is what "run as exactly
	// this gid with no extras" means.
	return syscall.Setgroups(g)
}

func (l *Linux) SetGID(gid uint32) error {
	return syscall.Setresgid(int(gid), int(gid), int(gid))
}

func (l *Linux) SetUID(uid uint32) error {
	return syscall.Setresuid(int(uid), int(uid), int(uid))
}

func (l *Linux) SetNoNewPrivs() error { return linuxutil.SetNoNewPrivs() }

func (l *Linux) SetNonDumpable() error { return linuxutil.SetNonDumpable() }

func (l *Linux) Setrlimit(resource string, value int64) error {
	var res int
	switch strings.ToUpper(resource) {
	case "RLIMIT_NOFILE":
		res = linuxutil.RLimitNoFile
	case "RLIMIT_NPROC":
		res = linuxutil.RLimitNProc
	case "RLIMIT_CORE":
		res = linuxutil.RLimitCore
	default:
		return fmt.Errorf("setrlimit: unknown resource %q", resource)
	}
	lim := &syscall.Rlimit{Cur: uint64(value), Max: uint64(value)}
	if err := syscall.Setrlimit(res, lim); err != nil {
		return fmt.Errorf("setrlimit(%s, %d): %w", resource, value, err)
	}
	return nil
}

func (l *Linux) SetCapabilities(caps []string) error {
	return linuxutil.SetBoundingCapabilities(caps)
}

func (l *Linux) RunHook(h spec.Hook) error {
	if h.Path == "" {
		return nil
	}
	cmd := exec.Command(h.Path, h.Args...)
	cmd.Env = h.Env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("hook %s: %w: %s", h.Path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Exec replaces the process image with the container's process.
//
// This is where the container becomes itself: after this call there is no
// runtime left in the process, just the container's own program with PID 1 in
// its namespace. On success it never returns.
func (l *Linux) Exec(argv []string, env []string) error {
	if len(argv) == 0 {
		return errors.New("exec: empty argv")
	}
	path, err := resolveInRoot(argv[0])
	if err != nil {
		return err
	}
	if env == nil {
		env = os.Environ()
	}
	if err := syscall.Exec(path, argv, env); err != nil {
		return fmt.Errorf("execve(%s): %w", path, err)
	}
	// Unreachable unless syscall.Exec itself is broken.
	return errors.New("exec: syscall.Exec returned unexpectedly")
}

// resolveInRoot finds the program to exec.
//
// After pivot_root the process root is the container's, so a lookup here
// correctly resolves against the container's filesystem rather than the host's.
// An absolute path is used as-is; otherwise the container's own PATH is
// consulted, which means the image controls what "/bin/sh" means.
func resolveInRoot(name string) (string, error) {
	if strings.ContainsRune(name, os.PathSeparator) {
		if _, err := os.Stat(name); err != nil {
			return "", fmt.Errorf("exec: %s: %w", name, err)
		}
		return name, nil
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("exec: %s not found in the container's PATH: %w", name, err)
	}
	return path, nil
}

// --- helpers ---------------------------------------------------------------

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

// parseTmpfs extracts size= and mode= from tmpfs mount options.
func parseTmpfs(flags []string) (sizeBytes int64, mode uint32) {
	sizeBytes = 64 << 10 // 64 MiB default
	mode = 0o755
	for _, f := range flags {
		switch {
		case strings.HasPrefix(f, "size="):
			if v, err := parseSize(f); err == nil {
				sizeBytes = v
			}
		case strings.HasPrefix(f, "mode="):
			var m uint64
			if _, err := fmt.Sscanf(f, "mode=%o", &m); err == nil {
				mode = uint32(m)
			}
		}
	}
	return sizeBytes, mode
}

// parseSize understands the 65536k / 1g / 1048576 suffixes used in mount
// options, which are not plain byte counts.
func parseSize(f string) (int64, error) {
	v := strings.TrimPrefix(f, "size=")
	mult := int64(1)
	switch {
	case strings.HasSuffix(v, "k"):
		mult, v = 1<<10, strings.TrimSuffix(v, "k")
	case strings.HasSuffix(v, "m"):
		mult, v = 1<<20, strings.TrimSuffix(v, "m")
	case strings.HasSuffix(v, "g"):
		mult, v = 1<<30, strings.TrimSuffix(v, "g")
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, err
	}
	return n * mult, nil
}
