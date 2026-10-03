package initseq

import (
	"fmt"
	"io"
	"strings"

	"kernelz/internal/spec"
)

// DryRun is a Backend that records what it was asked to do instead of doing it.
//
// It exists for two reasons. It backs `kz run --dry-run`, which makes an
// otherwise invisible sequence of privileged syscalls reviewable before anyone
// commits to them. And because it satisfies Backend on every platform, the
// dispatcher can be exercised end to end on a machine with no Linux kernel.
type DryRun struct {
	// Steps is the ordered log of calls, rendered as human-readable strings.
	Steps []string
	// Kinds is the op kind behind each entry in Steps, index-aligned.
	Kinds []spec.OpKind
	// Fail simulates a failure for the given op kinds. Used by tests, and by
	// `kz run --fail-at` to see how far a real run gets before it breaks.
	Fail map[spec.OpKind]error

	w io.Writer
}

// NewDryRun creates a DryRun that also streams each step to w. w may be nil.
func NewDryRun(w io.Writer) *DryRun { return &DryRun{w: w} }

func (d *DryRun) record(k spec.OpKind, format string, args ...any) error {
	line := fmt.Sprintf(format, args...)
	d.Steps = append(d.Steps, line)
	d.Kinds = append(d.Kinds, k)
	if d.w != nil {
		fmt.Fprintln(d.w, "  "+line)
	}
	if d.Fail != nil {
		return d.Fail[k]
	}
	return nil
}

// KindsSeen returns the distinct op kinds recorded, in first-occurrence order.
func (d *DryRun) KindsSeen() []spec.OpKind {
	var out []spec.OpKind
	seen := map[spec.OpKind]bool{}
	for _, k := range d.Kinds {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

func (d *DryRun) Clone(s *spec.Spec) error {
	var ns []string
	var argv []string
	if s != nil {
		for _, n := range s.Namespaces {
			ns = append(ns, strings.ToUpper(string(n)))
		}
		argv = s.Process.Args
	}
	return d.record(spec.OpClone, "clone(CLONE_NEW%s) argv=%v", strings.Join(ns, "|"), argv)
}

func (d *DryRun) Sethostname(name string) error {
	return d.record(spec.OpSethostname, "sethostname(%q)", name)
}

func (d *DryRun) MakePrivate(path string) error {
	return d.record(spec.OpMakePrivate, "mount(%q, %q, MS_REC|MS_PRIVATE)", "", path)
}

func (d *DryRun) Mount(m spec.Mount, flags []string) error {
	return d.record(spec.OpMount, "mount(%s -> %s, %s)", or(m.Type, "auto"), m.Destination, joinFlags(flags))
}

func (d *DryRun) BindMount(source, target string, ro bool) error {
	f := "MS_BIND|MS_REC"
	if ro {
		f += "|MS_RDONLY"
	}
	return d.record(spec.OpBind, "mount(%s -> %s, %s)", source, target, f)
}

func (d *DryRun) PivotRoot(newRoot, putOld string) error {
	return d.record(spec.OpPivotRoot, "pivot_root(%q, %q)", newRoot, putOld)
}

func (d *DryRun) Chdir(path string) error {
	return d.record(spec.OpChdir, "chdir(%q)", path)
}

func (d *DryRun) Umount(path string, lazy bool) error {
	f := "0"
	if lazy {
		f = "MNT_DETACH"
	}
	return d.record(spec.OpUmount, "umount2(%q, %s)", path, f)
}

func (d *DryRun) RemountReadOnly(path string) error {
	return d.record(spec.OpRemountRO, "remount(%q, MS_BIND|MS_REMOUNT|MS_RDONLY)", path)
}

func (d *DryRun) WriteCgroup(controller, file, value string) error {
	return d.record(spec.OpWriteCgroup, "cgroup %s: write %q <- %q", controller, file, value)
}

func (d *DryRun) SetupNetns(bridge string) error {
	if bridge == "" {
		return d.record(spec.OpNetnsSetup, "netns: bring up lo")
	}
	return d.record(spec.OpNetnsSetup, "netns: veth pair attached to bridge %q, address assigned", bridge)
}

func (d *DryRun) TeardownNetns(bridge string) error {
	return d.record(spec.OpNetnsTeardown, "netns: remove veth%s", bridgeSuffix(bridge))
}

func (d *DryRun) SetGroups(gids []string) error {
	return d.record(spec.OpSetGroups, "setgroups([%s])", strings.Join(gids, ","))
}

func (d *DryRun) SetGID(gid uint32) error {
	return d.record(spec.OpSetGID, "setresgid(%d)", gid)
}

func (d *DryRun) SetUID(uid uint32) error {
	return d.record(spec.OpSetUID, "setresuid(%d)", uid)
}

func (d *DryRun) SetNoNewPrivs() error {
	return d.record(spec.OpNoNewPrivs, "prctl(PR_SET_NO_NEW_PRIVS, 1)")
}

func (d *DryRun) SetNonDumpable() error {
	return d.record(spec.OpNonDumpable, "prctl(PR_SET_DUMPABLE, 0)")
}

func (d *DryRun) Setrlimit(resource string, value int64) error {
	return d.record(spec.OpSetrlimit, "setrlimit(%s, %d)", resource, value)
}

func (d *DryRun) SetCapabilities(caps []string) error {
	return d.record(spec.OpCapSet, "capset([%s])", strings.Join(caps, ","))
}

func (d *DryRun) RunHook(h spec.Hook) error {
	return d.record(spec.OpHook, "hook %s %v", h.Path, h.Args)
}

func (d *DryRun) Exec(argv, env []string) error {
	return d.record(spec.OpExec, "execve(%s) with %d env vars", strings.Join(argv, " "), len(env))
}

func (d *DryRun) Wait() (ExitInfo, error) {
	if err := d.record(spec.OpWaitReap, "wait4(init_pid): exited 0"); err != nil {
		return ExitInfo{}, err
	}
	return ExitInfo{ExitCode: 0}, nil
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func joinFlags(f []string) string {
	if len(f) == 0 {
		return "(defaults)"
	}
	return strings.Join(f, ",")
}

func bridgeSuffix(bridge string) string {
	if bridge == "" {
		return ""
	}
	return " on bridge " + bridge
}
