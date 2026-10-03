// Package initseq executes a compiled spec.Plan.
//
// The plan produced by internal/spec is a list of values. This package walks
// that list and calls the kernel. The division is deliberate:
//
//   - internal/spec decides *what* happens and asserts the ordering.
//   - initseq decides *how* each step is carried out.
//
// Backend is an interface so the dispatcher -- error handling, fatal-vs-
// best-effort semantics, teardown ordering, which steps may follow a failure --
// is ordinary portable code that can be tested with a fake, while every actual
// syscall lives behind the interface in backend_linux.go.
package initseq

import (
	"fmt"
	"strconv"
	"strings"

	"kernelz/internal/spec"
)

// Logger receives progress and non-fatal warnings. Optional.
type Logger func(format string, args ...any)

// Backend is the complete set of operations a plan can require.
//
// Every method is one kernel primitive. Implementations must be safe to call in
// the order the plan specifies and must not reorder work themselves.
type Backend interface {
	// Clone creates the container's initial process with its namespaces and
	// begins executing the plan inside it. It returns once the container process
	// has been created; the plan continues in the child.
	Clone(s *spec.Spec) error

	// --- Setup, executed inside the new namespaces.

	Sethostname(name string) error
	MakePrivate(path string) error
	Mount(m spec.Mount, flags []string) error
	BindMount(source, target string, readonly bool) error
	PivotRoot(newRoot, putOld string) error
	Chdir(path string) error
	Umount(path string, lazy bool) error
	RemountReadOnly(path string) error
	WriteCgroup(controller, file, value string) error
	SetupNetns(bridge string) error
	SetGroups(gids []string) error
	SetGID(gid uint32) error
	SetUID(uid uint32) error
	SetNoNewPrivs() error
	SetNonDumpable() error
	Setrlimit(resource string, value int64) error
	SetCapabilities(caps []string) error
	RunHook(h spec.Hook) error

	// Exec replaces the current process image. A successful Exec does not
	// return; it only returns an error if the exec itself failed.
	Exec(argv []string, env []string) error

	// --- Teardown, executed by the supervising parent.

	TeardownNetns(bridge string) error
	Wait() (ExitInfo, error)
}

// ExitInfo describes how a container terminated.
type ExitInfo struct {
	ExitCode int
	// Signal is set when the process was killed rather than exiting normally.
	Signal string
	// Duration is the wall-clock lifetime of the container, filled in by the
	// supervisor when it can be measured.
	Duration int64 // nanoseconds
}

// Result is what Run reports back.
type Result struct {
	Exit ExitInfo
	// StepsRun counts ops that completed, for diagnostics.
	StepsRun int
}

// FatalError marks a step that failed in a way the container cannot survive.
type FatalError struct {
	Op    spec.OpKind
	Index int
	Err   error
}

func (e *FatalError) Error() string {
	return fmt.Sprintf("step %d (%s): %v", e.Index, e.Op, e.Err)
}

func (e *FatalError) Unwrap() error { return e.Err }

// Run executes a plan against a backend.
//
// Ops marked FailFatal abort the run on error. Everything else is
// best-effort: a read-only remount that a kernel lacks MS_NOSYMFOLLOW for, or a
// /dev/mqueue mount on a kernel where it is unnecessary, must not take down a
// container that is otherwise correctly confined.
//
// On a fatal failure the teardown ops at the end of the plan are still
// attempted, because a setup that failed halfway has usually already leaked
// mounts and veth pairs onto the host.
func Run(b Backend, s *spec.Spec, p *spec.Plan, log Logger) (*Result, error) {
	if log == nil {
		log = func(string, ...any) {}
	}
	res := &Result{}
	execReached := false

	for i, op := range p.Ops {
		err := step(b, s, op)
		if op.Kind == spec.OpExec {
			// Marked before the error check: reaching exec at all means a
			// container process may exist and has to be reaped, even if the
			// execve itself then failed.
			execReached = true
		}
		if err == nil {
			res.StepsRun++
			continue
		}

		if !op.FailFatal {
			log("warning: %s failed (continuing): %v", op.Kind, err)
			continue
		}

		teardown(b, s, p, log, execReached)
		return res, &FatalError{Op: op.Kind, Index: i, Err: err}
	}

	return res, nil
}

// isTeardown reports whether an op belongs to the post-exec phase, which is
// still attempted after a fatal setup failure so the host is not left holding
// mounts or network interfaces that were already established.
func isTeardown(k spec.OpKind) bool {
	switch k {
	case spec.OpWaitReap, spec.OpNetnsTeardown:
		return true
	}
	return false
}

// teardown runs the teardown phase on a best-effort basis.
//
// The reap is skipped when exec was never reached: there is no container
// process to wait for, and blocking on wait4(2) for a pid that was never
// created would hang the runtime forever.
func teardown(b Backend, s *spec.Spec, p *spec.Plan, log Logger, execReached bool) {
	for _, op := range p.Ops {
		if !isTeardown(op.Kind) {
			continue
		}
		if op.Kind == spec.OpWaitReap && !execReached {
			continue
		}
		if err := step(b, s, op); err != nil {
			log("warning: teardown %s failed: %v", op.Kind, err)
		}
	}
}

// step dispatches one op to the backend.
func step(b Backend, s *spec.Spec, op spec.Op) error {
	switch op.Kind {
	case spec.OpClone:
		if s == nil {
			return fmt.Errorf("clone op requires a spec")
		}
		return b.Clone(s)

	case spec.OpSethostname:
		return b.Sethostname(op.Value)

	case spec.OpMakePrivate:
		return b.MakePrivate(op.Value)

	case spec.OpMount:
		if op.Mount == nil {
			return fmt.Errorf("mount op has no mount")
		}
		return b.Mount(*op.Mount, op.Values)

	case spec.OpBind:
		if op.Mount == nil {
			return fmt.Errorf("bind op has no mount")
		}
		return b.BindMount(op.Mount.Source, op.Mount.Destination, op.Mount.ReadOnly)

	case spec.OpPivotRoot:
		// Value carries new_root; Values[0] carries put_old.
		if len(op.Values) < 1 || op.Values[0] == "" {
			return fmt.Errorf("pivot_root op missing put_old")
		}
		return b.PivotRoot(op.Value, op.Values[0])

	case spec.OpChdir:
		return b.Chdir(op.Value)

	case spec.OpUmount:
		return b.Umount(op.Value, true)

	case spec.OpRemountRO:
		return b.RemountReadOnly(op.Value)

	case spec.OpWriteCgroup:
		if len(op.Values) < 2 {
			return fmt.Errorf("cgroup op missing file/value")
		}
		return b.WriteCgroup(op.Value, op.Values[0], op.Values[1])

	case spec.OpNetnsSetup:
		return b.SetupNetns(op.Value)

	case spec.OpNetnsTeardown:
		return b.TeardownNetns(op.Value)

	case spec.OpSetGroups:
		return b.SetGroups(op.Values)

	case spec.OpSetGID:
		gid, err := strconv.ParseUint(op.Value, 10, 32)
		if err != nil {
			return fmt.Errorf("bad gid %q: %w", op.Value, err)
		}
		return b.SetGID(uint32(gid))

	case spec.OpSetUID:
		uid, err := strconv.ParseUint(op.Value, 10, 32)
		if err != nil {
			return fmt.Errorf("bad uid %q: %w", op.Value, err)
		}
		return b.SetUID(uint32(uid))

	case spec.OpNoNewPrivs:
		return b.SetNoNewPrivs()

	case spec.OpNonDumpable:
		return b.SetNonDumpable()

	case spec.OpSetrlimit:
		return b.Setrlimit(op.Value, op.Num)

	case spec.OpCapSet:
		return b.SetCapabilities(op.Values)

	case spec.OpHook:
		return b.RunHook(spec.Hook{Path: op.Value, Args: op.Values})

	case spec.OpExec:
		return b.Exec(append([]string{op.Value}, op.Values...), op.Env)

	case spec.OpWaitReap:
		_, err := b.Wait()
		return err

	default:
		return fmt.Errorf("unknown op kind %q", op.Kind)
	}
}

// SetupOps returns the operations the *child* process runs: everything between
// the clone and the exec, exclusive of both.
//
// The split is a consequence of how namespaces work. A process cannot migrate
// into a new PID namespace, so the supervisor (parent) and the container init
// (child) are genuinely different processes with different jobs:
//
//	parent: clone, wait4, net teardown
//	child:  mounts, pivot_root, privilege drop, execve
//
// Running both halves in one process would be wrong, so a plan is explicitly
// partitioned rather than implicitly assumed.
func SetupOps(p *spec.Plan) []spec.Op {
	var out []spec.Op
	for _, op := range p.Ops {
		switch op.Kind {
		case spec.OpClone, spec.OpWaitReap, spec.OpNetnsTeardown:
			continue
		}
		out = append(out, op)
	}
	return out
}

// TeardownOps returns the operations the *supervisor* runs after the container
// process has exited.
func TeardownOps(p *spec.Plan) []spec.Op {
	var out []spec.Op
	for _, op := range p.Ops {
		switch op.Kind {
		case spec.OpWaitReap, spec.OpNetnsTeardown:
			out = append(out, op)
		}
	}
	return out
}

// SubPlan returns a plan containing only the requested ops, preserving the
// original indices so FatalError still points at the right step.
func SubPlan(p *spec.Plan, ops []spec.Op) *spec.Plan {
	return &spec.Plan{ID: p.ID, CloneFlags: p.CloneFlags, Ops: ops}
}

// SplitExecArgs separates the argv portion of an exec op from its environment.
// The plan keeps them in distinct fields, so this is a defensive copy that stops
// a backend from aliasing and mutating the plan.
func SplitExecArgs(op spec.Op) (argv, env []string) {
	argv = append([]string{op.Value}, op.Values...)
	env = append([]string{}, op.Env...)
	return argv, env
}

// Describe renders a one-line summary of an op, for logs.
func Describe(op spec.Op) string {
	if op.Detail != "" {
		return string(op.Kind) + ": " + op.Detail
	}
	var b strings.Builder
	b.WriteString(string(op.Kind))
	if op.Value != "" {
		fmt.Fprintf(&b, " %s", op.Value)
	}
	return b.String()
}
