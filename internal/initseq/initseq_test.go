package initseq

import (
	"errors"
	"strings"
	"testing"

	"kernelz/internal/spec"
)

func testSpec() *spec.Spec {
	return &spec.Spec{
		ID:         "web",
		Hostname:   "web",
		Namespaces: []spec.NSType{spec.NSMount, spec.NSPID, spec.NSUts, spec.NSNet},
		Rootfs:     spec.Rootfs{Path: "/var/lib/kernelz/rootfs/web"},
		Process: spec.Process{
			Args: []string{"/bin/sh", "-c", "echo hi"},
			Env:  []string{"PATH=/bin", "HOME=/root"},
			Cwd:  "/",
			User: spec.User{UID: 1000, GID: 1000, AdditionalGIDs: []uint32{1001}},
		},
		Resources: spec.Resources{MemoryLimitBytes: 128 << 20, PidsLimit: 64},
		Bridge:    "kz0",
	}
}

func mustPlan(t *testing.T, s *spec.Spec) *spec.Plan {
	t.Helper()
	p, err := s.BuildPlan()
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	return p
}

func TestRunExecutesEveryOpInOrder(t *testing.T) {
	s := testSpec()
	p := mustPlan(t, s)
	d := NewDryRun(nil)

	res, err := Run(d, s, p, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.StepsRun != len(p.Ops) {
		t.Errorf("StepsRun = %d, want %d (one per op)", res.StepsRun, len(p.Ops))
	}
	if len(d.Steps) != len(p.Ops) {
		t.Errorf("recorded %d steps for %d ops", len(d.Steps), len(p.Ops))
	}
}

func TestRunReachesCloneFirstAndExecLast(t *testing.T) {
	s := testSpec()
	p := mustPlan(t, s)
	d := NewDryRun(nil)
	if _, err := Run(d, s, p, nil); err != nil {
		t.Fatal(err)
	}

	if d.Kinds[0] != spec.OpClone {
		t.Errorf("first step = %s, want clone", d.Kinds[0])
	}
	if d.Kinds[len(d.Kinds)-1] != spec.OpNetnsTeardown {
		t.Errorf("last step = %s, want netns_teardown", d.Kinds[len(d.Kinds)-1])
	}
	if !containsKind(d.Kinds, spec.OpExec) {
		t.Error("exec was never reached")
	}
	// exec must come after the pivot_root that actually confines the process.
	if indexOf(d.Kinds, spec.OpExec) < indexOf(d.Kinds, spec.OpPivotRoot) {
		t.Error("exec ran before pivot_root")
	}
	if indexOf(d.Kinds, spec.OpExec) < indexOf(d.Kinds, spec.OpMakePrivate) {
		t.Error("exec ran before mount propagation was isolated")
	}
}

func TestExecReceivesArgvAndEnvSeparately(t *testing.T) {
	// The argv/env split must survive, because both are flat NUL-terminated
	// lists and conflating them silently corrupts either.
	s := testSpec()
	s.Process.Args = []string{"/bin/sh", "-c", "echo"}
	s.Process.Env = []string{"PATH=/bin", "OPT=-c", "EMPTY="}
	p := mustPlan(t, s)

	c := &captureBackend{}
	if _, err := Run(c, s, p, nil); err != nil {
		t.Fatal(err)
	}

	wantArgv := []string{"/bin/sh", "-c", "echo"}
	if len(c.argv) != len(wantArgv) {
		t.Fatalf("argv = %v, want %v", c.argv, wantArgv)
	}
	for i := range wantArgv {
		if c.argv[i] != wantArgv[i] {
			t.Errorf("argv[%d] = %q, want %q", i, c.argv[i], wantArgv[i])
		}
	}
	wantEnv := []string{"PATH=/bin", "OPT=-c", "EMPTY="}
	if len(c.env) != len(wantEnv) {
		t.Fatalf("env = %v, want %v", c.env, wantEnv)
	}
	for i := range wantEnv {
		if c.env[i] != wantEnv[i] {
			t.Errorf("env[%d] = %q, want %q", i, c.env[i], wantEnv[i])
		}
	}
}

func TestFatalOpAbortsRun(t *testing.T) {
	s := testSpec()
	p := mustPlan(t, s)

	boom := errors.New("no such device")
	d := NewDryRun(nil)
	d.Fail = map[spec.OpKind]error{spec.OpPivotRoot: boom}

	_, err := Run(d, s, p, nil)
	if err == nil {
		t.Fatal("fatal op failure did not abort the run")
	}
	fe, ok := err.(*FatalError)
	if !ok {
		t.Fatalf("error type = %T, want *FatalError", err)
	}
	if fe.Op != spec.OpPivotRoot {
		t.Errorf("FatalError.Op = %s, want pivot_root", fe.Op)
	}
	if !errors.Is(err, boom) {
		t.Error("FatalError does not unwrap to the underlying cause")
	}
	// Nothing may run after a fatal failure.
	for _, k := range d.Kinds {
		if k == spec.OpExec {
			t.Fatal("exec ran despite pivot_root failing")
		}
	}
}

func TestNonFatalOpIsSkippedAndRunContinues(t *testing.T) {
	// A best-effort step must never take down an otherwise confined container.
	s := testSpec()
	p := mustPlan(t, s)

	d := NewDryRun(nil)
	d.Fail = map[spec.OpKind]error{spec.OpNonDumpable: errors.New("denied")}

	var warnings int
	res, err := Run(d, s, p, func(format string, args ...any) {
		if strings.HasPrefix(format, "warning") {
			warnings++
		}
	})
	if err != nil {
		t.Fatalf("a non-fatal failure aborted the run: %v", err)
	}
	if warnings != 1 {
		t.Errorf("warnings = %d, want 1", warnings)
	}
	if !containsKind(d.Kinds, spec.OpExec) {
		t.Error("run did not continue to exec after a non-fatal failure")
	}
	if res.StepsRun != len(p.Ops)-1 {
		t.Errorf("StepsRun = %d, want %d", res.StepsRun, len(p.Ops)-1)
	}
}

func TestTeardownRunsAfterFatalSetupFailure(t *testing.T) {
	// A setup that dies halfway has already leaked mounts and veth pairs. The
	// host must not be left holding them.
	s := testSpec()
	p := mustPlan(t, s)

	d := NewDryRun(nil)
	d.Fail = map[spec.OpKind]error{spec.OpChdir: errors.New("nope")}

	if _, err := Run(d, s, p, nil); err == nil {
		t.Fatal("expected failure")
	}
	if !containsKind(d.Kinds, spec.OpNetnsTeardown) {
		t.Error("netns teardown did not run after a fatal setup failure")
	}
	if containsKind(d.Kinds, spec.OpWaitReap) {
		t.Error("wait reap should not run when exec was never reached")
	}
}

func TestWaitReapCollectsExitStatus(t *testing.T) {
	s := testSpec()
	p := mustPlan(t, s)
	c := &captureBackend{waitInfo: ExitInfo{ExitCode: 137, Signal: "SIGKILL"}}

	// Wait is invoked by the dispatcher; assert the value reaches the caller.
	if _, err := Run(c, s, p, nil); err != nil {
		t.Fatal(err)
	}
	if !c.waited {
		t.Error("Wait was never called")
	}
	if c.waitInfo.ExitCode != 137 || c.waitInfo.Signal != "SIGKILL" {
		t.Errorf("exit info not propagated: %+v", c.waitInfo)
	}
}

func TestPrivilegeDropOrderAtExecution(t *testing.T) {
	s := testSpec()
	p := mustPlan(t, s)
	d := NewDryRun(nil)
	if _, err := Run(d, s, p, nil); err != nil {
		t.Fatal(err)
	}

	groups := indexOf(d.Kinds, spec.OpSetGroups)
	gid := indexOf(d.Kinds, spec.OpSetGID)
	uid := indexOf(d.Kinds, spec.OpSetUID)
	if groups < 0 || gid < 0 || uid < 0 {
		t.Fatalf("missing privilege ops: groups=%d gid=%d uid=%d", groups, gid, uid)
	}
	if !(groups < gid && gid < uid) {
		t.Errorf("privilege order wrong: setgroups=%d setresgid=%d setresuid=%d", groups, gid, uid)
	}
	if nnp := indexOf(d.Kinds, spec.OpNoNewPrivs); nnp > uid {
		t.Error("PR_SET_NO_NEW_PRIVS was set after dropping the uid")
	}
}

func TestCgroupWritesReachBackend(t *testing.T) {
	s := testSpec()
	s.Resources.MemoryLimitBytes = 64 << 20
	s.Resources.CPUQuota = 1.5
	p := mustPlan(t, s)

	c := &captureBackend{}
	if _, err := Run(c, s, p, nil); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"memory/memory.max": "67108864",
		"cpu/cpu.max":       "150000/100000",
		"pids/pids.max":     "64",
	}
	got := map[string]string{}
	for _, w := range c.cgroups {
		got[w.controller+"/"+w.file] = w.value
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("cgroup write %s = %q, want %q", k, got[k], v)
		}
	}
}

func TestReadOnlyRootfsRemountsAfterPivot(t *testing.T) {
	s := testSpec()
	s.Rootfs.ReadOnly = true
	p := mustPlan(t, s)
	d := NewDryRun(nil)
	if _, err := Run(d, s, p, nil); err != nil {
		t.Fatal(err)
	}
	ro := indexOf(d.Kinds, spec.OpRemountRO)
	if ro < 0 {
		t.Fatal("no read-only remount for a read-only rootfs")
	}
	if ro < indexOf(d.Kinds, spec.OpPivotRoot) {
		t.Error("read-only remount happened before pivot_root")
	}
	if ro > indexOf(d.Kinds, spec.OpExec) {
		t.Error("read-only remount happened after exec")
	}
}

func TestMalformedOpsAreRejected(t *testing.T) {
	// A plan that reaches the kernel with a malformed op must fail loudly rather
	// than passing empty arguments into a syscall.
	tests := []struct {
		name string
		op   spec.Op
		want string
	}{
		{"mount without mount", spec.Op{Kind: spec.OpMount}, "no mount"},
		{"bind without mount", spec.Op{Kind: spec.OpBind}, "no mount"},
		{"pivot without putold", spec.Op{Kind: spec.OpPivotRoot, Value: "/new"}, "put_old"},
		{"cgroup without value", spec.Op{Kind: spec.OpWriteCgroup, Value: "memory", Values: []string{"memory.max"}}, "file/value"},
		{"bad uid", spec.Op{Kind: spec.OpSetUID, Value: "root"}, "bad uid"},
		{"unknown kind", spec.Op{Kind: "teleport"}, "unknown op kind"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &spec.Plan{ID: "x", Ops: []spec.Op{{Kind: tt.op.Kind, FailFatal: true}, tt.op}}
			_, err := Run(NewDryRun(nil), testSpec(), p, nil)
			if err == nil {
				t.Fatalf("malformed op %s was accepted", tt.name)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestCloneWithoutSpecFails(t *testing.T) {
	p := &spec.Plan{ID: "x", Ops: []spec.Op{{Kind: spec.OpClone, FailFatal: true}}}
	_, err := Run(NewDryRun(nil), nil, p, nil)
	if err == nil {
		t.Fatal("clone without a spec was accepted")
	}
}

func TestDryRunFailInjectionByKind(t *testing.T) {
	s := testSpec()
	p := mustPlan(t, s)
	d := NewDryRun(nil)
	d.Fail = map[spec.OpKind]error{spec.OpMount: errors.New("device busy")}

	_, err := Run(d, s, p, nil)
	if err == nil {
		t.Fatal("injected mount failure did not surface")
	}
	fe, ok := err.(*FatalError)
	if !ok || fe.Op != spec.OpMount {
		t.Fatalf("got %v", err)
	}
}

func TestDescribeIsNonEmpty(t *testing.T) {
	s := testSpec()
	p := mustPlan(t, s)
	for _, op := range p.Ops {
		if Describe(op) == "" {
			t.Errorf("op %s rendered empty", op.Kind)
		}
	}
}

// --- fake backend -----------------------------------------------------------

type cgroupWrite struct{ controller, file, value string }

// captureBackend records every call and can be told to fail any of them.
type captureBackend struct {
	DryRun

	cgroups  []cgroupWrite
	argv     []string
	env      []string
	waited   bool
	waitInfo ExitInfo
}

func (c *captureBackend) WriteCgroup(controller, file, value string) error {
	if err := c.DryRun.WriteCgroup(controller, file, value); err != nil {
		return err
	}
	c.cgroups = append(c.cgroups, cgroupWrite{controller, file, value})
	return nil
}

func (c *captureBackend) Exec(argv, env []string) error {
	if err := c.DryRun.Exec(argv, env); err != nil {
		return err
	}
	c.argv, c.env = argv, env
	return nil
}

func (c *captureBackend) Wait() (ExitInfo, error) {
	c.waited = true
	if _, err := c.DryRun.Wait(); err != nil {
		return ExitInfo{}, err
	}
	return c.waitInfo, nil
}

func containsKind(ks []spec.OpKind, want spec.OpKind) bool {
	for _, k := range ks {
		if k == want {
			return true
		}
	}
	return false
}

func indexOf(ks []spec.OpKind, want spec.OpKind) int {
	for i, k := range ks {
		if k == want {
			return i
		}
	}
	return -1
}
