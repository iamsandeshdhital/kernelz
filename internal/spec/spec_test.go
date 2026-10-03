package spec

import (
	"strings"
	"testing"
)

// base returns a valid spec that individual tests mutate, so that each test
// fails for exactly one reason rather than for a stack of preconditions.
func base() *Spec {
	return &Spec{
		ID:       "web",
		Hostname: "web",
		Namespaces: []NSType{
			NSPID, NSMount, NSNet, NSUts, NSIPC, NSCgroup,
		},
		Rootfs: Rootfs{Path: "/var/lib/kernelz/rootfs/web"},
		Process: Process{
			Args: []string{"/bin/sh"},
			Cwd:  "/",
			Env:  []string{"PATH=/usr/bin:/bin", "TERM=xterm"},
			User: User{UID: 0, GID: 0},
		},
		Resources: Resources{
			MemoryLimitBytes: 128 << 20,
			CPUQuota:         1.0,
			PidsLimit:        512,
		},
	}
}

func TestValidateAcceptsBaseline(t *testing.T) {
	if err := base().Validate(); err != nil {
		t.Fatalf("baseline spec should validate, got: %v", err)
	}
}

func TestValidateRejections(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Spec)
		wantField string
	}{
		{"empty id", func(s *Spec) { s.ID = "" }, "id"},
		{"id with slash", func(s *Spec) { s.ID = "a/b" }, "id"},
		{"id with space", func(s *Spec) { s.ID = "a b" }, "id"},
		{"no namespaces", func(s *Spec) { s.Namespaces = nil }, "namespaces"},
		{"unknown namespace", func(s *Spec) { s.Namespaces = []NSType{"banana"} }, "namespaces"},
		{
			// The single most important invariant in the whole runtime.
			"mount namespace omitted",
			func(s *Spec) {
				var kept []NSType
				for _, n := range s.Namespaces {
					if n != NSMount {
						kept = append(kept, n)
					}
				}
				s.Namespaces = kept
			},
			"namespaces",
		},
		{"empty rootfs path", func(s *Spec) { s.Rootfs.Path = "" }, "rootfs.path"},
		{"rootfs is host root", func(s *Spec) { s.Rootfs.Path = "/" }, "rootfs.path"},
		{"no args", func(s *Spec) { s.Process.Args = nil }, "process.args"},
		{"empty args", func(s *Spec) { s.Process.Args = []string{} }, "process.args"},
		{"relative cwd", func(s *Spec) { s.Process.Cwd = "work" }, "process.cwd"},
		{"hostname too long", func(s *Spec) { s.Hostname = strings.Repeat("a", 65) }, "hostname"},
		{"hostname with slash", func(s *Spec) { s.Hostname = "a/b" }, "hostname"},
		{"relative mount dest", func(s *Spec) {
			s.Mounts = []Mount{{Destination: "rel", Type: "tmpfs"}}
		}, "mounts[0].destination"},
		{"negative memory", func(s *Spec) { s.Resources.MemoryLimitBytes = -1 }, "resources.memory_limit_bytes"},
		{"swap below memory", func(s *Spec) {
			s.Resources.MemoryLimitBytes = 1000
			s.Resources.MemorySwapBytes = 500
		}, "resources.memory_swap_bytes"},
		{"oom adj out of range", func(s *Spec) { s.Resources.OOMScoreAdj = 5000 }, "resources.oom_score_adj"},
		{"bad pids limit", func(s *Spec) { s.Resources.PidsLimit = -2 }, "resources.pids_limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := base()
			tt.mutate(s)
			err := s.Validate()
			if err == nil {
				t.Fatalf("expected validation error for %s, got nil", tt.name)
			}
			pe, ok := err.(*PlanError)
			if !ok {
				t.Fatalf("expected *PlanError, got %T: %v", err, err)
			}
			if pe.Field != tt.wantField {
				t.Errorf("field = %q, want %q (reason: %s)", pe.Field, tt.wantField, pe.Reason)
			}
		})
	}
}

func TestBuildPlanRejectsInvalidSpec(t *testing.T) {
	s := base()
	s.Process.Args = nil
	if _, err := s.BuildPlan(); err == nil {
		t.Fatal("BuildPlan must not produce a plan for an invalid spec")
	}
}

// TestPlanOrdering pins the sequence that BuildPlan emits. Each assertion below
// encodes a kernel constraint, so this test is really a statement about the
// kernel, not about the code.
func TestPlanOrdering(t *testing.T) {
	p, err := base().BuildPlan()
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	idx := map[OpKind]int{}
	for i, o := range p.Ops {
		// First occurrence wins; several kinds legitimately repeat.
		if _, seen := idx[o.Kind]; !seen {
			idx[o.Kind] = i
		}
	}

	need := []OpKind{
		OpClone, OpSethostname, OpMakePrivate, OpMount, OpPivotRoot,
		OpChdir, OpWriteCgroup, OpNoNewPrivs, OpExec, OpWaitReap, OpNetnsTeardown,
	}
	for _, k := range need {
		if _, ok := idx[k]; !ok {
			t.Errorf("plan is missing a %s op", k)
		}
	}

	// A process is born into a PID namespace; it never migrates into one.
	if idx[OpClone] != 0 {
		t.Errorf("clone must be the first op, got index %d", idx[OpClone])
	}
	// Namespaces exist before we can mount into them.
	if idx[OpClone] > idx[OpMakePrivate] {
		t.Error("clone must precede the mount-namespace isolation")
	}
	// MS_PRIVATE must be established before any mount, or mounts leak to host.
	if idx[OpMakePrivate] > idx[OpMount] {
		t.Error("make_private must precede the first mount")
	}
	// The jail is only entered after the mount table is built.
	if idx[OpMount] > idx[OpPivotRoot] {
		t.Error("mounts must precede pivot_root")
	}
	// pivot_root leaves the cwd in the old root; chdir must follow immediately.
	if idx[OpChdir] != idx[OpPivotRoot]+1 {
		t.Errorf("chdir must immediately follow pivot_root, got %d then %d",
			idx[OpPivotRoot], idx[OpChdir])
	}
	// cgroups need privilege, so they are written before the uid drop.
	// Only meaningful when the spec actually drops privileges.
	if _, dropsPriv := idx[OpSetUID]; dropsPriv {
		if idx[OpWriteCgroup] > idx[OpSetUID] {
			t.Error("cgroup writes must precede setresuid")
		}
		if idx[OpNoNewPrivs] > idx[OpSetUID] {
			t.Error("PR_SET_NO_NEW_PRIVS must precede setresuid")
		}
	}
	// execve is the last setup step; teardown only happens after it returns.
	if idx[OpExec] > idx[OpWaitReap] {
		t.Error("exec must precede the reaping wait")
	}
}

func TestPlanIncludesDefaultMounts(t *testing.T) {
	p, err := base().BuildPlan()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"/proc": false, "/dev": false, "/dev/pts": false, "/sys": false}
	for _, o := range p.Ops {
		if o.Kind == OpMount && o.Mount != nil {
			if _, ok := want[o.Mount.Destination]; ok {
				want[o.Mount.Destination] = true
			}
		}
	}
	for d, found := range want {
		if !found {
			t.Errorf("plan does not mount %s", d)
		}
	}
}

func TestUserMountOverridesDefault(t *testing.T) {
	s := base()
	s.Mounts = []Mount{{Destination: "/dev/shm", Type: "tmpfs", Options: []string{"size=1g"}}}
	p, err := s.BuildPlan()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, o := range p.Ops {
		if o.Kind == OpMount && o.Mount != nil && o.Mount.Destination == "/dev/shm" {
			n++
			if !contains(o.Values, "size=1g") {
				t.Errorf("override options lost, got %v", o.Values)
			}
		}
	}
	if n != 1 {
		t.Errorf("expected exactly one /dev/shm mount after override, got %d", n)
	}
}

func TestPrivilegeDropOrder(t *testing.T) {
	s := base()
	s.Process.User = User{UID: 1000, GID: 1000, AdditionalGIDs: []uint32{1001, 1002}}
	p, err := s.BuildPlan()
	if err != nil {
		t.Fatal(err)
	}

	var gidIdx, uidIdx = -1, -1
	for i, o := range p.Ops {
		switch o.Kind {
		case OpSetUID:
			if o.Num == 1000 && uidIdx < 0 {
				uidIdx = i
			}
			if o.Num == 1000 && o.Value == "1000" {
				gidIdx = i // the first (gid) call
			}
		case OpSetGroups:
			if gidIdx < 0 {
				gidIdx = -2 // marker
			}
		}
	}

	// setgroups must come first, then setresgid, then setresuid.
	sg := -1
	for i, o := range p.Ops {
		if o.Kind == OpSetGroups {
			sg = i
		}
	}
	if sg < 0 {
		t.Fatal("setgroups op missing for a non-root uid")
	}
	if sg > uidIdx {
		t.Error("setgroups must precede setresuid (otherwise the gid drop is irreversible)")
	}
	if len(p.Ops[sg].Values) != 2 || p.Ops[sg].Values[0] != "1001" {
		t.Errorf("additional gids not carried into the plan: %v", p.Ops[sg].Values)
	}
}

func TestCgroupOpsForMemoryAndCPU(t *testing.T) {
	r := Resources{MemoryLimitBytes: 256 << 20, CPUQuota: 2.0, PidsLimit: 100}
	ops := r.cgroupOps("id")

	want := map[string]string{
		"memory/memory.max":      "268435456",
		"memory/memory.swap.max": "0",
		// 2.0 CPUs * 100000us period = quota 200000
		"cpu/cpu.max":   "200000/100000",
		"pids/pids.max": "100",
	}
	got := map[string]string{}
	for _, o := range ops {
		if len(o.Values) == 2 {
			got[o.Value+"/"+o.Values[0]] = o.Values[1]
		}
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestCgroupSwapNotDuplicated(t *testing.T) {
	r := Resources{MemoryLimitBytes: 1 << 30}
	n := 0
	for _, o := range r.cgroupOps("id") {
		if len(o.Values) == 2 && o.Values[0] == "memory.swap.max" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("memory.swap.max written %d times, want exactly 1", n)
	}
}

func TestCPUQuotaClamped(t *testing.T) {
	// A tiny quota starves the task; the kernel's CFS granularity is ~1ms.
	ops := Resources{CPUQuota: 0.000001}.cgroupOps("id")
	for _, o := range ops {
		if o.Value == "cpu" && o.Values[0] == "cpu.max" {
			if !strings.HasPrefix(o.Values[1], "1000/") {
				t.Errorf("tiny quota not clamped, got %q", o.Values[1])
			}
			return
		}
	}
	t.Fatal("cpu.max op not emitted")
}

func TestParseNamespaces(t *testing.T) {
	got, err := ParseNamespaces([]string{"pid", "net", "pid"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("duplicates not removed: %v", got)
	}

	got, err = ParseNamespaces([]string{"all"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(AllNamespaces) {
		t.Errorf("all -> %v, want %d entries", got, len(AllNamespaces))
	}

	if _, err := ParseNamespaces([]string{"wat"}); err == nil {
		t.Error("expected error for unknown namespace")
	}
	if _, err := ParseNamespaces(nil); err == nil {
		t.Error("expected error for empty namespace list")
	}
}

func TestEnvPair(t *testing.T) {
	env := []string{"PATH=/bin", "HOME=/root"}
	if v, ok := EnvPair(env, "PATH"); !ok || v != "/bin" {
		t.Errorf("PATH = %q, %v", v, ok)
	}
	// Must not match on prefix collisions.
	if _, ok := EnvPair(env, "PAT"); ok {
		t.Error("EnvPair matched a prefix, not a key")
	}
	if _, ok := EnvPair(env, "NOPE"); ok {
		t.Error("EnvPair found a key that does not exist")
	}
}

func TestHostnameAtLimitIsValid(t *testing.T) {
	s := base()
	s.Hostname = strings.Repeat("h", 64)
	if err := s.Validate(); err != nil {
		t.Errorf("64-byte hostname must be accepted: %v", err)
	}
}

func TestPlanIsDeterministic(t *testing.T) {
	// The same spec must always produce the same plan; otherwise the dry-run
	// output is worthless as a debugging artefact.
	a, _ := base().BuildPlan()
	b, _ := base().BuildPlan()
	if a.String() != b.String() {
		t.Error("BuildPlan is not deterministic")
	}
}

func TestNoHostRootPivotEvenWithOverlay(t *testing.T) {
	s := base()
	s.Rootfs.Path = "/"
	s.Rootfs.OverlayDirs = []string{"/low"}
	if err := s.Validate(); err == nil {
		t.Error("overlay must not be allowed to bypass the host-root check")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
