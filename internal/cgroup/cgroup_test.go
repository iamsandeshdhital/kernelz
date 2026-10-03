package cgroup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHierarchy builds a directory that looks like a cgroup filesystem, so the
// detection logic can be tested without a kernel and without root.
func fakeHierarchy(t *testing.T, v2Controllers string) string {
	t.Helper()
	root := t.TempDir()
	if v2Controllers != "" {
		if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte(v2Controllers), 0o644); err != nil {
			t.Fatal(err)
		}
		return root
	}
	for _, c := range []string{"cpu", "cpuacct", "memory", "pids"} {
		if err := os.MkdirAll(filepath.Join(root, c), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestDetectV2(t *testing.T) {
	root := fakeHierarchy(t, "cpu memory pids io")
	v, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if v != V2 {
		t.Errorf("Detect = %v, want v2", v)
	}
}

func TestDetectV1(t *testing.T) {
	root := fakeHierarchy(t, "")
	v, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if v != V1 {
		t.Errorf("Detect = %v, want v1", v)
	}
}

func TestDetectPrefersV2WhenBothMarkersExist(t *testing.T) {
	// A v2 host with a v1 hierarchy mounted underneath must be detected as v2:
	// writing memory.max to a v1 path would silently do nothing.
	root := fakeHierarchy(t, "memory")
	if err := os.MkdirAll(filepath.Join(root, "memory"), 0o755); err != nil {
		t.Fatal(err)
	}
	v, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if v != V2 {
		t.Errorf("Detect = %v, want v2 (the unified marker is authoritative)", v)
	}
}

func TestDetectRejectsUnknownLayout(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "some-other-fs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Detect(root); err == nil {
		t.Error("Detect accepted a directory that is not a cgroup hierarchy")
	}
}

func TestDetectMissingDirectory(t *testing.T) {
	if _, err := Detect(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("Detect accepted a missing directory")
	}
}

func TestAvailableControllers(t *testing.T) {
	root := fakeHierarchy(t, "cpu memory pids")
	got, err := AvailableControllers(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cpu", "memory", "pids"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("controller %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestControllerEnabled(t *testing.T) {
	root := fakeHierarchy(t, "cpu memory")
	if !ControllerEnabled(root, "memory") {
		t.Error("memory reported as not enabled")
	}
	// This is the case that matters: a limit written for a controller the host
	// never enabled is silently discarded by the kernel.
	if ControllerEnabled(root, "io") {
		t.Error("io reported as enabled on a hierarchy without it")
	}
}

func TestPathForV2(t *testing.T) {
	m := &Manager{Version: V2, Dir: "/sys/fs/cgroup/web", Mount: "/sys/fs/cgroup"}
	got := m.PathFor("memory", "memory.max")
	want := filepath.Join("/sys/fs/cgroup/web", "memory.max")
	if got != want {
		t.Errorf("PathFor = %q, want %q", got, want)
	}
}

func TestPathForV1TranslatesNames(t *testing.T) {
	// The v1 spelling differences are the single ugliest part of cgroups and
	// the main reason v2 exists; getting them wrong means a limit is applied to
	// nothing at all.
	m := &Manager{Version: V1, Dir: "/sys/fs/cgroup/memory/web", Mount: "/sys/fs/cgroup"}
	cases := map[string]string{
		"memory/memory.max":      "memory.limit_in_bytes",
		"memory/memory.swap.max": "memory.memsw.limit_in_bytes",
		"cpu/cpu.max":            "cpu.cfs_quota_us",
		"cpu/cpu.weight":         "cpu.shares",
		"pids/pids.max":          "pids.max", // identical in both versions
	}
	for in, wantName := range cases {
		parts := strings.SplitN(in, "/", 2)
		got := filepath.Base(m.PathFor(parts[0], parts[1]))
		if got != wantName {
			t.Errorf("v1 %s -> %q, want %q", in, got, wantName)
		}
	}
}

func TestCreateEnablesControllersWithPlusPrefix(t *testing.T) {
	// Under v2 a child inherits no controllers; without writing "+cpu" into the
	// parent's cgroup.subtree_control, every subsequent limit is ignored. This
	// is the most common reason a memory limit quietly does nothing.
	root := fakeHierarchy(t, "cpu memory pids")
	m := &Manager{Version: V2, Mount: root, Dir: filepath.Join(root, "web")}

	if err := m.Create([]string{"cpu", "memory", "io"}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := os.Stat(m.Dir); err != nil {
		t.Errorf("container cgroup dir not created: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
	if err != nil {
		t.Fatalf("subtree_control not written: %v", err)
	}
	got := string(b)
	for _, want := range []string{"+cpu", "+memory"} {
		if !strings.Contains(got, want) {
			t.Errorf("subtree_control = %q, missing %q", got, want)
		}
	}
	// io is not available on this hierarchy, so it must not be requested.
	if strings.Contains(got, "+io") {
		t.Errorf("subtree_control requested an unavailable controller: %q", got)
	}
}

func TestWriteSetsValue(t *testing.T) {
	root := fakeHierarchy(t, "memory")
	m := &Manager{Version: V2, Mount: root, Dir: filepath.Join(root, "web")}
	if err := m.Create(nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Write("memory", "memory.max", "134217728"); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(m.Dir, "memory.max"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != "134217728" {
		t.Errorf("memory.max = %q, want 134217728", b)
	}
}

func TestWriteCommitsAtomically(t *testing.T) {
	// The value is written via a temp file and renamed. If it were written in
	// place, a concurrent reader could observe a truncated value -- and the
	// kernel parses these files on open, so a partial write is silently read as
	// a different, usually far weaker, limit.
	root := fakeHierarchy(t, "memory")
	m := &Manager{Version: V2, Mount: root, Dir: filepath.Join(root, "web")}
	if err := m.Create(nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Write("memory", "memory.max", "999"); err != nil {
		t.Fatal(err)
	}
	// No temp files may be left behind.
	entries, err := os.ReadDir(m.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".kz-cgroup-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestAddPidWritesProcessID(t *testing.T) {
	root := fakeHierarchy(t, "memory pids")
	m := &Manager{Version: V2, Mount: root, Dir: filepath.Join(root, "web")}
	if err := m.Create(nil); err != nil {
		t.Fatal(err)
	}
	if err := m.AddPid(1234); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(m.Dir, "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != "1234" {
		t.Errorf("cgroup.procs = %q, want 1234", b)
	}
}

func TestReadLimitTranslatesMax(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "memory.max")
	if err := os.WriteFile(p, []byte("max\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readLimit(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != -1 {
		t.Errorf("readLimit(max) = %d, want -1", got)
	}

	if err := os.WriteFile(p, []byte("1024"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = readLimit(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1024 {
		t.Errorf("readLimit(1024) = %d", got)
	}
}

func TestRemoveIsIdempotent(t *testing.T) {
	root := fakeHierarchy(t, "memory")
	m := &Manager{Version: V2, Mount: root, Dir: filepath.Join(root, "web")}
	if err := m.Remove(); err != nil {
		t.Errorf("Remove of a missing dir should succeed, got %v", err)
	}
}

func TestVersionString(t *testing.T) {
	if V1.String() != "v1" || V2.String() != "v2" {
		t.Errorf("Version.String = %q/%q", V1, V2)
	}
}
