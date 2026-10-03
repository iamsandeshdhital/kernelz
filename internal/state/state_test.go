package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	s := newStore(t)
	want := &Container{
		ID:       "web-1",
		Rootfs:   "/var/lib/kernelz/rootfs/web-1",
		Status:   StatusRunning,
		InitPid:  4242,
		SpecPath: "/run/kernelz/web-1.spec.json",
	}
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}

	got, err := s.Load("web-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.Status != want.Status || got.InitPid != want.InitPid {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
	if got.Rootfs != want.Rootfs || got.SpecPath != want.SpecPath {
		t.Errorf("fields lost: %+v", got)
	}
}

func TestSaveRejectsBadRecords(t *testing.T) {
	s := newStore(t)
	cases := []struct {
		name string
		c    *Container
	}{
		{"no id", &Container{Status: StatusRunning}},
		{"bad status", &Container{ID: "ok", Status: "weird"}},
		{"id with slash", &Container{ID: "a/b", Status: StatusRunning}},
		{"id with space", &Container{ID: "a b", Status: StatusRunning}},
		{"id starting with a dot", &Container{ID: ".hidden", Status: StatusRunning}},
		{"empty id", &Container{ID: "", Status: StatusRunning}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.Save(tc.c); err == nil {
				t.Errorf("Save accepted an invalid record: %+v", tc.c)
			}
		})
	}
}

func TestLoadMissingReturnsErrNotFound(t *testing.T) {
	s := newStore(t)
	_, err := s.Load("nope")
	if err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestLoadCorruptRecordIsReported(t *testing.T) {
	// A corrupt record must surface as an error. Silently skipping it would make
	// a running container look absent, and the operator would have no idea where
	// to look.
	s := newStore(t)
	path := filepath.Join(s.Dir, "broken.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load("broken"); err == nil {
		t.Error("corrupt record parsed successfully")
	}
	if _, err := s.List(); err == nil {
		t.Error("List hid a corrupt record instead of reporting it")
	}
}

func TestListSkipsTempFiles(t *testing.T) {
	// A temp file from an interrupted Save must not appear as a container.
	s := newStore(t)
	if err := s.Save(&Container{ID: "real", Status: StatusRunning}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir, ".real-123456"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "real" {
		t.Errorf("List = %v, want exactly the real container", ids(list))
	}
}

func TestRemove(t *testing.T) {
	s := newStore(t)
	if err := s.Save(&Container{ID: "gone", Status: StatusStopped}); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("gone"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load("gone"); err != ErrNotFound {
		t.Errorf("record still present after Remove: %v", err)
	}
	// Removing something already gone is not an error.
	if err := s.Remove("gone"); err != nil {
		t.Errorf("second Remove failed: %v", err)
	}
}

func TestSpecRoundTrip(t *testing.T) {
	s := newStore(t)
	type doc struct {
		Rootfs string   `json:"rootfs"`
		Args   []string `json:"args"`
	}
	want := doc{Rootfs: "/rootfs/web", Args: []string{"/bin/sh", "-c", "sleep 1"}}
	if err := s.SaveSpec("web-2", want); err != nil {
		t.Fatal(err)
	}
	var got doc
	if err := s.LoadSpec("web-2", &got); err != nil {
		t.Fatal(err)
	}
	if got.Rootfs != want.Rootfs || len(got.Args) != len(want.Args) {
		t.Errorf("spec round trip mismatch: %+v", got)
	}
}

func TestValidID(t *testing.T) {
	good := []string{"web", "web-1", "a.b_c", "A1", strings.Repeat("x", 63)}
	for _, id := range good {
		if !ValidID(id) {
			t.Errorf("ValidID(%q) = false, want true", id)
		}
	}
	bad := []string{"", "-leading-dash", ".dot", "a/b", "a b", "a\nb", "a:b",
		strings.Repeat("x", 64), "UPPER!", "a\x00b"}
	for _, id := range bad {
		if ValidID(id) {
			t.Errorf("ValidID(%q) = true, want false", id)
		}
	}
}

func TestGenerateIDIsAlwaysValid(t *testing.T) {
	// Whatever the user typed, the generated id must be usable.
	inputs := []string{
		"", "web", "my app!", "../../etc", strings.Repeat("n", 200),
		"---", "..", "\x00", "web/../..",
	}
	for _, in := range inputs {
		id := GenerateID(in, 42)
		if !ValidID(id) {
			t.Errorf("GenerateID(%q, 42) = %q, which is not a valid id", in, id)
		}
	}
}

func TestGenerateIDPreservesSafeChars(t *testing.T) {
	if got := GenerateID("web-1", 7); got != "web-1-7" {
		t.Errorf("GenerateID = %q, want web-1-7", got)
	}
}

func TestRunningPredicate(t *testing.T) {
	tests := []struct {
		status Status
		want   bool
	}{
		{StatusCreated, true},
		{StatusRunning, true},
		{StatusStopped, false},
	}
	for _, tt := range tests {
		c := &Container{Status: tt.status}
		if c.Running() != tt.want {
			t.Errorf("Running() for %s = %v, want %v", tt.status, c.Running(), tt.want)
		}
	}
}

func TestAliveRejectsNonPositive(t *testing.T) {
	for _, pid := range []int{0, -1, -99999} {
		if Alive(pid) {
			t.Errorf("Alive(%d) = true, want false", pid)
		}
	}
}

func TestSaveIsAtomicUnderConcurrentReads(t *testing.T) {
	// Concurrent saves and loads must never expose a partial file. The
	// rename-based commit is what guarantees that; this exercises the path.
	s := newStore(t)
	done := make(chan error, 8)
	for i := 0; i < 4; i++ {
		go func(i int) {
			id := GenerateID("c", i)
			done <- s.Save(&Container{ID: id, Status: StatusRunning, InitPid: 100 + i})
		}(i)
	}
	go func() {
		for i := 0; i < 20; i++ {
			if _, err := s.List(); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 5; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent access failed: %v", err)
		}
	}
}

func ids(cs []*Container) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}
