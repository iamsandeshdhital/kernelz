// Package state persists what the runtime knows about running containers.
//
// A container's in-memory identity dies with the process that created it, so
// `kz ps` and `kz stop` need it on disk. The store is deliberately dumb: one
// JSON file per container under a root directory, no database, no locking
// scheme beyond an atomic rename.
//
// Keeping this free of OS dependencies also means the bookkeeping the CLI relies
// on -- id generation, lifecycle transitions, stale-entry detection -- can be
// tested without a kernel.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Status is a container's lifecycle state.
type Status string

const (
	// StatusCreated means the spec is valid but no process exists yet.
	StatusCreated Status = "created"
	// StatusRunning means the init process is alive.
	StatusRunning Status = "running"
	// StatusStopped means it exited normally or was killed; see ExitCode.
	StatusStopped Status = "stopped"
)

func (s Status) Valid() bool {
	switch s {
	case StatusCreated, StatusRunning, StatusStopped:
		return true
	}
	return false
}

// Container is the persisted record of one container.
type Container struct {
	ID     string `json:"id"`
	Bundle string `json:"bundle"`
	Rootfs string `json:"rootfs"`
	// InitPid is the host-visible pid of the container's init, and is 0 before
	// the clone happens.
	InitPid   int       `json:"init_pid"`
	Status    Status    `json:"status"`
	ExitCode  int       `json:"exit_code,omitempty"`
	Signal    string    `json:"signal,omitempty"`
	StartedAt time.Time `json:"started_at,omitempty"`
	EndedAt   time.Time `json:"ended_at,omitempty"`
	// SpecPath points at the saved spec, so `kz exec` can re-enter the
	// container's namespaces without reconstructing them.
	SpecPath string `json:"spec_path,omitempty"`
}

// Running reports whether the container may still have a live process.
func (c *Container) Running() bool { return c.Status == StatusRunning || c.Status == StatusCreated }

// Store is a directory of container records.
type Store struct {
	Dir string
	mu  sync.Mutex
}

// NewStore creates a store rooted at dir.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state: create %s: %w", dir, err)
	}
	return &Store{Dir: dir}, nil
}

func (s *Store) path(id string) string { return filepath.Join(s.Dir, id+".json") }

// Save writes a container record atomically.
//
// The write goes to a temp file and is renamed into place, because a container
// record is read by other processes while it is being written; a partial file
// would be parsed as a corrupt record and the container would look deleted.
func (s *Store) Save(c *Container) error {
	if c.ID == "" {
		return errors.New("state: container has no id")
	}
	if !c.Status.Valid() {
		return fmt.Errorf("state: invalid status %q", c.Status)
	}
	if !ValidID(c.ID) {
		return fmt.Errorf("state: invalid container id %q", c.ID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("state: marshal %s: %w", c.ID, err)
	}

	tmp, err := os.CreateTemp(s.Dir, "."+c.ID+"-*")
	if err != nil {
		return fmt.Errorf("state: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path(c.ID)); err != nil {
		return fmt.Errorf("state: commit %s: %w", c.ID, err)
	}
	return nil
}

// Load reads one container record.
func (s *Store) Load(id string) (*Container, error) {
	if !ValidID(id) {
		return nil, fmt.Errorf("state: invalid container id %q", id)
	}
	b, err := os.ReadFile(s.path(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("state: read %s: %w", id, err)
	}
	var c Container
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("state: parse %s: %w", id, err)
	}
	return &c, nil
}

// ErrNotFound reports a container id that has no record.
var ErrNotFound = errors.New("state: no such container")

// Remove deletes a container record.
func (s *Store) Remove(id string) error {
	err := os.Remove(s.path(id))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// List returns every record in the store, sorted by id.
//
// A record that fails to parse is reported rather than skipped: silently hiding
// it would make a container appear to not exist, which is the worst possible
// failure mode for a resource manager.
func (s *Store) List() ([]*Container, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, fmt.Errorf("state: read %s: %w", s.Dir, err)
	}

	var out []*Container
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			continue // in-flight temp file
		}
		b, err := os.ReadFile(filepath.Join(s.Dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("state: read %s: %w", e.Name(), err)
		}
		var c Container
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("state: parse %s: %w", e.Name(), err)
		}
		out = append(out, &c)
	}
	return out, nil
}

// Alive reports whether a pid names a live process.
//
// The implementation is platform-specific: see alive_linux.go for the signal-0
// probe and alive_other.go for the portable approximation. Keeping it out of
// this file is what lets the rest of the store build and be tested anywhere.

// idPattern restricts ids to what is safe as both a hostname and a filename.
//
// The id ends up as a UTS hostname (64-byte kernel limit) and as a path
// component, so anything with a slash, whitespace or a control character is
// rejected rather than sanitised: a silently mangled id would make the
// container unreachable by the name the user asked for.
var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

// ValidID reports whether id is usable as a container name.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// GenerateID derives a valid, unique-looking container id from a name.
func GenerateID(name string, n int) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
			return r
		default:
			return '-'
		}
	}, name)

	if len(safe) > 48 {
		safe = safe[:48]
	}
	safe = strings.Trim(safe, "-.")
	if safe == "" {
		safe = "ctr"
	}
	return fmt.Sprintf("%s-%d", safe, n)
}

// SpecDir is where a container's spec is stored alongside its record.
func (s *Store) SpecDir(id string) string { return filepath.Join(s.Dir, id+".spec.json") }

// SaveSpec persists the spec so kz-init and kz exec can read it back.
func (s *Store) SaveSpec(id string, spec any) error {
	b, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("state: marshal spec for %s: %w", id, err)
	}
	path := s.SpecDir(id)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("state: write spec for %s: %w", id, err)
	}
	return nil
}

// LoadSpec reads a persisted spec into v.
func (s *Store) LoadSpec(id string, v any) error {
	if !ValidID(id) {
		return fmt.Errorf("state: invalid container id %q", id)
	}
	b, err := os.ReadFile(s.SpecDir(id))
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("state: parse spec for %s: %w", id, err)
	}
	return nil
}

// Age returns how long a container has existed, for display.
func (c *Container) Age() time.Duration {
	if c.StartedAt.IsZero() {
		return 0
	}
	if !c.EndedAt.IsZero() {
		return c.EndedAt.Sub(c.StartedAt)
	}
	return time.Since(c.StartedAt)
}

// String renders a one-line summary.
func (c *Container) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-24s %-8s pid=%d", c.ID, c.Status, c.InitPid)
	if c.Status == StatusStopped {
		fmt.Fprintf(&b, " exit=%d", c.ExitCode)
		if c.Signal != "" {
			fmt.Fprintf(&b, " signal=%s", c.Signal)
		}
	}
	return b.String()
}
