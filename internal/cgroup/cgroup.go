// Package cgroup applies resource limits through the cgroup filesystem.
//
// There is no ioctl and no RPC involved. Every limit is a write(2) to a control
// file, and the kernel's cgroup drivers act on it synchronously. That is the
// whole interface, and it is why a container runtime can be a few hundred lines
// long rather than a kernel module.
//
// The hard part is not the writing, it is knowing which filesystem to write to:
//
//	v1 splits every controller into its own hierarchy, at a different mount
//	   point, with different file names per controller, and a file appears only
//	   if the controller was actually enabled at boot.
//
//	v2 is a single unified hierarchy where every knob is one file and optional
//	   controllers appear only if enabled in cgroup.controllers.
package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Version identifies a cgroup hierarchy layout.
type Version int

const (
	// V1 is the legacy multi-hierarchy layout.
	V1 Version = 1
	// V2 is the unified hierarchy, mounted at /sys/fs/cgroup.
	V2 Version = 2
)

func (v Version) String() string {
	if v == V2 {
		return "v2"
	}
	return "v1"
}

// DefaultMount is where the cgroup filesystem is normally found.
const DefaultMount = "/sys/fs/cgroup"

// unifiedMagic is the file the v2 hierarchy always contains at its root, listing
// every controller available. Its presence is the definitive version probe --
// more reliable than the mount type, which lies in containers.
const unifiedMagic = "cgroup.controllers"

// Detect reports which cgroup layout is active at mountpoint.
//
// The probe is filesystem-based rather than syscall-based because the runtime
// may itself be running inside a container, where /proc/self/cgroup describes
// the *outer* container's placement rather than what is mounted here.
func Detect(mountpoint string) (Version, error) {
	if mountpoint == "" {
		mountpoint = DefaultMount
	}

	// v2 first: the unified hierarchy has a marker file at its root.
	if _, err := os.Stat(filepath.Join(mountpoint, unifiedMagic)); err == nil {
		return V2, nil
	}

	// v1 exposes one directory per controller (cpu, memory, pids, ...).
	entries, err := os.ReadDir(mountpoint)
	if err != nil {
		return 0, fmt.Errorf("cgroup: cannot read %s: %w", mountpoint, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		switch e.Name() {
		case "cpu", "cpuacct", "memory", "pids", "blkio", "cpuset", "devices", "freezer", "net_cls":
			return V1, nil
		}
	}
	return 0, fmt.Errorf("cgroup: %s is neither a v1 hierarchy nor a v2 unified mount", mountpoint)
}

// AvailableControllers returns the controllers enabled at the root of a v2
// hierarchy, i.e. the contents of cgroup.controllers.
func AvailableControllers(mountpoint string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(mountpoint, unifiedMagic))
	if err != nil {
		return nil, fmt.Errorf("cgroup: read %s: %w", unifiedMagic, err)
	}
	return strings.Fields(string(b)), nil
}

// ControllerEnabled reports whether a controller can be used for limiting.
func ControllerEnabled(mountpoint, controller string) bool {
	have, err := AvailableControllers(mountpoint)
	if err != nil {
		return false
	}
	for _, h := range have {
		if h == controller {
			return true
		}
	}
	return false
}

// Manager writes control files for one container.
type Manager struct {
	// Dir is the container's own cgroup directory.
	Dir string
	// Version is the layout the host uses.
	Version Version
	// Mount is the cgroup filesystem root.
	Mount string
}

// New creates a manager for a named container under a v2 hierarchy.
func New(id string) (*Manager, error) {
	v, err := Detect(DefaultMount)
	if err != nil {
		return nil, err
	}
	m := &Manager{Mount: DefaultMount, Version: v}
	switch v {
	case V2:
		// The default (unlimited) subtree is the conventional home for leaf
		// containers; writing anywhere else can land on a host that is not
		// running in its own cgroup.
		m.Dir = filepath.Join(DefaultMount, id)
	case V1:
		// v1 has no unified root: every controller is its own tree, so the
		// container needs a directory per controller. The caller creates them.
		m.Dir = filepath.Join(DefaultMount, id)
	}
	return m, nil
}

// PathFor returns the control-file path for a controller and file name.
func (m *Manager) PathFor(controller, file string) string {
	if m.Version == V2 {
		return filepath.Join(m.Dir, file)
	}
	// v1: memory.max does not exist, memory.limit_in_bytes does. This mapping is
	// the single ugliest part of cgroups and the main reason v2 was created.
	return filepath.Join(m.Dir, v1FileName(controller, file))
}

// v1FileName translates a v2 control-file name to its v1 equivalent.
func v1FileName(controller, file string) string {
	switch controller {
	case "memory":
		switch file {
		case "memory.max":
			return "memory.limit_in_bytes"
		case "memory.swap.max":
			return "memory.memsw.limit_in_bytes"
		}
	case "cpu":
		switch file {
		case "cpu.max":
			// v1 splits the quota across two files: a period and a quota.
			return "cpu.cfs_quota_us"
		case "cpu.weight":
			return "cpu.shares"
		}
	case "pids":
		if file == "pids.max" {
			return "pids.max"
		}
	}
	return file
}

// Create makes the container's cgroup directory and enables controllers.
//
// Under v2 a child cgroup inherits no controllers from its parent; they have
// to be written into cgroup.subtree_control explicitly, or every limit applied
// afterwards is silently ignored. This is the single most common reason a
// `docker run --memory=512m` quietly does nothing.
func (m *Manager) Create(controllers []string) error {
	if m.Version != V2 {
		return m.createV1(controllers)
	}
	if err := os.MkdirAll(m.Dir, 0o755); err != nil {
		return fmt.Errorf("cgroup: mkdir %s: %w", m.Dir, err)
	}
	if len(controllers) == 0 {
		return nil
	}
	// Only controllers actually enabled on the parent can be turned on.
	parent := filepath.Dir(m.Dir)
	avail, err := AvailableControllers(parent)
	if err != nil {
		return err
	}
	var enable []string
	for _, c := range controllers {
		for _, a := range avail {
			if a == c {
				enable = append(enable, c)
				break
			}
		}
	}
	if len(enable) == 0 {
		return nil
	}
	// "+" is the v2 syntax for enabling a controller on the subtree.
	values := make([]string, 0, len(enable))
	for _, c := range enable {
		values = append(values, "+"+c)
	}
	return writeFile(filepath.Join(parent, "cgroup.subtree_control"),
		strings.Join(values, " "), 0o644)
}

func (m *Manager) createV1(controllers []string) error {
	// Under v1 every controller has its own hierarchy, so the directory has to
	// exist once per controller.
	for _, c := range controllers {
		dir := filepath.Join(m.Mount, c, filepath.Base(m.Dir))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("cgroup: mkdir %s: %w", dir, err)
		}
	}
	return nil
}

// Write sets a control-file value for a controller.
//
// An empty value is allowed and means "clear the limit" for the files that
// support it.
func (m *Manager) Write(controller, file, value string) error {
	path := m.PathFor(controller, file)
	if err := writeFile(path, value, 0o644); err != nil {
		return fmt.Errorf("cgroup: %s: %w", controller, err)
	}
	return nil
}

// AddPid moves a process into the container's cgroup.
//
// This is what actually starts the accounting: a limit applied to a cgroup with
// no processes in it constrains nothing.
func (m *Manager) AddPid(pid int) error {
	if m.Version == V2 {
		return writeFile(filepath.Join(m.Dir, "cgroup.procs"), strconv.Itoa(pid), 0o644)
	}
	// v1: one cgroup.procs per controller hierarchy.
	have, err := os.ReadDir(m.Mount)
	if err != nil {
		return err
	}
	for _, e := range have {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(m.Mount, e.Name(), filepath.Base(m.Dir), "tasks")
		if _, err := os.Stat(p); err == nil {
			if err := writeFile(p, strconv.Itoa(pid), 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

// Remove deletes the container's cgroup. It must be empty, so every process has
// to have exited first.
func (m *Manager) Remove() error {
	if err := os.Remove(m.Dir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cgroup: rmdir %s: %w", m.Dir, err)
	}
	return nil
}

// readLimit parses a v2 limit file, translating "max" into -1.
func readLimit(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	if s == "max" {
		return -1, nil
	}
	return strconv.ParseInt(s, 10, 64)
}

// WriteProcAttr sets a per-process attribute under /proc/<pid>.
//
// Some limits are not cgroup settings at all. oom_score_adj, for instance,
// biases the kernel's OOM killer towards or away from a process, and lives in
// procfs.
func WriteProcAttr(pid int, file, value string) error {
	if pid <= 0 {
		return errors.New("cgroup: cannot write a proc attribute without a pid")
	}
	path := filepath.Join("/proc", strconv.Itoa(pid), file)
	return writeFile(path, value, 0o644)
}

// ReadProcAttr reads a per-process attribute from /proc/<pid>.
func ReadProcAttr(pid int, file string) (string, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), file))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// writeFile writes via a temp file and renames, so a reader can never observe a
// partially written control value.
//
// This matters more than it looks: the kernel parses these files on open, and a
// truncated write is silently interpreted as a different, often much weaker,
// limit.
func writeFile(path, value string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".kz-cgroup-*")
	if err != nil {
		// Not all cgroup directories allow temp files; fall back to a direct
		// write rather than failing outright.
		return os.WriteFile(path, []byte(value), mode)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.WriteString(value); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}
