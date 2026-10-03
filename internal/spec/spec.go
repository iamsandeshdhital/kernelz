// Package spec describes what a container *should* look like and compiles that
// description into an ordered execution plan.
//
// This package is deliberately free of any syscall or OS dependency. It is
// pure data plus pure functions, which is what makes the whole container
// lifecycle reproducible, diffable and testable without a Linux kernel: the
// executor in internal/initseq is the only thing that actually touches the
// machine.
//
// The model follows the OCI runtime-spec closely enough to be familiar, but is
// self-contained so the runtime has no third-party dependencies.
package spec

import "fmt"

// NSType enumerates the Linux namespaces this runtime understands.
type NSType string

const (
	NSPID     NSType = "pid"
	NSMount   NSType = "mount"
	NSNet     NSType = "net"
	NSUts     NSType = "uts"
	NSIPC     NSType = "ipc"
	NSCgroup  NSType = "cgroup"
	NSUser    NSType = "user"
	nsAllType        = "all"
)

// AllNamespaces is every namespace this runtime can create, in the order they
// must be applied. Order matters for the plan executor: the mount namespace has
// to exist before anything can be mounted into it, and the PID namespace is
// applied last because it only takes effect for children of the caller.
var AllNamespaces = []NSType{NSCgroup, NSIPC, NSMount, NSNet, NSUts, NSPID}

// ValidNSType reports whether s is a namespace this runtime supports.
func ValidNSType(s NSType) bool {
	for _, n := range AllNamespaces {
		if n == s {
			return true
		}
	}
	return false
}

// ParseNamespaces validates and normalises a list of namespace names.
func ParseNamespaces(in []string) ([]NSType, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("no namespaces given")
	}
	var out []NSType
	for _, raw := range in {
		s := NSType(raw)
		if s == nsAllType {
			out = append(out, AllNamespaces...)
			continue
		}
		if !ValidNSType(s) {
			return nil, fmt.Errorf("unknown namespace %q", raw)
		}
		out = append(out, s)
	}
	return dedupeNSTypes(out), nil
}

func dedupeNSTypes(in []NSType) []NSType {
	seen := make(map[NSType]bool, len(in))
	out := make([]NSType, 0, len(in))
	for _, n := range in {
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// Mount is a single filesystem to establish inside the container.
type Mount struct {
	Destination string `json:"destination"`
	Source      string `json:"source,omitempty"`
	Type        string `json:"type,omitempty"`
	ReadOnly    bool   `json:"readonly,omitempty"`
	// Options are passed verbatim in the mount(2) data field.
	Options []string `json:"options,omitempty"`
}

// Resource limits, mapped onto cgroup controllers.
type Resources struct {
	MemoryLimitBytes  int64    `json:"memory_limit_bytes,omitempty"`
	MemorySwapBytes   int64    `json:"memory_swap_bytes,omitempty"`
	CPUQuota          float64  `json:"cpu_quota,omitempty"`
	CPUShares         uint64   `json:"cpu_shares,omitempty"`
	CPUSetCPUs        string   `json:"cpuset_cpus,omitempty"`
	PidsLimit         int64    `json:"pids_limit,omitempty"`
	OOMScoreAdj       int      `json:"oom_score_adj,omitempty"`
	DisableOOMKiller  bool     `json:"disable_oom_killer,omitempty"`
	BlkioWeight       uint16   `json:"blkio_weight,omitempty"`
	AllowedDevicesRaw []string `json:"allowed_devices,omitempty"`
}

// Process is the container's initial process.
type Process struct {
	Args     []string `json:"args"`
	Env      []string `json:"env,omitempty"`
	Cwd      string   `json:"cwd,omitempty"`
	User     User     `json:"user"`
	Terminal bool     `json:"terminal,omitempty"`
	// AllowNewPrivs is an escape hatch, not a feature.
	//
	// PR_SET_NO_NEW_PRIVS is set unconditionally unless this is explicitly
	// true, because a setuid-root binary in an otherwise confined image is
	// otherwise a trivial privilege escalation out of the container.
	AllowNewPrivs bool              `json:"allow_new_privs,omitempty"`
	OOMScoreAdj   int               `json:"oom_score_adj,omitempty"`
	Capabilities  *Caps             `json:"capabilities,omitempty"`
	ExtraArgs     map[string]string `json:"-"`
}

// User is the uid/gid the process drops to. Running as a non-zero uid inside
// the container is one of the cheapest isolation wins available: it removes root
// from the picture entirely.
type User struct {
	UID            uint32   `json:"uid"`
	GID            uint32   `json:"gid"`
	AdditionalGIDs []uint32 `json:"additional_gids,omitempty"`
	Username       string   `json:"username,omitempty"`
}

// Caps is a capability set, expressed as an allow-list over the bounding set.
type Caps struct {
	Bounding    []string `json:"bounding,omitempty"`
	Effective   []string `json:"effective,omitempty"`
	Permitted   []string `json:"permitted,omitempty"`
	Inheritable []string `json:"inheritable,omitempty"`
	Ambient     []string `json:"ambient,omitempty"`
}

// Hook is a user-defined program run at a lifecycle point. Hooks are how
// runc integrates with systemd, checkpoint/restore and service managers, and
// this runtime keeps the same shape.
type Hook struct {
	Path string   `json:"path"`
	Args []string `json:"args,omitempty"`
	Env  []string `json:"env,omitempty"`
}

// Spec is the complete description of a container.
type Spec struct {
	ID         string            `json:"id"`
	Hostname   string            `json:"hostname,omitempty"`
	Namespaces []NSType          `json:"namespaces"`
	Rootfs     Rootfs            `json:"rootfs"`
	Process    Process           `json:"process"`
	Mounts     []Mount           `json:"mounts,omitempty"`
	Resources  Resources         `json:"resources,omitempty"`
	Hooks      map[string][]Hook `json:"hooks,omitempty"`
	// Annotations is free-form metadata, mirroring OCI. Carried into
	// /proc/<pid>/... style inspection output.
	Annotations    map[string]string `json:"annotations,omitempty"`
	ReadonlyRootfs bool              `json:"readonly_rootfs,omitempty"`
	// Bridge names the host-side bridge to attach the container's veth to.
	Bridge string `json:"bridge,omitempty"`
	// Hostname on Linux is capped at 64 bytes by the kernel.
}

// Rootfs locates the container's filesystem.
type Rootfs struct {
	Path     string `json:"path"`
	ReadOnly bool   `json:"readonly,omitempty"`
	// OverlayDirs, when set, makes the executor mount an overlayfs instead of
	// using Path directly. This is how a layered image becomes a single
	// writable directory without copying every byte of the base layer.
	OverlayDirs []string `json:"overlay_dirs,omitempty"`
}

// DefaultMounts returns the mounts every container needs beyond the image's
// own contents. /proc is mandatory (Go binaries and most C libraries read it),
// and the others are what you would otherwise be quietly missing inside.
func DefaultMounts() []Mount {
	return []Mount{
		{Destination: "/proc", Type: "proc", Options: []string{"nosuid", "noexec", "nodev"}},
		{Destination: "/dev", Type: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
		{Destination: "/dev/pts", Type: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
		{Destination: "/dev/shm", Type: "tmpfs", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
		{Destination: "/sys", Type: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
		{Destination: "/dev/mqueue", Type: "mqueue", Options: []string{"nosuid", "noexec", "nodev"}},
		{Destination: "/sys/fs/cgroup", Type: "cgroup", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
	}
}

// EnvPair returns the value for key in a POSIX-style environment slice.
func EnvPair(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, e := range env {
		if len(e) >= len(prefix) && e[:len(prefix)] == prefix {
			return e[len(prefix):], true
		}
	}
	return "", false
}

// String renders a short human-readable summary, used by `kz ps`.
func (s *Spec) String() string {
	p := "<none>"
	if len(s.Process.Args) > 0 {
		p = s.Process.Args[0]
	}
	return fmt.Sprintf("%s (%s) ns=%v", s.ID, p, s.Namespaces)
}
