package spec

import (
	"fmt"
	"strings"
)

// OpKind identifies one kernel operation in a plan.
type OpKind string

const (
	OpClone         OpKind = "clone"          // fork+exec with new namespaces
	OpMount         OpKind = "mount"          // mount(2)
	OpBind          OpKind = "bind"           // recursive bind mount
	OpSymlink       OpKind = "symlink"        // create device-ish symlinks
	OpPivotRoot     OpKind = "pivot_root"     // pivot_root(2)
	OpChdir         OpKind = "chdir"          // chdir(2), used to escape old root
	OpSethostname   OpKind = "sethostname"    // sethostname(2) in the UTS ns
	OpCgroupApply   OpKind = "cgroup_apply"   // write cgroup controller files
	OpCgroupAttach  OpKind = "cgroup_attach"  // move a pid into a cgroup
	OpNetnsSetup    OpKind = "netns_setup"    // veth + bridge + addresses
	OpNetnsTeardown OpKind = "netns_teardown" // remove veth/bridge
	OpSetUID        OpKind = "setuid"         // setresuid/setresgid
	OpSetGroups     OpKind = "setgroups"      // setgroups(2)
	OpNoNewPrivs    OpKind = "no_new_privs"   // prctl(PR_SET_NO_NEW_PRIVS)
	OpSetrlimit     OpKind = "setrlimit"      // RLIMIT_NOFILE etc.
	OpCapSet        OpKind = "cap_set"        // capset/capset ambient
	OpNonDumpable   OpKind = "non_dumpable"   // prctl(PR_SET_DUMPABLE, 0)
	OpExec          OpKind = "exec"           // execve(2) the container process
	OpUmount        OpKind = "umount"         // umount2(2)
	OpMakePrivate   OpKind = "make_private"   // MS_REC|MS_PRIVATE
	OpRemountRO     OpKind = "remount_ro"     // remount read-only
	OpHook          OpKind = "hook"           // run a lifecycle hook
	OpSignalRelay   OpKind = "signal_relay"   // forward a signal to the init proc
	OpWriteCgroup   OpKind = "write_cgroup"   // single cgroup control-file write
	OpWaitReap      OpKind = "wait_reap"      // waitid()/wait4() on the init proc
)

// Op is one step in a container's lifecycle.
//
// Ops are values, not calls. Nothing in this package has a side effect, which
// is the whole point: a plan can be printed, diffed, asserted on in a unit
// test, or replayed against a fake executor without a kernel anywhere in sight.
type Op struct {
	Kind OpKind `json:"kind"`
	// Detail is a short human-readable rendering, used by `kz run --dry-run`.
	Detail string `json:"detail,omitempty"`
	// FailFatal marks ops after which the container cannot continue. The
	// executor treats these as fatal by default; non-fatal ops are used for
	// best-effort steps such as read-only remounts that older kernels lack
	// MS_NOSYMFOLLOW for.
	FailFatal bool `json:"fail_fatal,omitempty"`
	// Mount carries filesystem arguments for mount-family ops.
	Mount *Mount `json:"mount,omitempty"`
	// Value carries the argument for scalar ops (uid, path, hostname...).
	Value string `json:"value,omitempty"`
	// Values carries a list for multi-arg ops (env, caps, flags).
	Values []string `json:"values,omitempty"`
	// Num carries numeric args (rlimit value, pids limit...).
	Num int64 `json:"num,omitempty"`
}

// Plan is an ordered, complete description of the syscalls to perform.
type Plan struct {
	ID  string `json:"id"`
	Ops []Op   `json:"ops"`
	// CloneFlags is the unshare(2) flag set this plan will apply, rendered for
	// inspection. The executor computes the real value with syscall constants.
	CloneFlags []string `json:"clone_flags"`
}

// PlanError is a structured validation failure, so the CLI can point at the
// exact field rather than dumping a wall of text.
type PlanError struct {
	Field  string
	Reason string
}

func (e *PlanError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Reason) }

func errf(field, format string, args ...any) error {
	return &PlanError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

// Validate checks internal consistency of a spec. It runs before any syscall is
// attempted, because the single most expensive mistake in a runtime is
// discovering a malformed spec halfway through tearing down the host's mount
// table.
func (s *Spec) Validate() error {
	if s.ID == "" {
		return errf("id", "must not be empty")
	}
	if strings.ContainsAny(s.ID, " \t\n/\\") {
		return errf("id", "%q contains characters that are unsafe in a path or hostname", s.ID)
	}
	if len(s.Namespaces) == 0 {
		return errf("namespaces", "at least one namespace is required")
	}
	if !s.hasNS(NSMount) {
		return errf("namespaces", "a mount namespace is mandatory: without one, pivot_root would alter the host root")
	}
	for _, n := range s.Namespaces {
		if !ValidNSType(n) {
			return errf("namespaces", "unknown namespace %q", n)
		}
	}

	if s.Rootfs.Path == "" {
		return errf("rootfs.path", "must not be empty")
	}
	if s.Rootfs.Path == "/" {
		// Unconditional, including when overlay dirs are set. An overlay mount
		// is itself performed inside the new mount namespace, so it could never
		// make pivoting onto the host root safe -- the exemption was only ever
		// a way to shoot the host in the foot.
		return errf("rootfs.path", "refusing to pivot_root onto the host root")
	}

	if len(s.Process.Args) == 0 {
		return errf("process.args", "at least one argument is required")
	}
	if s.Process.Cwd == "" {
		return errf("process.cwd", "must not be empty")
	}
	if !strings.HasPrefix(s.Process.Cwd, "/") {
		return errf("process.cwd", "%q must be an absolute path", s.Process.Cwd)
	}

	if s.Hostname != "" && len(s.Hostname) > 64 {
		return errf("hostname", "%q exceeds the kernel's 64-byte limit", s.Hostname)
	}
	if s.Hostname != "" && strings.ContainsAny(s.Hostname, " \t\n/") {
		return errf("hostname", "%q contains characters the kernel rejects", s.Hostname)
	}

	seenDest := map[string]bool{}
	for i, m := range s.Mounts {
		// Field names are built with Sprintf rather than embedded in errf's
		// `field` argument, because errf takes the field verbatim and would
		// leave the index unsubstituted.
		field := fmt.Sprintf("mounts[%d].destination", i)
		if !strings.HasPrefix(m.Destination, "/") {
			return &PlanError{Field: field, Reason: fmt.Sprintf("%q must be absolute", m.Destination)}
		}
		if seenDest[m.Destination] {
			return &PlanError{Field: field, Reason: fmt.Sprintf("duplicate mount destination %q", m.Destination)}
		}
		seenDest[m.Destination] = true
	}

	return s.Resources.validate()
}

func (s *Spec) hasNS(n NSType) bool {
	for _, x := range s.Namespaces {
		if x == n {
			return true
		}
	}
	return false
}

func (r *Resources) validate() error {
	if r.MemoryLimitBytes < 0 {
		return errf("resources.memory_limit_bytes", "must not be negative")
	}
	if r.PidsLimit < -1 {
		return errf("resources.pids_limit", "must be -1 (unlimited) or non-negative")
	}
	if r.CPUQuota < 0 {
		return errf("resources.cpu_quota", "must not be negative")
	}
	if r.MemorySwapBytes != 0 && r.MemoryLimitBytes != 0 && r.MemorySwapBytes < r.MemoryLimitBytes {
		return errf("resources.memory_swap_bytes",
			"swap limit (%d) below memory limit (%d) would make the container unschedulable",
			r.MemorySwapBytes, r.MemoryLimitBytes)
	}
	if r.OOMScoreAdj < -1000 || r.OOMScoreAdj > 1000 {
		return errf("resources.oom_score_adj", "%d outside the kernel's [-1000,1000] range", r.OOMScoreAdj)
	}
	return nil
}

// BuildPlan compiles a validated spec into the ordered op sequence that
// creates the container.
//
// The ordering encodes several hard-won facts about kernel behaviour, and it is
// the reason this function exists as its own well-tested unit:
//
//   - Namespaces must be created by the *clone* that also execs the init
//     process. unshare(CLONE_NEWPID) would not help, because a PID namespace
//     only affects processes forked *after* the call.
//   - procfs must be mounted after the PID namespace exists, or it will show the
//     host's process table.
//   - The old root must be made MS_PRIVATE *before* pivot_root, or the pivot
//     propagates to the host.
//   - pivot_root must be followed by a chdir, because the cwd is still inside
//     the now-unreachable old root.
//   - The init process must drop privileges *last*, after setup, so that setup
//     itself does not run unprivileged.
func (s *Spec) BuildPlan() (*Plan, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	p := &Plan{ID: s.ID, CloneFlags: cloneFlagNames(s.Namespaces)}

	// --- 1. Hooks the runtime supports before the container exists.
	for _, h := range s.Hooks["prestart"] {
		p.add(Op{Kind: OpHook, Value: h.Path, Values: append(append([]string{}, h.Args...), h.Env...)})
	}

	// --- 2. The clone that creates every namespace and execs the init shim.
	//     Done in one step: a process can only ever be *born* into a new PID
	//     namespace, never migrate into one.
	p.add(Op{
		Kind:      OpClone,
		Value:     s.Rootfs.Path,
		Detail:    fmt.Sprintf("clone(CLONE_NEW%s...) exec=kz-init", strings.Join(flagSuffixes(s.Namespaces), "|")),
		FailFatal: true,
	})

	// --- 3. UTS: hostname is per-namespace, so this must happen inside.
	if s.hasNS(NSUts) && s.Hostname != "" {
		p.add(Op{Kind: OpSethostname, Value: s.Hostname, Detail: "sethostname(" + s.Hostname + ")", FailFatal: true})
	}

	// --- 4. Mount namespace: isolate propagation, then build the mount table.
	p.add(Op{
		Kind:      OpMakePrivate,
		Value:     "/",
		Detail:    "mount(\"\", \"/\", MS_REC|MS_PRIVATE)",
		FailFatal: true,
	})

	mounts := mergeMounts(DefaultMounts(), s.Mounts)
	for _, m := range mounts {
		p.add(mountOp(m))
	}

	// --- 5. Overlay the layered image into a single writable directory.
	if len(s.Rootfs.OverlayDirs) > 0 {
		p.add(Op{
			Kind:      OpMount,
			Mount:     &Mount{Destination: s.Rootfs.Path, Type: "overlay", ReadOnly: s.Rootfs.ReadOnly},
			Values:    s.Rootfs.OverlayDirs,
			Detail:    "overlayfs(lowerdir=" + strings.Join(s.Rootfs.OverlayDirs, ":") + ",upperdir=...,workdir=...)",
			FailFatal: true,
		})
	}

	// --- 6. pivot_root into the jail, then escape the old root via chdir.
	p.add(Op{
		Kind:      OpPivotRoot,
		Value:     s.Rootfs.Path,
		Values:    []string{s.Rootfs.Path + "/.oldroot"},
		Detail:    "pivot_root(" + s.Rootfs.Path + ", " + s.Rootfs.Path + "/.oldroot)",
		FailFatal: true,
	})
	// The kernel leaves the cwd pointing into the old root after a pivot. Until
	// this chdir, every relative path resolves inside a tree the process cannot
	// reach -- and getcwd(2) returns ENOENT.
	p.add(Op{Kind: OpChdir, Value: s.Process.Cwd, Detail: "chdir(" + s.Process.Cwd + ")", FailFatal: true})
	p.add(Op{Kind: OpUmount, Value: "/.oldroot", Detail: "umount2(/.oldroot, MNT_DETACH)", FailFatal: false})

	// --- 7. Drop the old root's recursive mount so nothing is left behind.
	if s.Rootfs.ReadOnly {
		p.add(Op{Kind: OpRemountRO, Value: "/", Detail: "remount(\"/\", MS_BIND|MS_REMOUNT|MS_RDONLY)"})
	}

	// --- 8. Resource limits. Applied while still privileged; cgroup writes
	//     need CAP_SYS_ADMIN in the cgroup namespace's owning hierarchy.
	if resOps := s.Resources.cgroupOps(s.ID); len(resOps) > 0 {
		p.add(resOps...)
	}

	// --- 9. Network. The veth peer has to be moved into the new netns by the
	//     *parent*, since the container cannot reach the host's namespace from
	//     inside its own.
	//
	//     A net namespace is unusable until at least loopback is up, so this op
	//     is emitted for every netns even with no bridge attached -- otherwise
	//     the container has no working 127.0.0.1 and most software hangs on it.
	if s.hasNS(NSNet) {
		detail := "bring up lo in the new netns"
		if s.Bridge != "" {
			detail = fmt.Sprintf("veth pair -> bridge %s, assign address, bring up lo", s.Bridge)
		}
		p.add(Op{
			Kind:      OpNetnsSetup,
			Value:     s.Bridge,
			Detail:    detail,
			FailFatal: true,
		})
	}

	// --- 10. Hardening, then the privilege drop.
	//
	// PR_SET_NO_NEW_PRIVS is set unconditionally unless the caller explicitly
	// opted out, and always *before* the uid change, because it is precisely
	// what stops the setuid binary in the image from handing root back.
	if !s.Process.AllowNewPrivs {
		p.add(Op{Kind: OpNoNewPrivs, Detail: "prctl(PR_SET_NO_NEW_PRIVS, 1)", FailFatal: true})
	}
	p.add(Op{Kind: OpNonDumpable, Detail: "prctl(PR_SET_DUMPABLE, 0)", FailFatal: false})
	p.add(Op{Kind: OpSetrlimit, Value: "RLIMIT_NOFILE", Num: 1024, Detail: "setrlimit(NOFILE, 1024)"})

	if s.Process.User.UID != 0 || s.Process.User.GID != 0 {
		p.add(Op{
			Kind:      OpSetGroups,
			Values:    u32ToStrings(s.Process.User.AdditionalGIDs),
			Detail:    fmt.Sprintf("setgroups(%v)", s.Process.User.AdditionalGIDs),
			FailFatal: true,
		})
		// setresgid must precede setresuid: once the uid is dropped there is
		// no privilege left to change the gid.
		p.add(Op{Kind: OpSetUID, Value: u32ToString(s.Process.User.GID), Num: int64(s.Process.User.GID),
			Detail: fmt.Sprintf("setresgid(%d)", s.Process.User.GID), FailFatal: true})
		p.add(Op{Kind: OpSetUID, Value: u32ToString(s.Process.User.UID), Num: int64(s.Process.User.UID),
			Detail: fmt.Sprintf("setresuid(%d)", s.Process.User.UID), FailFatal: true})
	}
	if s.Process.Capabilities != nil && len(s.Process.Capabilities.Bounding) > 0 {
		p.add(Op{Kind: OpCapSet, Values: s.Process.Capabilities.Bounding,
			Detail: "capset(bounding=" + strings.Join(s.Process.Capabilities.Bounding, ",") + ")"})
	}

	// --- 11. Finally, become the container process.
	p.add(Op{
		Kind:      OpExec,
		Value:     s.Process.Args[0],
		Values:    append(append([]string{}, s.Process.Args[1:]...), s.Process.Env...),
		Detail:    "execve(" + strings.Join(s.Process.Args, " ") + ")",
		FailFatal: true,
	})

	// --- 12. Teardown, run by the parent once the child exits.
	for _, h := range s.Hooks["poststop"] {
		p.add(Op{Kind: OpHook, Value: h.Path, Values: h.Args})
	}
	p.add(Op{Kind: OpWaitReap, Detail: "wait4(init_pid) and reap orphans"})
	if s.hasNS(NSNet) {
		p.add(Op{Kind: OpNetnsTeardown, Value: s.Bridge})
	}

	return p, nil
}

func (p *Plan) add(ops ...Op) {
	for _, o := range ops {
		if o.Kind == "" {
			panic("plan: op with no kind")
		}
		if o.Detail == "" {
			o.Detail = string(o.Kind)
		}
		p.Ops = append(p.Ops, o)
	}
}

// mountOp converts a declarative Mount into the concrete op that realises it.
func mountOp(m Mount) Op {
	flags := []string{}
	if m.ReadOnly {
		flags = append(flags, "ro")
	}
	flags = append(flags, m.Options...)

	switch m.Type {
	case "bind":
		return Op{
			Kind: OpBind, Mount: &m,
			Detail:    fmt.Sprintf("mount(%s -> %s, MS_BIND|MS_REC)", m.Source, m.Destination),
			FailFatal: true,
		}
	case "proc":
		// Fatal, because a Go binary inside will not start without /proc, and
		// a silently-absent /proc is far more confusing than a failed container.
		return Op{
			Kind: OpMount, Mount: &m, Values: flags,
			Detail:    "mount(proc -> " + m.Destination + ", nosuid|noexec|nodev)",
			FailFatal: true,
		}
	case "devpts":
		// A container without a private devpts shares the host's /dev/pts, so
		// every terminal on the host shows up inside it.
		return Op{
			Kind: OpMount, Mount: &m, Values: flags,
			Detail:    "mount(devpts -> " + m.Destination + ", newinstance)",
			FailFatal: true,
		}
	default:
		return Op{
			Kind: OpMount, Mount: &m, Values: flags,
			Detail:    fmt.Sprintf("mount(%s -> %s, %s)", m.Type, m.Destination, strings.Join(flags, ",")),
			FailFatal: true,
		}
	}
}

// mergeMounts layers user mounts over the defaults: the user wins on conflict.
func mergeMounts(defaults, user []Mount) []Mount {
	out := append([]Mount{}, defaults...)
	idx := make(map[string]int, len(out))
	for i, m := range out {
		idx[m.Destination] = i
	}
	for _, m := range user {
		if i, ok := idx[m.Destination]; ok {
			out[i] = m
			continue
		}
		idx[m.Destination] = len(out)
		out = append(out, m)
	}
	return out
}

func cloneFlagNames(ns []NSType) []string {
	var out []string
	for _, n := range ns {
		out = append(out, "NEW"+strings.ToUpper(string(n)))
	}
	return out
}

func flagSuffixes(ns []NSType) []string {
	var out []string
	for _, n := range ns {
		out = append(out, strings.ToUpper(string(n)))
	}
	return out
}

func u32ToString(v uint32) string { return fmt.Sprintf("%d", v) }

func u32ToStrings(in []uint32) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, u32ToString(v))
	}
	return out
}

// String renders the plan for `kz run --dry-run`.
func (p *Plan) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "plan for %s\n", p.ID)
	fmt.Fprintf(&b, "  clone flags: %s\n", strings.Join(p.CloneFlags, "|"))
	for i, o := range p.Ops {
		sev := "  "
		if o.FailFatal {
			sev = "!!"
		}
		fmt.Fprintf(&b, "  %s %2d. %-16s %s\n", sev, i, o.Kind, o.Detail)
	}
	return b.String()
}
