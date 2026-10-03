// Command kz is the container runtime's user-facing interface.
//
// The inspection half of the CLI -- plan, ps, inspect, rm -- is portable and
// works on any platform, because it operates entirely on the pure-data side of
// the runtime: a spec, a compiled plan, and a state directory. That is a direct
// consequence of keeping internal/spec syscall-free, and it means the most
// useful debugging tool the runtime has is available without a Linux kernel.
//
// The execution half -- run, stop, kill -- is Linux-only and lives in
// run_linux.go, because namespaces, cgroups and pivot_root have no equivalent
// anywhere else.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"kernelz/internal/initseq"
	"kernelz/internal/spec"
	"kernelz/internal/state"
)

const usage = `kernelz - a container runtime built on kernel primitives

usage: kz <command> [flags]

commands:
  plan      print the kernel operations a spec would perform (no syscalls)
  run       create and start a container            [linux, requires root]
  ps        list containers
  stop      send SIGTERM to a container             [linux]
  kill      send SIGKILL to a container             [linux]
  rm        remove a container's state
  inspect   print a container's full record

run flags:
  --name          container id (generated if omitted)
  --rootfs        container root filesystem directory (required)
  --hostname      container hostname
  --cmd           container command; repeatable or comma-separated
  --env           KEY=VALUE; repeatable
  --memory        memory limit (accepts bytes, 128m, 1g)
  --cpus          CPU quota as a fraction, e.g. 0.5 or 2
  --pids-max      maximum number of processes
  --network       attach to a named host bridge
  --user          uid[:gid] to drop to
  --read-only     mount the rootfs read-only
  --dry-run       print the plan and the syscalls without touching the host
  --detach        return once the container is started
  --verbose       log every step

  kz run requires root, a Linux kernel with namespace and cgroup support, and
  the kz-init binary alongside kz.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "plan":
		err = cmdPlan(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "ps":
		err = cmdPs(os.Args[2:])
	case "stop":
		err = cmdStop(os.Args[2:])
	case "kill":
		err = cmdKill(os.Args[2:])
	case "rm":
		err = cmdRm(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "kz: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "kz: %v\n", err)
		// 125 is the OCI convention for a runtime-level failure, as distinct
		// from a non-zero exit of the container's own program.
		os.Exit(125)
	}
}

// --- plan ------------------------------------------------------------------

// cmdPlan prints what would happen without touching the host. It is the
// cheapest way to review a change to the setup sequence.
func cmdPlan(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	var (
		name     = fs.String("name", "example", "container id")
		rootfs   = fs.String("rootfs", "/var/lib/kernelz/rootfs/example", "root filesystem directory")
		hostname = fs.String("hostname", "", "container hostname")
		memory   = fs.String("memory", "", "memory limit")
		cpus     = fs.String("cpus", "", "cpu quota, e.g. 0.5")
		pidsMax  = fs.Int("pids-max", -1, "max processes")
		network  = fs.String("network", "", "host bridge")
		readOnly = fs.Bool("read-only", false, "read-only rootfs")
		userSpec = fs.String("user", "", "uid[:gid]")
	)
	var cmdArgs, envs stringList
	fs.Var(&cmdArgs, "cmd", "container command")
	fs.Var(&envs, "env", "KEY=VALUE")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Everything after "--" is the container command, joined onto any --cmd
	// flags. Go's flag package stops parsing at the first non-flag argument, so
	// without this `kz run --cmd /bin/sh -c "echo hi"` would reject "-c": the
	// container command almost always contains its own flags, which have to be
	// passed through untouched rather than parsed by the runtime.
	cmdArgs = append(cmdArgs, fs.Args()...)
	if len(cmdArgs) == 0 {
		cmdArgs = stringList{"/bin/sh"}
	}

	s, err := buildSpec(*name, *rootfs, *hostname, *memory, *cpus, *pidsMax,
		*network, *userSpec, *readOnly, cmdArgs, envs)
	if err != nil {
		return err
	}
	plan, err := s.BuildPlan()
	if err != nil {
		return err
	}
	fmt.Print(plan.String())
	fmt.Println()
	fmt.Println("would perform:")
	_, err = initseq.Run(initseq.NewDryRun(os.Stdout), s, plan, nil)
	return err
}

// --- ps --------------------------------------------------------------------

func cmdPs(args []string) error {
	fs := flag.NewFlagSet("ps", flag.ContinueOnError)
	stateDir := fs.String("state", defaultStateDir(), "state directory")
	quiet := fs.Bool("q", false, "only print ids")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := state.NewStore(*stateDir)
	if err != nil {
		return err
	}
	list, err := store.List()
	if err != nil {
		return err
	}
	if !*quiet {
		fmt.Printf("%-24s %-8s %-7s %-10s %s\n", "ID", "STATUS", "PID", "AGE", "EXIT")
	}
	for _, c := range list {
		// A record can claim to be running while its process died without the
		// runtime getting a chance to update it: a crash, a reboot, or a kill
		// from outside. Report what is true now, not what was last written.
		if c.Running() && c.InitPid > 0 && !state.Alive(c.InitPid) {
			c.Status = state.StatusStopped
			c.ExitCode = -1
			c.Signal = "unknown"
			_ = store.Save(c)
		}
		if *quiet {
			fmt.Println(c.ID)
			continue
		}
		exit := ""
		if c.Status == state.StatusStopped {
			exit = fmt.Sprintf("%d", c.ExitCode)
			if c.Signal != "" {
				exit += "/" + c.Signal
			}
		}
		fmt.Printf("%-24s %-8s %-7d %-10s %s\n", c.ID, c.Status, c.InitPid, shortAge(c.Age()), exit)
	}
	return nil
}

func cmdInspect(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: kz inspect <id>")
	}
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	stateDir := fs.String("state", defaultStateDir(), "state directory")
	_ = fs.Parse(args[1:])

	store, err := state.NewStore(*stateDir)
	if err != nil {
		return err
	}
	c, err := store.Load(args[0])
	if err != nil {
		return err
	}
	fmt.Println(c.String())
	fmt.Printf("rootfs: %s\nspec:   %s\n", c.Rootfs, c.SpecPath)
	if !c.StartedAt.IsZero() {
		fmt.Printf("started: %s\n", c.StartedAt.Format(time.RFC3339))
	}
	if !c.EndedAt.IsZero() {
		fmt.Printf("ended:   %s\n", c.EndedAt.Format(time.RFC3339))
	}
	return nil
}

func cmdRm(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: kz rm <id>")
	}
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	stateDir := fs.String("state", defaultStateDir(), "state directory")
	_ = fs.Parse(args[1:])

	store, err := state.NewStore(*stateDir)
	if err != nil {
		return err
	}
	c, err := store.Load(args[0])
	if err != nil {
		return err
	}
	if c.Running() && c.InitPid > 0 && state.Alive(c.InitPid) {
		return fmt.Errorf("refusing to remove %s: still running (pid %d)", c.ID, c.InitPid)
	}
	return store.Remove(c.ID)
}

// --- spec construction -----------------------------------------------------

// buildSpec assembles a spec from flags. It is shared by `run` and `plan`, so
// the thing previewed is exactly the thing that would run.
func buildSpec(name, rootfs, hostname, memory, cpus string, pidsMax int,
	network, userSpec string, readOnly bool, cmdArgs, envs stringList) (*spec.Spec, error) {

	id := name
	if id == "" {
		// path.Base, not filepath.Base: the rootfs is a Linux path and must be
		// split the same way on every host platform, or a previewed plan would
		// differ from the one that actually runs.
		id = state.GenerateID(path.Base(rootfs), int(time.Now().Unix()))
	}
	if !state.ValidID(id) {
		return nil, fmt.Errorf("invalid container id %q: use letters, digits, '_', '-', '.' (max 63 chars)", id)
	}

	s := &spec.Spec{
		ID:       id,
		Hostname: hostname,
		Namespaces: []spec.NSType{
			spec.NSCgroup, spec.NSIPC, spec.NSMount, spec.NSNet, spec.NSUts, spec.NSPID,
		},
		Rootfs:    spec.Rootfs{Path: path.Clean(rootfs), ReadOnly: readOnly},
		Process:   spec.Process{Args: cmdArgs, Env: envs, Cwd: "/"},
		Resources: spec.Resources{PidsLimit: int64(pidsMax)},
		Bridge:    network,
	}
	if s.Hostname == "" {
		s.Hostname = id
	}

	if memory != "" {
		v, err := parseSize(memory)
		if err != nil {
			return nil, fmt.Errorf("--memory: %w", err)
		}
		s.Resources.MemoryLimitBytes = v
	}
	if cpus != "" {
		var f float64
		if _, err := fmt.Sscanf(cpus, "%g", &f); err != nil {
			return nil, fmt.Errorf("--cpus: %w", err)
		}
		s.Resources.CPUQuota = f
	}
	if userSpec != "" {
		u, err := parseUser(userSpec)
		if err != nil {
			return nil, err
		}
		s.Process.User = u
	}
	return s, nil
}

func parseUser(s string) (spec.User, error) {
	parts := strings.SplitN(s, ":", 2)
	uid, err := parseUint32(parts[0])
	if err != nil {
		return spec.User{}, fmt.Errorf("--user: %w", err)
	}
	gid := uid
	if len(parts) == 2 {
		if gid, err = parseUint32(parts[1]); err != nil {
			return spec.User{}, fmt.Errorf("--user: %w", err)
		}
	}
	return spec.User{UID: uid, GID: gid}, nil
}

// --- helpers ---------------------------------------------------------------

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

func defaultStateDir() string {
	if v := os.Getenv("KZ_STATE_DIR"); v != "" {
		return v
	}
	return "/run/kernelz"
}

func shortAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// parseSize accepts plain bytes as well as the k/m/g suffixes people expect
// from every other container tool.
func parseSize(s string) (int64, error) {
	lower := strings.ToLower(strings.TrimSpace(s))
	mult := int64(1)

	switch {
	case strings.HasSuffix(lower, "kb"), strings.HasSuffix(lower, "k"):
		mult, lower = 1<<10, trimSizeSuffix(lower)
	case strings.HasSuffix(lower, "mb"), strings.HasSuffix(lower, "m"):
		mult, lower = 1<<20, trimSizeSuffix(lower)
	case strings.HasSuffix(lower, "gb"), strings.HasSuffix(lower, "g"):
		mult, lower = 1<<30, trimSizeSuffix(lower)
	}

	var v int64
	if _, err := fmt.Sscanf(lower, "%d", &v); err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return v * mult, nil
}

// trimSizeSuffix strips a trailing "b" if present, leaving the unit letter.
func trimSizeSuffix(s string) string {
	if len(s) > 0 && s[len(s)-1] == 'b' {
		return s[:len(s)-1]
	}
	return s
}

func parseUint32(s string) (uint32, error) {
	var v uint64
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &v); err != nil {
		return 0, fmt.Errorf("invalid number %q", s)
	}
	if v > 1<<32-1 {
		return 0, fmt.Errorf("value %d out of range", v)
	}
	return uint32(v), nil
}
