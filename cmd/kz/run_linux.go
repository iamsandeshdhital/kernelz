//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kernelz/internal/initseq"
	"kernelz/internal/state"
)

// cmdRun creates and starts a container.
//
// The supervisor's job is deliberately small: validate, compile, clone, record,
// wait, clean up. Everything inside the namespaces belongs to kz-init. This
// division exists because a process is born into a PID namespace rather than
// entering one, so the supervisor and the container init are unavoidably
// different processes.
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var (
		name     = fs.String("name", "", "container id")
		rootfs   = fs.String("rootfs", "", "root filesystem directory")
		hostname = fs.String("hostname", "", "container hostname")
		memory   = fs.String("memory", "", "memory limit, e.g. 512m")
		cpus     = fs.String("cpus", "", "cpu quota, e.g. 0.5")
		pidsMax  = fs.Int("pids-max", -1, "max processes (-1 unlimited)")
		network  = fs.String("network", "", "host bridge to attach")
		userSpec = fs.String("user", "", "uid[:gid] to drop to")
		readOnly = fs.Bool("read-only", false, "read-only rootfs")
		dryRun   = fs.Bool("dry-run", false, "print operations without touching the host")
		detach   = fs.Bool("detach", false, "return once started")
		verbose  = fs.Bool("verbose", false, "log every step")
		stateDir = fs.String("state", defaultStateDir(), "state directory")
	)
	var cmdArgs, envs stringList
	fs.Var(&cmdArgs, "cmd", "container command (repeatable)")
	fs.Var(&envs, "env", "KEY=VALUE (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Everything after "--" is the container command. Without this the runtime's
	// own flag parser would try to interpret the container's flags.
	cmdArgs = append(cmdArgs, fs.Args()...)

	if *rootfs == "" {
		return errors.New("--rootfs is required")
	}
	if len(cmdArgs) == 0 {
		return errors.New("--cmd is required: this runtime does not assume a default entrypoint")
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

	if *dryRun {
		fmt.Print(plan.String())
		fmt.Println()
		fmt.Println("dry run: these syscalls would be performed, and nothing else:")
		_, err := initseq.Run(initseq.NewDryRun(os.Stdout), s, plan, nil)
		return err
	}

	if os.Geteuid() != 0 {
		return errors.New("root is required: creating namespaces and writing cgroups need CAP_SYS_ADMIN")
	}
	if _, err := os.Stat(*rootfs); err != nil {
		return fmt.Errorf("--rootfs %s: %w", *rootfs, err)
	}

	store, err := state.NewStore(*stateDir)
	if err != nil {
		return err
	}
	if err := store.SaveSpec(s.ID, s); err != nil {
		return err
	}

	rec := &state.Container{
		ID:       s.ID,
		Rootfs:   s.Rootfs.Path,
		Status:   state.StatusCreated,
		SpecPath: store.SpecDir(s.ID),
	}
	if err := store.Save(rec); err != nil {
		return err
	}

	log := func(format string, args ...any) {
		if *verbose {
			fmt.Fprintf(os.Stderr, "[kz %s] %s\n", s.ID, fmt.Sprintf(format, args...))
		}
	}

	be := initseq.New("", *stateDir)
	if err := be.Clone(s); err != nil {
		_ = store.Remove(s.ID)
		return fmt.Errorf("clone: %w", err)
	}

	rec.InitPid = be.Child
	rec.Status = state.StatusRunning
	rec.StartedAt = time.Now()
	if err := store.Save(rec); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s started pid=%d\n", s.ID, be.Child)

	if *detach {
		return nil
	}

	// Forward signals so Ctrl-C reaches the container instead of orphaning it,
	// and so the runtime is not killed before it can tear the container down.
	sigc := make(chan os.Signal, 4)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigc)
	go func() {
		for sig := range sigc {
			if be.Child > 0 {
				_ = syscall.Kill(be.Child, sig.(syscall.Signal))
			}
		}
	}()

	res, err := initseq.Run(be, s, initseq.SubPlan(plan, initseq.TeardownOps(plan)), log)
	if err != nil {
		rec.Status = state.StatusStopped
		rec.EndedAt = time.Now()
		_ = store.Save(rec)
		return err
	}

	rec.Status = state.StatusStopped
	rec.EndedAt = time.Now()
	rec.ExitCode = res.Exit.ExitCode
	rec.Signal = res.Exit.Signal
	if err := store.Save(rec); err != nil {
		return err
	}

	if res.Exit.Signal != "" {
		fmt.Fprintf(os.Stderr, "%s killed by %s\n", s.ID, res.Exit.Signal)
	} else {
		fmt.Fprintf(os.Stderr, "%s exited %d\n", s.ID, res.Exit.ExitCode)
	}
	if res.Exit.ExitCode != 0 {
		os.Exit(res.Exit.ExitCode)
	}
	return nil
}

// cmdStop and cmdKill forward a signal to a container's init process.
func cmdStop(args []string) error { return signalContainer(args, syscall.SIGTERM) }

func cmdKill(args []string) error { return signalContainer(args, syscall.SIGKILL) }

func signalContainer(args []string, sig syscall.Signal) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kz %s <id>", sig)
	}
	fs := flag.NewFlagSet("signal", flag.ContinueOnError)
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
	if c.InitPid <= 0 || !state.Alive(c.InitPid) {
		return fmt.Errorf("container %s is not running", c.ID)
	}

	// Signal the whole process group. Signalling only the init is a trap: a
	// shell wrapper may keep running as an orphan and hold the rootfs busy
	// after its parent is gone.
	if err := syscall.Kill(-c.InitPid, sig); err != nil {
		// Not a group leader; fall back to the init alone.
		if err2 := syscall.Kill(c.InitPid, sig); err2 != nil {
			return fmt.Errorf("signal %s: %w", sig, err2)
		}
	}
	return nil
}
