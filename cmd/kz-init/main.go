//go:build linux

// Command kz-init is the first process inside a container.
//
// It is exec'd by kz with every requested namespace already applied, which is
// the only way a process can enter a PID namespace: namespaces are a property of
// birth, not something you walk into afterwards.
//
// From here it runs the setup half of the plan -- mounts, pivot_root, the
// privilege drop -- and finally execve's the container's own process. When that
// execve succeeds nothing of this program survives: the container's PID 1 is
// the user's program, and the runtime is gone from the address space.
package main

import (
	"flag"
	"fmt"
	"os"

	"kernelz/internal/initseq"
	"kernelz/internal/spec"
	"kernelz/internal/state"
)

func main() {
	var (
		stateDir = flag.String("state", defaultStateDir(), "container state directory")
		id       = flag.String("id", os.Getenv("KZ_CONTAINER_ID"), "container id")
		verbose  = flag.Bool("v", false, "log every step")
	)
	flag.Parse()

	if *id == "" {
		fail("no container id: pass -id or set KZ_CONTAINER_ID")
	}

	store, err := state.NewStore(*stateDir)
	if err != nil {
		fail("%v", err)
	}

	var s spec.Spec
	if err := store.LoadSpec(*id, &s); err != nil {
		fail("load spec for %s: %v", *id, err)
	}

	plan, err := s.BuildPlan()
	if err != nil {
		fail("build plan for %s: %v", *id, err)
	}

	log := func(format string, args ...any) {
		if *verbose {
			fmt.Fprintf(os.Stderr, "[kz-init %s] %s\n", *id, fmt.Sprintf(format, args...))
		}
	}

	// Only the setup half runs here. The clone already happened, and the
	// teardown half belongs to the supervising parent: this process is about to
	// become the container and will not be around to clean anything up.
	be := initseq.New(os.Args[0], *stateDir)
	setup := initseq.SubPlan(plan, initseq.SetupOps(plan))

	if _, err := initseq.Run(be, &s, setup, log); err != nil {
		// A setup failure has to be visible. Exit 125 is what the OCI runtime
		// spec reserves for "the runtime itself failed", distinguishing it from
		// the container's own exit status.
		fmt.Fprintf(os.Stderr, "kz-init: setup failed: %v\n", err)
		os.Exit(125)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "kz-init: "+format+"\n", args...)
	os.Exit(125)
}

func defaultStateDir() string {
	if v := os.Getenv("KZ_STATE_DIR"); v != "" {
		return v
	}
	return "/run/kernelz"
}
