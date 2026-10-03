//go:build !linux

package main

import "errors"

// The execution half of the CLI is Linux-only. plan, ps, inspect and rm all work
// on any platform because they operate purely on the runtime's data structures.

func cmdRun(args []string) error {
	return errors.New("kz run requires Linux: namespaces, cgroups and pivot_root have no equivalent elsewhere")
}

func cmdStop(args []string) error {
	return errors.New("kz stop requires Linux: signalling a container's init needs Linux process semantics")
}

func cmdKill(args []string) error {
	return cmdStop(args)
}
