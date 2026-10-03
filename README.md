# kernelz — a container runtime from kernel primitives

**Status: work in progress. Compiles and is heavily tested; never executed
against a Linux kernel.**

A container runtime built directly on Linux kernel primitives — namespaces,
cgroups, `pivot_root` — with no dependency on Docker, containerd, or runc. It
has a complete CLI, a plan executor, cgroup and netlink backends, and 106
passing tests.

Read [Status](#status) first. The plumbing is done and reviewed; the syscalls it
makes have never run.

---

## The idea

A container is not a virtual machine. It is a process whose view of the world has
been narrowed by a specific, ordered set of kernel configuration calls:

| Primitive | What it actually does |
|---|---|
| `unshare(2)` / `clone(2)` | Duplicates kernel structures so the process sees a private PID/mount/net/UTS table |
| `pivot_root(2)` | Atomically swaps the process root; unlike `chroot`, the old root cannot be recovered |
| cgroups | A filesystem where each "setting" is literally a `write(2)` to a control file |
| netlink + veth | A virtual network cable, half in the host and half in the container |
| `PR_SET_NO_NEW_PRIVS` | Makes privilege escalation via setuid binaries impossible |

There is no hypervisor, no guest agent, and no image format the kernel
understands. The isolation *is* the configuration.

## Architecture

The decision that shapes everything: **a spec compiles into an ordered plan of
kernel operations, and a separate executor walks that plan.**

```
Spec  ──compile──▶  Plan  ──execute──▶  Kernel
(pure data)         (pure data)         (the only part that calls the kernel)
```

`internal/spec` has **no syscall and no OS dependency**; a plan is just a list of
op values. The same split applies to execution: `initseq.Run` is portable
dispatch logic, and `initseq.Backend` is the interface whose only real
implementation is Linux-only.

That boundary is what makes this testable. `initseq.NewDryRun` satisfies
`Backend` on every platform, so the whole executor — ordering, fatal vs
best-effort handling, teardown after a half-failed setup, argv/env separation —
is verified with no kernel anywhere:

```console
$ kz plan --name web --rootfs /var/lib/kernelz/rootfs/web \
      --memory 512m --cpus 1.5 --pids-max 256 --network kz0 --user 1000:1000

plan for web
  clone flags: NEWCGROUP|NEWIPC|NEWMOUNT|NEWNET|NEWUTS|NEWPID
  !!  0. clone          clone(CLONE_NEWCGROUP|IPC|MOUNT|NET|UTS|PID...) exec=kz-init
  !!  1. sethostname    sethostname(web)
  !!  2. make_private   mount("", "/", MS_REC|MS_PRIVATE)
  !!  3. mount          mount(proc -> /proc, nosuid|noexec|nodev)
  ...
  !! 10. pivot_root     pivot_root(/var/lib/kernelz/rootfs/web, ...web/.oldroot)
  !! 11. chdir          chdir(/)
  !! 13. write_cgroup   cgroup v2 memory/memory.max <- "536870912"
  !! 15. write_cgroup   cgroup v2 cpu/cpu.max <- "150000/100000"
  !! 16. write_cgroup   cgroup v2 pids/pids.max <- "256"
  !! 18. no_new_privs   prctl(PR_SET_NO_NEW_PRIVS, 1)
  !! 22. setgid         setresgid(1000)
  !! 23. setuid         setresuid(1000)
  !! 24. exec           execve(/bin/sh -c echo hi)
```

`kz plan` works on any OS, Windows included, because it touches none of the
Linux-only code.

### Why the order is what it is

Each constraint is a statement about the kernel, asserted in
`internal/spec/spec_test.go` and `internal/initseq/initseq_test.go`:

- `clone` must be first — a process is **born** into a PID namespace, it never
  migrates into one. `unshare(CLONE_NEWPID)` would leave the parent in the old
  namespace, which is not a container.
- `make_private` must precede every mount, or mounts propagate back to the host.
- `pivot_root` must be immediately followed by `chdir`, because the kernel
  leaves the cwd inside the now-unreachable old root and `getcwd(2)` returns
  `ENOENT` until you do.
- procfs must be mounted *after* the PID namespace exists, or it shows the host's
  process table.
- cgroup writes and `setresgid` must precede `setresuid`: after the uid drop
  there is no privilege left to change the gid, or to write cgroups.
- The reap is skipped when `exec` was never reached — otherwise `wait4(2)` blocks
  forever on a process that was never created.

### Supervisor and init are different processes

`SetupOps` and `TeardownOps` partition a plan explicitly, because namespaces make
this unavoidable:

```
parent  kz       clone, wait4, net teardown, state
child   kz-init  mounts, pivot_root, privilege drop, execve
```

## Status

### Implemented

| Package | Prod | Test | What it does |
|---|---|---|---|
| `internal/spec` | 734 | 342 | Spec model, validation, plan compiler, cgroup op derivation |
| `internal/image` | 317 | 402 | OCI layer extraction, whiteout semantics, traversal defense |
| `internal/initseq` | 869 | 353 | Plan dispatcher, dry-run backend, **Linux syscall backend** |
| `internal/cgroup` | 319 | 250 | v1/v2 detection, control-file writes, controller negotiation |
| `internal/state` | 308 | 222 | Container records, spec persistence, stale-pid reconciliation |
| `internal/linuxutil` | 451 | — | Raw syscall layer (`setns`, `prctl`, `pivot_root`, mount, caps) |
| `internal/netns` | 420 | — | veth pairs, bridges, loopback, addresses (raw netlink) |
| `cmd/kz`, `cmd/kz-init` | 615 | — | CLI and the PID-1 shim |

**106 tests pass, 0 fail.** 4,033 lines of production code, 1,569 of tests.
`linuxutil` and `netns` have no tests because their code is untestable without a
real kernel — see the caveat below.

Verified: `gofmt` clean; `go build` and `go vet` clean for `linux/amd64`,
`linux/arm64`, `linux/arm`, `windows/amd64`, `darwin/amd64`.

Security-relevant behaviour under test:

- layer entries rejected for path traversal, absolute paths and symlink
  redirection rather than silently normalised
- `.wh..wh..opq` handled distinctly from `.wh.<name>`, so stale lower-layer files
  are not left reachable
- setuid/setgid bits never materialised from an image
- `PR_SET_NO_NEW_PRIVS` on by default, with an explicit `AllowNewPrivs` escape
  hatch
- a spec is rejected if it lacks a mount namespace or targets the host root
- cgroup writes are never duplicated, and are translated correctly to v1 names

### Not implemented

- **Overlayfs unpacking.** `MountOverlay` exists and validates its options, but
  nothing assembles an OCI image into layered directories yet. Point `--rootfs`
  at a prepared rootfs.
- **User namespaces** — rejected explicitly rather than half-done. They need
  `uid_map`/`gid_map` written from the parent with `setgroups` disabled first,
  which Go's `SysProcAttr` cannot express.
- **`kz exec`** — `setns(2)` is implemented in `linuxutil` but not wired to a
  subcommand.
- Capability negotiation, seccomp, image pull.

### The most important caveat

> **Nothing here has ever been executed on a Linux kernel.**

It was developed on Windows with a cross-compiling Go toolchain. The Linux build
is verified to *compile, link, vet clean and produce a valid ELF binary* — and
nothing more. Not one `clone`, `pivot_root`, cgroup write or netlink message has
been executed.

Compilation is a weak guarantee here specifically. `pivot_root` compiles
perfectly and returns `EINVAL` on first call if the mount propagation or
`put_old` prerequisites are wrong. **The netlink veth message construction in
`internal/netns` is the least-verified code in the repository** — structurally
sound, but it has never seen a kernel response.

Two `internal/image` tests are skipped on Windows (symlink creation needs
`SeCreateSymbolicLinkPrivilege`) and have never run.

## Usage

```bash
go build -o bin/kz ./cmd/kz
go build -o bin/kz-init ./cmd/kz-init   # must sit next to kz

sudo bin/kz run --name web --rootfs /path/to/rootfs \
     --memory 512m --cpus 1.5 --pids-max 256 --read-only \
     -- /bin/sh -c 'echo hello'
```

`run` requires root, `CAP_SYS_ADMIN`, and a writable cgroup v2 hierarchy. The
container command goes after `--` so its own flags are not parsed by `kz`.

```bash
kz plan      # preview; any OS, no privileges, no side effects
kz ps        # list containers
kz inspect   # full record
kz stop      # SIGTERM the container's process group
kz kill      # SIGKILL
kz rm        # drop state
```

## Testing on real hardware

Honest verification needs a Linux host — a VM, WSL2, or a platform that grants
`CAP_SYS_ADMIN` and a writable cgroup v2 hierarchy. The plan:

1. Create a container with PID/mount/UTS namespaces; confirm `ps` inside shows
   one process.
2. Verify isolation *negatively*: it cannot see host PIDs, cannot write to a
   read-only rootfs, and dies at `pids.max`.
3. Confirm the host is left clean afterwards — no leaked veth pairs or mounts.

CI runs on `ubuntu-latest`, which at least compiles and vets the Linux build and
runs the portable tests on a real kernel.

## Notes worth keeping

- **Never use `filepath` on a container path.** Container paths are
  slash-separated on every host; `path.Clean` is correct where `filepath.Clean`
  silently yields backslashes on Windows. This bit twice during development.
- **`execve` argv and env must stay in separate fields.** Both are flat
  NUL-terminated lists, so concatenating them is unrecoverable — `OPT=-c` is
  indistinguishable from the flag `-c`.
- **A v2 child cgroup inherits no controllers.** They must be written into the
  parent's `cgroup.subtree_control` as `+cpu`, or every limit applied afterwards
  is silently discarded. This is the most common reason `--memory=512m` quietly
  does nothing.
- **Never pass user input through a shell.** `kz run ... -- sh -c "$INPUT"` is
  injection; that is the caller's call, not the runtime's to make.

## License

MIT — Copyright (c) 2026 Sandesh Dhital. See [LICENSE](LICENSE).
