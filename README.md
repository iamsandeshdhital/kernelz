# kernelz — a container runtime from kernel primitives

**Status: work in progress. Not a working container runtime.**

This repository is an in-progress implementation of a container runtime built
directly on Linux kernel primitives — namespaces, cgroups, `pivot_root` — with
no dependency on Docker, containerd, or runc.

Read [Status](#status) before drawing any conclusions from this README. What
exists is real and tested; what does not exist is the part that makes it a
runtime.

---

## The idea

A container is not a virtual machine. It is a process whose view of the world
has been narrowed by a specific, ordered set of kernel configuration calls:

| Primitive | What it actually does |
|---|---|
| `unshare(2)` / `clone(2)` | Duplicates kernel structures so the process sees a private PID/mount/net/UTS table |
| `pivot_root(2)` | Atomically swaps the process root; unlike `chroot`, the old root cannot be recovered |
| cgroups | A filesystem where each "setting" is literally a `write(2)` to a control file |
| netlink + veth | A virtual network cable, half in the host and half in the container |
| `PR_SET_NO_NEW_PRIVS` | Makes privilege escalation via setuid binaries impossible |

There is no hypervisor, no image format the kernel understands, and no agent
inside the guest. The isolation *is* the configuration.

## Architecture

The design decision that shapes everything else: **a spec is compiled into an
ordered plan of kernel operations, and a separate executor walks that plan.**

```
Spec  ──compile──▶  Plan  ──execute──▶  Kernel
(pure data)         (pure data)         (the only part that calls the kernel)
```

`internal/spec` has **no syscall and no OS dependency**. A plan is a list of
op values. That makes the entire container lifecycle inspectable, diffable, and
assertable in a unit test with no kernel involved:

```
plan for web
  clone flags: NEWCGROUP|NEWIPC|NEWMOUNT|NEWNET|NEWUTS|NEWPID
  !!  0. clone            clone(CLONE_NEWMOUNT|NEWPID|...) exec=kz-init
  !!  1. sethostname      sethostname(web)
  !!  2. make_private     mount("", "/", MS_REC|MS_PRIVATE)
  !!  3. mount            mount(proc -> /proc, nosuid|noexec|nodev)
  ...
  !! 14. exec             execve(/bin/sh)
  !! 15. wait_reap        wait4(init_pid) and reap orphans
```

The plan encodes ordering constraints that are really statements about the
kernel, each of which is asserted in `internal/spec/spec_test.go`:

- `clone` must be first — a process is **born** into a PID namespace, it never
  migrates into one. `unshare(CLONE_NEWPID)` would not help.
- `make_private` must precede every mount, or mounts propagate back to the host.
- `pivot_root` must be immediately followed by `chdir`, because the kernel
  leaves the working directory inside the now-unreachable old root.
- procfs must be mounted after the PID namespace exists, or it shows the host's
  process table.
- cgroup writes must precede `setresuid`, and `setresgid` must precede
  `setresuid` — after the uid drop there is no privilege left to change the gid.

## Status

### Implemented and tested

| Package | Prod LOC | Test LOC | What it does | Verification |
|---|---|---|---|---|
| `internal/spec` | 717 | 354 | Spec model, validation, plan compiler, cgroup op derivation | 15 tests + 18 subtests passing |
| `internal/image` | 317 | 402 | OCI layer extraction, whiteout semantics, path-traversal defense | 18 tests passing, 2 skipped on Windows |
| `internal/linuxutil` | 293 | — | Raw syscall layer (`setns`, `prctl`, `pivot_root`, mount helpers) | Compiles for `linux/amd64`, vet clean |

33 tests pass, 0 fail. `internal/linuxutil` has no tests because its code is
untestable without a Linux kernel — see the caveat below.

Notable behaviours covered by tests:

- **Path traversal defense.** Layer entries are validated before use. A tar
  member named `../../etc/shadow` or `/etc/shadow` is rejected outright rather
  than silently normalised — an image that attempts this is broken or hostile,
  and the operator should hear about it.
- **Whiteout semantics.** `.wh.<name>` hides a single lower-layer entry;
  `.wh..wh..opq` discards a directory's entire lower-layer contents. Conflating
  the two leaves stale files — including old `/etc/shadow` or setuid binaries —
  reachable in the final rootfs.
- **Symlink redirection defense.** A symlink planted by a lower layer is
  unlinked before a higher layer writes through it, so a layer cannot use one to
  write outside the rootfs.
- **setuid stripping.** Setuid/setgid bits are never materialised from an image.
- **Validation invariants.** A spec without a mount namespace, or whose rootfs
  is `/`, is rejected — both would let `pivot_root` alter the host root.
- **`PR_SET_NO_NEW_PRIVS` is on by default**, with an explicit
  `AllowNewPrivs` escape hatch.

### Not implemented

These packages are referenced in the architecture and **do not exist yet**:

| Missing | Consequence |
|---|---|
| `internal/initseq` | **The plan executor. Nothing actually calls the syscalls.** |
| `internal/cgroup` | cgroup v1/v2 detection and controller writes |
| `internal/netns` | veth pairs, bridges, addresses (netlink) |
| `internal/state` | Container state persistence, `ps`/`stop`/`exec` |
| `cmd/kz` | The CLI |
| `cmd/kz-init` | The PID-1 shim |

**There is no executable. You cannot run this.**

### The most important caveat

> **Nothing here has ever been executed on a Linux kernel.**

It was developed on Windows with a cross-compiling Go toolchain, so the Linux
build is verified to *compile* and to *link* into a valid ELF binary — and
nothing more. Not one `unshare`, `pivot_root`, or cgroup write has been
executed.

Compilation is a weak guarantee for this particular project. `pivot_root` in
particular compiles perfectly and returns `EINVAL` on first call if the mount
propagation or `put_old` prerequisites are wrong. **Expect the executor to be
substantially incomplete and partly incorrect when it is written.**

Two of the `internal/image` tests are skipped on Windows because creating a
symlink there requires `SeCreateSymbolicLinkPrivilege`. They have never run
either; CI on Linux will run them.

## Building

```bash
go build ./...          # all platforms
GOOS=linux go build ./...
go vet ./...
go test ./...
```

`internal/linuxutil` is `//go:build linux` only, since it wraps Linux syscalls.

Two syscall constants Go omits on `linux/amd64` are defined in
`internal/linuxutil/const_linux.go` rather than pulling in `golang.org/x/sys`:

- `SYS_SETNS` (308) — Go defines this for arm/riscv64/s390x but **not** amd64.
- `PR_SET_NO_NEW_PRIVS` (0x26) and `PR_SET_CHILD_SUBREAPER` (0x24) — likewise absent on amd64.

`prctl(2)` needs `RawSyscall6`, not `RawSyscall`; it takes six words.

## Testing on real hardware

The honest way to verify this project needs a Linux host — a VM, WSL2, or a
container platform that can grant `CAP_SYS_ADMIN` and a writable cgroup v2
hierarchy. The plan for that is:

1. Implement `internal/initseq` as a `plan.Op` interpreter.
2. Verify a container can be created with a PID/mount/UTS namespace and a
   read-only rootfs, and that `ps` inside shows one process.
3. Verify isolation *negatively*: confirm the container cannot see host PIDs,
   cannot write to a read-only rootfs, and dies at `pids.max`.
4. Only then claim it works.

The CI workflow runs the test suite on `ubuntu-latest`, which at least validates
the Linux build and executes the platform-independent tests on a real kernel.

## Why build this

To demonstrate that a container is not a virtual machine but a particular
configuration of low-level kernel primitives — and to make each of those
primitives explicit, ordered and testable rather than hidden behind a daemon.

## License

MIT — see [LICENSE](LICENSE). The copyright holder is a placeholder.
