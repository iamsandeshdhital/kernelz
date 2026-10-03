package spec

import (
	"fmt"
	"strings"
)

// cgroupOps converts declarative resource limits into concrete writes against
// the cgroup virtual filesystem.
//
// cgroups are a control-plane masquerading as a filesystem: every "setting" is
// literally a write(2) to a control file, and the kernel's cgroup drivers
// validate and act on it synchronously. There is no ioctl, no RPC.
//
// v2 is a single unified hierarchy and the file names are the knobs. v1 splits
// controllers across separate hierarchies with different file names per
// controller, which is why v2 writes and v1 writes look nothing alike. The
// executor probes the host and picks a path; this function records intent in a
// controller-agnostic way.
func (r Resources) cgroupOps(id string) []Op {
	var ops []Op

	add := func(controller, file, value string, fatal bool) {
		ops = append(ops, Op{
			Kind:      OpWriteCgroup,
			Value:     controller,
			Values:    []string{file, value},
			Detail:    fmt.Sprintf("cgroup v2 %s/%s <- %q", controller, file, value),
			FailFatal: fatal,
		})
	}

	// --- Memory. memory.max is the hard limit; "max" means unlimited.
	//
	// Note the asymmetry: a container with no memory.max is limited only by
	// physical RAM, and can therefore OOM the *host*. This is the single most
	// important cgroup write a runtime makes.
	if r.MemoryLimitBytes > 0 {
		add("memory", "memory.max", fmt.Sprintf("%d", r.MemoryLimitBytes), true)
	}
	if r.MemorySwapBytes > 0 {
		// memory.swap is *additional* swap beyond memory.max, not a total.
		add("memory", "memory.swap.max", fmt.Sprintf("%d", r.MemorySwapBytes), false)
	} else if r.MemoryLimitBytes > 0 {
		// The kernel swaps a container before it OOM-kills it, and those pages
		// land in the *host's* swap. That hands the container a timing channel
		// against its co-tenants, so runc defaults swap off and so do we: a
		// memory-limited container gets OOM-killed instead of being swapped.
		add("memory", "memory.swap.max", "0", false)
	}

	// --- CPU. cpu.max is a $MAX/$PERIOD pair, e.g. "150000/100000" = 1.5 CPUs.
	if r.CPUQuota > 0 {
		const period = 100000 // 100ms, the kernel's default CFS period
		quota := int64(r.CPUQuota * float64(period))
		if quota < 1000 {
			// Below 10ms of quota the task is starved; the kernel treats an
			// absurdly small quota as a throttle storm, so clamp it.
			quota = 1000
		}
		add("cpu", "cpu.max", fmt.Sprintf("%d/%d", quota, period), true)
	}
	if r.CPUShares > 0 {
		// cpu.weight is the v2 spelling of cpuset/CPU shares: 1..10000,
		// default 100. It is a *relative* weight, not a percentage.
		w := r.CPUShares
		if w < 1 {
			w = 1
		}
		if w > 10000 {
			w = 10000
		}
		add("cpu", "cpu.weight", fmt.Sprintf("%d", w), false)
	}
	if r.CPUSetCPUs != "" {
		// cpuset.cpus must be a subset of the parent's effective mask, or the
		// write is rejected with EINVAL.
		add("cpu", "cpuset.cpus", r.CPUSetCPUs, false)
	}

	// --- PIDs. Without pids.max a container can fork until it exhausts the
	// host's PID space and takes down every other process on the machine.
	// This is a denial-of-service primitive aimed at the host, not the
	// container, so it is treated as fatal when explicitly requested.
	if r.PidsLimit >= 0 {
		add("pids", "pids.max", fmt.Sprintf("%d", r.PidsLimit), true)
	}

	// --- OOM behaviour.
	if r.OOMScoreAdj != 0 {
		// oom_score_adj lives in /proc/<pid>/, not in the cgroup fs.
		ops = append(ops, Op{
			Kind:   OpWriteCgroup,
			Value:  "proc",
			Values: []string{"oom_score_adj", fmt.Sprintf("%d", r.OOMScoreAdj)},
			Detail: fmt.Sprintf("/proc/<init>/oom_score_adj <- %d", r.OOMScoreAdj),
		})
	}
	if r.DisableOOMKiller {
		add("memory", "memory.oom_control", "", false)
	}

	// --- Devices. v2 expresses this as an eBPF program, not a file, so on a v2
	// host it is a no-op and the executor reports the gap rather than
	// pretending to enforce it.
	for _, d := range r.AllowedDevicesRaw {
		if !strings.HasPrefix(d, "/dev/") {
			return append(ops, Op{
				Kind:   OpWriteCgroup,
				Value:  "devices",
				Values: []string{"deny", d},
				Detail: fmt.Sprintf("devices.allow %s (unsupported on cgroup v2)", d),
			})
		}
	}

	return ops
}
