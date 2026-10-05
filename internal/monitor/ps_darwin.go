package monitor

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type psMetrics struct {
	startSeconds int64
	rss, virtual uint64
	cpuSeconds   float64
	threads      int
	state        string
}

func parsePSTime(value string) (float64, error) {
	// macOS ps prints cumulative CPU time as minutes:seconds.hundredths.
	minutes, seconds, ok := strings.Cut(value, ":")
	if !ok {
		return 0, fmt.Errorf("invalid ps CPU time")
	}
	m, e1 := strconv.ParseUint(minutes, 10, 64)
	s, e2 := strconv.ParseFloat(seconds, 64)
	if e1 != nil || e2 != nil || s < 0 || s >= 60 || math.IsNaN(s) || math.IsInf(s, 0) {
		return 0, fmt.Errorf("invalid ps CPU time")
	}
	return float64(m)*60 + s, nil
}

func parsePSMetrics(data string) map[int]psMetrics {
	result := make(map[int]psMetrics)
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		// -M adds a built-in thread prefix, including a truncated command.
		// Our explicitly requested columns are always the final ten fields.
		if len(fields) < 10 {
			continue
		}
		f := fields[len(fields)-10:]
		pid, e1 := strconv.Atoi(f[0])
		rss, e2 := strconv.ParseUint(f[1], 10, 64)
		virtual, e3 := strconv.ParseUint(f[2], 10, 64)
		cpu, e4 := parsePSTime(f[3])
		started, e5 := time.Parse("Mon Jan 2 15:04:05 2006", strings.Join(f[5:], " "))
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || pid <= 0 || rss > math.MaxUint64/1024 || virtual > math.MaxUint64/1024 {
			continue
		}
		state := f[4][:1]
		if !strings.Contains("RSDTUIZ?", state) {
			continue
		}
		m := result[pid]
		if m.threads > 0 && m.startSeconds != started.Unix() {
			continue
		}
		m.startSeconds, m.rss, m.virtual, m.cpuSeconds = started.Unix(), rss*1024, virtual*1024, cpu
		m.threads++
		if m.state == "" || state == "R" || (m.state != "R" && state == "T") {
			m.state = state
		}
		result[pid] = m
	}
	return result
}

func applyPSMetrics(p *Process, m psMetrics, currentIdentity uint64) bool {
	// ps reports birth time to the second; the fresh kernel table also verifies
	// the original microsecond identity, so PID reuse cannot mix our samples.
	if p.StartTicks == 0 || p.StartTicks != currentIdentity || int64(p.StartTicks/1_000_000) != m.startSeconds || m.threads == 0 {
		return false
	}
	p.CPUSeconds, p.RSS, p.Virtual, p.Threads = m.cpuSeconds, m.rss, m.virtual, m.threads
	if p.State != "T" && p.State != "Z" {
		p.State = m.state
	}
	p.MetricsSource = "ps"
	p.Unavailable = slices.DeleteFunc(p.Unavailable, func(metric string) bool {
		return metric == "cpu" || metric == "memory" || metric == "threads"
	})
	return true
}

// Apple's /bin/ps can read basic statistics for other users' processes that
// proc_pidinfo denies to this process. One bounded batch, no shell or sudo.
func fillDarwinProcessMetrics(processes []Process) error {
	var pids []string
	for _, p := range processes {
		if !p.MetricAvailable("cpu") || !p.MetricAvailable("memory") {
			pids = append(pids, strconv.Itoa(p.PID))
		}
	}
	if len(pids) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/ps", "-M", "-p", strings.Join(pids, ","), "-o", "pid=,rss=,vsz=,time=,state=,lstart=")
	cmd.Env = append(os.Environ(), "LC_ALL=C", "TZ=UTC")
	cmd.WaitDelay = 100 * time.Millisecond
	data, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("macOS process fallback: %w", err)
	}
	metrics := parsePSMetrics(string(data))
	entries, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return fmt.Errorf("verify process identities: %w", err)
	}
	identities := make(map[int]uint64, len(entries))
	for _, k := range entries {
		identities[int(k.Proc.P_pid)] = darwinIdentity(&k)
	}
	for i := range processes {
		p := &processes[i]
		if !p.MetricAvailable("cpu") || !p.MetricAvailable("memory") {
			applyPSMetrics(p, metrics[p.PID], identities[p.PID])
		}
	}
	return nil
}
