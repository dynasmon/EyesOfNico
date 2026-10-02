package monitor

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Options struct {
	ProcRoot string
	SysRoot  string
}

// Collector has one owner. Call Sample from a single goroutine.
type Collector struct {
	proc, sys, host, kernel, model string
	pageSize                       uint64
	ticks                          float64
	last                           time.Time
	cpus                           map[string]cpuTicks
	stats                          map[string]uint64
	networks                       map[string]Network
	disks                          map[string]Disk
	processes                      map[int]Process
	users                          map[uint32]string
	blocks                         map[string]bool
	blockSizes                     map[string]uint64
	lastDiscovery                  time.Time
	slow                           Slow
	slowRequest                    chan struct{}
	slowResult                     chan Slow
	stop                           chan struct{}
	closeOnce                      sync.Once
	lastSlow                       time.Time
	statBuffer                     [4096]byte
}

func New(opts Options) (*Collector, error) {
	if opts.ProcRoot == "" {
		opts.ProcRoot = "/proc"
	}
	if opts.SysRoot == "" {
		opts.SysRoot = "/sys"
	}
	if _, err := os.Stat(filepath.Join(opts.ProcRoot, "stat")); err != nil {
		return nil, fmt.Errorf("Linux /proc is required: %w", err)
	}
	host, _ := os.Hostname()
	c := &Collector{proc: opts.ProcRoot, sys: opts.SysRoot, host: host, pageSize: uint64(os.Getpagesize()), ticks: clockTicks(opts.ProcRoot),
		networks: make(map[string]Network), disks: make(map[string]Disk), processes: make(map[int]Process), users: readUsers(),
		slowRequest: make(chan struct{}, 1), slowResult: make(chan Slow, 1), stop: make(chan struct{})}
	c.kernel = strings.TrimSpace(readText(filepath.Join(c.proc, "sys/kernel/osrelease")))
	for _, line := range strings.Split(readText(filepath.Join(c.proc, "cpuinfo")), "\n") {
		key, val, ok := strings.Cut(line, ":")
		if ok && (strings.TrimSpace(key) == "model name" || strings.TrimSpace(key) == "Hardware") {
			c.model = strings.TrimSpace(val)
			break
		}
	}
	if c.model == "" {
		c.model = "Linux CPU"
	}
	go c.slowWorker()
	return c, nil
}

func (c *Collector) Close() { c.closeOnce.Do(func() { close(c.stop) }) }

func readText(path string) string { b, _ := os.ReadFile(path); return string(b) }

func readLimited(path string, limit int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, limit))
	return string(b)
}

func clockTicks(proc string) float64 {
	b, _ := os.ReadFile(filepath.Join(proc, "self/auxv"))
	word := strconv.IntSize / 8
	for i := 0; i+2*word <= len(b); i += 2 * word {
		var key, val uint64
		if word == 8 {
			key = binary.NativeEndian.Uint64(b[i:])
			val = binary.NativeEndian.Uint64(b[i+word:])
		} else {
			key = uint64(binary.NativeEndian.Uint32(b[i:]))
			val = uint64(binary.NativeEndian.Uint32(b[i+word:]))
		}
		if key == 17 && val > 0 {
			return float64(val)
		} // AT_CLKTCK, no getconf subprocess.
	}
	return 100 // Linux USER_HZ on the supported amd64 and arm64 targets.
}

func readUsers() map[uint32]string {
	users := make(map[uint32]string)
	for _, line := range strings.Split(readText("/etc/passwd"), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 3 {
			n, err := strconv.ParseUint(f[2], 10, 32)
			if err == nil {
				users[uint32(n)] = f[0]
			}
		}
	}
	return users
}

func (c *Collector) Sample(processIO bool) (Snapshot, error) {
	start := time.Now()
	s := Snapshot{At: start, Host: c.host, Kernel: c.kernel, CPUModel: c.model, Pressure: make(map[string]Pressure)}
	if !c.last.IsZero() {
		s.Interval = start.Sub(c.last).Seconds()
		s.Ready = true
	}
	data, err := os.ReadFile(filepath.Join(c.proc, "stat"))
	if err != nil {
		return s, fmt.Errorf("read CPU counters: %w", err)
	}
	cpus, stats := parseCPU(string(data))
	if _, ok := cpus["cpu"]; !ok {
		return s, fmt.Errorf("missing aggregate CPU counters")
	}
	for name, cur := range cpus {
		v := CPU{Name: name}
		if old, ok := c.cpus[name]; ok {
			v = cpuUsage(name, cur, old)
		}
		if name == "cpu" {
			s.CPU = v
		} else {
			s.Cores = append(s.Cores, v)
		}
	}
	sort.Slice(s.Cores, func(i, j int) bool { return integer(s.Cores[i].Name[3:]) < integer(s.Cores[j].Name[3:]) })
	s.Blocked = int(stats["procs_blocked"])
	if s.Ready {
		s.ContextSwitches = rate(stats["ctxt"], c.stats["ctxt"], s.Interval)
		s.Forks = rate(stats["processes"], c.stats["processes"], s.Interval)
	}
	mem, err := os.ReadFile(filepath.Join(c.proc, "meminfo"))
	if err != nil {
		return s, fmt.Errorf("read memory: %w", err)
	}
	s.Memory = parseMemory(string(mem))
	if s.Memory.Total == 0 {
		return s, fmt.Errorf("missing MemTotal in /proc/meminfo")
	}
	if f := strings.Fields(readText(filepath.Join(c.proc, "uptime"))); len(f) > 0 {
		s.Uptime = decimal(f[0])
	}
	if f := strings.Fields(readText(filepath.Join(c.proc, "loadavg"))); len(f) >= 3 {
		for i := range s.Load {
			s.Load[i] = decimal(f[i])
		}
	}
	for _, name := range []string{"cpu", "memory", "io"} {
		s.Pressure[name] = parsePressure(readText(filepath.Join(c.proc, "pressure", name)))
	}
	if c.lastDiscovery.IsZero() || start.Sub(c.lastDiscovery) >= 10*time.Second {
		c.blocks = make(map[string]bool)
		c.blockSizes = make(map[string]uint64)
		entries, _ := os.ReadDir(filepath.Join(c.sys, "block"))
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), "loop") && !strings.HasPrefix(e.Name(), "ram") {
				c.blocks[e.Name()] = true
				c.blockSizes[e.Name()] = number(strings.TrimSpace(readText(filepath.Join(c.sys, "block", e.Name(), "size")))) * 512
			}
		}
		c.lastDiscovery = start
	}
	if b, e := os.ReadFile(filepath.Join(c.proc, "net/dev")); e == nil {
		s.Networks = parseNetworks(string(b))
		next := make(map[string]Network, len(s.Networks))
		for i := range s.Networks {
			n := &s.Networks[i]
			if old, ok := c.networks[n.Name]; ok && s.Ready {
				n.Ready = true
				n.RXRate = rate(n.RXBytes, old.RXBytes, s.Interval)
				n.TXRate = rate(n.TXBytes, old.TXBytes, s.Interval)
				n.RXPackets = rate(n.rxPackets, old.rxPackets, s.Interval)
				n.TXPackets = rate(n.txPackets, old.txPackets, s.Interval)
			}
			next[n.Name] = *n
		}
		c.networks = next
		sort.Slice(s.Networks, func(i, j int) bool { return s.Networks[i].Name < s.Networks[j].Name })
	} else {
		c.networks = make(map[string]Network)
		s.Warnings = append(s.Warnings, "network counters unavailable")
	}
	if b, e := os.ReadFile(filepath.Join(c.proc, "diskstats")); e == nil {
		next := make(map[string]Disk)
		for _, d := range parseDisks(string(b)) {
			if !c.blocks[d.Name] {
				continue
			}
			d.SizeBytes = c.blockSizes[d.Name]
			if old, ok := c.disks[d.Name]; ok && s.Ready {
				d.Ready = true
				d.ReadRate = rate(d.readSectors, old.readSectors, s.Interval) * 512
				d.WriteRate = rate(d.writeSectors, old.writeSectors, s.Interval) * 512
				ops := delta(d.reads, old.reads) + delta(d.writes, old.writes)
				d.IOPS = float64(ops) / s.Interval
				d.Busy = min(100, rate(d.busyMS, old.busyMS, s.Interval)/10)
				d.Queue = rate(d.weightedMS, old.weightedMS, s.Interval) / 1000
				if ops > 0 {
					d.Await = float64(delta(d.readMS, old.readMS)+delta(d.writeMS, old.writeMS)) / float64(ops)
				}
			}
			next[d.Name] = d
			s.Disks = append(s.Disks, d)
		}
		c.disks = next
		sort.Slice(s.Disks, func(i, j int) bool { return s.Disks[i].Name < s.Disks[j].Name })
	} else {
		c.disks = make(map[string]Disk)
		s.Warnings = append(s.Warnings, "disk counters unavailable")
	}
	s.Processes, err = c.collectProcesses(start, s.Interval, processIO)
	if err != nil {
		s.Warnings = append(s.Warnings, err.Error())
	}
	for _, p := range s.Processes {
		s.Threads += p.Threads
		if p.State == "R" {
			s.Running++
		}
	}
	select {
	case c.slow = <-c.slowResult:
	default:
	}
	if c.lastSlow.IsZero() || start.Sub(c.lastSlow) >= 5*time.Second {
		select {
		case c.slowRequest <- struct{}{}:
			c.lastSlow = start
		default:
		}
	}
	s.Slow = c.slow
	c.last = start
	c.cpus = cpus
	c.stats = stats
	s.CollectMS = float64(time.Since(start).Microseconds()) / 1000
	return s, nil
}

func (c *Collector) collectProcesses(now time.Time, elapsed float64, withIO bool) ([]Process, error) {
	entries, err := os.ReadDir(c.proc)
	if err != nil {
		c.processes = make(map[int]Process)
		return nil, fmt.Errorf("process list: %w", err)
	}
	next := make(map[int]Process, len(c.processes))
	result := make([]Process, 0, len(c.processes))
	denied := 0
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		pid, e := strconv.Atoi(name)
		if e != nil || pid <= 0 {
			continue
		}
		base := filepath.Join(c.proc, name)
		b, e := readSmall(filepath.Join(base, "stat"), c.statBuffer[:])
		if e != nil {
			if os.IsPermission(e) {
				denied++
			}
			continue
		}
		p, e := parseProcess(string(b), c.pageSize)
		if e != nil {
			continue
		}
		old, exists := c.processes[pid]
		same := exists && old.StartTicks == p.StartTicks
		p.CPUSeconds = float64(p.Ticks) / c.ticks
		if same {
			p.CPU = rate(p.Ticks, old.Ticks, elapsed) / c.ticks * 100
		}
		if same && p.Name == old.Name && now.Sub(old.metadataAt) < 5*time.Second {
			p.User = old.User
			p.UID = old.UID
			p.Command = old.Command
			p.metadataAt = old.metadataAt
		} else {
			p.UID = ^uint32(0)
			p.User = "?"
			p.metadataAt = now
			for _, line := range strings.Split(readText(filepath.Join(base, "status")), "\n") {
				if strings.HasPrefix(line, "Uid:") {
					f := strings.Fields(line)
					if len(f) >= 3 {
						p.UID = uint32(number(f[2]))
						p.User = c.users[p.UID]
						if p.User == "" {
							p.User = strconv.FormatUint(uint64(p.UID), 10)
						}
					}
					break
				}
			}
			p.Command = strings.TrimSpace(strings.ReplaceAll(readLimited(filepath.Join(base, "cmdline"), 16384), "\x00", " "))
			if p.Command == "" {
				p.Command = "[" + p.Name + "]"
			}
		}
		if withIO {
			p.readBytes, p.writeBytes, p.IOAvailable = parseIO(readText(filepath.Join(base, "io")))
			if same && old.IOAvailable && p.IOAvailable {
				p.ReadRate = rate(p.readBytes, old.readBytes, elapsed)
				p.WriteRate = rate(p.writeBytes, old.writeBytes, elapsed)
			}
		}
		next[pid] = p
		result = append(result, p)
	}
	c.processes = next
	if denied > 0 {
		return result, fmt.Errorf("%d processes hidden by permissions", denied)
	}
	return result, nil
}
