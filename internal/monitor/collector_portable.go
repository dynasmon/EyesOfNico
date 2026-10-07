//go:build darwin || windows

package monitor

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
)

// Collector has one owner. Call Sample from a single goroutine.
type Collector struct {
	host, kernel, model string
	last                time.Time
	cpus                map[string]cpuTicks
	networks            map[string]Network
	disks               map[string]disk.IOCountersStat
	processes           map[int]Process
	users               map[uint32]string
	slow                Slow
	slowRequest         chan struct{}
	slowResult          chan Slow
	stop                chan struct{}
	closeOnce           sync.Once
	lastSlow            time.Time
}

func New(opts Options) (*Collector, error) {
	if opts.ProcRoot != "" || opts.SysRoot != "" {
		return nil, fmt.Errorf("ProcRoot and SysRoot overrides are only supported on Linux")
	}
	c := &Collector{
		cpus: make(map[string]cpuTicks), networks: make(map[string]Network),
		disks: make(map[string]disk.IOCountersStat), processes: make(map[int]Process), users: make(map[uint32]string),
		slowRequest: make(chan struct{}, 1), slowResult: make(chan Slow, 1), stop: make(chan struct{}),
	}
	c.host, _ = os.Hostname()
	c.kernel, _ = host.KernelVersion()
	c.model = runtime.GOARCH
	if info, err := cpu.Info(); err == nil && len(info) > 0 && info[0].ModelName != "" {
		c.model = info[0].ModelName
	}
	go c.slowWorker()
	return c, nil
}

func (c *Collector) Close() { c.closeOnce.Do(func() { close(c.stop) }) }

func portableTicks(t cpu.TimesStat) cpuTicks {
	// Windows kernel time already contains interrupt time. Linux-style
	// accounting must not add it a second time.
	if runtime.GOOS == "windows" {
		t.Irq = 0
	}
	return cpuTicks{uint64(t.User * 1e6), uint64(t.Nice * 1e6), uint64(t.System * 1e6),
		uint64(t.Idle * 1e6), uint64(t.Iowait * 1e6), uint64(t.Irq * 1e6),
		uint64(t.Softirq * 1e6), uint64(t.Steal * 1e6)}
}

func (c *Collector) Sample(processIO bool) (Snapshot, error) {
	start := time.Now()
	s := Snapshot{At: start, OS: runtime.GOOS, Host: c.host, Kernel: c.kernel, CPUModel: c.model,
		Pressure: map[string]Pressure{"cpu": {}, "memory": {}, "io": {}},
		Unavailable: []string{"psi", "cpu_iowait", "cpu_steal", "context_switches", "forks", "disk_busy", "disk_queue", "disk_size", "disk_in_flight", "sensors",
			"memory_cache", "memory_buffers", "memory_slab", "memory_dirty", "process_processor"}}
	if runtime.GOOS == "windows" {
		s.Unavailable = append(s.Unavailable, "disk_await", "process_state", "process_nice", "process_priority", "inodes")
	}
	if !c.last.IsZero() {
		s.Interval = start.Sub(c.last).Seconds()
		s.Ready = true
	}
	times, err := cpu.Times(true)
	if err != nil || len(times) == 0 {
		return s, fmt.Errorf("read CPU counters: %v", err)
	}
	nextCPU := make(map[string]cpuTicks, len(times)+1)
	var total cpuTicks
	for i, t := range times {
		name := fmt.Sprintf("cpu%d", i)
		cur := portableTicks(t)
		v := CPU{Name: name}
		if old, ok := c.cpus[name]; ok {
			v = cpuUsage(name, cur, old)
		}
		s.Cores = append(s.Cores, v)
		nextCPU[name] = cur
		for j := range cur {
			total[j] += cur[j]
		}
	}
	s.CPU = CPU{Name: "cpu"}
	if old, ok := c.cpus["cpu"]; ok && len(c.cpus) == len(nextCPU)+1 {
		s.CPU = cpuUsage("cpu", total, old)
	}
	nextCPU["cpu"] = total
	m, err := mem.VirtualMemory()
	if err != nil {
		return s, fmt.Errorf("read memory: %w", err)
	}
	if m.Total == 0 {
		return s, fmt.Errorf("missing physical memory total")
	}
	s.Memory = Memory{Total: m.Total, Available: min(m.Available, m.Total),
		Used: delta(m.Total, m.Available), Cached: m.Cached, Buffers: m.Buffers, Slab: m.Slab, Dirty: m.Dirty}
	if swap, e := mem.SwapMemory(); e == nil {
		s.Memory.SwapTotal, s.Memory.SwapUsed = swap.Total, swap.Used
	} else {
		s.Unavailable = append(s.Unavailable, "swap")
	}
	if uptime, e := host.Uptime(); e == nil {
		s.Uptime = float64(uptime)
	}
	if avg, e := loadAverage(); e == nil {
		s.Load = avg
	} else {
		s.Unavailable = append(s.Unavailable, "load")
	}
	c.collectPlatform(&s)
	s.Networks, err = c.collectNetworks(s.Interval)
	if err != nil {
		s.Warnings = append(s.Warnings, "network counters: "+err.Error())
	}
	s.Disks, err = c.collectDisks(s.Interval)
	if err != nil {
		s.Warnings = append(s.Warnings, "disk counters: "+err.Error())
	}
	s.Processes, err = c.collectProcesses(start, processIO)
	if err != nil {
		s.Warnings = append(s.Warnings, "process list: "+err.Error())
	}
	nextProcesses := make(map[int]Process, len(s.Processes))
	for i := range s.Processes {
		p := &s.Processes[i]
		if old, ok := c.processes[p.PID]; ok {
			processRates(p, old, s.Interval)
		}
		nextProcesses[p.PID] = *p
		s.Threads += p.Threads
		if p.State == "R" {
			s.Running++
		}
		if p.State == "D" {
			s.Blocked++
		}
	}
	c.processes = nextProcesses
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
	if len(s.Slow.Sensors) > 0 {
		for i, name := range s.Unavailable {
			if name == "sensors" {
				s.Unavailable = append(s.Unavailable[:i], s.Unavailable[i+1:]...)
				break
			}
		}
	}
	c.last, c.cpus = start, nextCPU
	s.CollectMS = float64(time.Since(start).Microseconds()) / 1000
	return s, nil
}

func processRates(p *Process, old Process, elapsed float64) {
	if elapsed <= 0 || p.StartTicks == 0 || p.StartTicks != old.StartTicks {
		return
	}
	if p.MetricAvailable("cpu") && old.MetricAvailable("cpu") && p.MetricsSource == old.MetricsSource {
		p.CPU = max(0, p.CPUSeconds-old.CPUSeconds) / elapsed * 100
	}
	if p.IOAvailable && old.IOAvailable {
		p.ReadRate = rate(p.readBytes, old.readBytes, elapsed)
		p.WriteRate = rate(p.writeBytes, old.writeBytes, elapsed)
	}
}

func (c *Collector) collectNetworks(elapsed float64) ([]Network, error) {
	counters, err := gnet.IOCounters(true)
	if err != nil {
		c.networks = make(map[string]Network)
		return nil, err
	}
	loopbacks := make(map[string]bool)
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		loopbacks[iface.Name] = iface.Flags&net.FlagLoopback != 0
	}
	next := make(map[string]Network, len(counters))
	result := make([]Network, 0, len(counters))
	for _, cur := range counters {
		n := Network{Name: cur.Name, Loopback: loopbacks[cur.Name], RXBytes: cur.BytesRecv, TXBytes: cur.BytesSent,
			rxPackets: cur.PacketsRecv, txPackets: cur.PacketsSent,
			Errors: cur.Errin + cur.Errout, Drops: cur.Dropin + cur.Dropout}
		if old, ok := c.networks[n.Name]; ok && elapsed > 0 {
			n.Ready = true
			n.RXRate, n.TXRate = rate(n.RXBytes, old.RXBytes, elapsed), rate(n.TXBytes, old.TXBytes, elapsed)
			n.RXPackets, n.TXPackets = rate(n.rxPackets, old.rxPackets, elapsed), rate(n.txPackets, old.txPackets, elapsed)
		}
		next[n.Name] = n
		result = append(result, n)
	}
	c.networks = next
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func portableDisk(cur, old disk.IOCountersStat, elapsed float64, ready bool) Disk {
	d := Disk{Name: cur.Name, InFlight: cur.IopsInProgress, Ready: ready && elapsed > 0}
	if d.Ready {
		d.ReadRate = rate(cur.ReadBytes, old.ReadBytes, elapsed)
		d.WriteRate = rate(cur.WriteBytes, old.WriteBytes, elapsed)
		ops := delta(cur.ReadCount, old.ReadCount) + delta(cur.WriteCount, old.WriteCount)
		d.IOPS = float64(ops) / elapsed
		if ops > 0 {
			d.Await = float64(delta(cur.ReadTime, old.ReadTime)+delta(cur.WriteTime, old.WriteTime)) / float64(ops)
		}
	}
	return d
}

func (c *Collector) collectDisks(elapsed float64) ([]Disk, error) {
	counters, err := disk.IOCounters()
	if err != nil {
		c.disks = make(map[string]disk.IOCountersStat)
		return nil, err
	}
	result := make([]Disk, 0, len(counters))
	for name, cur := range counters {
		cur.Name = name
		old, ok := c.disks[name]
		d := portableDisk(cur, old, elapsed, ok)
		if runtime.GOOS == "windows" {
			// This backend does not expose sufficiently precise latency counters.
			d.Await = 0
		}
		result = append(result, d)
	}
	c.disks = counters
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}
