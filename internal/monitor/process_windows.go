package monitor

import (
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

// Windows has no Unix 1/5/15-minute load averages.
func loadAverage() ([3]float64, error) { return [3]float64{}, fmt.Errorf("unavailable on Windows") }

func (c *Collector) collectProcesses(now time.Time, withIO bool) ([]Process, error) {
	pids, err := process.Pids()
	if err != nil {
		return nil, err
	}
	result := make([]Process, 0, len(pids))
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		native := &process.Process{Pid: pid}
		created, e := native.CreateTime()
		if e != nil || created <= 0 {
			continue // Protected or exited processes cannot establish an identity.
		}
		p := Process{PID: int(pid), StartTicks: uint64(created), UID: ^uint32(0), Processor: -1, State: "?"}
		old, same := c.processes[p.PID]
		if same && old.StartTicks == p.StartTicks && now.Sub(old.metadataAt) < 5*time.Second {
			p.Name, p.Command, p.User, p.PPID, p.metadataAt = old.Name, old.Command, old.User, old.PPID, old.metadataAt
		} else {
			p.metadataAt = now
			p.Name, _ = native.Name()
			p.Command, _ = native.Cmdline()
			p.User, _ = native.Username()
			ppid, _ := native.Ppid()
			p.PPID = int(ppid)
			if p.Command == "" {
				p.Command = "[" + p.Name + "]"
			}
			if p.User == "" {
				p.User = "?"
			}
		}
		if times, e := native.Times(); e == nil {
			p.CPUSeconds = times.User + times.System
		} else {
			p.Unavailable = append(p.Unavailable, "cpu")
		}
		if memory, e := native.MemoryInfo(); e == nil {
			p.RSS, p.Virtual = memory.RSS, memory.VMS
		} else {
			p.Unavailable = append(p.Unavailable, "memory")
		}
		if threads, e := native.NumThreads(); e == nil {
			p.Threads = int(threads)
		} else {
			p.Unavailable = append(p.Unavailable, "threads")
		}
		if withIO {
			if io, e := native.IOCounters(); e == nil {
				p.readBytes, p.writeBytes, p.IOAvailable = io.ReadBytes, io.WriteBytes, true
			}
		}
		result = append(result, p)
	}
	return result, nil
}
