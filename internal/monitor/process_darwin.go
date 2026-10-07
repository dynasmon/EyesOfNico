package monitor

import (
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"
)

func loadAverage() ([3]float64, error) {
	avg, err := load.Avg()
	if err != nil {
		return [3]float64{}, err
	}
	return [3]float64{avg.Load1, avg.Load5, avg.Load15}, nil
}

func darwinIdentity(k *unix.KinfoProc) uint64 {
	return uint64(k.Proc.P_starttime.Sec)*1_000_000 + uint64(k.Proc.P_starttime.Usec)
}

func (c *Collector) collectProcesses(now time.Time, withIO bool) ([]Process, error) {
	reader, err := loadDarwinTaskReader()
	if err != nil {
		return nil, err
	}
	// Fetch state, identity and ownership together. gopsutil's Darwin Status
	// invokes ps per PID, so use this bulk kernel table instead.
	entries, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	result := make([]Process, 0, len(entries))
	for _, k := range entries {
		if k.Proc.P_pid <= 0 {
			continue
		}
		p := Process{PID: int(k.Proc.P_pid), PPID: int(k.Eproc.Ppid), UID: k.Eproc.Ucred.Uid,
			Name: unix.ByteSliceToString(k.Proc.P_comm[:]), StartTicks: darwinIdentity(&k),
			Nice: int(k.Proc.P_nice), Priority: int(k.Proc.P_priority), Processor: -1, State: "?"}
		// sys/proc.h: SIDL, SRUN, SSLEEP, SSTOP, SZOMB.
		switch k.Proc.P_stat {
		case 1:
			p.State = "I"
		case 2:
			p.State = "R"
		case 3:
			p.State = "S"
		case 4:
			p.State = "T"
		case 5:
			p.State = "Z"
		}
		native := &process.Process{Pid: k.Proc.P_pid}
		old, same := c.processes[p.PID]
		if same && old.StartTicks == p.StartTicks && old.UID == p.UID && now.Sub(old.metadataAt) < 5*time.Second {
			p.Name, p.Command, p.User, p.metadataAt = old.Name, old.Command, old.User, old.metadataAt
		} else {
			p.metadataAt = now
			p.Command, _ = native.Cmdline()
			if exe, e := native.Exe(); e == nil && exe != "" {
				p.Name = filepath.Base(exe)
			}
			p.User = c.users[p.UID]
			if p.User == "" {
				p.User = strconv.FormatUint(uint64(p.UID), 10)
				if current, e := user.Current(); e == nil && current.Uid == p.User {
					p.User = current.Username
				} else if owner, e := user.LookupId(p.User); e == nil {
					p.User = owner.Username
				}
				c.users[p.UID] = p.User
			}
			if strings.TrimSpace(p.Command) == "" {
				p.Command = "[" + p.Name + "]"
			}
		}
		reader.read(&p)
		if withIO {
			if io, e := native.IOCounters(); e == nil {
				p.readBytes, p.writeBytes, p.IOAvailable = io.DiskReadBytes, io.DiskWriteBytes, true
			}
		}
		result = append(result, p)
	}
	return result, fillDarwinProcessMetrics(result)
}
