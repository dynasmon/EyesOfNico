//go:build darwin || windows

package monitor

import (
	"net"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
)

func localPartition(p disk.PartitionStat) bool {
	if runtime.GOOS == "darwin" && !slices.Contains(p.Opts, "local") {
		return false
	}
	switch strings.ToLower(p.Fstype) {
	case "apfs", "hfs", "hfs+", "msdos", "exfat", "ntfs", "refs", "fat", "fat32", "udf", "cd9660":
		return true
	}
	return false
}

func (c *Collector) collectSlow() Slow {
	s := Slow{NetworkState: make(map[string]string)}
	partitions, err := disk.Partitions(false)
	if err != nil {
		s.Warnings = append(s.Warnings, "filesystems: "+err.Error())
	}
	seen := make(map[string]bool)
	for _, p := range partitions {
		if !localPartition(p) || seen[p.Device] {
			continue
		}
		seen[p.Device] = true
		usage, e := disk.Usage(p.Mountpoint)
		if e != nil {
			s.Warnings = append(s.Warnings, p.Mountpoint+": "+e.Error())
			continue
		}
		if usage.Total > 0 {
			s.Filesystems = append(s.Filesystems, Filesystem{Mount: p.Mountpoint, Device: p.Device, Type: p.Fstype,
				Total: usage.Total, Used: usage.Used, Available: usage.Free, InodeUsed: usage.InodesUsedPercent})
		}
	}
	sort.Slice(s.Filesystems, func(i, j int) bool { return s.Filesystems[i].Mount < s.Filesystems[j].Mount })
	if info, e := cpu.Info(); e == nil && len(info) > 0 {
		s.FrequencyMHz = info[0].Mhz
	}
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		state := "down"
		if iface.Flags&net.FlagUp != 0 {
			state = "up"
		}
		s.NetworkState[iface.Name] = state
	}
	collectPlatformSensors(&s)
	s.At = time.Now()
	return s
}
