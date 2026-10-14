package monitor

import (
	"github.com/shirou/gopsutil/v4/disk"
	"sort"
)

type platformState struct{}

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
		result = append(result, d)
	}
	c.disks = counters
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}
