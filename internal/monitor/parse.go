package monitor

import (
	"fmt"
	"strconv"
	"strings"
)

func number(s string) uint64   { n, _ := strconv.ParseUint(s, 10, 64); return n }
func integer(s string) int     { n, _ := strconv.Atoi(s); return n }
func decimal(s string) float64 { n, _ := strconv.ParseFloat(s, 64); return n }

type cpuTicks [8]uint64 // guest and guest_nice already belong to user and nice.

func parseCPU(data string) (map[string]cpuTicks, map[string]uint64) {
	cpus := make(map[string]cpuTicks)
	stats := make(map[string]uint64)
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if (f[0] == "cpu" || (strings.HasPrefix(f[0], "cpu") && len(f[0]) > 3 && f[0][3] >= '0' && f[0][3] <= '9')) && len(f) >= 5 {
			var t cpuTicks
			for i := 0; i < len(t) && i+1 < len(f); i++ {
				t[i] = number(f[i+1])
			}
			cpus[f[0]] = t
		} else if len(f) == 2 {
			stats[f[0]] = number(f[1])
		}
	}
	return cpus, stats
}

func cpuUsage(name string, cur, old cpuTicks) CPU {
	c := CPU{Name: name}
	var d [8]float64
	var total float64
	for i := range cur {
		d[i] = float64(delta(cur[i], old[i]))
		total += d[i]
	}
	if total == 0 {
		return c
	}
	c.User = (d[0] + d[1]) / total * 100
	c.System = (d[2] + d[5] + d[6]) / total * 100
	c.Wait = d[4] / total * 100
	c.Steal = d[7] / total * 100
	c.Busy = c.User + c.System + c.Steal
	return c
}

func parseMemory(data string) Memory {
	v := make(map[string]uint64, 32)
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			v[strings.TrimSuffix(f[0], ":")] = number(f[1]) * 1024
		}
	}
	available, ok := v["MemAvailable"]
	if !ok {
		available = v["MemFree"] + v["Buffers"] + v["Cached"] + v["SReclaimable"]
	}
	available = min(available, v["MemTotal"])
	return Memory{Total: v["MemTotal"], Available: available, Used: delta(v["MemTotal"], available),
		Cached: delta(v["Cached"]+v["SReclaimable"], v["Shmem"]), Buffers: v["Buffers"],
		Slab: v["Slab"], Dirty: v["Dirty"] + v["Writeback"], SwapTotal: v["SwapTotal"], SwapUsed: delta(v["SwapTotal"], v["SwapFree"])}
}

func parsePressure(data string) Pressure {
	var p Pressure
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || (f[0] != "some" && f[0] != "full") {
			continue
		}
		var v [3]float64
		count := 0
		for _, field := range f[1:] {
			k, val, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			i := -1
			switch k {
			case "avg10":
				i = 0
			case "avg60":
				i = 1
			case "avg300":
				i = 2
			}
			if i >= 0 {
				n, err := strconv.ParseFloat(val, 64)
				if err == nil {
					v[i] = n
					count++
				}
			}
		}
		if count != 3 {
			continue
		}
		if f[0] == "some" {
			p.Some = v
			p.Available = true
		} else {
			p.Full = v
		}
	}
	return p
}

func parseNetworks(data string) []Network {
	var result []Network
	for _, line := range strings.Split(data, "\n") {
		name, values, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(values)
		if len(f) < 16 {
			continue
		}
		result = append(result, Network{Name: strings.TrimSpace(name), RXBytes: number(f[0]), TXBytes: number(f[8]),
			rxPackets: number(f[1]), txPackets: number(f[9]), Errors: number(f[2]) + number(f[10]), Drops: number(f[3]) + number(f[11])})
	}
	return result
}

func parseDisks(data string) []Disk {
	var result []Disk
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 14 {
			continue
		}
		result = append(result, Disk{Name: f[2], reads: number(f[3]), readSectors: number(f[5]), readMS: number(f[6]),
			writes: number(f[7]), writeSectors: number(f[9]), writeMS: number(f[10]), InFlight: number(f[11]), busyMS: number(f[12]), weightedMS: number(f[13])})
	}
	return result
}

func parseProcess(data string, pageSize uint64) (Process, error) {
	// comm may contain spaces, newlines and parentheses, including ')'.
	left, right := strings.IndexByte(data, '('), strings.LastIndexByte(data, ')')
	if left < 1 || right <= left {
		return Process{}, fmt.Errorf("invalid process stat")
	}
	// /proc/PID/stat has a fixed numeric tail. A stack array avoids allocating
	// a Fields slice for every process on every tick.
	var fields [52]string
	count := 0
	tail := data[right+1:]
	for i := 0; i < len(tail) && count < len(fields); {
		for i < len(tail) && tail[i] <= ' ' {
			i++
		}
		start := i
		for i < len(tail) && tail[i] > ' ' {
			i++
		}
		if start < i {
			fields[count] = tail[start:i]
			count++
		}
	}
	f := fields[:count]
	if len(f) < 22 {
		return Process{}, fmt.Errorf("short process stat")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(data[:left]))
	if err != nil || pid <= 0 {
		return Process{}, fmt.Errorf("invalid pid")
	}
	start, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return Process{}, err
	}
	p := Process{PID: pid, Name: strings.Clone(data[left+1 : right]), State: strings.Clone(f[0]), PPID: integer(f[1]), Ticks: number(f[11]) + number(f[12]),
		Priority: integer(f[15]), Nice: integer(f[16]), Threads: integer(f[17]), StartTicks: start, Virtual: number(f[20]), RSS: number(f[21]) * pageSize}
	if len(f) > 36 {
		p.Processor = integer(f[36])
	}
	return p, nil
}

func parseIO(data string) (read, write uint64, ok bool) {
	count := 0
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		switch f[0] {
		case "read_bytes:":
			read = number(f[1])
			count++
		case "write_bytes:":
			write = number(f[1])
			count++
		}
	}
	return read, write, count == 2
}
