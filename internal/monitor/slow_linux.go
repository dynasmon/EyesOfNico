package monitor

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

var mountEscapes = strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)

func localMounts(data string) []Filesystem {
	// Avoid remote/FUSE/autofs mounts: statfs on an unavailable server can hang.
	local := map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true, "vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "overlay": true, "bcachefs": true, "jfs": true, "reiserfs": true}
	seen := make(map[string]bool)
	var result []Filesystem
	for _, line := range strings.Split(data, "\n") {
		left, right, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		a, b := strings.Fields(left), strings.Fields(right)
		if len(a) < 6 || len(b) < 2 || !local[b[0]] {
			continue
		}
		mount := mountEscapes.Replace(a[4])
		root := mountEscapes.Replace(a[3])
		// Container layers beneath another root are not host storage volumes.
		if b[0] == "overlay" && mount != "/" {
			continue
		}
		// A bind of a file/subdirectory is not another filesystem. Btrfs subvolumes share capacity.
		key := a[2] + ":" + b[0]
		if seen[key] || (root != "/" && b[0] != "btrfs") {
			continue
		}
		seen[key] = true
		result = append(result, Filesystem{Mount: mount, Device: mountEscapes.Replace(b[1]), Type: b[0]})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Mount < result[j].Mount })
	return result
}

func (c *Collector) collectSlow() Slow {
	s := Slow{NetworkState: make(map[string]string)}
	for _, fs := range localMounts(readText(filepath.Join(c.proc, "self/mountinfo"))) {
		var v syscall.Statfs_t
		if err := syscall.Statfs(fs.Mount, &v); err != nil {
			s.Warnings = append(s.Warnings, fs.Mount+": "+err.Error())
			continue
		}
		if v.Blocks == 0 {
			continue
		}
		fs.Total = v.Blocks * uint64(v.Bsize)
		fs.Used = delta(v.Blocks, v.Bfree) * uint64(v.Bsize)
		fs.Available = v.Bavail * uint64(v.Bsize)
		fs.InodeUsed = Percent(delta(v.Files, v.Ffree), v.Files)
		s.Filesystems = append(s.Filesystems, fs)
	}
	paths, _ := filepath.Glob(filepath.Join(c.sys, "class/hwmon/hwmon*/temp*_input"))
	for _, path := range paths {
		raw := strings.TrimSpace(readText(path))
		if raw == "" {
			continue
		}
		v := decimal(raw) / 1000
		if v < -20 || v > 150 {
			continue
		}
		base := filepath.Dir(path)
		name := strings.TrimSpace(readText(filepath.Join(base, "name")))
		label := strings.TrimSpace(readText(strings.TrimSuffix(path, "_input") + "_label"))
		if label == "" {
			label = strings.TrimSuffix(filepath.Base(path), "_input")
		}
		s.Sensors = append(s.Sensors, Sensor{Name: name + " " + label, Celsius: v})
	}
	if len(s.Sensors) == 0 {
		paths, _ = filepath.Glob(filepath.Join(c.sys, "class/thermal/thermal_zone*/temp"))
		for _, path := range paths {
			raw := strings.TrimSpace(readText(path))
			if raw == "" {
				continue
			}
			v := decimal(raw) / 1000
			if v >= -20 && v <= 150 {
				s.Sensors = append(s.Sensors, Sensor{Name: strings.TrimSpace(readText(filepath.Join(filepath.Dir(path), "type"))), Celsius: v})
			}
		}
	}
	paths, _ = filepath.Glob(filepath.Join(c.sys, "devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq"))
	n := 0
	for _, path := range paths {
		v := decimal(strings.TrimSpace(readText(path)))
		if v > 0 {
			s.FrequencyMHz += v / 1000
			n++
		}
	}
	if n > 0 {
		s.FrequencyMHz /= float64(n)
	}
	entries, _ := os.ReadDir(filepath.Join(c.sys, "class/net"))
	for _, e := range entries {
		s.NetworkState[e.Name()] = strings.TrimSpace(readText(filepath.Join(c.sys, "class/net", e.Name(), "operstate")))
	}
	s.At = time.Now()
	return s
}
