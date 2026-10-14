package monitor

import (
	"errors"
	"fmt"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DISK_PERFORMANCE durations are cumulative 100 ns units, not milliseconds.
// QueueDepth is an instantaneous count, not an average queue length.
// https://learn.microsoft.com/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_disk_performance
type windowsDiskCounters struct {
	BytesRead, BytesWritten, ReadTime, WriteTime, IdleTime int64
	ReadCount, WriteCount, QueueDepth, SplitCount          uint32
	QueryTime                                              int64
	StorageDeviceNumber                                    uint32
	StorageManagerName                                     [8]uint16
}

type platformState struct {
	disks map[string]windowsDiskCounters
}

func readWindowsDisk(name string) (windowsDiskCounters, error) {
	var v windowsDiskCounters
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(`\\.\`+name), 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return v, err
	}
	defer windows.CloseHandle(h)
	var returned uint32
	err = windows.DeviceIoControl(h, 0x70020, nil, 0, (*byte)(unsafe.Pointer(&v)), uint32(unsafe.Sizeof(v)), &returned, nil)
	if err == nil && returned < uint32(unsafe.Sizeof(v)) {
		err = fmt.Errorf("short DISK_PERFORMANCE response: %d bytes", returned)
	}
	return v, err
}

func windowsDisk(name string, cur, old windowsDiskCounters, elapsed float64, ready bool) Disk {
	d := Disk{Name: name, InFlight: uint64(cur.QueueDepth)}
	// Device replacement, counter reset, and clock changes establish a new baseline.
	if !ready || elapsed <= 0 || cur.QueryTime <= old.QueryTime ||
		cur.StorageDeviceNumber != old.StorageDeviceNumber || cur.StorageManagerName != old.StorageManagerName ||
		cur.BytesRead < old.BytesRead || cur.BytesWritten < old.BytesWritten ||
		cur.ReadTime < old.ReadTime || cur.WriteTime < old.WriteTime || cur.IdleTime < old.IdleTime ||
		cur.ReadCount < old.ReadCount || cur.WriteCount < old.WriteCount {
		return d
	}
	d.Ready = true
	d.ReadRate = float64(cur.BytesRead-old.BytesRead) / elapsed
	d.WriteRate = float64(cur.BytesWritten-old.BytesWritten) / elapsed
	ops := uint64(cur.ReadCount-old.ReadCount) + uint64(cur.WriteCount-old.WriteCount)
	d.IOPS = float64(ops) / elapsed
	if ops > 0 {
		d.Await = (float64(cur.ReadTime-old.ReadTime) + float64(cur.WriteTime-old.WriteTime)) / 1e4 / float64(ops)
	}
	d.Busy = max(0, min(100, 100*(1-float64(cur.IdleTime-old.IdleTime)/float64(cur.QueryTime-old.QueryTime))))
	return d
}

func (c *Collector) collectDisks(elapsed float64) ([]Disk, error) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		c.platform.disks = nil
		return nil, err
	}
	next := make(map[string]windowsDiskCounters)
	var result []Disk
	var failures []error
	for letter := 0; letter < 26; letter++ {
		if mask&(1<<letter) == 0 {
			continue
		}
		name := fmt.Sprintf("%c:", 'A'+letter)
		if windows.GetDriveType(windows.StringToUTF16Ptr(name+`\`)) != windows.DRIVE_FIXED {
			continue
		}
		cur, e := readWindowsDisk(name)
		if e != nil {
			failures = append(failures, fmt.Errorf("%s: %w", name, e))
			continue
		}
		old, ok := c.platform.disks[name]
		result = append(result, windowsDisk(name, cur, old, elapsed, ok))
		next[name] = cur
	}
	c.platform.disks = next
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, errors.Join(failures...)
}
