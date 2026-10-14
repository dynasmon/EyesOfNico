package monitor

import (
	"fmt"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PERFORMANCE_INFORMATION uses pointer-sized page counts on both architectures.
// https://learn.microsoft.com/windows/win32/api/psapi/ns-psapi-performance_information
type windowsPerformanceInfo struct {
	Size                                               uint32
	CommitTotal, CommitLimit, CommitPeak               uintptr
	PhysicalTotal, PhysicalAvailable, SystemCache      uintptr
	KernelTotal, KernelPaged, KernelNonpaged, PageSize uintptr
	HandleCount, ProcessCount, ThreadCount             uint32
}

var getPerformanceInfo = windows.NewLazySystemDLL("psapi.dll").NewProc("GetPerformanceInfo")

func windowsMemory(v windowsPerformanceInfo) *WindowsMemory {
	page := uint64(v.PageSize)
	return &WindowsMemory{Available: page > 0,
		CommitTotal: uint64(v.CommitTotal) * page, CommitLimit: uint64(v.CommitLimit) * page,
		CommitPeak: uint64(v.CommitPeak) * page, KernelPaged: uint64(v.KernelPaged) * page,
		KernelNonpaged: uint64(v.KernelNonpaged) * page,
		Handles:        v.HandleCount, Processes: v.ProcessCount, Threads: v.ThreadCount}
}

func (c *Collector) collectPlatform(s *Snapshot) {
	s.Memory.Windows = &WindowsMemory{}
	var v windowsPerformanceInfo
	v.Size = uint32(unsafe.Sizeof(v))
	ok, _, err := getPerformanceInfo.Call(uintptr(unsafe.Pointer(&v)), uintptr(v.Size))
	if ok == 0 || v.PageSize == 0 {
		s.Warnings = append(s.Warnings, fmt.Sprintf("Windows memory counters: %v", err))
		return
	}
	s.Memory.Windows = windowsMemory(v)
	s.Memory.Cached = uint64(v.SystemCache) * uint64(v.PageSize)
	s.Unavailable = slices.DeleteFunc(s.Unavailable, func(name string) bool { return name == "memory_cache" })
}
