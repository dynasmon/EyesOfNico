package monitor

import (
	"fmt"
	"os"
	"slices"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// The stable rev1 prefix of vm_statistics64 in mach/vm_statistics.h. Request
// exactly this revision's count (38 32-bit words), including 64-bit alignment.
type darwinVMStats struct {
	Free, Active, Inactive, Wired                      uint32
	ZeroFill, Reactivations, Pageins, Pageouts, Faults uint64
	COWFaults, Lookups, Hits, Purges                   uint64
	Purgeable, Speculative                             uint32
	Decompressions, Compressions, Swapins, Swapouts    uint64
	Compressor, Throttled, External, Internal          uint32
	Uncompressed                                       uint64
}

type darwinVMReader struct {
	host uint32
	read func(uint32, int32, unsafe.Pointer, *uint32) int32
}

var loadDarwinVMReader = sync.OnceValues(func() (*darwinVMReader, error) {
	lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_LAZY|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	symbol, err := purego.Dlsym(lib, "host_statistics64")
	if err != nil {
		return nil, err
	}
	r := &darwinVMReader{}
	purego.RegisterFunc(&r.read, symbol)
	symbol, err = purego.Dlsym(lib, "mach_host_self")
	if err != nil {
		return nil, err
	}
	var hostSelf func() uint32
	purego.RegisterFunc(&hostSelf, symbol)
	r.host = hostSelf() // Retain one host port for the process lifetime.
	return r, nil
})

func darwinMemory(v darwinVMStats, pageSize uint64) *DarwinMemory {
	return &DarwinMemory{Available: true, Free: uint64(v.Free) * pageSize,
		Active: uint64(v.Active) * pageSize, Inactive: uint64(v.Inactive) * pageSize,
		Wired: uint64(v.Wired) * pageSize, Compressed: uint64(v.Compressor) * pageSize,
		Purgeable: uint64(v.Purgeable) * pageSize}
}

func (c *Collector) collectPlatform(s *Snapshot) {
	m := &DarwinMemory{}
	s.Memory.Darwin = m
	if level, err := unix.SysctlUint32("kern.memorystatus_vm_pressure_level"); err == nil {
		m.PressureLevel = map[uint32]string{1: "normal", 2: "warning", 4: "critical"}[level]
	}
	r, err := loadDarwinVMReader()
	if err != nil {
		s.Warnings = append(s.Warnings, "macOS memory: "+err.Error())
		return
	}
	var v darwinVMStats
	count := uint32(unsafe.Sizeof(v) / 4)
	if status := r.read(r.host, 4, unsafe.Pointer(&v), &count); status != 0 || count < 38 {
		s.Warnings = append(s.Warnings, fmt.Sprintf("macOS VM statistics unavailable (%d)", status))
		return
	}
	pageSize := uint64(os.Getpagesize())
	s.Memory.Darwin = darwinMemory(v, pageSize)
	s.Memory.Darwin.PressureLevel = m.PressureLevel
	s.Memory.Cached = uint64(v.External) * pageSize // File-backed pages, not Linux Cached.
	s.Unavailable = slices.DeleteFunc(s.Unavailable, func(name string) bool { return name == "memory_cache" })
}
