package monitor

import (
	"testing"
	"unsafe"
)

func TestDarwinVMLayoutAndPageAccounting(t *testing.T) {
	var v darwinVMStats
	if unsafe.Sizeof(v) != 152 || unsafe.Offsetof(v.Compressor) != 128 || unsafe.Offsetof(v.External) != 136 {
		t.Fatalf("HOST_VM_INFO64 ABI mismatch: %d bytes", unsafe.Sizeof(v))
	}
	v = darwinVMStats{Free: 10, Active: 20, Inactive: 30, Wired: 40, Compressor: 50, Purgeable: 5, Speculative: 3}
	for _, pageSize := range []uint64{4096, 16384} {
		m := darwinMemory(v, pageSize)
		if !m.Available || m.Free != 10*pageSize || m.Wired != 40*pageSize || m.Compressed != 50*pageSize || m.Purgeable != 5*pageSize {
			t.Fatalf("wrong VM bytes (speculative must not be added to free): %+v", m)
		}
	}
}

func TestDarwinNativeMemory(t *testing.T) {
	c, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.Sample(false)
	if err != nil {
		t.Fatal(err)
	}
	if s.Memory.Darwin == nil || !s.Memory.Darwin.Available || s.Memory.Darwin.Wired == 0 || !s.MetricAvailable("memory_cache") {
		t.Fatalf("native memory missing: %+v, warnings %v", s.Memory.Darwin, s.Warnings)
	}
	if s.Memory.Cached > s.Memory.Total || s.Memory.Darwin.Compressed > s.Memory.Total {
		t.Fatal("native memory values exceed physical memory")
	}
}
