package monitor

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/shirou/gopsutil/v4/process"
)

type darwinTaskReader struct {
	info  func(int32, int32, uint64, unsafe.Pointer, int32) int32
	scale float64
}

// Keep libSystem loaded for the lifetime of its registered function pointers.
var loadDarwinTaskReader = sync.OnceValues(func() (*darwinTaskReader, error) {
	lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_LAZY|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	symbol, err := purego.Dlsym(lib, "proc_pidinfo")
	if err != nil {
		return nil, err
	}
	r := &darwinTaskReader{}
	purego.RegisterFunc(&r.info, symbol)
	symbol, err = purego.Dlsym(lib, "mach_timebase_info")
	if err != nil {
		return nil, err
	}
	var timebase func(unsafe.Pointer) int32
	purego.RegisterFunc(&timebase, symbol)
	var ratio struct{ Numer, Denom uint32 }
	if timebase(unsafe.Pointer(&ratio)) != 0 || ratio.Denom == 0 {
		return nil, fmt.Errorf("mach_timebase_info unavailable")
	}
	r.scale = float64(ratio.Numer) / float64(ratio.Denom) / 1e9
	return r, nil
})

func (r *darwinTaskReader) read(p *Process) {
	// PROC_PIDTASKINFO, defined in Apple's bsd/sys/proc_info.h. Reuse the
	// architecture-specific generated ABI layout from gopsutil.
	var task process.ProcTaskInfo
	size := int32(unsafe.Sizeof(task))
	if r.info(int32(p.PID), 4, 0, unsafe.Pointer(&task), size) != size {
		p.Unavailable = []string{"cpu", "memory", "threads"}
		if p.State == "R" {
			p.State = "?"
		}
		return
	}
	p.CPUSeconds = (float64(task.Total_user) + float64(task.Total_system)) * r.scale
	p.RSS, p.Virtual, p.Threads = task.Resident_size, task.Virtual_size, int(task.Threadnum)
	// Darwin's SRUN is the task lifecycle state, not a thread run state.
	if p.State == "R" && task.Numrunning == 0 {
		p.State = "S"
	}
}
