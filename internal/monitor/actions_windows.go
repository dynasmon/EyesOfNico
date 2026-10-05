package monitor

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// The handle pins the process: PID reuse cannot redirect the termination.
func Signal(p Process, action Action) error {
	if err := CheckAction(p, action); err != nil {
		return err
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, uint32(p.PID))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return err
	}
	if p.StartTicks == 0 || uint64(created.Nanoseconds()/1_000_000) != p.StartTicks {
		return fmt.Errorf("process exited or PID was reused; action cancelled")
	}
	return windows.TerminateProcess(handle, 1)
}
