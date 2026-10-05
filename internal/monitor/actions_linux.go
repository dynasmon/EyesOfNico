package monitor

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"
)

// Signal pins the process with a pidfd before checking its identity. A recycled
// PID can never redirect an action to a different process. No racy kill fallback.
func Signal(p Process, action Action) error {
	if err := CheckAction(p, action); err != nil {
		return err
	}
	sig := map[Action]syscall.Signal{Terminate: syscall.SIGTERM, Kill: syscall.SIGKILL, Stop: syscall.SIGSTOP, Continue: syscall.SIGCONT}[action]
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("process actions support amd64/arm64 only")
	}
	const pidfdOpen = 434
	const pidfdSendSignal = 424
	fd, _, errno := syscall.Syscall(pidfdOpen, uintptr(p.PID), 0, 0)
	if errno != 0 {
		return fmt.Errorf("pidfd_open (Linux 5.3+ required): %w", errno)
	}
	defer syscall.Close(int(fd))
	b, err := os.ReadFile("/proc/" + strconv.Itoa(p.PID) + "/stat")
	if err != nil {
		return fmt.Errorf("process exited: %w", err)
	}
	current, err := parseProcess(string(b), uint64(os.Getpagesize()))
	if err != nil || current.StartTicks != p.StartTicks {
		return fmt.Errorf("process exited or PID was reused; action cancelled")
	}
	_, _, errno = syscall.Syscall6(pidfdSendSignal, fd, uintptr(sig), 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("signal PID %d: %w", p.PID, errno)
	}
	return nil
}
