package monitor

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Darwin has no pidfd. Recheck the microsecond birth time immediately before
// kill; unlike Linux and Windows, the identity check and action are not atomic.
func Signal(p Process, action Action) error {
	if err := CheckAction(p, action); err != nil {
		return err
	}
	current, err := unix.SysctlKinfoProc("kern.proc.pid", p.PID)
	if err != nil {
		return fmt.Errorf("process exited or inaccessible: %w", err)
	}
	if current.Proc.P_pid != int32(p.PID) || p.StartTicks == 0 || darwinIdentity(current) != p.StartTicks {
		return fmt.Errorf("process exited or PID was reused; action cancelled")
	}
	sig := map[Action]unix.Signal{Terminate: unix.SIGTERM, Kill: unix.SIGKILL, Stop: unix.SIGSTOP, Continue: unix.SIGCONT}[action]
	return unix.Kill(p.PID, sig)
}
