package monitor

import (
	"fmt"
	"os"
	"runtime"
)

type Action int

const (
	Terminate Action = iota + 1
	Kill
	Stop
	Continue
)

func (a Action) String() string {
	if runtime.GOOS == "windows" && a == Kill {
		return "TerminateProcess"
	}
	switch a {
	case Terminate:
		return "SIGTERM"
	case Kill:
		return "SIGKILL"
	case Stop:
		return "SIGSTOP"
	case Continue:
		return "SIGCONT"
	}
	return "unknown action"
}

func CheckAction(p Process, action Action) error {
	if p.PID <= 1 || p.PID == os.Getpid() || (runtime.GOOS == "windows" && p.PID == 4) {
		return fmt.Errorf("refusing to signal PID %d", p.PID)
	}
	if action < Terminate || action > Continue {
		return fmt.Errorf("unsupported process action")
	}
	if runtime.GOOS == "windows" && action != Kill {
		return fmt.Errorf("%s is unavailable on Windows; x requests a confirmed forced termination", action)
	}
	return nil
}
