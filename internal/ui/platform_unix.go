//go:build linux || darwin

package ui

import (
	"io"
	"os"
	"os/signal"
	"syscall"
)

const supportsSuspend = true

func configureOutput(_ *os.File) (func(), error) { return func() {}, nil }

func watchSignals(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGWINCH, syscall.SIGTSTP, syscall.SIGCONT)
}

func classifySignal(sig os.Signal) string {
	switch sig {
	case syscall.SIGWINCH, syscall.SIGCONT:
		return "redraw"
	case syscall.SIGTSTP:
		return "suspend"
	}
	return "quit"
}

func suspendProcess(signals <-chan os.Signal) error {
	if err := syscall.Kill(os.Getpid(), syscall.SIGSTOP); err != nil {
		return err
	}
	// SIGSTOP may return before another thread completes the group stop.
	// Restore raw mode only after SIGCONT.
	for {
		sig := <-signals
		if sig == syscall.SIGCONT {
			return nil
		}
		if classifySignal(sig) == "quit" {
			return io.EOF
		}
	}
}
