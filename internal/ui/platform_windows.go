package ui

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/windows"
)

const supportsSuspend = false

func configureOutput(out *os.File) (func(), error) {
	handle := windows.Handle(out.Fd())
	var saved uint32
	if err := windows.GetConsoleMode(handle, &saved); err != nil {
		return nil, err
	}
	if err := windows.SetConsoleMode(handle, saved|windows.ENABLE_PROCESSED_OUTPUT|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return nil, fmt.Errorf("ANSI terminal required (Windows 10+ / Windows Terminal): %w", err)
	}
	return func() { _ = windows.SetConsoleMode(handle, saved) }, nil
}

func watchSignals(ch chan<- os.Signal)        { signal.Notify(ch, os.Interrupt, syscall.SIGTERM) }
func classifySignal(_ os.Signal) string       { return "quit" }
func suspendProcess(_ <-chan os.Signal) error { return fmt.Errorf("suspend is unavailable on Windows") }
