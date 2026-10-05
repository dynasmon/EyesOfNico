package ui

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

type Terminal struct {
	in, out           *os.File
	saved             *term.State
	restoreOutput     func()
	active, alternate bool
}

func OpenTerminal(noAlt bool) (*Terminal, error) {
	if os.Getenv("TERM") == "dumb" {
		return nil, fmt.Errorf("TERM=dumb has no cursor control; use --snapshot or --json")
	}
	t := &Terminal{in: os.Stdin, out: os.Stdout, alternate: !noAlt}
	var err error
	if t.saved, err = term.GetState(int(t.in.Fd())); err != nil {
		return nil, fmt.Errorf("interactive mode needs a terminal; use --json or --snapshot")
	}
	if !term.IsTerminal(int(t.out.Fd())) {
		return nil, fmt.Errorf("stdout is not a terminal; use --json or --snapshot")
	}
	if err := t.Resume(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Terminal) Resume() error {
	if _, err := term.MakeRaw(int(t.in.Fd())); err != nil {
		return err
	}
	var err error
	if t.restoreOutput, err = configureOutput(t.out); err != nil {
		_ = term.Restore(int(t.in.Fd()), t.saved)
		return err
	}
	t.active = true
	sequence := "\x1b[?25l\x1b[?7l\x1b[?2004h"
	if t.alternate {
		sequence = "\x1b[?1049h" + sequence
	}
	if _, err := t.out.WriteString(sequence); err != nil {
		t.Close()
		return err
	}
	return nil
}

func (t *Terminal) Close() {
	if !t.active {
		return
	}
	t.active = false
	sequence := "\x1b[0m\x1b[?2004l\x1b[?7h\x1b[?25h"
	if t.alternate {
		sequence += "\x1b[?1049l"
	} else {
		_, h := t.Size()
		sequence += fmt.Sprintf("\x1b[%d;1H\r\n", h)
	}
	_, _ = t.out.WriteString(sequence)
	if t.restoreOutput != nil {
		t.restoreOutput()
	}
	_ = term.Restore(int(t.in.Fd()), t.saved)
}

func (t *Terminal) Size() (int, int) {
	w, h, err := term.GetSize(int(t.out.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		return 80, 24
	}
	// Guard against pathological PTYs allocating enormous screens.
	return min(w, 1000), min(h, 500)
}
