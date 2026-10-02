package ui

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

type Terminal struct {
	in, out           *os.File
	saved             syscall.Termios
	active, alternate bool
}

func ioctl(fd uintptr, request uintptr, ptr unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, uintptr(ptr))
	if errno != 0 {
		return errno
	}
	return nil
}

func OpenTerminal(noAlt bool) (*Terminal, error) {
	if os.Getenv("TERM") == "dumb" {
		return nil, fmt.Errorf("TERM=dumb has no cursor control; use --snapshot or --json")
	}
	t := &Terminal{in: os.Stdin, out: os.Stdout, alternate: !noAlt}
	if err := ioctl(t.in.Fd(), syscall.TCGETS, unsafe.Pointer(&t.saved)); err != nil {
		return nil, fmt.Errorf("interactive mode needs a terminal; use --json or --snapshot")
	}
	var output syscall.Termios
	if err := ioctl(t.out.Fd(), syscall.TCGETS, unsafe.Pointer(&output)); err != nil {
		return nil, fmt.Errorf("stdout is not a terminal; use --json or --snapshot")
	}
	if err := t.Resume(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Terminal) Resume() error {
	raw := t.saved
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ICRNL | syscall.INLCR | syscall.IGNCR | syscall.INPCK | syscall.ISTRIP | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.IEXTEN | syscall.ISIG
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	if err := ioctl(t.in.Fd(), syscall.TCSETS, unsafe.Pointer(&raw)); err != nil {
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
	_ = ioctl(t.in.Fd(), syscall.TCSETS, unsafe.Pointer(&t.saved))
}

func (t *Terminal) Size() (int, int) {
	var size struct{ Rows, Cols, X, Y uint16 }
	if err := ioctl(t.out.Fd(), syscall.TIOCGWINSZ, unsafe.Pointer(&size)); err != nil || size.Cols == 0 || size.Rows == 0 {
		return 80, 24
	}
	// Guard against pathological PTYs allocating enormous screens.
	return min(int(size.Cols), 1000), min(int(size.Rows), 500)
}
