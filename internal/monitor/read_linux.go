package monitor

import (
	"fmt"
	"syscall"
)

// Proc stat records fit in one page on supported kernels. Avoid ReadFile's
// per-file stat syscall, heap buffer and os.File bookkeeping in this hot path.
// The buffer belongs to the collector; parsers must not retain its contents.
func readSmall(path string, buf []byte) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	n := 0
	for n < len(buf) {
		read, err := syscall.Read(fd, buf[n:])
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		if read == 0 {
			return buf[:n], nil
		}
		n += read
	}
	return nil, fmt.Errorf("proc stat exceeds %d bytes", len(buf))
}
