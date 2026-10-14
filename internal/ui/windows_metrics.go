package ui

import (
	"fmt"
	"time"
)

func (s *State) windowsMemoryLine(line int) string {
	m := s.Snapshot.Memory.Windows
	if m == nil || !m.Available {
		if line == 0 {
			return "Windows memory counters unavailable"
		}
		return ""
	}
	switch line {
	case 0:
		return fmt.Sprintf("Committed %s / %s", bytes(float64(m.CommitTotal)), bytes(float64(m.CommitLimit)))
	case 1:
		return fmt.Sprintf("Pool paged %s / nonpaged %s", bytes(float64(m.KernelPaged)), bytes(float64(m.KernelNonpaged)))
	default:
		return fmt.Sprintf("Commit peak %s / handles %d", bytes(float64(m.CommitPeak)), m.Handles)
	}
}

func (s *State) windowsSystemPanel(screen *Screen, r Rect) {
	in := screen.Box(r, "WINDOWS / TEMPERATURE", "5s sensor cache")
	lines := []string{s.windowsMemoryLine(0)}
	if m := s.Snapshot.Memory.Windows; m != nil && m.Available {
		lines = append(lines, fmt.Sprintf("%d processes / %d threads / %d handles", m.Processes, m.Threads, m.Handles))
	}
	slow := s.Snapshot.Slow
	switch {
	case slow.At.IsZero():
		lines = append(lines, "Collecting temperature sensors...")
	case !s.Paused && time.Since(slow.At) > 15*time.Second:
		lines = append(lines, "Sensor sample is stale; waiting for Windows")
	case len(slow.Sensors) == 0:
		lines = append(lines, "No temperature sensors exposed.",
			"For CPU/GPU: open LibreHardwareMonitor",
			"and enable its web server on port 8085.")
	default:
		lines = append(lines, slow.SensorStatus)
	}
	for i, line := range lines {
		if i >= in.H {
			break
		}
		screen.Text(in.X, in.Y+i, in.W, line, Muted)
	}
	if slow.At.IsZero() || (!s.Paused && time.Since(slow.At) > 15*time.Second) {
		return
	}
	for i, sensor := range slow.Sensors {
		y := len(lines) + i
		if y >= in.H {
			break
		}
		// Keep the measurement visible even when the hardware's name is long.
		screen.Text(in.X, in.Y+y, max(0, in.W-9), sensor.Name, Cyan)
		screen.Text(in.X+max(0, in.W-8), in.Y+y, 8, fmt.Sprintf("%6.1f C", sensor.Celsius), Yellow)
	}
}
