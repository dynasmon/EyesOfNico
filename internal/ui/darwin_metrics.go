package ui

import (
	"fmt"
	"strings"
)

func (s *State) darwinPressure() string {
	if m := s.Snapshot.Memory.Darwin; m != nil && m.PressureLevel != "" {
		return strings.ToUpper(m.PressureLevel)
	}
	return "unavailable"
}

func (s *State) darwinPressurePanel(screen *Screen, r Rect) {
	in := screen.Box(r, "MEMORY PRESSURE", "macOS")
	if in.H < 1 {
		return
	}
	pressure := s.darwinPressure()
	style := Green
	if pressure == "WARNING" || pressure == "unavailable" {
		style = Yellow
	} else if pressure == "CRITICAL" {
		style = Red
	}
	lines := []string{"Memory pressure: " + pressure}
	if m := s.Snapshot.Memory.Darwin; m != nil && m.Available {
		lines = append(lines,
			fmt.Sprintf("Wired %s / compressed %s", bytes(float64(m.Wired)), bytes(float64(m.Compressed))),
			fmt.Sprintf("File-backed %s / purgeable %s", bytes(float64(s.Snapshot.Memory.Cached)), bytes(float64(m.Purgeable))))
	}
	lines = append(lines, "macOS pressure level; Linux PSI percentages do not apply.")
	if len(s.Snapshot.Slow.Sensors) == 0 {
		text := "Temperature: not exposed by this Mac"
		if s.Snapshot.Slow.At.IsZero() {
			text = "Collecting temperature sensors..."
		}
		lines = append(lines, text)
	} else {
		var sensors []string
		for _, sensor := range s.Snapshot.Slow.Sensors {
			sensors = append(sensors, fmt.Sprintf("%s %.1fC", sensor.Name, sensor.Celsius))
		}
		lines = append(lines, sensors...)
	}
	for i, line := range lines {
		if i >= in.H {
			break
		}
		color := Muted
		if i == 0 {
			color = style
		} else if i > 3 {
			color = Cyan
		}
		screen.Text(in.X, in.Y+i, in.W, line, color)
	}
}
