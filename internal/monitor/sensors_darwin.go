package monitor

import (
	"context"
	"math"
	"sort"

	"github.com/shirou/gopsutil/v4/sensors"
)

func collectPlatformSensors(s *Slow) {
	values, err := sensors.TemperaturesWithContext(context.Background())
	if err != nil {
		return // Sensor access is hardware/OS-dependent, not a sampling failure.
	}
	for _, v := range values {
		// Unsupported SMC keys report zero; do not invent a 0°C reading.
		if v.Temperature > 0 && v.Temperature < 150 && !math.IsNaN(v.Temperature) {
			s.Sensors = append(s.Sensors, Sensor{Name: v.SensorKey, Celsius: v.Temperature})
		}
	}
	sort.Slice(s.Sensors, func(i, j int) bool { return s.Sensors[i].Name < s.Sensors[j].Name })
}
