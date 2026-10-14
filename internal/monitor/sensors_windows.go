package monitor

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yusufpapurcu/wmi"
)

// Current LibreHardwareMonitor versions expose sensors through their optional
// local web server. No driver, runtime, or service is installed by nicotop.
var hardwareMonitorClient = &http.Client{
	Timeout:       time.Second,
	Transport:     &http.Transport{Proxy: nil, ResponseHeaderTimeout: time.Second},
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
}

type hardwareSensorNode struct {
	Text, SensorID, HardwareID, Value string
	RawValue                          json.RawMessage
	Children                          []hardwareSensorNode
}

func hardwareTemperatures(client *http.Client, url string) ([]Sensor, error) {
	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sensor server: HTTP %d", response.StatusCode)
	}
	const limit = 2 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || len(data) > limit {
		return nil, fmt.Errorf("invalid sensor response size or read error: %v", err)
	}
	var root hardwareSensorNode
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	var result []Sensor
	var visit func(hardwareSensorNode, string, int)
	visit = func(node hardwareSensorNode, hardware string, depth int) {
		if depth > 32 {
			return
		}
		if node.HardwareID != "" {
			hardware = node.Text
		}
		if strings.Contains(node.SensorID, "/temperature/") {
			value, ok := hardwareTemperature(node)
			if ok {
				name := node.Text
				if hardware != "" {
					name = hardware + " / " + name
				}
				result = append(result, Sensor{Name: name, Celsius: value, Source: "LibreHardwareMonitor"})
			}
		}
		for _, child := range node.Children {
			visit(child, hardware, depth+1)
		}
	}
	visit(root, "", 0)
	return result, nil
}

func validWindowsTemperature(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value > 0 && value < 150
}

func hardwareTemperature(node hardwareSensorNode) (float64, bool) {
	var value float64
	if len(node.RawValue) > 0 {
		// An explicit null is an unavailable sensor, even if formatted text is stale.
		if string(node.RawValue) == "null" || json.Unmarshal(node.RawValue, &value) != nil {
			return 0, false
		}
	} else {
		// Older server versions only have formatted values, in the UI's locale/unit.
		text := strings.TrimSpace(node.Value)
		fahrenheit := strings.HasSuffix(text, "°F")
		if !fahrenheit && !strings.HasSuffix(text, "°C") {
			return 0, false
		}
		text = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(text, "°C"), "°F"))
		parsed, err := strconv.ParseFloat(strings.ReplaceAll(text, ",", "."), 64)
		if err != nil {
			return 0, false
		}
		value = parsed
		if fahrenheit {
			value = (value - 32) * 5 / 9
		}
	}
	return value, validWindowsTemperature(value)
}

type acpiTemperature struct {
	InstanceName       string
	CurrentTemperature uint32
}

func collectPlatformSensors(s *Slow) {
	// Only loopback is queried; do not use HTTP proxies or follow redirects.
	s.Sensors, _ = hardwareTemperatures(hardwareMonitorClient, "http://127.0.0.1:8085/data.json")
	if len(s.Sensors) > 0 {
		s.SensorStatus = "LibreHardwareMonitor / 5s cache"
	} else {
		var zones []acpiTemperature
		// This runs on the single bounded slow worker. Do not spawn a goroutine
		// per timeout: WMI does not support cancellation and could leak workers.
		if err := wmi.QueryNamespace("SELECT InstanceName, CurrentTemperature FROM MSAcpi_ThermalZoneTemperature", &zones, `root\WMI`); err == nil {
			for _, zone := range zones {
				value := float64(zone.CurrentTemperature)/10 - 273.15
				if validWindowsTemperature(value) {
					s.Sensors = append(s.Sensors, Sensor{Name: "ACPI / " + zone.InstanceName, Celsius: value, Source: "ACPI thermal zone"})
				}
			}
		}
		s.SensorStatus = "ACPI thermal zones; not CPU core temperatures"
		if len(s.Sensors) == 0 {
			s.SensorStatus = "No sensors exposed by ACPI or LibreHardwareMonitor"
		}
	}
	sort.Slice(s.Sensors, func(i, j int) bool { return s.Sensors[i].Name < s.Sensors[j].Name })
}
