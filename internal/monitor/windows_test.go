//go:build windows

package monitor

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestWindowsNativeLayoutsAndMemory(t *testing.T) {
	var v windowsPerformanceInfo
	var d windowsDiskCounters
	if unsafe.Sizeof(v) != 104 || unsafe.Offsetof(v.CommitTotal) != 8 || unsafe.Offsetof(v.HandleCount) != 88 {
		t.Fatalf("PERFORMANCE_INFORMATION ABI mismatch: %d", unsafe.Sizeof(v))
	}
	if unsafe.Sizeof(d) != 88 || unsafe.Offsetof(d.QueryTime) != 56 || unsafe.Offsetof(d.StorageManagerName) != 68 {
		t.Fatalf("DISK_PERFORMANCE ABI mismatch: %d", unsafe.Sizeof(d))
	}
	m := windowsMemory(windowsPerformanceInfo{PageSize: 4096, CommitTotal: 10, CommitLimit: 30, CommitPeak: 20, KernelPaged: 5, KernelNonpaged: 2, HandleCount: 42})
	if !m.Available || m.CommitTotal != 40960 || m.CommitLimit != 122880 || m.KernelPaged != 20480 || m.KernelNonpaged != 8192 || m.Handles != 42 {
		t.Fatalf("page counts not converted to bytes: %+v", m)
	}
}

func TestWindowsDiskUnitsAndBaseline(t *testing.T) {
	old := windowsDiskCounters{BytesRead: 1000, BytesWritten: 2000, ReadCount: 10, WriteCount: 10, ReadTime: 100, WriteTime: 100, IdleTime: 100, QueryTime: 1000}
	cur := windowsDiskCounters{BytesRead: 5096, BytesWritten: 4048, ReadCount: 12, WriteCount: 14, ReadTime: 200100, WriteTime: 400100, IdleTime: 15000100, QueryTime: 20001000, QueueDepth: 3}
	d := windowsDisk("C:", cur, old, 2, true)
	if !d.Ready || d.ReadRate != 2048 || d.WriteRate != 1024 || d.IOPS != 3 || d.Await != 10 || d.Busy != 25 || d.InFlight != 3 || d.Queue != 0 {
		t.Fatalf("incorrect Windows disk units/queue semantics: %+v", d)
	}
	for _, tc := range []struct {
		cur, old windowsDiskCounters
		elapsed  float64
		ready    bool
	}{
		{cur, old, 2, false}, {old, cur, 2, true}, {cur, old, 0, true},
		{cur, cur, 2, true}, {cur, windowsDiskCounters{StorageDeviceNumber: 99}, 2, true},
	} {
		if d := windowsDisk("C:", tc.cur, tc.old, tc.elapsed, tc.ready); d.Ready || d.ReadRate != 0 || d.Busy != 0 || d.Await != 0 {
			t.Fatalf("reset/hotplug used lifetime counters: %+v", d)
		}
	}
}

func TestHardwareMonitorTemperatures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/data.json" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Write([]byte(`{"Children":[{"Text":"Example CPU","HardwareId":"/cpu/0","Children":[
		{"Text":"Package","SensorId":"/cpu/0/temperature/0","RawValue":42.5,"Value":"108.5 °F"},
		{"Text":"Missing","SensorId":"/cpu/0/temperature/1","RawValue":null,"Value":"70 °C"},
		{"Text":"Core","SensorId":"/cpu/0/temperature/2","Value":"43,5 °C"},
		{"Text":"Fan","SensorId":"/cpu/0/fan/0","RawValue":1200},
		{"Text":"Invalid","SensorId":"/cpu/0/temperature/3","RawValue":0}
		]}]}`))
	}))
	defer server.Close()
	values, err := hardwareTemperatures(server.Client(), server.URL+"/data.json")
	if err != nil || len(values) != 2 || values[0].Celsius != 42.5 || values[1].Celsius != 43.5 || values[0].Name != "Example CPU / Package" || values[0].Source != "LibreHardwareMonitor" {
		t.Fatalf("incorrect sensor readings: %+v, %v", values, err)
	}
	for _, tc := range []struct {
		raw, formatted string
		value          float64
		ok             bool
	}{
		{"", "104 °F", 40, true}, {"null", "50 °C", 0, false}, {"0", "", 0, false},
		{"150", "", 150, false}, {"", "NaN °C", math.NaN(), false}, {"", "42", 0, false},
	} {
		value, ok := hardwareTemperature(hardwareSensorNode{RawValue: json.RawMessage(tc.raw), Value: tc.formatted})
		if ok != tc.ok || (ok && math.Abs(value-tc.value) > 0.001) {
			t.Fatalf("raw=%q formatted=%q: got %v, %v", tc.raw, tc.formatted, value, ok)
		}
	}
}

func TestHardwareMonitorRejectsInvalidResponses(t *testing.T) {
	for _, tc := range []struct {
		code int
		body string
	}{
		{http.StatusUnauthorized, `{}`}, {http.StatusOK, `not JSON`}, {http.StatusOK, strings.Repeat(" ", (2<<20)+1)},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.code)
			w.Write([]byte(tc.body))
		}))
		_, err := hardwareTemperatures(server.Client(), server.URL)
		server.Close()
		if err == nil {
			t.Fatal("invalid sensor response was accepted")
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://example.invalid/")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	if _, err := hardwareTemperatures(hardwareMonitorClient, server.URL); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("redirect not rejected locally: %v", err)
	}
}

func TestWindowsNativeMemoryAndPriority(t *testing.T) {
	c, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.Sample(false)
	if err != nil {
		t.Fatal(err)
	}
	m := s.Memory.Windows
	if m == nil || !m.Available || m.CommitTotal == 0 || m.CommitLimit == 0 || m.Handles == 0 || m.Threads == 0 || !s.MetricAvailable("memory_cache") {
		t.Fatalf("Windows performance counters missing: %+v, %v", m, s.Warnings)
	}
	for _, p := range s.Processes {
		if p.PID == os.Getpid() {
			if !p.MetricAvailable("priority") || p.Priority == 0 {
				t.Fatalf("self priority missing: %+v", p)
			}
			return
		}
	}
	t.Fatal("self process missing")
}

func TestWindowsNativeDiskCollection(t *testing.T) {
	c, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	first, err := c.collectDisks(0)
	if len(first) == 0 {
		t.Skipf("host does not expose disk counters: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	disks, err := c.collectDisks(.03)
	if len(disks) == 0 {
		t.Fatalf("disk counters disappeared: %v", err)
	}
	for _, d := range disks {
		if !d.Ready || d.Busy < 0 || d.Busy > 100 || math.IsNaN(d.Busy) || d.Await < 0 {
			t.Fatalf("invalid native disk: %+v", d)
		}
	}
}
