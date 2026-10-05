package ui

import (
	"eyesofnico/internal/monitor"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLoopbackExcludedFromTotalsAndHistory(t *testing.T) {
	s := NewState(time.Second, false)
	s.Accept(monitor.Snapshot{Ready: true, Networks: []monitor.Network{
		{Name: "en0", RXRate: 10, TXRate: 20},
		{Name: "lo0", RXRate: 1000},
		{Name: "Loopback Pseudo-Interface 1", Loopback: true, RXRate: 2000},
	}})
	rx := s.NetHistory["*"].A.Values()
	if len(rx) != 1 || rx[0] != 10 {
		t.Fatalf("aggregate contains loopback: %v", rx)
	}
	s.View = 3
	screen := NewScreen(120, 40, true)
	s.Draw(screen)
	if !strings.Contains(screen.Plain(), "all except loopback") {
		t.Fatal("network scope is not documented in the UI")
	}
}

func TestCurrentUserFilter(t *testing.T) {
	s := NewState(time.Second, false)
	s.OwnOnly = true
	s.ownUID, s.ownUser = 123, `DESKTOP\nico`
	owner := monitor.Process{PID: 10, UID: 123, User: `desktop\Nico`}
	other := monitor.Process{PID: 20, UID: 456, User: `desktop\another`}
	if runtime.GOOS == "windows" {
		owner.UID, other.UID = ^uint32(0), ^uint32(0)
	}
	for _, tree := range []bool{false, true} {
		s.Tree = tree
		s.Accept(monitor.Snapshot{Processes: []monitor.Process{owner, other}})
		if len(s.Rows) != 1 || s.Rows[0].Process.PID != owner.PID {
			t.Fatalf("own-user filter (tree=%v): %+v", tree, s.Rows)
		}
	}
}

func TestUnavailableMetricsAreNotDisplayedAsZero(t *testing.T) {
	s := demoState()
	s.Snapshot.Unavailable = []string{"load", "cpu_iowait", "cpu_steal", "context_switches", "forks", "disk_busy", "disk_queue"}
	s.View = 1
	screen := NewScreen(120, 40, true)
	s.Draw(screen)
	for _, text := range []string{"Load n/a", "wait n/a", "ctx n/a"} {
		if !strings.Contains(screen.Plain(), text) {
			t.Fatalf("missing %q", text)
		}
	}
	s.View = 4
	s.Draw(screen)
	if !strings.Contains(screen.Plain(), "n/a") {
		t.Fatal("unavailable disk counters displayed as zero")
	}
	p := monitor.Process{Unavailable: []string{"cpu", "memory"}}
	if processMetric(p, "cpu", "%.1f", p.CPU) != "n/a" || processMetric(p, "memory", "%d", p.RSS) != "n/a" {
		t.Fatal("inaccessible process counters displayed as zero")
	}
}

func TestDarwinPanelsUseNativeMetrics(t *testing.T) {
	s := demoState()
	s.Snapshot.OS = "darwin"
	s.Snapshot.Unavailable = []string{"psi", "cpu_iowait", "cpu_steal", "context_switches", "forks", "memory_buffers", "memory_slab", "memory_dirty", "disk_busy", "disk_queue", "process_processor"}
	s.Snapshot.Memory.Cached = 3 << 30
	s.Snapshot.Memory.Darwin = &monitor.DarwinMemory{Available: true, Wired: 1 << 30, Compressed: 512 << 20, PressureLevel: "normal"}
	s.Snapshot.Slow.Sensors = []monitor.Sensor{{Name: "PMU tdie1", Celsius: 42}}
	for _, size := range [][2]int{{40, 12}, {80, 24}, {120, 40}} {
		for view := 0; view < 6; view++ {
			s.View = view
			screen := NewScreen(size[0], size[1], true)
			s.Draw(screen)
			if strings.Contains(screen.Plain(), "n/a") {
				t.Fatalf("Mac view %d at %v still contains Linux-only placeholders:\n%s", view, size, screen.Plain())
			}
			if view == 1 && size[0] == 120 {
				for _, want := range []string{"MEMORY PRESSURE", "NORMAL", "Wired", "compressed", "42.0C"} {
					if !strings.Contains(screen.Plain(), want) {
						t.Fatalf("missing native metric %q", want)
					}
				}
			}
			if view == 4 && size[0] == 120 {
				if strings.Contains(screen.Plain(), "BUSY%") || strings.Contains(screen.Plain(), "QUEUE") || !strings.Contains(screen.Plain(), "AWAITms") {
					t.Fatal("Mac disks should show available IOPS/latency columns")
				}
			}
		}
	}
}
