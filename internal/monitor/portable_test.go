//go:build darwin || windows

package monitor

import (
	"math"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
)

func TestPortableProcessRates(t *testing.T) {
	old := Process{StartTicks: 123, CPUSeconds: 10, IOAvailable: true, readBytes: 1024, writeBytes: 2048}
	fresh := Process{StartTicks: 123, CPUSeconds: 11.5, IOAvailable: true, readBytes: 3072, writeBytes: 4096}
	for _, tc := range []struct {
		name    string
		before  Process
		now     Process
		elapsed float64
		cpu, io float64
	}{
		{"one core plus half", old, fresh, 1, 150, 2048},
		{"actual elapsed", old, fresh, 2, 75, 1024},
		{"reused PID", old, Process{StartTicks: 124, CPUSeconds: 1000, IOAvailable: true, readBytes: 1 << 30}, 1, 0, 0},
		{"counter reset", fresh, old, 1, 0, 0},
		{"IO re-enabled", Process{StartTicks: 123, CPUSeconds: 10}, fresh, 1, 150, 0},
		{"baseline", old, fresh, 0, 0, 0},
		{"CPU access restored", Process{StartTicks: 123, Unavailable: []string{"cpu"}}, fresh, 1, 0, 0},
		{"CPU source switched", Process{StartTicks: 123, CPUSeconds: 10, MetricsSource: "ps"}, fresh, 1, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			processRates(&tc.now, tc.before, tc.elapsed)
			if tc.now.CPU != tc.cpu || tc.now.ReadRate != tc.io {
				t.Fatalf("CPU=%v read=%v, want %v %v", tc.now.CPU, tc.now.ReadRate, tc.cpu, tc.io)
			}
		})
	}
}

func TestPortableDiskRates(t *testing.T) {
	old := disk.IOCountersStat{ReadBytes: 1000, WriteBytes: 2000, ReadCount: 10, WriteCount: 10, ReadTime: 100, WriteTime: 200}
	cur := disk.IOCountersStat{Name: "disk0", ReadBytes: 5096, WriteBytes: 4048, ReadCount: 12, WriteCount: 14, ReadTime: 120, WriteTime: 240}
	d := portableDisk(cur, old, 2, true)
	if !d.Ready || d.ReadRate != 2048 || d.WriteRate != 1024 || d.IOPS != 3 || d.Await != 10 {
		t.Fatalf("bad rates: %+v", d)
	}
	if d = portableDisk(cur, old, 2, false); d.Ready || d.ReadRate != 0 {
		t.Fatalf("hotplug used lifetime counters: %+v", d)
	}
	if d = portableDisk(old, cur, 1, true); d.ReadRate != 0 || d.IOPS != 0 {
		t.Fatalf("reset counters underflowed: %+v", d)
	}
}

func TestNativeCollection(t *testing.T) {
	if _, err := New(Options{ProcRoot: t.TempDir()}); err == nil {
		t.Fatal("silently ignored a Linux override")
	}
	c, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	first, err := c.Sample(false)
	if err != nil || first.Ready {
		t.Fatalf("baseline: %v, ready=%v", err, first.Ready)
	}
	time.Sleep(50 * time.Millisecond)
	s, err := c.Sample(true)
	if err != nil {
		t.Fatal(err)
	}
	if s.OS != runtime.GOOS || !s.Ready || s.Interval <= 0 || s.Memory.Total == 0 || len(s.Cores) == 0 || s.Pressure["cpu"].Available {
		t.Fatalf("invalid native snapshot: %+v", s)
	}
	if s.CPU.Busy < 0 || s.CPU.Busy > 100.0001 || math.IsNaN(s.CPU.Busy) {
		t.Fatalf("invalid CPU rate: %v", s.CPU.Busy)
	}
	for _, p := range s.Processes {
		if p.PID == os.Getpid() {
			if p.StartTicks == 0 || p.Name == "" || p.RSS == 0 || p.Threads == 0 {
				t.Fatalf("missing self metrics: %+v", p)
			}
			return
		}
	}
	t.Fatal("collector did not find itself")
}

func TestActionChild(t *testing.T) {
	if os.Getenv("NICOTOP_TEST_CHILD") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

func TestNativeActionIdentity(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestActionChild$")
	cmd.Env = append(os.Environ(), "NICOTOP_TEST_CHILD=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	c, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.Sample(false)
	if err != nil {
		t.Fatal(err)
	}
	var target Process
	for _, p := range s.Processes {
		if p.PID == cmd.Process.Pid {
			target = p
		}
	}
	if target.PID == 0 {
		t.Fatal("disposable child not found")
	}
	wrong := target
	wrong.StartTicks++
	if err := Signal(wrong, Kill); err == nil {
		t.Fatal("accepted wrong process identity")
	}
	if runtime.GOOS == "windows" {
		for _, action := range []Action{Terminate, Stop, Continue} {
			if err := Signal(target, action); err == nil {
				t.Fatalf("unsupported action %v succeeded", action)
			}
		}
	}
	if err := Signal(target, Kill); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("termination did not reach the child")
	}
	for _, pid := range []int{0, 1, os.Getpid()} {
		if err := Signal(Process{PID: pid}, Kill); err == nil {
			t.Fatalf("protected PID %d accepted", pid)
		}
	}
}
