package monitor

import (
	"os/exec"
	"testing"
	"time"
)

func TestDarwinSleepingProcessState(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	time.Sleep(50 * time.Millisecond)
	c, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.Sample(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range s.Processes {
		if p.PID == cmd.Process.Pid {
			if p.State != "S" || !p.MetricAvailable("cpu") || !p.MetricAvailable("memory") {
				t.Fatalf("sleeping task reported as running or unavailable: %+v", p)
			}
			return
		}
	}
	t.Fatal("sleeping process missing")
}
