package monitor

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func near(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 0.0001 {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCPUAccounting(t *testing.T) {
	cpus, _ := parseCPU("cpu 100 10 50 700 30 5 5 100 80 8\ncpu0 0 0 0 0\n")
	c := cpuUsage("cpu", cpus["cpu"], cpuTicks{})
	near(t, c.Busy, 27)
	near(t, c.User, 11)
	near(t, c.System, 6)
	near(t, c.Wait, 3)
	near(t, c.Steal, 10)
	// iowait can decrease: only that counter is clamped, no unsigned underflow.
	c = cpuUsage("cpu", cpuTicks{20, 0, 0, 90, 2}, cpuTicks{10, 0, 0, 80, 5})
	near(t, c.Busy, 50)
	near(t, c.Wait, 0)
	near(t, cpuUsage("cpu", cpuTicks{}, cpuTicks{100, 0, 0, 100}).Busy, 0)
}

func TestMemoryAccounting(t *testing.T) {
	m := parseMemory("MemTotal: 1000 kB\nMemAvailable: 650 kB\nMemFree: 200 kB\nCached: 300 kB\nSReclaimable: 80 kB\nShmem: 30 kB\nSwapTotal: 100 kB\nSwapFree: 40 kB\n")
	if m.Used != 350*1024 || m.Cached != 350*1024 || m.SwapUsed != 60*1024 {
		t.Fatalf("bad memory: %+v", m)
	}
	m = parseMemory("MemTotal: 1000 kB\nMemFree: 200 kB\nBuffers: 50 kB\nCached: 300 kB\nSReclaimable: 100 kB\n")
	if m.Available != 650*1024 {
		t.Fatalf("fallback: %+v", m)
	}
	m = parseMemory("MemTotal: 100 kB\nMemAvailable: 200 kB\nSwapTotal: 10 kB\nSwapFree: 20 kB\n")
	if m.Used != 0 || m.SwapUsed != 0 {
		t.Fatal("counter underflow")
	}
}

func TestPressureAndNetwork(t *testing.T) {
	p := parsePressure("some avg300=0.30 avg10=1.20 avg60=0.80 total=500\nfull avg10=0.01 avg60=0.02 avg300=0.03 total=10\n")
	if !p.Available || p.Some != [3]float64{1.2, .8, .3} || p.Full[0] != .01 {
		t.Fatalf("bad PSI: %+v", p)
	}
	if parsePressure("some avg10=nope").Available {
		t.Fatal("malformed PSI shown as available")
	}
	n := parseNetworks("Inter-| Receive | Transmit\n eth0: 1024 8 1 2 0 0 0 0 2048 16 3 4 0 0 0 0\n")
	if len(n) != 1 || n[0].Name != "eth0" || n[0].RXBytes != 1024 || n[0].Errors != 4 || n[0].Drops != 6 {
		t.Fatalf("bad net: %+v", n)
	}
}

func processStat(pid int, name string, ticks, start uint64) string {
	f := make([]string, 40)
	for i := range f {
		f[i] = "0"
	}
	f[0] = "S"
	f[1] = "1"
	f[11] = strconv.FormatUint(ticks, 10)
	f[12] = "10"
	f[15] = "20"
	f[16] = "-5"
	f[17] = "3"
	f[19] = strconv.FormatUint(start, 10)
	f[20] = "1048576"
	f[21] = "16"
	f[36] = "7"
	return fmt.Sprintf("%d (%s) %s\n", pid, name, strings.Join(f, " "))
}

func TestProcessStatNamesAndIdentity(t *testing.T) {
	for _, name := range []string{"worker", "a (b) ) c", "line\nbreak", "proc\x1b[2J"} {
		p, err := parseProcess(processStat(123, name, 100, 500), 4096)
		if err != nil || p.Name != name || p.Ticks != 110 || p.StartTicks != 500 || p.RSS != 65536 || p.Nice != -5 || p.Processor != 7 {
			t.Fatalf("%q: %+v %v", name, p, err)
		}
	}
	for _, data := range []string{"", "1 (short) S 2", "a (test) S", "0 (init) S"} {
		if _, err := parseProcess(data, 4096); err == nil {
			t.Fatalf("accepted %q", data)
		}
	}
}

func TestMountFilteringAndEscapes(t *testing.T) {
	data := "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n" +
		"2 1 8:1 /home /bind rw - ext4 /dev/sda1 rw\n" +
		"3 1 8:2 / /media/my\\040disk rw - xfs /dev/sdb1 rw\n" +
		"4 1 0:5 / /remote rw - nfs server:/data rw\n" +
		"5 1 0:6 / /fuse rw - fuse.sshfs x rw\n" +
		"6 1 0:7 / /auto rw - autofs auto rw\n" +
		"7 1 0:8 / /var/lib/docker/overlay2/a/merged rw - overlay overlay rw\n"
	fs := localMounts(data)
	if len(fs) != 2 || fs[1].Mount != "/media/my disk" {
		t.Fatalf("mounts: %+v", fs)
	}
}

func writeFixture(t *testing.T, root, path, value string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(value), 0644); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) *Collector {
	t.Helper()
	root := t.TempDir()
	proc, sys := filepath.Join(root, "proc"), filepath.Join(root, "sys")
	writeFixture(t, proc, "stat", "cpu 100 0 100 800 0 0 0 0\ncpu0 100 0 100 800 0 0 0 0\nctxt 10\nprocesses 2\n")
	writeFixture(t, proc, "meminfo", "MemTotal: 1000 kB\nMemAvailable: 700 kB\n")
	writeFixture(t, proc, "net/dev", "eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n")
	writeFixture(t, proc, "diskstats", "8 0 sda 10 0 100 20 20 0 200 40 0 60 80\n8 1 sda1 10 0 100 20 20 0 200 40 0 60 80\n")
	writeFixture(t, sys, "block/sda/size", "100000")
	writeFixture(t, proc, "123/stat", processStat(123, "first", 100, 500))
	writeFixture(t, proc, "123/status", "Uid:\t1000\t1000\t1000\t1000\n")
	writeFixture(t, proc, "123/cmdline", "first\x00--hello\x00")
	writeFixture(t, proc, "123/io", "read_bytes: 1000\nwrite_bytes: 2000\n")
	c, err := New(Options{ProcRoot: proc, SysRoot: sys})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestCollectorBaselinesDeltasAndHotplug(t *testing.T) {
	c := fixture(t)
	first, err := c.Sample(true)
	if err != nil {
		t.Fatal(err)
	}
	if first.Ready || first.CPU.Busy != 0 || first.Networks[0].RXRate != 0 || len(first.Disks) != 1 || first.Processes[0].CPU != 0 {
		t.Fatalf("bad baseline: %+v", first)
	}
	writeFixture(t, c.proc, "stat", "cpu 150 0 125 825 0 0 0 0\ncpu0 150 0 125 825 0 0 0 0\nctxt 20\nprocesses 3\n")
	writeFixture(t, c.proc, "net/dev", "eth0: 2024 20 0 0 0 0 0 0 4048 40 0 0 0 0 0 0\nnew0: 90000 90 0 0 0 0 0 0 90000 90 0 0 0 0 0 0\n")
	writeFixture(t, c.proc, "diskstats", "8 0 sda 12 0 102 30 22 0 204 70 1 160 280\n")
	writeFixture(t, c.proc, "123/stat", processStat(123, "first", 150, 500))
	writeFixture(t, c.proc, "123/io", "read_bytes: 2024\nwrite_bytes: 4048\n")
	c.last = time.Now().Add(-time.Second)
	s, err := c.Sample(true)
	if err != nil {
		t.Fatal(err)
	}
	near(t, s.CPU.Busy, 75)
	near(t, s.Networks[0].RXRate*s.Interval, 1024)
	near(t, s.Disks[0].ReadRate*s.Interval, 1024)
	near(t, s.Disks[0].WriteRate*s.Interval, 2048)
	near(t, s.Disks[0].Await, 10)
	near(t, s.Disks[0].Busy*s.Interval, 10)
	near(t, s.Processes[0].CPU*s.Interval, 50)
	near(t, s.Processes[0].ReadRate*s.Interval, 1024)
	if s.Networks[1].Ready || s.Networks[1].RXRate != 0 {
		t.Fatal("hotplug produced lifetime-rate spike")
	}
	// Removal prunes state. A reset/reappearance starts another baseline.
	writeFixture(t, c.proc, "net/dev", "")
	_, _ = c.Sample(false)
	writeFixture(t, c.proc, "net/dev", "eth0: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n")
	writeFixture(t, c.proc, "123/stat", processStat(123, "second", 9000, 600))
	writeFixture(t, c.proc, "123/cmdline", "second\x00")
	s, err = c.Sample(true)
	if err != nil {
		t.Fatal(err)
	}
	if s.Networks[0].Ready || s.Networks[0].RXRate != 0 || s.Processes[0].CPU != 0 || s.Processes[0].Command != "second" {
		t.Fatalf("reuse/reset mishandled: %+v", s.Processes)
	}
	if s.Processes[0].ReadRate != 0 {
		t.Fatal("I/O re-enable did not baseline")
	}
}

func TestCollectorFailureAndOptionalMetrics(t *testing.T) {
	c := fixture(t)
	if err := os.Remove(filepath.Join(c.proc, "net/dev")); err != nil {
		t.Fatal(err)
	}
	s, err := c.Sample(false)
	if err != nil || len(s.Warnings) != 1 || s.Pressure["cpu"].Available {
		t.Fatalf("optional collection: %v, %v", s.Warnings, err)
	}
	writeFixture(t, c.proc, "meminfo", "")
	if _, err = c.Sample(false); err == nil {
		t.Fatal("empty memory treated as valid")
	}
}

func TestSignalPinnedIdentity(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	p, err := parseProcess(string(b), 4096)
	if err != nil {
		t.Fatal(err)
	}
	wrong := p
	wrong.StartTicks++
	if err = Signal(wrong, Terminate); err == nil {
		t.Fatal("signalled wrong identity")
	}
	if err = cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("wrong-identity check killed child")
	}
	if err = Signal(p, Terminate); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("SIGTERM did not reach child")
	}
	if err = Signal(Process{PID: 1}, Terminate); err == nil {
		t.Fatal("PID 1 was not protected")
	}
}

func BenchmarkParseProcess(b *testing.B) {
	data := processStat(123, "worker (main)", 100, 500)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = parseProcess(data, 4096)
	}
}

func BenchmarkSampleHost(b *testing.B) {
	c, err := New(Options{})
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Sample(false)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = c.Sample(false); err != nil {
			b.Fatal(err)
		}
	}
}
