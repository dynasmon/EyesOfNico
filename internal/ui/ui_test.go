package ui

import (
	bytebuf "bytes"
	"eyesofnico/internal/monitor"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func demoState() *State {
	s := NewState(time.Second, false)
	snapshot := monitor.Snapshot{At: time.Unix(1700000000, 0), Ready: true, Host: "test-host", Kernel: "6.8.0", CPUModel: "Eight-core test CPU", Uptime: 34567, CPU: monitor.CPU{Busy: 37.5}, Memory: monitor.Memory{Total: 16 << 30, Used: 6 << 30, Available: 10 << 30, SwapTotal: 4 << 30}, Pressure: map[string]monitor.Pressure{"cpu": {Available: true}}, Slow: monitor.Slow{At: time.Now(), NetworkState: map[string]string{"eth0": "up"}}}
	for i := 0; i < 64; i++ {
		snapshot.Cores = append(snapshot.Cores, monitor.CPU{Name: fmt.Sprintf("cpu%d", i), Busy: float64(i)})
	}
	snapshot.Networks = []monitor.Network{{Name: "eth0", RXRate: 1024, TXRate: 4096}, {Name: "lo", RXRate: 9e6}}
	snapshot.Disks = []monitor.Disk{{Name: "fd0", SizeBytes: 4096}, {Name: "nvme0n1", SizeBytes: 1 << 40, ReadRate: 1 << 20}}
	snapshot.Slow.Filesystems = []monitor.Filesystem{{Mount: "/", Total: 100 << 30, Used: 25 << 30, Available: 75 << 30}}
	for i := 1; i <= 100; i++ {
		snapshot.Processes = append(snapshot.Processes, monitor.Process{PID: i, PPID: i / 2, StartTicks: uint64(i * 100), Name: fmt.Sprintf("worker%d", i), Command: fmt.Sprintf("worker%d --argument", i), User: "nico", UID: uint32(os.Getuid()), State: "S", CPU: float64(i), RSS: uint64(i) << 20, Threads: 2})
	}
	for i := 0; i < 40; i++ {
		snapshot.CPU.Busy = float64(i * 7 % 100)
		s.Accept(snapshot)
	}
	return s
}

func TestLayoutsAtAllSizes(t *testing.T) {
	s := demoState()
	for _, size := range [][2]int{{1, 1}, {20, 8}, {40, 12}, {60, 18}, {80, 24}, {100, 30}, {120, 40}, {180, 55}} {
		for view := 0; view < 6; view++ {
			for _, ascii := range []bool{false, true} {
				s.View = view
				screen := NewScreen(size[0], size[1], ascii)
				s.Draw(screen)
				lines := strings.Split(strings.TrimSuffix(screen.Plain(), "\n"), "\n")
				if len(lines) != size[1] {
					t.Fatal("wrong height")
				}
				for _, line := range lines {
					if textWidth(line) != size[0] {
						t.Fatalf("view %d at %v: row width %d: %q", view, size, textWidth(line), line)
					}
				}
				if strings.ContainsRune(screen.Plain(), '\x1b') {
					t.Fatal("escape injection")
				}
			}
		}
	}
}

func TestRendererDiffAndSanitization(t *testing.T) {
	var buf bytebuf.Buffer
	r := NewRenderer(&buf, true, true)
	screen := NewScreen(20, 4, false)
	screen.Text(0, 0, 20, "e\u0301 中文 \x1b[2J\nsecret", Normal)
	if err := r.Flush(screen); err != nil {
		t.Fatal(err)
	}
	if strings.Count(buf.String(), "\x1b[2J") != 1 {
		t.Fatal("untrusted escape sequence reached terminal")
	}
	buf.Reset()
	_ = r.Flush(screen)
	if buf.Len() != 0 {
		t.Fatal("unchanged screen emitted output")
	}
	screen.Text(0, 1, 10, "changed", Cyan)
	_ = r.Flush(screen)
	if !strings.Contains(buf.String(), "\x1b[2;1H") || strings.Contains(buf.String(), "\x1b[1;1H") {
		t.Fatal("did not limit output to changed row")
	}
	buf.Reset()
	small := NewScreen(10, 2, false)
	_ = r.Flush(small)
	if !strings.Contains(buf.String(), "\x1b[2J") {
		t.Fatal("resize did not clear stale cells")
	}
}

func TestHistoryBounded(t *testing.T) {
	var h History
	for i := 0; i < 500; i++ {
		h.Add(float64(i))
	}
	v := h.Values()
	if len(v) != historyLimit || v[0] != 260 || v[len(v)-1] != 499 {
		t.Fatalf("bad ring: %v", v)
	}
}

func TestWideGlyphReplacementAndOverlays(t *testing.T) {
	screen := NewScreen(8, 2, false)
	screen.Text(0, 0, 8, "中文测试", Normal)
	screen.Fill(Rect{1, 0, 4, 1}, Selected)
	if w := textWidth(strings.Split(screen.Plain(), "\n")[0]); w != 8 {
		t.Fatalf("overlay split a wide glyph: width %d", w)
	}
	screen.Text(2, 0, 4, "a界", Normal)
	if w := textWidth(strings.Split(screen.Plain(), "\n")[0]); w != 8 {
		t.Fatalf("replacement left a continuation cell: %d", w)
	}
}

func TestSelectionAndTree(t *testing.T) {
	s := demoState()
	if s.Rows[0].Process.PID != 100 || s.Selected.PID != 100 {
		t.Fatal("initial sort must follow highest CPU")
	}
	s.move(3)
	selected := s.Selected
	s.Reverse = true
	s.Rebuild()
	if s.Selected != selected {
		t.Fatal("selection lost after resort")
	}
	s.Tree = true
	s.Filter = "worker99 "
	s.Rebuild()
	if len(s.Rows) < 2 {
		t.Fatal("search lost tree ancestors")
	}
	if s.Rows[0].Process.PID != 1 || !s.Rows[0].Ancestor {
		t.Fatal("expected root ancestor")
	}
	found := false
	for _, row := range s.Rows {
		if row.Process.PID == 99 {
			found = true
			if row.Ancestor {
				t.Fatal("match marked ancestor")
			}
		}
	}
	if !found {
		t.Fatal("tree dropped match")
	}
	s.Filter = ""
	s.Snapshot.Processes = []monitor.Process{{PID: 1, PPID: 2}, {PID: 2, PPID: 1}}
	s.Rebuild()
	if len(s.Rows) != 2 {
		t.Fatal("tree cycle dropped nodes")
	}
}

func TestDecoderFragmentationAndPaste(t *testing.T) {
	var d Decoder
	if len(d.Feed("\x1b[")) != 0 {
		t.Fatal("partial sequence dispatched")
	}
	keys := d.Feed("A")
	if len(keys) != 1 || keys[0].Name != "up" {
		t.Fatalf("up: %+v", keys)
	}
	if len(d.Feed("\xc3")) != 0 {
		t.Fatal("partial UTF8 dispatched")
	}
	keys = d.Feed("\xa9")
	if len(keys) != 1 || keys[0].Text != "é" {
		t.Fatalf("UTF8: %+v", keys)
	}
	keys = d.Feed("\x1b[200~kyq\x1b[20")
	if len(keys) != 0 {
		t.Fatal("paste dispatched shortcuts")
	}
	keys = d.Feed("1~")
	if len(keys) != 1 || keys[0].Name != "paste" || keys[0].Text != "kyq" {
		t.Fatalf("paste: %+v", keys)
	}
	_ = d.Feed("\x1b")
	keys = d.Escape()
	if len(keys) != 1 || keys[0].Name != "escape" {
		t.Fatal("bare Escape failed")
	}
}

func TestInteractionAndCapturedIdentity(t *testing.T) {
	s := demoState()
	s.View = 5
	s.Handle(Key{Name: "text", Text: "k"})
	target := s.Confirm
	if target == nil || target.PID != 100 {
		t.Fatal("signal did not capture selection")
	}
	s.Snapshot.Processes = nil
	s.Rebuild()
	if s.Confirm.PID != 100 {
		t.Fatal("signal target changed")
	}
	s.Handle(Key{Name: "paste", Text: "y"})
	if s.Confirm == nil {
		t.Fatal("pasted confirmation was accepted")
	}
	s.Handle(Key{Name: "escape"})
	s = demoState()
	s.Handle(Key{Name: "text", Text: "/"})
	s.Handle(Key{Name: "text", Text: "worker77"})
	if len(s.Rows) != 1 {
		t.Fatal("live search failed")
	}
	s.Handle(Key{Name: "escape"})
	if s.Filter != "" || len(s.Rows) != 100 {
		t.Fatal("search cancel failed")
	}
	s.Handle(Key{Name: "enter"})
	old := s.DetailTarget.PID
	s.Snapshot.Processes = nil
	s.Rebuild()
	screen := NewScreen(100, 30, false)
	s.Draw(screen)
	if !strings.Contains(screen.Plain(), "EXITED") || !strings.Contains(screen.Plain(), fmt.Sprintf("PID %d", old)) {
		t.Fatal("detail view switched process after exit")
	}
}

func BenchmarkDrawDashboard(b *testing.B) {
	s := demoState()
	screen := NewScreen(160, 50, false)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Draw(screen)
	}
}

func TestStaleSnapshotIsVisible(t *testing.T) {
	s := demoState()
	s.LastError = "read CPU counters: unavailable"
	screen := NewScreen(100, 30, false)
	s.Draw(screen)
	if !strings.Contains(screen.Plain(), "STALE") || !strings.Contains(screen.Plain(), s.LastError) {
		t.Fatal("stale sample presented as live")
	}
	s.Accept(s.Snapshot)
	if s.LastError != "" {
		t.Fatal("collector recovery did not clear error")
	}
}

func BenchmarkSortProcesses(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s := NewState(time.Second, false)
			for i := 0; i < n; i++ {
				s.Snapshot.Processes = append(s.Snapshot.Processes, monitor.Process{PID: i + 1, CPU: float64(i * 7 % 100), Name: "worker", User: "nico"})
			}
			s.Rebuild()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.Rebuild()
			}
		})
	}
}
