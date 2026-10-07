package ui

import (
	"eyesofnico/internal/monitor"
	"fmt"
	"sort"
	"strings"
	"time"
)

func bytes(v float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f B", v)
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}
func shortBytes(v float64) string {
	u := []string{"B", "K", "M", "G", "T", "P"}
	i := 0
	for v >= 1024 && i < len(u)-1 {
		v /= 1024
		i++
	}
	if v >= 100 || i == 0 {
		return fmt.Sprintf("%.0f%s", v, u[i])
	}
	return fmt.Sprintf("%.1f%s", v, u[i])
}
func uptime(v float64) string {
	d := int(v) / 86400
	h := int(v) / 3600 % 24
	m := int(v) / 60 % 60
	if d > 0 {
		return fmt.Sprintf("%dd %02dh %02dm", d, h, m)
	}
	return fmt.Sprintf("%02dh %02dm", h, m)
}
func duration(v float64) string {
	h := int(v) / 3600
	m := int(v) / 60 % 60
	sec := int(v) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm", h, m)
	}
	return fmt.Sprintf("%d:%02d", m, sec)
}
func peak(values []float64) float64 {
	v := 0.0
	for _, n := range values {
		v = max(v, n)
	}
	return v
}

func (s *State) metric(name, format string, args ...any) string {
	if !s.Snapshot.MetricAvailable(name) {
		return "n/a"
	}
	return fmt.Sprintf(format, args...)
}

func (s *State) loadText() string {
	return "Load " + s.metric("load", "%.2f %.2f %.2f", s.Snapshot.Load[0], s.Snapshot.Load[1], s.Snapshot.Load[2])
}

func processMetric(p monitor.Process, name, format string, args ...any) string {
	if !p.MetricAvailable(name) {
		return "n/a"
	}
	return fmt.Sprintf(format, args...)
}

func (s *State) Draw(screen *Screen) {
	screen.Clear()
	w, h := screen.W, screen.H
	if w < 40 || h < 12 {
		screen.Text(1, 1, w-2, "EyesOfNico", Magenta)
		screen.Text(1, 3, w-2, "Terminal too small", White)
		screen.Text(1, 4, w-2, fmt.Sprintf("%dx%d / minimum 40x12", w, h), Muted)
		screen.Text(1, 6, w-2, "Resize the terminal. q: quit", Cyan)
		return
	}
	screen.Text(1, 0, 16, "EYES OF NICO", Magenta)
	status := "LIVE"
	style := Green
	if s.Paused {
		status = "PAUSED"
		style = Yellow
	} else if !s.Snapshot.Ready {
		status = "WARMUP"
		style = Yellow
	}
	if s.LastError != "" && !s.Paused {
		status = "STALE"
		style = Red
	}
	screen.Text(16, 0, 7, status, style)
	if w >= 75 {
		screen.Text(24, 0, w-48, s.Snapshot.Host+" / "+s.Snapshot.Kernel, Muted)
	}
	stamp := fmt.Sprintf("%s  %.1fs", s.Snapshot.At.Local().Format("15:04:05"), s.Interval.Seconds())
	screen.Text(w-textWidth(stamp)-1, 0, textWidth(stamp), stamp, White)
	tabs := []string{"Overview", "CPU", "Memory", "Network", "Disks", "Processes"}
	x := 1
	for i, name := range tabs {
		if w < 78 {
			name = []string{"All", "CPU", "Mem", "Net", "Disk", "Proc"}[i]
		}
		label := fmt.Sprintf(" %d %s ", i+1, name)
		if w < 58 {
			label = fmt.Sprintf("%d%s", i+1, name)
		}
		st := Muted
		if s.View == i {
			st = Selected
		}
		screen.Text(x, 1, w-x, label, st)
		x += textWidth(label) + 1
	}
	r := Rect{0, 3, w, h - 5}
	switch s.View {
	case 1:
		if r.H >= 20 {
			s.cpuPanel(screen, Rect{r.X, r.Y, r.W, r.H - 8}, true)
			s.pressurePanel(screen, Rect{r.X, r.Y + r.H - 8, r.W, 8})
		} else {
			s.cpuPanel(screen, r, true)
		}
	case 2:
		if r.H >= 16 {
			top := min(12, r.H/2)
			if w >= 95 {
				s.memoryPanel(screen, Rect{0, r.Y, w / 2, top})
				s.pressurePanel(screen, Rect{w / 2, r.Y, w - w/2, top})
			} else {
				s.memoryPanel(screen, Rect{0, r.Y, w, top})
			}
			s.processPanel(screen, Rect{0, r.Y + top, w, r.H - top})
		} else {
			s.memoryPanel(screen, r)
		}
	case 3:
		s.networkFull(screen, r)
	case 4:
		s.diskFull(screen, r)
	case 5:
		s.processPanel(screen, r)
	default:
		s.overview(screen, r)
	}
	footer := fmt.Sprintf("%d processes / %d threads / %s running / %s blocked   up %s   collect %.1fms", len(s.Snapshot.Processes), s.Snapshot.Threads, s.metric("process_state", "%d", s.Snapshot.Running), s.metric("process_state", "%d", s.Snapshot.Blocked), uptime(s.Snapshot.Uptime), s.Snapshot.CollectMS)
	st := Muted
	if len(s.Snapshot.Warnings) > 0 {
		footer = s.Snapshot.Warnings[0]
		st = Yellow
	}
	if s.Filter != "" {
		footer = fmt.Sprintf("Filter: %s | %d matches | Esc: clear", s.Filter, len(s.Rows))
		st = Cyan
	}
	if s.LastError != "" {
		footer = s.LastError
		st = Red
	}
	if s.Message != "" && time.Now().Before(s.messageUntil) {
		footer = s.Message
		st = Yellow
	}
	if s.Searching {
		footer = "Search: " + s.Filter + "_  Enter: apply / Esc: cancel"
		st = White
	}
	screen.Text(1, h-2, w-2, footer, st)
	keys := "/ search  s sort  t tree  Enter details  k signal  p pause  +/- speed  ? help  q quit"
	if s.Snapshot.OS == "windows" {
		keys = "/ search  s sort  t tree  Enter details  x terminate  p pause  ? help  q quit"
	}
	if s.View == 1 {
		keys = "Up/Down scroll cores  p pause  +/- speed  1 overview  ? help  q quit"
	}
	if s.View == 3 || s.View == 4 {
		keys = "[/] device  Up/Down scroll  p pause  +/- speed  ? help  q quit"
	}
	if w < 85 {
		keys = "1-6 views  / search  p pause  ? help  q quit"
	}
	if w < 58 {
		keys = "1-6 views  / find  ? help  q quit"
	}
	screen.Text(1, h-1, w-2, keys, Cyan)
	if s.Help {
		s.help(screen)
	}
	if s.Details {
		s.details(screen)
	}
	if s.Confirm != nil {
		s.confirm(screen)
	}
}

func (s *State) overview(screen *Screen, r Rect) {
	if r.W >= 100 && r.H >= 23 {
		top := 10
		if r.H >= 31 {
			top = 12
		}
		split := r.W * 62 / 100
		s.cpuPanel(screen, Rect{0, r.Y, split, top}, false)
		s.memoryPanel(screen, Rect{split, r.Y, r.W - split, top})
		left := r.W * 36 / 100
		bottom := r.H - top
		netHeight := bottom / 2
		s.networkPanel(screen, Rect{0, r.Y + top, left, netHeight})
		s.diskPanel(screen, Rect{0, r.Y + top + netHeight, left, bottom - netHeight})
		s.processPanel(screen, Rect{left, r.Y + top, r.W - left, bottom})
	} else if r.H >= 16 {
		top := min(9, r.H/2)
		if r.W < 100 {
			top = 7
		}
		if r.W >= 100 {
			split := r.W * 58 / 100
			s.cpuPanel(screen, Rect{0, r.Y, split, top}, false)
			s.memoryPanel(screen, Rect{split, r.Y, r.W - split, top})
		} else {
			s.compactSummary(screen, Rect{0, r.Y, r.W, top})
		}
		s.processPanel(screen, Rect{0, r.Y + top, r.W, r.H - top})
	} else {
		s.processPanel(screen, r)
	}
}

func (s *State) compactSummary(screen *Screen, r Rect) {
	in := screen.Box(r, "SYSTEM", "host scope")
	if in.H < 1 {
		return
	}
	m := s.Snapshot.Memory
	rows := []struct {
		label, value string
		p            float64
	}{
		{"CPU", fmt.Sprintf("%.1f%% / %d cores", s.Snapshot.CPU.Busy, len(s.Snapshot.Cores)), s.Snapshot.CPU.Busy},
		{"RAM", bytes(float64(m.Used)) + " / " + bytes(float64(m.Total)), monitor.Percent(m.Used, m.Total)},
		{"SWAP", s.metric("swap", "%s / %s", bytes(float64(m.SwapUsed)), bytes(float64(m.SwapTotal))), monitor.Percent(m.SwapUsed, m.SwapTotal)},
	}
	for i, row := range rows {
		if i >= in.H {
			break
		}
		screen.Text(in.X, in.Y+i, 6, row.label, White)
		screen.Text(in.X+6, in.Y+i, 25, row.value, valueStyle(row.p))
		if in.W > 33 {
			screen.Bar(in.X+33, in.Y+i, in.W-33, row.p, valueStyle(row.p))
		}
	}
	if in.H > 3 {
		screen.Text(in.X, in.Y+4, in.W, s.loadText()+" / up "+uptime(s.Snapshot.Uptime), Muted)
	}
}

func (s *State) cpuPanel(screen *Screen, r Rect, full bool) {
	in := screen.Box(r, "CPU", fmt.Sprintf("%d logical", len(s.Snapshot.Cores)))
	if in.H < 1 {
		return
	}
	cp := s.Snapshot.CPU
	screen.Text(in.X, in.Y, 20, fmt.Sprintf("%5.1f%% busy", cp.Busy), valueStyle(cp.Busy))
	screen.Bar(in.X+16, in.Y, in.W-16, cp.Busy, valueStyle(cp.Busy))
	if in.H < 2 {
		return
	}
	model := s.Snapshot.CPUModel
	if s.Snapshot.Slow.FrequencyMHz > 0 {
		model = fmt.Sprintf("%.2f GHz / %s", s.Snapshot.Slow.FrequencyMHz/1000, model)
	}
	screen.Text(in.X, in.Y+1, in.W, model, Muted)
	graphH := 0
	if in.H >= 6 {
		graphH = 2
	}
	if full && in.H >= 12 {
		graphH = min(6, in.H/3)
	}
	if graphH > 0 {
		screen.Graph(Rect{in.X, in.Y + 2, in.W, graphH}, s.CPUHistory.Values(), 100, Magenta)
	}
	y := in.Y + 2 + graphH
	if y < in.Y+in.H {
		line := s.loadText()
		if s.Snapshot.OS != "darwin" {
			line += " / wait " + s.metric("cpu_iowait", "%.1f%%", cp.Wait) + "  steal " + s.metric("cpu_steal", "%.1f%%", cp.Steal)
		}
		screen.Text(in.X, y, in.W, line, Cyan)
		y++
	}
	if full && y < in.Y+in.H {
		line := fmt.Sprintf("User %.1f%%  system %.1f%%", cp.User, cp.System)
		if s.Snapshot.OS != "darwin" {
			line += fmt.Sprintf("  ctx %s  forks %s", s.metric("context_switches", "%.0f/s", s.Snapshot.ContextSwitches), s.metric("forks", "%.0f/s", s.Snapshot.Forks))
		}
		screen.Text(in.X, y, in.W, line, Muted)
		y++
	}
	cols := max(1, in.W/24)
	cw := in.W / cols
	available := max(0, in.Y+in.H-y)
	offset := 0
	if full {
		offset = min(s.CoreOffset, max(0, len(s.Snapshot.Cores)-available*cols))
	}
	for i := 0; i < available*cols && i+offset < len(s.Snapshot.Cores); i++ {
		c := s.Snapshot.Cores[i+offset]
		x := in.X + (i%cols)*cw
		row := y + i/cols
		screen.Text(x, row, 5, strings.TrimPrefix(c.Name, "cpu"), Muted)
		screen.Bar(x+4, row, cw-12, c.Busy, valueStyle(c.Busy))
		screen.Text(x+cw-7, row, 6, fmt.Sprintf("%5.1f%%", c.Busy), valueStyle(c.Busy))
	}
	if full && offset+available*cols < len(s.Snapshot.Cores) {
		screen.Text(r.X+r.W-29, r.Y+r.H-1, 26, " scroll for more cores ", Cyan)
	}
}

func (s *State) memoryPanel(screen *Screen, r Rect) {
	in := screen.Box(r, "MEMORY", "host scope")
	if in.H < 1 {
		return
	}
	m := s.Snapshot.Memory
	p := monitor.Percent(m.Used, m.Total)
	screen.Text(in.X, in.Y, in.W, fmt.Sprintf("RAM %5.1f%%   %s / %s", p, bytes(float64(m.Used)), bytes(float64(m.Total))), valueStyle(p))
	if in.H > 1 {
		screen.Bar(in.X, in.Y+1, in.W, p, Magenta)
	}
	if in.H > 2 {
		label := "cache"
		if s.Snapshot.OS == "darwin" {
			label = "file cache"
		}
		screen.Text(in.X, in.Y+2, in.W, "Available "+bytes(float64(m.Available))+"  "+label+" "+s.metric("memory_cache", "%s", bytes(float64(m.Cached))), Cyan)
	}
	if in.H > 3 {
		t := "Swap disabled"
		if m.SwapTotal > 0 {
			t = fmt.Sprintf("SWAP %4.1f%%  %s / %s", monitor.Percent(m.SwapUsed, m.SwapTotal), bytes(float64(m.SwapUsed)), bytes(float64(m.SwapTotal)))
		}
		if !s.Snapshot.MetricAvailable("swap") {
			t = "Swap unavailable"
		}
		screen.Text(in.X, in.Y+3, in.W, t, White)
	}
	if in.H > 4 {
		screen.Bar(in.X, in.Y+4, in.W, monitor.Percent(m.SwapUsed, m.SwapTotal), Purple)
	}
	if in.H > 5 {
		line := "Buffers " + s.metric("memory_buffers", "%s", bytes(float64(m.Buffers))) + "  slab " + s.metric("memory_slab", "%s", bytes(float64(m.Slab)))
		if s.Snapshot.OS == "darwin" {
			line = "Native memory statistics unavailable"
			if m.Darwin != nil && m.Darwin.Available {
				line = fmt.Sprintf("Wired %s  compressed %s", bytes(float64(m.Darwin.Wired)), bytes(float64(m.Darwin.Compressed)))
			}
		}
		screen.Text(in.X, in.Y+5, in.W, line, Muted)
	}
	if in.H > 6 {
		line := "Dirty/writeback " + s.metric("memory_dirty", "%s", bytes(float64(m.Dirty)))
		if s.Snapshot.OS == "darwin" {
			line = ""
			if m.Darwin != nil && m.Darwin.Available {
				line = fmt.Sprintf("Active %s  inactive %s", bytes(float64(m.Darwin.Active)), bytes(float64(m.Darwin.Inactive)))
			}
		}
		screen.Text(in.X, in.Y+6, in.W, line, Muted)
	}
	if in.H > 7 {
		p := s.Snapshot.Pressure["memory"]
		text := "Memory pressure: unavailable"
		if p.Available {
			text = fmt.Sprintf("Memory pressure 10s: %.2f%%", p.Some[0])
		}
		if s.Snapshot.OS == "darwin" {
			text = "Memory pressure: " + s.darwinPressure()
		}
		screen.Text(in.X, in.Y+7, in.W, text, Cyan)
	}
	if in.H > 9 {
		screen.Graph(Rect{in.X, in.Y + 9, in.W, in.H - 9}, s.MemoryHistory.Values(), 100, Purple)
	}
}

func (s *State) pressurePanel(screen *Screen, r Rect) {
	if s.Snapshot.OS == "darwin" {
		s.darwinPressurePanel(screen, r)
		return
	}
	in := screen.Box(r, "PRESSURE / PSI", "time stalled")
	if in.H < 1 {
		return
	}
	screen.Text(in.X, in.Y, in.W, "RESOURCE       SOME 10s     60s    300s    FULL 10s", Table)
	for i, name := range []string{"cpu", "memory", "io"} {
		if i+1 >= in.H {
			break
		}
		p := s.Snapshot.Pressure[name]
		text := fmt.Sprintf("%-10s   unavailable", name)
		if p.Available {
			text = fmt.Sprintf("%-10s   %7.2f%% %6.2f%% %6.2f%%    %6.2f%%", name, p.Some[0], p.Some[1], p.Some[2], p.Full[0])
		}
		screen.Text(in.X, in.Y+i+1, in.W, text, Cyan)
	}
	if in.H > 4 {
		screen.Text(in.X, in.Y+4, in.W, "some: one or more tasks stalled / full: all non-idle tasks stalled", Muted)
	}
	if in.H > 5 {
		text := "Temperature sensors unavailable"
		if len(s.Snapshot.Slow.Sensors) > 0 {
			var parts []string
			for _, v := range s.Snapshot.Slow.Sensors {
				parts = append(parts, fmt.Sprintf("%s %.0fC", v.Name, v.Celsius))
			}
			text = strings.Join(parts, " / ")
		}
		screen.Text(in.X, in.Y+5, in.W, text, Yellow)
	}
}

func (s *State) networkValues() (float64, float64, *PairHistory) {
	var rx, tx float64
	for _, n := range s.Snapshot.Networks {
		if s.NetDevice == "*" && !n.IsLoopback() || n.Name == s.NetDevice {
			rx += n.RXRate
			tx += n.TXRate
		}
	}
	h := s.NetHistory[s.NetDevice]
	if h == nil {
		h = &PairHistory{}
	}
	return rx, tx, h
}

func (s *State) networkPanel(screen *Screen, r Rect) {
	in := screen.Box(r, "NETWORK", "4 expand")
	if in.H < 1 {
		return
	}
	rx, tx, h := s.networkValues()
	screen.Text(in.X, in.Y, in.W, "RX  "+bytes(rx)+"/s", Cyan)
	if in.H > 1 {
		screen.Graph(Rect{in.X, in.Y + 1, in.W, 1}, h.A.Values(), max(1024, peak(h.A.Values())), Cyan)
	}
	if in.H > 2 {
		screen.Text(in.X, in.Y+2, in.W, "TX  "+bytes(tx)+"/s", Magenta)
	}
	if in.H > 3 {
		screen.Graph(Rect{in.X, in.Y + 3, in.W, 1}, h.B.Values(), max(1024, peak(h.B.Values())), Magenta)
	}
	networks := append([]monitor.Network(nil), s.Snapshot.Networks...)
	sort.SliceStable(networks, func(i, j int) bool {
		return networks[i].RXRate+networks[i].TXRate > networks[j].RXRate+networks[j].TXRate
	})
	for i, n := range networks {
		y := in.Y + 4 + i
		if y >= in.Y+in.H {
			break
		}
		screen.Text(in.X, y, in.W, fmt.Sprintf("%-12s %8s %8s", clip(n.Name, 12), shortBytes(n.RXRate)+"/s", shortBytes(n.TXRate)+"/s"), Muted)
	}
}

func (s *State) rateGraph(screen *Screen, r Rect, title string, values []float64, now float64, style Style) {
	in := screen.Box(r, title, "bytes/s")
	if in.H < 1 {
		return
	}
	scale := max(1024, peak(values))
	screen.Text(in.X, in.Y, in.W, fmt.Sprintf("%s/s   peak %s/s", bytes(now), bytes(peak(values))), style)
	if in.H > 2 {
		screen.Graph(Rect{in.X, in.Y + 2, in.W, in.H - 2}, values, scale, style)
		screen.Text(in.X, in.Y+1, in.W, "scale "+bytes(scale)+"/s", Muted)
	}
}

func (s *State) networkFull(screen *Screen, r Rect) {
	rx, tx, h := s.networkValues()
	device := s.NetDevice
	if device == "*" {
		device = "all except loopback"
	}
	top := max(5, min(12, r.H/2))
	if r.H < 13 {
		top = 0
	}
	if top > 0 {
		half := r.W / 2
		s.rateGraph(screen, Rect{r.X, r.Y, half, top}, "RX / "+device, h.A.Values(), rx, Cyan)
		s.rateGraph(screen, Rect{r.X + half, r.Y, r.W - half, top}, "TX / "+device, h.B.Values(), tx, Magenta)
	}
	in := screen.Box(Rect{r.X, r.Y + top, r.W, r.H - top}, "INTERFACES", "[/] select")
	if in.H < 1 {
		return
	}
	header := "INTERFACE       STATE        RX/s        TX/s       ERRORS    DROPS"
	if in.W < 65 {
		header = "INTERFACE        RX/s      TX/s"
	}
	screen.Text(in.X, in.Y, in.W, header, Table)
	offset := min(s.NetOffset, max(0, len(s.Snapshot.Networks)-max(1, in.H-3)))
	for i := offset; i < len(s.Snapshot.Networks); i++ {
		y := in.Y + 1 + i - offset
		if y >= in.Y+in.H-2 {
			break
		}
		n := s.Snapshot.Networks[i]
		st := Normal
		if n.Name == s.NetDevice {
			st = Selected
		}
		text := fmt.Sprintf("%s %s %11s %11s %8d %8d", pad(n.Name, 15), pad(s.Snapshot.Slow.NetworkState[n.Name], 7), shortBytes(n.RXRate), shortBytes(n.TXRate), n.Errors, n.Drops)
		if in.W < 65 {
			text = fmt.Sprintf("%s %9s %9s", pad(n.Name, 12), shortBytes(n.RXRate), shortBytes(n.TXRate))
		}
		if in.W >= 100 {
			text += fmt.Sprintf("   total RX %s / TX %s", bytes(float64(n.RXBytes)), bytes(float64(n.TXBytes)))
		}
		screen.Text(in.X, y, in.W, pad(text, in.W), st)
	}
	if in.H >= 3 {
		screen.Text(in.X, in.Y+in.H-2, in.W, "All excludes loopback; bridges/tunnels can count traffic twice.", Muted)
	}
	if in.H >= 2 {
		screen.Text(in.X, in.Y+in.H-1, in.W, "Choose an interface with [ or ]. Errors and drops are lifetime counters.", Muted)
	}
}

func (s *State) selectedDisk() monitor.Disk {
	for _, d := range s.Snapshot.Disks {
		if d.Name == s.DiskDevice {
			return d
		}
	}
	return monitor.Disk{}
}

func (s *State) diskPanel(screen *Screen, r Rect) {
	in := screen.Box(r, "DISKS", "5 expand")
	if in.H < 1 {
		return
	}
	d := s.selectedDisk()
	if d.Name != "" {
		screen.Text(in.X, in.Y, in.W, fmt.Sprintf("%s  R %s/s  W %s/s", d.Name, shortBytes(d.ReadRate), shortBytes(d.WriteRate)), Cyan)
		if in.H > 1 {
			if s.Snapshot.OS == "darwin" {
				screen.Text(in.X, in.Y+1, in.W, fmt.Sprintf("IOPS %.0f  latency %.2f ms", d.IOPS, d.Await), Purple)
			} else {
				screen.Text(in.X, in.Y+1, 13, "Busy "+s.metric("disk_busy", "%5.1f%%", d.Busy), valueStyle(d.Busy))
				if s.Snapshot.MetricAvailable("disk_busy") {
					screen.Bar(in.X+14, in.Y+1, in.W-14, d.Busy, Purple)
				}
			}
		}
	} else {
		screen.Text(in.X, in.Y, in.W, "No block device counters", Muted)
	}
	if s.Snapshot.Slow.At.IsZero() {
		if in.H > 2 {
			screen.Text(in.X, in.Y+2, in.W, "Collecting filesystem usage...", Muted)
		}
		return
	}
	for i, fs := range s.Snapshot.Slow.Filesystems {
		y := in.Y + 2 + i
		if y >= in.Y+in.H {
			break
		}
		p := monitor.Percent(fs.Used, fs.Used+fs.Available)
		screen.Text(in.X, y, in.W, fmt.Sprintf("%s %5.1f%% %s free", pad(fs.Mount, min(13, max(4, in.W-22))), p, bytes(float64(fs.Available))), valueStyle(p))
	}
}

func (s *State) diskFull(screen *Screen, r Rect) {
	d := s.selectedDisk()
	h := s.DiskHistory[d.Name]
	if h == nil {
		h = &PairHistory{}
	}
	top := 0
	if r.H >= 20 {
		top = min(10, r.H/3)
	}
	if top > 0 {
		half := r.W / 2
		s.rateGraph(screen, Rect{r.X, r.Y, half, top}, "READ / "+d.Name, h.A.Values(), d.ReadRate, Cyan)
		s.rateGraph(screen, Rect{r.X + half, r.Y, r.W - half, top}, "WRITE / "+d.Name, h.B.Values(), d.WriteRate, Magenta)
	}
	tableH := min(max(5, len(s.Snapshot.Disks)+4), max(4, (r.H-top)/2))
	in := screen.Box(Rect{r.X, r.Y + top, r.W, tableH}, "BLOCK DEVICES", "[/] select")
	if in.H > 0 {
		header := "DEVICE         READ/s   WRITE/s     IOPS    BUSY%   AWAITms    QUEUE"
		if in.W < 65 {
			header = "DEVICE      READ/s   WRITE/s   BUSY%"
		}
		if s.Snapshot.OS == "darwin" {
			header = "DEVICE         READ/s   WRITE/s     IOPS   AWAITms"
			if in.W < 65 {
				header = "DEVICE      READ/s   WRITE/s    IOPS"
			}
		}
		screen.Text(in.X, in.Y, in.W, header, Table)
		idx := 0
		for i, v := range s.Snapshot.Disks {
			if v.Name == s.DiskDevice {
				idx = i
			}
		}
		offset := max(0, idx-max(1, in.H-2)+1)
		for i := offset; i < len(s.Snapshot.Disks) && i-offset < in.H-1; i++ {
			v := s.Snapshot.Disks[i]
			st := Normal
			if v.Name == s.DiskDevice {
				st = Selected
			}
			busy := s.metric("disk_busy", "%.1f", v.Busy)
			line := fmt.Sprintf("%s %9s %9s %8.0f %7s %9s %8s", pad(v.Name, 12), shortBytes(v.ReadRate), shortBytes(v.WriteRate), v.IOPS, busy, s.metric("disk_await", "%.2f", v.Await), s.metric("disk_queue", "%.2f", v.Queue))
			if in.W < 65 {
				line = fmt.Sprintf("%s %8s %8s %6s", pad(v.Name, 9), shortBytes(v.ReadRate), shortBytes(v.WriteRate), busy)
			}
			if s.Snapshot.OS == "darwin" {
				line = fmt.Sprintf("%s %9s %9s %8.0f %9.2f", pad(v.Name, 12), shortBytes(v.ReadRate), shortBytes(v.WriteRate), v.IOPS, v.Await)
				if in.W < 65 {
					line = fmt.Sprintf("%s %8s %8s %7.0f", pad(v.Name, 9), shortBytes(v.ReadRate), shortBytes(v.WriteRate), v.IOPS)
				}
			}
			screen.Text(in.X, in.Y+1+i-offset, in.W, pad(line, in.W), st)
		}
	}
	in = screen.Box(Rect{r.X, r.Y + top + tableH, r.W, r.H - top - tableH}, "FILESYSTEMS", "5s cache / local only")
	if in.H < 1 {
		return
	}
	if s.Snapshot.Slow.At.IsZero() {
		screen.Text(in.X, in.Y, in.W, "Collecting local filesystem usage...", Muted)
		return
	}
	header := "MOUNT                       USED      TOTAL       FREE    USE%  INODE%"
	if in.W < 70 {
		header = "MOUNT          USED      FREE   USE%"
	}
	screen.Text(in.X, in.Y, in.W, header, Table)
	offset := min(s.DiskOffset, max(0, len(s.Snapshot.Slow.Filesystems)-max(1, in.H-2)))
	for i := offset; i < len(s.Snapshot.Slow.Filesystems) && i-offset < in.H-2; i++ {
		fs := s.Snapshot.Slow.Filesystems[i]
		p := monitor.Percent(fs.Used, fs.Used+fs.Available)
		line := fmt.Sprintf("%s %9s %9s %9s %6.1f %7s", pad(fs.Mount, 23), shortBytes(float64(fs.Used)), shortBytes(float64(fs.Total)), shortBytes(float64(fs.Available)), p, s.metric("inodes", "%.1f", fs.InodeUsed))
		if in.W < 70 {
			line = fmt.Sprintf("%s %8s %8s %6.1f", pad(fs.Mount, 10), shortBytes(float64(fs.Used)), shortBytes(float64(fs.Available)), p)
		}
		screen.Text(in.X, in.Y+1+i-offset, in.W, line, valueStyle(p))
	}
	if in.H > 1 {
		message := "Capacity excludes reserved blocks from available space."
		if !s.Paused && time.Since(s.Snapshot.Slow.At) > 15*time.Second {
			message = "Filesystem sample is stale; a storage query may be blocked."
		}
		if len(s.Snapshot.Slow.Warnings) > 0 {
			message = s.Snapshot.Slow.Warnings[0]
		}
		screen.Text(in.X, in.Y+in.H-1, in.W, message, Muted)
	}
}

func (s *State) processPanel(screen *Screen, r Rect) {
	mode := strings.ToUpper(s.Sort)
	if s.Reverse {
		mode += " asc"
	}
	if s.Tree {
		mode += " / tree"
	}
	if s.OwnOnly {
		mode += " / own"
	}
	in := screen.Box(r, "PROCESSES", mode)
	if in.H < 1 {
		return
	}
	s.PageSize = max(1, in.H-2)
	s.ensureSelection()
	wide := in.W >= 100
	medium := in.W >= 65
	header := "    PID  S   CPU%    MEM    COMMAND"
	if medium {
		header = "    PID USER      S   CPU%    MEM   MEM%  COMMAND"
	}
	if wide {
		header = "    PID USER      NI  S   CPU%    MEM   MEM%   THR    TIME+  COMMAND"
	}
	showIO := s.ProcessIO && in.W >= 115
	if showIO {
		header = "    PID USER      NI  S   CPU%    MEM   READ/s  WRITE/s   THR  COMMAND"
	}
	screen.Text(in.X, in.Y, in.W, pad(header, in.W), Table)
	if len(s.Rows) == 0 && in.H > 1 {
		screen.Text(in.X, in.Y+1, in.W, "No matching processes. Esc clears the search.", Muted)
	}
	for i := s.Offset; i < len(s.Rows) && i-s.Offset < s.PageSize; i++ {
		row := s.Rows[i]
		p := row.Process
		y := in.Y + 1 + i - s.Offset
		cpu := processMetric(p, "cpu", "%.1f", p.CPU)
		rss := processMetric(p, "memory", "%s", shortBytes(float64(p.RSS)))
		memPercent := processMetric(p, "memory", "%.1f", monitor.Percent(p.RSS, s.Snapshot.Memory.Total))
		threads := processMetric(p, "threads", "%d", p.Threads)
		cpuTime := processMetric(p, "cpu", "%s", duration(p.CPUSeconds))
		prefix := fmt.Sprintf("%7d  %s %6s %6s  ", p.PID, p.State, cpu, rss)
		if medium {
			prefix = fmt.Sprintf("%7d %s %s %6s %6s %6s  ", p.PID, pad(p.User, 9), p.State, cpu, rss, memPercent)
		}
		if wide {
			prefix = fmt.Sprintf("%7d %s %3s  %s %6s %6s %6s %5s %8s  ", p.PID, pad(p.User, 9), s.metric("process_nice", "%d", p.Nice), p.State, cpu, rss, memPercent, threads, cpuTime)
		}
		if showIO {
			read, write := "-", "-"
			if p.IOAvailable {
				read = shortBytes(p.ReadRate)
				write = shortBytes(p.WriteRate)
			}
			prefix = fmt.Sprintf("%7d %s %3s  %s %6s %6s %8s %8s %5s  ", p.PID, pad(p.User, 9), s.metric("process_nice", "%d", p.Nice), p.State, cpu, rss, read, write, threads)
		}
		cmd := p.Command
		if !s.FullCommand {
			cmd = p.Name
		}
		if s.Tree {
			depth := min(row.Depth, max(0, (in.W-textWidth(prefix)-10)/2))
			branch := "└─"
			if screen.ASCII {
				branch = "`-"
			}
			cmd = strings.Repeat("  ", depth) + branch + cmd
		}
		st := Normal
		if p.State == "R" {
			st = Green
		}
		if p.State == "Z" || p.State == "D" {
			st = Yellow
		}
		if row.Ancestor {
			st = Muted
		}
		if p.PID == s.Selected.PID && p.StartTicks == s.Selected.Start {
			st = Selected
		}
		screen.Text(in.X, y, in.W, pad(prefix+cmd, in.W), st)
	}
	if in.H > 1 {
		screen.Text(in.X, in.Y+in.H-1, in.W, fmt.Sprintf("%d-%d / %d  |  CPU: 100%% = one core  |  s: sort / r: reverse", min(len(s.Rows), s.Offset+1), min(len(s.Rows), s.Offset+s.PageSize), len(s.Rows)), Muted)
	}
}

func modal(screen *Screen, width, height int, title string) Rect {
	w, h := min(screen.W-2, width), min(screen.H-2, height)
	r := Rect{(screen.W - w) / 2, (screen.H - h) / 2, w, h}
	screen.Fill(r, Normal)
	return screen.Box(r, title, "Esc closes")
}

func (s *State) help(screen *Screen) {
	lines := []string{
		"1 Overview   2 CPU   3 Memory   4 Network   5 Disks   6 Processes",
		"Tab next view / d overview / y CPU / n network",
		"Up/Down select or scroll / PgUp/PgDn page / Home/End jump",
		"/ search PID, user or command / Enter apply / Esc clear",
		"c CPU sort / m memory sort / s next sort / r reverse",
		"t process tree / u current user / f command or short name",
		"i process I/O (extra collection; permissions may hide it)",
		processKeys(),
		"Actions require y confirmation and recheck process identity.",
		"[ / ] or Left/Right choose network interface or block device",
		pauseKeys(),
		"q or Ctrl-C quit / ? or h help",
		"",
		"CPU/memory: visible host scope; no cgroup normalization.",
		"CPU: interval usage; 100% per process = one logical core.",
		"Memory used = total - available. RSS is the kernel estimate.",
		"PSI measures time stalled. Disk await is read/write latency.",
		"Rates use monotonic time. First sample establishes a baseline.",
		"History: last 240 samples. Pause stops all new sampling.",
		"Filesystems and sensors: 5s cache; remote mounts excluded.",
		"Unavailable metrics stay unavailable; no root required.",
	}
	in := modal(screen, 82, len(lines)+2, "KEYBOARD / METRICS")
	s.ModalOffset = min(s.ModalOffset, max(0, len(lines)-in.H))
	for i, line := range lines[s.ModalOffset:] {
		if i >= in.H {
			break
		}
		st := Normal
		if i >= 13 {
			st = Muted
		}
		screen.Text(in.X, in.Y+i, in.W, line, st)
	}
}

func (s *State) details(screen *Screen) {
	in := modal(screen, 86, 17, "PROCESS DETAILS")
	if s.DetailTarget == nil {
		screen.Text(in.X, in.Y, in.W, "The process is no longer available.", Yellow)
		return
	}
	p := *s.DetailTarget
	alive := false
	for _, current := range s.Snapshot.Processes {
		if current.PID == p.PID && current.StartTicks == p.StartTicks {
			p = current
			alive = true
			break
		}
	}
	lines := []string{
		fmt.Sprintf("PID %d / parent %d / user %s (%d)", p.PID, p.PPID, p.User, p.UID),
		fmt.Sprintf("State %s / nice %s / priority %s / CPU #%s", p.State, s.metric("process_nice", "%d", p.Nice), s.metric("process_priority", "%d", p.Priority), s.metric("process_processor", "%d", p.Processor)),
		fmt.Sprintf("CPU %s / total time %s / threads %s", processMetric(p, "cpu", "%.1f%%", p.CPU), processMetric(p, "cpu", "%s", duration(p.CPUSeconds)), processMetric(p, "threads", "%d", p.Threads)),
		fmt.Sprintf("Resident %s / virtual %s", processMetric(p, "memory", "%s", bytes(float64(p.RSS))), processMetric(p, "memory", "%s", bytes(float64(p.Virtual)))),
		fmt.Sprintf("Start identity: PID %d + %d (platform birth token)", p.PID, p.StartTicks),
	}
	if s.Snapshot.OS == "windows" {
		lines[0] = fmt.Sprintf("PID %d / parent %d / user %s", p.PID, p.PPID, p.User)
	}
	if s.Snapshot.OS == "darwin" {
		lines[1] = fmt.Sprintf("State %s / nice %d / priority %d", p.State, p.Nice, p.Priority)
	}
	if !alive {
		lines[0] += " / EXITED"
	}
	if p.IOAvailable {
		lines = append(lines, fmt.Sprintf("I/O read %s/s / write %s/s", bytes(p.ReadRate), bytes(p.WriteRate)))
	} else {
		lines = append(lines, "Process I/O unavailable or disabled (i toggles collection)")
	}
	lines = append(lines, "", "Command:")
	// Wrap by terminal columns, while keeping control characters inert.
	command := []rune(p.Command)
	for len(command) > 0 && len(lines) < 512 {
		n := 0
		cols := 0
		for n < len(command) {
			w := runeWidth(safeRune(command[n]))
			if cols+w > in.W {
				break
			}
			cols += w
			n++
		}
		if n == 0 {
			break
		}
		lines = append(lines, string(command[:n]))
		command = command[n:]
	}
	s.ModalOffset = min(s.ModalOffset, max(0, len(lines)-in.H))
	for i, line := range lines[s.ModalOffset:] {
		if i >= in.H {
			break
		}
		st := Normal
		if i == 0 {
			st = Cyan
		}
		screen.Text(in.X, in.Y+i, in.W, line, st)
	}
}

func (s *State) confirm(screen *Screen) {
	p := s.Confirm
	in := modal(screen, 76, 9, "CONFIRM PROCESS SIGNAL")
	lines := []string{fmt.Sprintf("Send %s to PID %d (%s)?", signalName(s.Signal), p.PID, p.Name),
		clip(p.Command, in.W), "", "y sends the signal / n or Esc cancels", "The selected process identity is checked again before sending."}
	if s.Signal == monitor.Kill {
		lines = append(lines, "Forced termination is immediate; unsaved work may be lost.")
	}
	for i, line := range lines {
		if i >= in.H {
			break
		}
		st := Normal
		if i == 0 {
			st = Yellow
		}
		screen.Text(in.X, in.Y+i, in.W, line, st)
	}
}
