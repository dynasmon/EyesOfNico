package ui

import (
	"eyesofnico/internal/monitor"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const historyLimit = 240

type History struct {
	values      [historyLimit]float64
	next, count int
}

func (h *History) Add(v float64) {
	h.values[h.next] = v
	h.next = (h.next + 1) % historyLimit
	h.count = min(historyLimit, h.count+1)
}
func (h *History) Values() []float64 {
	v := make([]float64, h.count)
	for i := range v {
		v[i] = h.values[(h.next-h.count+i+historyLimit)%historyLimit]
	}
	return v
}

type PairHistory struct{ A, B History }

type ProcessRow struct {
	Process  monitor.Process
	Depth    int
	Ancestor bool
}
type identity struct {
	PID   int
	Start uint64
}

type State struct {
	Snapshot                                                      monitor.Snapshot
	View                                                          int
	Interval                                                      time.Duration
	Paused, ASCII, Tree, Reverse, OwnOnly, FullCommand, ProcessIO bool
	Sort                                                          string
	Filter                                                        string
	Searching                                                     bool
	filterBefore                                                  string
	Rows                                                          []ProcessRow
	Selected                                                      identity
	SelectionPinned                                               bool
	DetailTarget                                                  *monitor.Process
	ModalOffset                                                   int
	Offset, PageSize, CoreOffset, NetOffset, DiskOffset           int
	NetDevice, DiskDevice                                         string
	CPUHistory, MemoryHistory                                     History
	NetHistory, DiskHistory                                       map[string]*PairHistory
	Help, Details                                                 bool
	Confirm                                                       *monitor.Process
	Signal                                                        syscall.Signal
	Message                                                       string
	LastError                                                     string
	messageUntil                                                  time.Time
}

func NewState(interval time.Duration, ascii bool) *State {
	return &State{Interval: interval, ASCII: ascii, Sort: "cpu", FullCommand: true, PageSize: 10, NetHistory: make(map[string]*PairHistory), DiskHistory: make(map[string]*PairHistory)}
}

func (s *State) Accept(snapshot monitor.Snapshot) {
	s.LastError = ""
	s.Snapshot = snapshot
	if snapshot.Ready {
		s.CPUHistory.Add(snapshot.CPU.Busy)
		s.MemoryHistory.Add(monitor.Percent(snapshot.Memory.Used, snapshot.Memory.Total))
		nets := make(map[string]bool)
		var rx, tx float64
		for _, n := range snapshot.Networks {
			nets[n.Name] = true
			h := s.NetHistory[n.Name]
			if h == nil {
				h = &PairHistory{}
				s.NetHistory[n.Name] = h
			}
			h.A.Add(n.RXRate)
			h.B.Add(n.TXRate)
			if n.Name != "lo" {
				rx += n.RXRate
				tx += n.TXRate
			}
		}
		for name := range s.NetHistory {
			if name != "*" && !nets[name] {
				delete(s.NetHistory, name)
			}
		}
		h := s.NetHistory["*"]
		if h == nil {
			h = &PairHistory{}
			s.NetHistory["*"] = h
		}
		h.A.Add(rx)
		h.B.Add(tx)
		disks := make(map[string]bool)
		for _, d := range snapshot.Disks {
			disks[d.Name] = true
			h := s.DiskHistory[d.Name]
			if h == nil {
				h = &PairHistory{}
				s.DiskHistory[d.Name] = h
			}
			h.A.Add(d.ReadRate)
			h.B.Add(d.WriteRate)
		}
		for name := range s.DiskHistory {
			if !disks[name] {
				delete(s.DiskHistory, name)
			}
		}
	}
	if s.NetDevice == "" {
		s.NetDevice = "*"
	}
	if s.NetDevice != "*" {
		found := false
		for _, n := range snapshot.Networks {
			if n.Name == s.NetDevice {
				found = true
			}
		}
		if !found {
			s.NetDevice = "*"
		}
	}
	found := false
	for _, d := range snapshot.Disks {
		if d.Name == s.DiskDevice {
			found = true
		}
	}
	if !found {
		s.DiskDevice = ""
		var largest uint64
		for _, d := range snapshot.Disks {
			if s.DiskDevice == "" || d.SizeBytes > largest {
				s.DiskDevice = d.Name
				largest = d.SizeBytes
			}
		}
	}
	s.Rebuild()
}

func (s *State) less(a, b monitor.Process) bool {
	var cmp int
	switch s.Sort {
	case "mem":
		if a.RSS < b.RSS {
			cmp = -1
		} else if a.RSS > b.RSS {
			cmp = 1
		}
	case "pid":
		if a.PID < b.PID {
			cmp = 1
		} else if a.PID > b.PID {
			cmp = -1
		}
	case "name":
		cmp = -strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	case "io":
		if a.ReadRate+a.WriteRate < b.ReadRate+b.WriteRate {
			cmp = -1
		} else if a.ReadRate+a.WriteRate > b.ReadRate+b.WriteRate {
			cmp = 1
		}
	default:
		if a.CPU < b.CPU {
			cmp = -1
		} else if a.CPU > b.CPU {
			cmp = 1
		}
	}
	if cmp == 0 {
		return a.PID < b.PID
	}
	if s.Reverse {
		return cmp < 0
	}
	return cmp > 0
}

func (s *State) Rebuild() {
	query := strings.ToLower(s.Filter)
	uid := uint32(os.Getuid())
	s.Rows = s.Rows[:0]
	// The usual flat view needs no PID maps or ancestry graph.
	if !s.Tree {
		for _, p := range s.Snapshot.Processes {
			if s.OwnOnly && p.UID != uid {
				continue
			}
			if query != "" && !strings.Contains(strings.ToLower(p.Command+" "+p.Name+" "+p.User+" "+strconv.Itoa(p.PID)), query) {
				continue
			}
			s.Rows = append(s.Rows, ProcessRow{Process: p})
		}
		sort.Slice(s.Rows, func(i, j int) bool { return s.less(s.Rows[i].Process, s.Rows[j].Process) })
		s.ensureSelection()
		return
	}
	all := make(map[int]monitor.Process, len(s.Snapshot.Processes))
	matches := make(map[int]bool)
	for _, p := range s.Snapshot.Processes {
		if s.OwnOnly && p.UID != uid {
			continue
		}
		all[p.PID] = p
		if query == "" || strings.Contains(strings.ToLower(p.Command+" "+p.Name+" "+p.User+" "+strconv.Itoa(p.PID)), query) {
			matches[p.PID] = true
		}
	}
	included := make(map[int]bool, len(matches))
	for pid := range matches {
		for n := 0; n <= len(all); n++ {
			p, ok := all[pid]
			if !ok || included[pid] {
				break
			}
			included[pid] = true
			pid = p.PPID
		}
	}
	children := make(map[int][]monitor.Process)
	var roots []monitor.Process
	for pid := range included {
		p := all[pid]
		if included[p.PPID] && p.PPID != pid {
			children[p.PPID] = append(children[p.PPID], p)
		} else {
			roots = append(roots, p)
		}
	}
	sortList := func(v []monitor.Process) { sort.Slice(v, func(i, j int) bool { return s.less(v[i], v[j]) }) }
	sortList(roots)
	for _, v := range children {
		sortList(v)
	}
	// Iterative traversal also tolerates synthetic cycles and extreme depth.
	type item struct {
		p     monitor.Process
		depth int
	}
	var stack []item
	visited := make(map[int]bool)
	walk := func(root monitor.Process) {
		stack = append(stack, item{root, 0})
		for len(stack) > 0 {
			entry := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			p := entry.p
			if visited[p.PID] {
				continue
			}
			visited[p.PID] = true
			s.Rows = append(s.Rows, ProcessRow{Process: p, Depth: entry.depth, Ancestor: !matches[p.PID]})
			v := children[p.PID]
			for i := len(v) - 1; i >= 0; i-- {
				stack = append(stack, item{v[i], entry.depth + 1})
			}
		}
	}
	for _, p := range roots {
		walk(p)
	}
	// Cycle-only components have no root; keep every matching process visible.
	var leftovers []monitor.Process
	for pid := range included {
		if !visited[pid] {
			leftovers = append(leftovers, all[pid])
		}
	}
	sortList(leftovers)
	for _, p := range leftovers {
		if !visited[p.PID] {
			walk(p)
		}
	}
	s.ensureSelection()
}

func (s *State) selectedIndex() int {
	for i, row := range s.Rows {
		p := row.Process
		if p.PID == s.Selected.PID && p.StartTicks == s.Selected.Start {
			return i
		}
	}
	return -1
}

func (s *State) ensureSelection() {
	if len(s.Rows) == 0 {
		s.Selected = identity{}
		s.Offset = 0
		return
	}
	i := s.selectedIndex()
	if !s.SelectionPinned {
		i = 0
		s.Offset = 0
		p := s.Rows[0].Process
		s.Selected = identity{p.PID, p.StartTicks}
	}
	if i < 0 {
		i = min(s.Offset, len(s.Rows)-1)
		p := s.Rows[i].Process
		s.Selected = identity{p.PID, p.StartTicks}
	}
	s.Offset = min(s.Offset, max(0, len(s.Rows)-s.PageSize))
	if i < s.Offset {
		s.Offset = i
	}
	if i >= s.Offset+s.PageSize {
		s.Offset = max(0, i-s.PageSize+1)
	}
}

func (s *State) move(delta int) {
	if len(s.Rows) == 0 {
		return
	}
	s.SelectionPinned = true
	i := max(0, min(len(s.Rows)-1, s.selectedIndex()+delta))
	p := s.Rows[i].Process
	s.Selected = identity{p.PID, p.StartTicks}
	s.ensureSelection()
}

func (s *State) current() (monitor.Process, bool) {
	i := s.selectedIndex()
	if i < 0 {
		return monitor.Process{}, false
	}
	return s.Rows[i].Process, true
}
func (s *State) notify(text string) {
	s.Message = text
	s.messageUntil = time.Now().Add(5 * time.Second)
}

func (s *State) cycleDevice(delta int) {
	var names []string
	current := ""
	if s.View == 3 {
		names = append(names, "*")
		for _, n := range s.Snapshot.Networks {
			names = append(names, n.Name)
		}
		current = s.NetDevice
	} else {
		for _, d := range s.Snapshot.Disks {
			names = append(names, d.Name)
		}
		current = s.DiskDevice
	}
	if len(names) == 0 {
		return
	}
	idx := 0
	for i, name := range names {
		if name == current {
			idx = i
		}
	}
	idx = (idx + delta + len(names)) % len(names)
	if s.View == 3 {
		s.NetDevice = names[idx]
		s.NetOffset = max(0, idx-1)
	} else {
		s.DiskDevice = names[idx]
	}
}

// Handle returns quit/suspend; all process signals require a separate explicit
// 'y' key, operate on the captured identity, and reject pasted confirmation.
func (s *State) Handle(k Key) (quit, suspend bool) {
	if k.Name == "quit" {
		return true, false
	}
	if k.Name == "suspend" {
		return false, true
	}
	if s.Confirm != nil {
		if k.Name == "text" && k.Text == "y" {
			p := *s.Confirm
			err := monitor.Signal(p, s.Signal)
			if err != nil {
				s.notify(err.Error())
			} else {
				s.notify(fmt.Sprintf("%s sent to PID %d", signalName(s.Signal), p.PID))
			}
			s.Confirm = nil
		} else if k.Name == "escape" || (k.Name == "text" && (k.Text == "n" || k.Text == "q")) {
			s.Confirm = nil
		}
		return
	}
	if s.Searching {
		switch k.Name {
		case "escape":
			s.Filter = s.filterBefore
			s.Searching = false
		case "enter":
			s.Searching = false
		case "backspace":
			r := []rune(s.Filter)
			if len(r) > 0 {
				s.Filter = string(r[:len(r)-1])
			}
		case "clear":
			s.Filter = ""
		case "text", "paste":
			if len(s.Filter) < 256 {
				s.Filter += clip(k.Text, 256-len(s.Filter))
			}
		}
		s.Rebuild()
		return
	}
	if s.Help || s.Details {
		if k.Name == "up" || k.Name == "pgup" {
			s.ModalOffset = max(0, s.ModalOffset-5)
		}
		if k.Name == "down" || k.Name == "pgdown" {
			s.ModalOffset += 5
		}
		if k.Name == "escape" || k.Name == "enter" || (k.Name == "text" && (k.Text == "q" || k.Text == "h" || k.Text == "?")) {
			s.Help = false
			s.Details = false
			s.ModalOffset = 0
		}
		return
	}
	switch k.Name {
	case "escape":
		if s.Filter != "" {
			s.Filter = ""
			s.Rebuild()
		} else {
			s.View = 0
		}
	case "help":
		s.Help = true
	case "tab":
		s.View = (s.View + 1) % 6
	case "up", "down", "pgup", "pgdown", "home", "end":
		d := 1
		if k.Name == "up" {
			d = -1
		}
		if k.Name == "pgup" {
			d = -s.PageSize
		}
		if k.Name == "pgdown" {
			d = s.PageSize
		}
		if k.Name == "home" {
			d = -1 << 20
		}
		if k.Name == "end" {
			d = 1 << 20
		}
		switch s.View {
		case 1:
			s.CoreOffset = max(0, min(max(0, len(s.Snapshot.Cores)-1), s.CoreOffset+d))
		case 3:
			s.NetOffset = max(0, min(max(0, len(s.Snapshot.Networks)-1), s.NetOffset+d))
		case 4:
			s.DiskOffset = max(0, min(max(0, len(s.Snapshot.Slow.Filesystems)-1), s.DiskOffset+d))
		default:
			s.move(d)
		}
	case "left":
		if s.View == 3 || s.View == 4 {
			s.cycleDevice(-1)
		}
	case "right":
		if s.View == 3 || s.View == 4 {
			s.cycleDevice(1)
		}
	case "enter":
		if p, ok := s.current(); ok && (s.View == 0 || s.View == 2 || s.View == 5) {
			s.Details = true
			s.DetailTarget = &p
			s.SelectionPinned = true
		}
	case "text":
		t := strings.ToLower(k.Text)
		if t >= "1" && t <= "6" {
			s.View = int(t[0] - '1')
			return
		}
		switch t {
		case "q":
			return true, false
		case "h", "?":
			s.Help = true
		case "d":
			s.View = 0
		case "y":
			s.View = 1
		case "n":
			s.View = 3
		case "p", " ":
			s.Paused = !s.Paused
		case "+", "=":
			s.Interval = max(200*time.Millisecond, s.Interval-200*time.Millisecond)
		case "-":
			s.Interval = min(10*time.Second, s.Interval+200*time.Millisecond)
		case "/":
			s.Searching = true
			s.filterBefore = s.Filter
			if s.View != 0 && s.View != 2 && s.View != 5 {
				s.View = 5
			}
		case "t":
			s.Tree = !s.Tree
			s.Rebuild()
		case "r":
			s.Reverse = !s.Reverse
			s.Rebuild()
		case "u":
			s.OwnOnly = !s.OwnOnly
			s.Rebuild()
		case "c":
			s.Sort = "cpu"
			s.Rebuild()
		case "m":
			s.Sort = "mem"
			s.Rebuild()
		case "s":
			order := []string{"cpu", "mem", "pid", "name", "io"}
			idx := 0
			for i, v := range order {
				if v == s.Sort {
					idx = i
				}
			}
			s.Sort = order[(idx+1)%len(order)]
			if s.Sort == "io" {
				s.ProcessIO = true
			}
			s.Rebuild()
		case "i":
			s.ProcessIO = !s.ProcessIO
			if !s.ProcessIO && s.Sort == "io" {
				s.Sort = "cpu"
			}
			s.Rebuild()
		case "f":
			s.FullCommand = !s.FullCommand
		case "[":
			if s.View == 3 || s.View == 4 {
				s.cycleDevice(-1)
			}
		case "]":
			if s.View == 3 || s.View == 4 {
				s.cycleDevice(1)
			}
		case "k", "x", "z":
			if s.View != 0 && s.View != 2 && s.View != 5 {
				return
			}
			p, ok := s.current()
			if !ok {
				return
			}
			s.Signal = syscall.SIGTERM
			if t == "x" {
				s.Signal = syscall.SIGKILL
			}
			if t == "z" {
				s.Signal = syscall.SIGSTOP
				if p.State == "T" || p.State == "t" {
					s.Signal = syscall.SIGCONT
				}
			}
			s.Confirm = &p
		}
	}
	return
}

func signalName(sig syscall.Signal) string {
	switch sig {
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGKILL:
		return "SIGKILL"
	case syscall.SIGSTOP:
		return "SIGSTOP"
	case syscall.SIGCONT:
		return "SIGCONT"
	}
	return "signal"
}
