package main

import (
	"encoding/json"
	"errors"
	"eyesofnico/internal/monitor"
	"eyesofnico/internal/ui"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const version = "2.0.0"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "nicotop:", err)
		os.Exit(1)
	}
}

func run(args []string, out, errOut io.Writer) error {
	f := flag.NewFlagSet("nicotop", flag.ContinueOnError)
	f.SetOutput(errOut)
	refresh := f.Float64("refresh", 1, "sampling interval, 0.2 to 10 seconds")
	jsonMode := f.Bool("json", false, "write newline-delimited JSON snapshots (no terminal required)")
	count := f.Int("count", 0, "JSON samples to emit; 0 runs until interrupted")
	snapshot := f.String("snapshot", "", "print one plain dashboard, e.g. 120x40")
	view := f.String("view", "overview", "overview, cpu, memory, network, disks, processes")
	sortBy := f.String("sort", "cpu", "process sort: cpu, mem, pid, name, io")
	filter := f.String("filter", "", "initial process search")
	ascii := f.Bool("ascii", false, "use ASCII borders and graphs")
	noColor := f.Bool("no-color", false, "disable terminal colors (also honors NO_COLOR)")
	noAlt := f.Bool("no-alt", false, "draw in the current terminal screen")
	processIO := f.Bool("process-io", false, "collect per-process I/O when supported (extra collection)")
	safe := f.Bool("safe", false, "compatibility flag; all collection is local and unprivileged")
	showVersion := f.Bool("version", false, "print version")
	f.Usage = func() {
		fmt.Fprint(errOut, "EyesOfNico / neon system monitor (Linux, macOS, Windows)\n\nUsage: nicotop [options]\n\n")
		f.PrintDefaults()
		fmt.Fprintln(errOut, "\nKeys: 1-6 views / search / s sort / t tree / p pause / ? help / q quit")
	}
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *showVersion {
		fmt.Fprintln(out, "EyesOfNico", version)
		return nil
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected argument: %s", f.Arg(0))
	}
	if math.IsNaN(*refresh) || math.IsInf(*refresh, 0) || *refresh < 0.2 || *refresh > 10 {
		return fmt.Errorf("--refresh must be between 0.2 and 10 seconds")
	}
	if *count < 0 {
		return fmt.Errorf("--count cannot be negative")
	}
	if *count != 0 && !*jsonMode {
		return fmt.Errorf("--count requires --json")
	}
	if *jsonMode && *snapshot != "" {
		return fmt.Errorf("--json and --snapshot are mutually exclusive")
	}
	views := map[string]int{"overview": 0, "cpu": 1, "memory": 2, "network": 3, "disks": 4, "processes": 5}
	viewID, ok := views[*view]
	if !ok {
		return fmt.Errorf("unknown view: %s", *view)
	}
	switch *sortBy {
	case "cpu", "mem", "pid", "name", "io":
	default:
		return fmt.Errorf("unknown sort: %s", *sortBy)
	}
	if *sortBy == "io" {
		*processIO = true
	}
	w, h := 0, 0
	if *snapshot != "" {
		a, b, ok := strings.Cut(*snapshot, "x")
		if ok {
			w, _ = strconv.Atoi(a)
			h, _ = strconv.Atoi(b)
		}
		if w < 40 || w > 300 || h < 12 || h > 120 {
			return fmt.Errorf("--snapshot requires WIDTHxHEIGHT within 40x12 and 300x120")
		}
	}
	_ = safe
	c, err := monitor.New(monitor.Options{})
	if err != nil {
		return err
	}
	defer c.Close()
	interval := time.Duration(*refresh * float64(time.Second))
	if *jsonMode {
		return stream(c, interval, *count, *processIO, out)
	}
	if *snapshot != "" {
		s := ui.NewState(interval, *ascii)
		s.View = viewID
		s.Sort = *sortBy
		s.Filter = *filter
		s.ProcessIO = *processIO
		first, e := c.Sample(*processIO)
		if e != nil {
			return e
		}
		s.Accept(first)
		time.Sleep(200 * time.Millisecond)
		second, e := c.Sample(*processIO)
		if e != nil {
			return e
		}
		s.Accept(second)
		screen := ui.NewScreen(w, h, *ascii)
		s.Draw(screen)
		_, err = io.WriteString(out, screen.Plain())
		return err
	}
	_, noColorEnv := os.LookupEnv("NO_COLOR")
	locale := os.Getenv("LC_ALL")
	if locale == "" {
		locale = os.Getenv("LC_CTYPE")
	}
	if locale == "" {
		locale = os.Getenv("LANG")
	}
	useASCII := *ascii || locale == "C" || locale == "POSIX"
	return ui.Run(c, ui.Options{Interval: interval, ASCII: useASCII, NoColor: *noColor || noColorEnv, NoAlt: *noAlt, ProcessIO: *processIO, View: viewID, Sort: *sortBy, Filter: *filter})
}

func stream(c *monitor.Collector, interval time.Duration, count int, withIO bool, out io.Writer) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	if _, err := c.Sample(withIO); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	encoder := json.NewEncoder(out)
	for emitted := 0; count == 0 || emitted < count; emitted++ {
		select {
		case <-signals:
			return nil
		case <-ticker.C:
		}
		s, err := c.Sample(withIO)
		if err != nil {
			return err
		}
		if err = encoder.Encode(s); err != nil {
			return err
		}
	}
	return nil
}
