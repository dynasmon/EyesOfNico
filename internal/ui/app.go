package ui

import (
	"eyesofnico/internal/monitor"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"
)

type Options struct {
	Interval                         time.Duration
	ASCII, NoColor, NoAlt, ProcessIO bool
	View                             int
	Sort, Filter                     string
}

type sampleResult struct {
	snapshot monitor.Snapshot
	err      error
}
type inputResult struct {
	text string
	err  error
}

func Run(c *monitor.Collector, opts Options) error {
	signals := make(chan os.Signal, 8)
	watchSignals(signals)
	defer signal.Stop(signals)
	term, err := OpenTerminal(opts.NoAlt)
	if err != nil {
		return err
	}
	defer term.Close()
	s := NewState(opts.Interval, opts.ASCII)
	s.View = opts.View
	s.ProcessIO = opts.ProcessIO
	if opts.Sort != "" {
		s.Sort = opts.Sort
	}
	s.Filter = opts.Filter
	name := os.Getenv("TERM")
	colors256 := strings.Contains(name, "256") || strings.Contains(name, "direct") || os.Getenv("COLORTERM") != ""
	renderer := NewRenderer(os.Stdout, !opts.NoColor, colors256)
	w, h := term.Size()
	screen := NewScreen(w, h, opts.ASCII)
	done := make(chan struct{})
	defer close(done)
	input := make(chan inputResult, 8)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, e := os.Stdin.Read(buf)
			select {
			case input <- inputResult{string(buf[:n]), e}:
			case <-done:
				return
			}
			if e != nil {
				return
			}
		}
	}()
	requests := make(chan bool, 1)
	results := make(chan sampleResult, 1)
	go func() {
		for {
			select {
			case <-done:
				return
			case withIO := <-requests:
				snapshot, e := c.Sample(withIO)
				select {
				case results <- sampleResult{snapshot, e}:
				case <-done:
					return
				}
			}
		}
	}()
	inFlight := false
	request := func() {
		if !s.Paused && !inFlight {
			requests <- s.ProcessIO
			inFlight = true
		}
	}
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	escapeTimer := time.NewTimer(time.Hour)
	if !escapeTimer.Stop() {
		<-escapeTimer.C
	}
	defer escapeTimer.Stop()
	var decoder Decoder
	suspend := func() error {
		if !supportsSuspend {
			s.notify("Ctrl-Z suspension is unavailable on Windows; p pauses sampling")
			return nil
		}
		term.Close()
		if err := suspendProcess(signals); err != nil {
			return err
		}
		if err := term.Resume(); err != nil {
			return err
		}
		renderer.Invalidate()
		return nil
	}
	handle := func(keys []Key) (bool, error) {
		for _, k := range keys {
			if screen.W < 40 || screen.H < 12 {
				if k.Name == "quit" || (k.Name == "text" && strings.EqualFold(k.Text, "q")) {
					return true, nil
				}
				if k.Name != "suspend" {
					continue
				} // Never accept an invisible confirmation.
			}
			previous := s.Interval
			wasPaused := s.Paused
			quit, stop := s.Handle(k)
			if quit {
				return true, nil
			}
			if stop {
				if err := suspend(); err != nil {
					if err == io.EOF {
						return true, nil
					}
					return true, err
				}
			}
			if s.Interval != previous {
				ticker.Reset(s.Interval)
			}
			if wasPaused && !s.Paused {
				request()
			}
		}
		return false, nil
	}
	request()
	for {
		w, h = term.Size()
		if screen.W != w || screen.H != h {
			screen = NewScreen(w, h, opts.ASCII)
		}
		s.Draw(screen)
		if err := renderer.Flush(screen); err != nil {
			return err
		}
		select {
		case sig := <-signals:
			switch classifySignal(sig) {
			case "redraw":
				renderer.Invalidate()
			case "suspend":
				if err := suspend(); err != nil {
					if err == io.EOF {
						return nil
					}
					return err
				}
			default:
				return nil
			}
		case <-ticker.C:
			request()
		case result := <-results:
			inFlight = false
			if result.err != nil {
				s.LastError = result.err.Error()
			} else if !s.Paused {
				s.Accept(result.snapshot)
			}
		case result := <-input:
			if result.err != nil {
				if result.err == io.EOF {
					return nil
				}
				return result.err
			}
			if quit, e := handle(decoder.Feed(result.text)); quit {
				return e
			}
			if !escapeTimer.Stop() {
				select {
				case <-escapeTimer.C:
				default:
				}
			}
			if decoder.pending != "" && !decoder.paste {
				escapeTimer.Reset(120 * time.Millisecond)
			}
		case <-escapeTimer.C:
			if quit, e := handle(decoder.Escape()); quit {
				return e
			}
		}
	}
}
