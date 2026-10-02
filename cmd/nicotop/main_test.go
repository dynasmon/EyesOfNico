package main

import (
	"bytes"
	"encoding/json"
	"eyesofnico/internal/monitor"
	"strings"
	"testing"
)

func TestCLIValidation(t *testing.T) {
	for _, args := range [][]string{{"--refresh", "0"}, {"--refresh", "NaN"}, {"--refresh", "Inf"}, {"--refresh", "-1"}, {"--refresh"}, {"--count", "-1"}, {"--count", "2"}, {"--json", "--snapshot", "80x24"}, {"--snapshot", "10x2"}, {"--view", "bad"}, {"--sort", "bad"}, {"unexpected"}} {
		var out, errOut bytes.Buffer
		if err := run(args, &out, &errOut); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	for _, arg := range []string{"--help", "--version"} {
		var out, errOut bytes.Buffer
		if err := run([]string{arg}, &out, &errOut); err != nil {
			t.Fatal(err)
		}
	}
}

func TestJSONHasMeasuredRates(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"--json", "--count", "2", "--refresh", "0.2"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d snapshots", len(lines))
	}
	for _, line := range lines {
		var s monitor.Snapshot
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			t.Fatal(err)
		}
		if !s.Ready || s.Interval < .1 || s.Memory.Total == 0 || len(s.Cores) == 0 {
			t.Fatal("snapshot not measured")
		}
	}
}
