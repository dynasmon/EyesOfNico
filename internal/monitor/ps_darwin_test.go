package monitor

import (
	"math"
	"testing"
	"time"
)

func TestPSMetricsThreadsAndUnits(t *testing.T) {
	data := "USER PID TT %CPU STAT PRI STIME UTIME COMMAND\n" +
		"root 42 ?? 0.0 S 31T 0:00.00 0:00.00 name with spaces 42 123 456 125:03.45 S Mon Oct 5 19:15:15 2026\n" +
		"42 1.0 R 37T 0:00.41 0:00.10 42 123 456 125:03.45 R Mon Oct 5 19:15:15 2026\n" +
		"42 bad 456 1:00.00 R Mon Oct 5 19:15:15 2026\n" +
		"43 123 456 NaN S Mon Oct 5 19:15:15 2026\n" +
		"44 123 456 1:00.00 S invalid start time\n"
	m := parsePSMetrics(data)
	if len(m) != 1 || m[42].threads != 2 || m[42].state != "R" || m[42].rss != 123*1024 || m[42].virtual != 456*1024 || math.Abs(m[42].cpuSeconds-7503.45) > 0.001 {
		t.Fatalf("invalid ps metrics: %+v", m)
	}
	for _, value := range []string{"NaN", "1:NaN", "1:Inf", "-1:00", "1:99", "1:-1"} {
		if _, err := parsePSTime(value); err == nil {
			t.Fatalf("accepted invalid CPU time %q", value)
		}
	}
}

func TestPSFallbackRejectsPIDReuse(t *testing.T) {
	started := time.Date(2026, 10, 5, 19, 15, 15, 0, time.UTC).Unix()
	token := uint64(started)*1_000_000 + 123
	m := psMetrics{startSeconds: started, rss: 1234, cpuSeconds: 9, threads: 2, state: "S"}
	for _, current := range []uint64{0, token + 1, token + 1_000_000} {
		p := Process{StartTicks: token, Unavailable: []string{"cpu", "memory", "threads"}}
		if applyPSMetrics(&p, m, current) || p.MetricAvailable("cpu") {
			t.Fatal("merged a reused or exited PID")
		}
	}
	p := Process{StartTicks: token, Unavailable: []string{"cpu", "memory", "threads", "other"}}
	if !applyPSMetrics(&p, m, token) || !p.MetricAvailable("cpu") || p.MetricAvailable("other") || p.RSS != 1234 || p.Threads != 2 {
		t.Fatalf("valid fallback not merged: %+v", p)
	}
	m.startSeconds++
	if applyPSMetrics(&p, m, token) {
		t.Fatal("accepted a different ps birth time")
	}
}
