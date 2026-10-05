// Package monitor collects local system metrics on Linux, macOS and Windows.
package monitor

import "time"

// ProcRoot and SysRoot override Linux filesystems for testing. Other platforms
// use native host APIs and reject these overrides.
type Options struct {
	ProcRoot string
	SysRoot  string
}

type CPU struct {
	Name   string  `json:"name"`
	Busy   float64 `json:"busy_percent"`
	User   float64 `json:"user_percent"`
	System float64 `json:"system_percent"`
	Wait   float64 `json:"iowait_percent"`
	Steal  float64 `json:"steal_percent"`
}

type Memory struct {
	Darwin    *DarwinMemory `json:"darwin,omitempty"`
	Total     uint64        `json:"total_bytes"`
	Available uint64        `json:"available_bytes"`
	Used      uint64        `json:"used_bytes"`
	Cached    uint64        `json:"cached_bytes"`
	Buffers   uint64        `json:"buffers_bytes"`
	Slab      uint64        `json:"slab_bytes"`
	Dirty     uint64        `json:"dirty_bytes"`
	SwapTotal uint64        `json:"swap_total_bytes"`
	SwapUsed  uint64        `json:"swap_used_bytes"`
}

// DarwinMemory contains macOS VM categories; these are not Linux slab/buffers
// or PSI percentages. All byte counters come from HOST_VM_INFO64.
type DarwinMemory struct {
	Available     bool   `json:"available"`
	Free          uint64 `json:"free_bytes"`
	Active        uint64 `json:"active_bytes"`
	Inactive      uint64 `json:"inactive_bytes"`
	Wired         uint64 `json:"wired_bytes"`
	Compressed    uint64 `json:"compressed_bytes"`
	Purgeable     uint64 `json:"purgeable_bytes"`
	PressureLevel string `json:"pressure_level,omitempty"`
}

type Pressure struct {
	Available bool       `json:"available"`
	Some      [3]float64 `json:"some_percent_10_60_300s"`
	Full      [3]float64 `json:"full_percent_10_60_300s"`
}

type Network struct {
	Name                 string  `json:"name"`
	Loopback             bool    `json:"loopback"`
	RXBytes              uint64  `json:"rx_bytes"`
	TXBytes              uint64  `json:"tx_bytes"`
	RXRate               float64 `json:"rx_bytes_per_second"`
	TXRate               float64 `json:"tx_bytes_per_second"`
	RXPackets            float64 `json:"rx_packets_per_second"`
	TXPackets            float64 `json:"tx_packets_per_second"`
	Errors               uint64  `json:"errors"`
	Drops                uint64  `json:"drops"`
	Ready                bool    `json:"rates_ready"`
	rxPackets, txPackets uint64
}

type Disk struct {
	SizeBytes                                                                     uint64  `json:"size_bytes"`
	Name                                                                          string  `json:"name"`
	ReadRate                                                                      float64 `json:"read_bytes_per_second"`
	WriteRate                                                                     float64 `json:"write_bytes_per_second"`
	IOPS                                                                          float64 `json:"operations_per_second"`
	Busy                                                                          float64 `json:"busy_percent"`
	Await                                                                         float64 `json:"await_ms"`
	Queue                                                                         float64 `json:"average_queue_depth"`
	InFlight                                                                      uint64  `json:"in_flight"`
	Ready                                                                         bool    `json:"rates_ready"`
	readSectors, writeSectors, reads, writes, readMS, writeMS, busyMS, weightedMS uint64
}

func (n Network) IsLoopback() bool {
	return n.Loopback || n.Name == "lo" || n.Name == "lo0"
}

func (s Snapshot) MetricAvailable(name string) bool {
	for _, unavailable := range s.Unavailable {
		if unavailable == name {
			return false
		}
	}
	return true
}

type Process struct {
	MetricsSource         string   `json:"metrics_source,omitempty"`
	Unavailable           []string `json:"unavailable_metrics,omitempty"`
	PID                   int      `json:"pid"`
	PPID                  int      `json:"ppid"`
	UID                   uint32   `json:"uid"`
	User                  string   `json:"user"`
	Name                  string   `json:"name"`
	Command               string   `json:"command"`
	State                 string   `json:"state"`
	CPU                   float64  `json:"cpu_percent"`
	RSS                   uint64   `json:"rss_bytes"`
	Virtual               uint64   `json:"virtual_bytes"`
	Threads               int      `json:"threads"`
	Nice                  int      `json:"nice"`
	Priority              int      `json:"priority"`
	Processor             int      `json:"processor"`
	StartTicks            uint64   `json:"start_ticks"`
	CPUSeconds            float64  `json:"cpu_seconds"`
	ReadRate              float64  `json:"read_bytes_per_second"`
	WriteRate             float64  `json:"write_bytes_per_second"`
	IOAvailable           bool     `json:"io_available"`
	Ticks                 uint64   `json:"-"`
	readBytes, writeBytes uint64
	metadataAt            time.Time
}

func (p Process) MetricAvailable(name string) bool {
	for _, unavailable := range p.Unavailable {
		if unavailable == name {
			return false
		}
	}
	return true
}

type Filesystem struct {
	Mount     string  `json:"mount"`
	Device    string  `json:"device"`
	Type      string  `json:"type"`
	Total     uint64  `json:"total_bytes"`
	Used      uint64  `json:"used_bytes"`
	Available uint64  `json:"available_bytes"`
	InodeUsed float64 `json:"inode_used_percent"`
}

type Sensor struct {
	Name    string  `json:"name"`
	Celsius float64 `json:"celsius"`
}

// Slow metrics are collected by one bounded worker, never by the UI goroutine.
type Slow struct {
	At           time.Time         `json:"at"`
	Filesystems  []Filesystem      `json:"filesystems"`
	Sensors      []Sensor          `json:"sensors"`
	FrequencyMHz float64           `json:"frequency_mhz"`
	NetworkState map[string]string `json:"network_state"`
	Warnings     []string          `json:"warnings,omitempty"`
}

type Snapshot struct {
	OS              string              `json:"os"`
	Unavailable     []string            `json:"unavailable_metrics,omitempty"`
	At              time.Time           `json:"at"`
	Interval        float64             `json:"interval_seconds"`
	Ready           bool                `json:"rates_ready"`
	Host            string              `json:"host"`
	Kernel          string              `json:"kernel"`
	CPUModel        string              `json:"cpu_model"`
	Uptime          float64             `json:"uptime_seconds"`
	Load            [3]float64          `json:"load"`
	CPU             CPU                 `json:"cpu"`
	Cores           []CPU               `json:"cores"`
	Memory          Memory              `json:"memory"`
	Pressure        map[string]Pressure `json:"pressure"`
	Networks        []Network           `json:"networks"`
	Disks           []Disk              `json:"disks"`
	Processes       []Process           `json:"processes"`
	Running         int                 `json:"running"`
	Threads         int                 `json:"threads"`
	Blocked         int                 `json:"blocked"`
	ContextSwitches float64             `json:"context_switches_per_second"`
	Forks           float64             `json:"forks_per_second"`
	Slow            Slow                `json:"slow"`
	CollectMS       float64             `json:"collection_ms"`
	Warnings        []string            `json:"warnings,omitempty"`
}

func Percent(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) / float64(total) * 100
}

func delta(now, before uint64) uint64 {
	if now < before {
		return 0
	}
	return now - before
}

func rate(now, before uint64, elapsed float64) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(delta(now, before)) / elapsed
}
