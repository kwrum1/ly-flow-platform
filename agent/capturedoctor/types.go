// Package capturedoctor monitors a ly_probe capture host at runtime:
// interface counters, drop/error rates, ring/offload state, PF_RING and the
// sensor process. It reports issues and only restarts when an operator has
// explicitly configured a restart command.
package capturedoctor

import (
	"context"
	"log"
	"time"
)

type InterfaceInfo struct {
	Exists    bool
	Up        bool
	MTU       int
	RXPackets uint64
	RXDropped uint64
	RXErrors  uint64
	RXFIFO    uint64
}

type SoftnetInfo struct {
	Dropped  uint64
	Squeezed uint64
}

type EthtoolInfo struct {
	Available bool
	RingRX    int
	GRO       bool
	GSO       bool
	RXMissed  uint64
	RXFIFO    uint64
	RXOver    uint64
	NoBuffer  uint64
}

type ProcessInfo struct {
	Running bool   `json:"running"`
	PID     int    `json:"pid"`
	Name    string `json:"name"`
	RSSKB   int    `json:"rss_kb"`
}

// Probe isolates the Linux host from the doctor logic so thresholds and
// restart policy can be tested without a real NIC.
type Probe interface {
	Interface(name string) (InterfaceInfo, error)
	Softnet() (SoftnetInfo, error)
	Ethtool(name string) (EthtoolInfo, error)
	Process(pidFile, name string) (ProcessInfo, error)
	PFRing() bool
	Now() time.Time
}

type Issue struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type Metrics struct {
	InterfaceUp      bool    `json:"interface_up"`
	MTU              int     `json:"mtu"`
	RXPackets        uint64  `json:"rx_packets"`
	RXDropped        uint64  `json:"rx_dropped"`
	RXErrors         uint64  `json:"rx_errors"`
	RXPacketsDelta   uint64  `json:"rx_packets_delta"`
	RXDroppedDelta   uint64  `json:"rx_dropped_delta"`
	PPS              float64 `json:"pps"`
	DropPct          float64 `json:"drop_pct"`
	SoftnetDropped   uint64  `json:"softnet_dropped"`
	SoftnetDelta     uint64  `json:"softnet_dropped_delta"`
	EthtoolAvailable bool    `json:"ethtool_available"`
	RingRX           int     `json:"ring_rx"`
	GRO              bool    `json:"gro"`
	GSO              bool    `json:"gso"`
	RXMissedDelta    uint64  `json:"rx_missed_delta"`
	RXFIFODelta      uint64  `json:"rx_fifo_delta"`
	RXOverDelta      uint64  `json:"rx_over_delta"`
	NoBufferDelta    uint64  `json:"rx_no_buffer_delta"`
	PFRing           bool    `json:"pf_ring"`
}

type Snapshot struct {
	Timestamp time.Time   `json:"timestamp"`
	Interface string      `json:"interface"`
	Status    string      `json:"status"`
	Issues    []Issue     `json:"issues"`
	Metrics   Metrics     `json:"metrics"`
	Process   ProcessInfo `json:"process"`
	Restarted bool        `json:"restarted"`
}

type Config struct {
	Interface       string
	PIDFile         string
	ProcessName     string
	DropWarnPct     float64
	DropCritPct     float64
	RingMin         int
	RestartAfter    int
	RestartCooldown time.Duration
	RestartCommand  []string
	RestartFunc     func(context.Context) error
	Logger          *log.Logger
	Probe           Probe
}

type Doctor struct {
	cfg                 Config
	probe               Probe
	lastInterface       InterfaceInfo
	lastEthtool         EthtoolInfo
	lastSoftnet         SoftnetInfo
	lastTime            time.Time
	haveBaseline        bool
	consecutiveCritical int
	lastRestart         time.Time
}

func New(cfg Config) *Doctor {
	if cfg.DropWarnPct <= 0 {
		cfg.DropWarnPct = 1.0
	}
	if cfg.DropCritPct <= cfg.DropWarnPct {
		cfg.DropCritPct = 5.0
	}
	if cfg.RingMin <= 0 {
		cfg.RingMin = 2048
	}
	if cfg.RestartAfter <= 0 {
		cfg.RestartAfter = 3
	}
	if cfg.RestartCooldown <= 0 {
		cfg.RestartCooldown = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	probe := cfg.Probe
	if probe == nil {
		probe = LinuxProbe{}
	}
	return &Doctor{cfg: cfg, probe: probe}
}

func (d *Doctor) Config() Config {
	return d.cfg
}
