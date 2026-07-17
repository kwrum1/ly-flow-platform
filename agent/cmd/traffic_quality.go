package main

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"

	transport "github.com/lyflow/ly-flow-platform/transportreliability"
)

type trafficClock interface {
	Now() time.Time
}

type systemTrafficClock struct{}

func (systemTrafficClock) Now() time.Time { return time.Now().UTC() }

type captureQualityConfig struct {
	SampleEveryN       uint64
	RateLimitPerSecond uint64
	StaleAfter         time.Duration
	MaxClockSkew       time.Duration
}

type captureSocketStats struct {
	Packets        uint64
	Drops          uint64
	InterfaceDrops uint64
	QueueFreezes   uint64
}

type trafficQualityMonitor struct {
	clock           trafficClock
	config          captureQualityConfig
	mu              sync.RWMutex
	afStatsMu       sync.Mutex
	afStats         captureSocketStats
	afStatsReady    bool
	bridgePolicy    containerBridgePolicy
	interfaceName   string
	interfaceError  string
	windowStart     time.Time
	windowCount     uint64
	packets         atomic.Uint64
	eligiblePackets atomic.Uint64
	published       atomic.Uint64
	kernelPackets   atomic.Uint64
	kernelDrops     atomic.Uint64
	interfaceDrops  atomic.Uint64
	ringFreezes     atomic.Uint64
	parserDrops     atomic.Uint64
	bridgeFiltered  atomic.Uint64
	sampledOut      atomic.Uint64
	rateLimited     atomic.Uint64
	publishErrors   atomic.Uint64
	spoolFull       atomic.Uint64
	publishDegraded atomic.Bool
	publishReason   atomic.Value
	lossKnown       atomic.Bool
	lastPacketNano  atomic.Int64
	clockSkewNanos  atomic.Int64
}

func captureQualityConfigFrom(config *Config) captureQualityConfig {
	return captureQualityConfigFromValues(config.TrafficSampleEveryN, config.MaxTrafficEventsPerSec)
}

func captureQualityConfigFromValues(sampleEvery, rate int) captureQualityConfig {
	if sampleEvery <= 0 {
		sampleEvery = 1
	}
	if rate < 0 {
		rate = 0
	}
	return captureQualityConfig{SampleEveryN: uint64(sampleEvery), RateLimitPerSecond: uint64(rate), StaleAfter: 2 * time.Minute, MaxClockSkew: 30 * time.Second}
}

func newTrafficQualityMonitor(clock trafficClock, config captureQualityConfig) *trafficQualityMonitor {
	if config.SampleEveryN == 0 {
		config.SampleEveryN = 1
	}
	if config.StaleAfter <= 0 {
		config.StaleAfter = 2 * time.Minute
	}
	if config.MaxClockSkew <= 0 {
		config.MaxClockSkew = 30 * time.Second
	}
	return &trafficQualityMonitor{clock: clock, config: config}
}

func (monitor *trafficQualityMonitor) UpdateConfig(config captureQualityConfig) {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	monitor.config = config
	monitor.windowStart = time.Time{}
	monitor.windowCount = 0
}

func (monitor *trafficQualityMonitor) ConfigureInterface(name string, policy containerBridgePolicy, err error) {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	monitor.interfaceName = name
	monitor.bridgePolicy = policy
	monitor.interfaceError = ""
	if err != nil {
		monitor.interfaceError = err.Error()
	}
}

func (monitor *trafficQualityMonitor) RecordPacket(observation trafficObservation) {
	now := monitor.clock.Now().UTC()
	monitor.packets.Add(1)
	monitor.lastPacketNano.Store(now.UnixNano())
	if !observation.Timestamp.IsZero() {
		skew := now.Sub(observation.Timestamp.UTC())
		if skew < 0 {
			skew = -skew
		}
		monitor.clockSkewNanos.Store(int64(skew))
	}
}

func (monitor *trafficQualityMonitor) AllowPublish(time.Time) bool {
	sequence := monitor.eligiblePackets.Add(1)
	monitor.mu.RLock()
	config := monitor.config
	monitor.mu.RUnlock()
	if config.SampleEveryN > 1 && sequence%config.SampleEveryN != 0 {
		monitor.sampledOut.Add(1)
		return false
	}
	if config.RateLimitPerSecond == 0 {
		return true
	}
	now := monitor.clock.Now().UTC()
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	if monitor.windowStart.IsZero() || now.Sub(monitor.windowStart) >= time.Second || now.Before(monitor.windowStart) {
		monitor.windowStart = now
		monitor.windowCount = 0
	}
	if monitor.windowCount >= config.RateLimitPerSecond {
		monitor.rateLimited.Add(1)
		return false
	}
	monitor.windowCount++
	return true
}

func (monitor *trafficQualityMonitor) IsBridgeTraffic(srcIP, dstIP string) bool {
	monitor.mu.RLock()
	defer monitor.mu.RUnlock()
	return monitor.bridgePolicy.Contains(srcIP, dstIP)
}

func (monitor *trafficQualityMonitor) RecordAFPacketStats(stats captureSocketStats) {
	monitor.afStatsMu.Lock()
	previous, ready := monitor.afStats, monitor.afStatsReady
	monitor.afStats = stats
	monitor.afStatsReady = true
	monitor.afStatsMu.Unlock()
	if !ready {
		previous = captureSocketStats{}
	}
	monitor.kernelPackets.Add(afPacketCounterDelta(previous.Packets, stats.Packets))
	monitor.kernelDrops.Add(afPacketCounterDelta(previous.Drops, stats.Drops))
	monitor.interfaceDrops.Add(afPacketCounterDelta(previous.InterfaceDrops, stats.InterfaceDrops))
	monitor.ringFreezes.Add(afPacketCounterDelta(previous.QueueFreezes, stats.QueueFreezes))
	monitor.lossKnown.Store(true)
}

func (monitor *trafficQualityMonitor) ResetAFPacketStats() {
	monitor.afStatsMu.Lock()
	defer monitor.afStatsMu.Unlock()
	monitor.afStats = captureSocketStats{}
	monitor.afStatsReady = false
}

func afPacketCounterDelta(previous, current uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	return uint64(math.MaxUint32) - previous + 1 + current
}

func (monitor *trafficQualityMonitor) RecordPCAPStats(stats captureSocketStats) {
	monitor.kernelPackets.Store(stats.Packets)
	monitor.kernelDrops.Store(stats.Drops)
	monitor.interfaceDrops.Store(stats.InterfaceDrops)
	monitor.lossKnown.Store(true)
}

func (monitor *trafficQualityMonitor) RecordStatsUnavailable() { monitor.lossKnown.Store(false) }

func (monitor *trafficQualityMonitor) RecordParserDrop() { monitor.parserDrops.Add(1) }
func (monitor *trafficQualityMonitor) RecordBridgeDrop() { monitor.bridgeFiltered.Add(1) }
func (monitor *trafficQualityMonitor) RecordPublish() {
	monitor.published.Add(1)
	monitor.publishDegraded.Store(false)
	monitor.publishReason.Store("")
}

func (monitor *trafficQualityMonitor) RecordSpoolFailure(err error) {
	monitor.publishErrors.Add(1)
	monitor.publishDegraded.Store(true)
	reason := "publish_failed"
	if errors.Is(err, transport.ErrSpoolFull) {
		monitor.spoolFull.Add(1)
		reason = "spool_full"
	} else if errors.Is(err, context.DeadlineExceeded) {
		reason = "timeout"
	} else if errors.Is(err, context.Canceled) {
		reason = "canceled"
	}
	monitor.publishReason.Store(reason)
}
