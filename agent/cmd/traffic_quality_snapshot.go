package main

import "time"

type trafficQualitySnapshot struct {
	Status               string `json:"status"`
	SensorStatus         string `json:"sensor_status"`
	ClockStatus          string `json:"clock_status"`
	ClockSource          string `json:"clock_source"`
	InterfaceStatus      string `json:"interface_status"`
	InterfaceError       string `json:"interface_error,omitempty"`
	SelectedInterface    string `json:"selected_interface"`
	Visibility           string `json:"visibility"`
	VisibilityComplete   bool   `json:"visibility_complete"`
	LossStatus           string `json:"loss_status"`
	ParserCoverage       string `json:"parser_coverage"`
	SamplingEveryN       uint64 `json:"sampling_every_n"`
	RateLimitPerSecond   uint64 `json:"rate_limit_per_second"`
	Packets              uint64 `json:"packets"`
	Published            uint64 `json:"published"`
	KernelPackets        uint64 `json:"kernel_packets"`
	KernelDrops          uint64 `json:"kernel_drops"`
	InterfaceDrops       uint64 `json:"interface_drops"`
	RingFreezes          uint64 `json:"ring_freezes"`
	ParserDrops          uint64 `json:"parser_drops"`
	BridgeFiltered       uint64 `json:"bridge_filtered"`
	SampledOut           uint64 `json:"sampled_out"`
	RateLimited          uint64 `json:"rate_limited"`
	PublishErrors        uint64 `json:"publish_errors"`
	PublishStatus        string `json:"publish_status"`
	PublishErrorReason   string `json:"publish_error_reason,omitempty"`
	SpoolFull            uint64 `json:"spool_full"`
	SpoolPendingFiles    uint64 `json:"spool_pending_files"`
	SpoolBytes           int64  `json:"spool_bytes"`
	SpoolMaxBytes        int64  `json:"spool_max_bytes"`
	SpoolPressurePercent uint64 `json:"spool_pressure_percent"`
	SpoolStatus          string `json:"spool_status"`
	SpoolError           string `json:"spool_error,omitempty"`
	LastPacketAt         string `json:"last_packet_at"`
	LastPacketAgeSeconds int64  `json:"last_packet_age_seconds"`
	ClockSkewMillis      int64  `json:"clock_skew_millis"`
}

func (monitor *trafficQualityMonitor) Snapshot(spool spoolPressure) trafficQualitySnapshot {
	now := monitor.clock.Now().UTC()
	monitor.mu.RLock()
	interfaceName, interfaceError, config := monitor.interfaceName, monitor.interfaceError, monitor.config
	monitor.mu.RUnlock()
	lastPacketNano := monitor.lastPacketNano.Load()
	sensorStatus, lastPacketAt := "unknown", ""
	var age int64
	if lastPacketNano > 0 {
		lastPacket := time.Unix(0, lastPacketNano).UTC()
		lastPacketAt = lastPacket.Format(time.RFC3339Nano)
		age = max(int64(0), int64(now.Sub(lastPacket).Seconds()))
		sensorStatus = "active"
		if now.Sub(lastPacket) > config.StaleAfter {
			sensorStatus = "stale"
		}
	}
	skew := time.Duration(monitor.clockSkewNanos.Load())
	clockStatus := "unknown"
	if lastPacketNano > 0 {
		clockStatus = "consistent"
		if skew > config.MaxClockSkew {
			clockStatus = "skewed"
		}
	}
	interfaceStatus := "valid"
	if interfaceName == "" {
		interfaceStatus = "unvalidated"
	} else if interfaceError != "" {
		interfaceStatus = "invalid"
	}
	lossStatus := "unknown"
	if monitor.lossKnown.Load() {
		lossStatus = "known"
	}
	status := "healthy"
	publishStatus, publishErrorReason := "healthy", ""
	if monitor.publishDegraded.Load() {
		publishStatus = "degraded"
		if raw := monitor.publishReason.Load(); raw != nil {
			publishErrorReason, _ = raw.(string)
		}
	}
	if interfaceStatus == "invalid" {
		status = "unhealthy"
	} else if sensorStatus != "active" || clockStatus != "consistent" || lossStatus == "unknown" || monitor.kernelDrops.Load()+monitor.interfaceDrops.Load()+monitor.parserDrops.Load()+monitor.ringFreezes.Load() > 0 || publishStatus == "degraded" || spool.Pressured || spool.ReadError != "" {
		status = "degraded"
	}
	return trafficQualitySnapshot{Status: status, SensorStatus: sensorStatus, ClockStatus: clockStatus, ClockSource: "local_wall_clock_no_external_sync", InterfaceStatus: interfaceStatus, InterfaceError: interfaceError, SelectedInterface: interfaceName, Visibility: "partial", VisibilityComplete: false, LossStatus: lossStatus, ParserCoverage: "bounded_l3_l4_best_effort_l7", SamplingEveryN: config.SampleEveryN, RateLimitPerSecond: config.RateLimitPerSecond, Packets: monitor.packets.Load(), Published: monitor.published.Load(), KernelPackets: monitor.kernelPackets.Load(), KernelDrops: monitor.kernelDrops.Load(), InterfaceDrops: monitor.interfaceDrops.Load(), RingFreezes: monitor.ringFreezes.Load(), ParserDrops: monitor.parserDrops.Load(), BridgeFiltered: monitor.bridgeFiltered.Load(), SampledOut: monitor.sampledOut.Load(), RateLimited: monitor.rateLimited.Load(), PublishErrors: monitor.publishErrors.Load(), PublishStatus: publishStatus, PublishErrorReason: publishErrorReason, SpoolFull: monitor.spoolFull.Load(), SpoolPendingFiles: spool.PendingFiles, SpoolBytes: spool.Bytes, SpoolMaxBytes: spool.MaxBytes, SpoolPressurePercent: spool.Percent, SpoolStatus: spool.Status, SpoolError: spool.ReadError, LastPacketAt: lastPacketAt, LastPacketAgeSeconds: age, ClockSkewMillis: skew.Milliseconds()}
}
