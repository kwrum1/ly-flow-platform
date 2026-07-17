package main

import (
	"runtime"
)

type liveCaptureConfig struct {
	Enabled                   bool
	Interface                 string
	CaptureEngine             string
	BPFFilter                 string
	Promiscuous               bool
	SampleEveryN              int
	MaxTrafficEventsPerSecond int
}

type trafficPublishAttempt struct {
	attempted bool
	err       error
}

func (a *Agent) captureConfigSnapshot() liveCaptureConfig {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return liveCaptureConfig{
		Enabled:                   a.cfg.TrafficEnabled,
		Interface:                 a.cfg.TrafficInterface,
		CaptureEngine:             a.cfg.CaptureEngine,
		BPFFilter:                 a.cfg.BPFFilter,
		Promiscuous:               a.cfg.Promiscuous,
		SampleEveryN:              a.cfg.TrafficSampleEveryN,
		MaxTrafficEventsPerSecond: a.cfg.MaxTrafficEventsPerSec,
	}
}

func (a *Agent) ensureTrafficQuality() *trafficQualityMonitor {
	if a.trafficQuality == nil {
		clock := a.clock
		if clock == nil {
			clock = systemTrafficClock{}
		}
		config := a.captureConfigSnapshot()
		a.trafficQuality = newTrafficQualityMonitor(clock, captureQualityConfigFromValues(config.SampleEveryN, config.MaxTrafficEventsPerSecond))
	}
	return a.trafficQuality
}

func (a *Agent) prepareTrafficQualityForInterface(interfaceName string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	interfaces, err := loadCaptureInterfaces()
	if err != nil {
		a.ensureTrafficQuality().ConfigureInterface(interfaceName, containerBridgePolicy{}, err)
		return err
	}
	validationErr := validateCaptureInterface(interfaceName, interfaces)
	policy := deriveContainerBridgePolicy(interfaceName, interfaces)
	a.ensureTrafficQuality().ConfigureInterface(interfaceName, policy, validationErr)
	return validationErr
}

func (a *Agent) processCapturedObservation(detector *portScanDetector, observation trafficObservation) (map[string]interface{}, bool) {
	quality := a.ensureTrafficQuality()
	quality.RecordPacket(observation)
	if observation.Protocol == "" {
		quality.RecordParserDrop()
		return nil, false
	}
	if quality.IsBridgeTraffic(observation.SrcIP, observation.DstIP) {
		quality.RecordBridgeDrop()
		return nil, false
	}
	a.markTrafficPacket(observation)
	alert := detector.observe(observation, a)
	return alert, quality.AllowPublish(observation.Timestamp)
}

func (a *Agent) markTrafficPublishQuality() {
	a.markTrafficPublish()
	a.ensureTrafficQuality().RecordPublish()
}

func (a *Agent) markTrafficPublishError(err error) {
	a.markTrafficError(err)
	a.ensureTrafficQuality().RecordSpoolFailure(err)
}

func (a *Agent) recordTrafficPublishOutcome(alertAttempt, flowAttempt trafficPublishAttempt) {
	published := false
	if alertAttempt.attempted {
		if alertAttempt.err != nil {
			a.markTrafficPublishError(alertAttempt.err)
		} else {
			a.markTrafficPublishQuality()
			published = true
		}
	}
	if !flowAttempt.attempted {
		return
	}
	if flowAttempt.err != nil {
		a.markTrafficPublishError(flowAttempt.err)
		return
	}
	if !published {
		a.markTrafficPublishQuality()
	}
}

func (a *Agent) captureQualityCapability() map[string]interface{} {
	trafficConfig := a.captureConfigSnapshot()
	pressure := spoolPressure{MaxBytes: a.cfg.SpoolMaxBytes, Status: "not_started"}
	a.trafficSpoolMu.Lock()
	spool := a.trafficSpool
	a.trafficSpoolMu.Unlock()
	if spool != nil {
		if measured, err := spoolPressureFromDir(spool.dir, spool.maxBytes); err == nil {
			pressure = measured
		} else {
			pressure.Status = "error"
			pressure.ReadError = err.Error()
		}
	}
	capability := structToMap(a.ensureTrafficQuality().Snapshot(pressure))
	if !trafficConfig.Enabled {
		capability["status"] = "disabled"
		capability["sensor_status"] = "disabled"
	}
	return capability
}
