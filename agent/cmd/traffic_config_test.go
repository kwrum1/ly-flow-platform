package main

import (
	"sync"
	"testing"
)

func TestTrafficQualityLimitsParseFromYAMLAndEnvironment(t *testing.T) {
	// Given
	config := &Config{TrafficSampleEveryN: 1}
	yamlValues := map[string]string{"traffic.sample_every_n": "4", "traffic.max_events_per_second": "250"}

	// When
	applyYAMLConfig(config, yamlValues)

	// Then
	if config.TrafficSampleEveryN != 4 || config.MaxTrafficEventsPerSec != 250 {
		t.Fatalf("YAML limits = sample %d rate %d", config.TrafficSampleEveryN, config.MaxTrafficEventsPerSec)
	}
	t.Setenv("TRAFFIC_SAMPLE_EVERY_N", "8")
	t.Setenv("TRAFFIC_MAX_EVENTS_PER_SECOND", "500")
	applyEnvOverrides(config)
	if config.TrafficSampleEveryN != 8 || config.MaxTrafficEventsPerSec != 500 {
		t.Fatalf("environment limits = sample %d rate %d", config.TrafficSampleEveryN, config.MaxTrafficEventsPerSec)
	}
}

func TestPulledTrafficQualityLimitsUpdateRuntimeMonitor(t *testing.T) {
	// Given
	agent := NewAgent(&Config{TrafficEnabled: false, TrafficSampleEveryN: 1})

	// When
	agent.applyPulledConfig(map[string]interface{}{"policy": map[string]interface{}{"traffic": map[string]interface{}{"enabled": false, "sample_every_n": 5, "max_events_per_second": 12}}})

	// Then
	snapshot := agent.trafficQuality.Snapshot(spoolPressure{})
	if snapshot.SamplingEveryN != 5 || snapshot.RateLimitPerSecond != 12 {
		t.Fatalf("runtime limits = sample %d rate %d", snapshot.SamplingEveryN, snapshot.RateLimitPerSecond)
	}
}

func TestApplyPulledConfigSynchronizesConcurrentCaptureReaders(t *testing.T) {
	// Given
	agent := NewAgent(&Config{TrafficEnabled: true, TrafficInterface: "ens33", CaptureEngine: "af_packet", TrafficSampleEveryN: 1})
	agent.trafficStarted = true
	const iterations = 1000
	var workers sync.WaitGroup
	workers.Add(2)

	// When
	go func() {
		defer workers.Done()
		for index := 0; index < iterations; index++ {
			iface := "ens33"
			if index%2 == 0 {
				iface = "ens160"
			}
			agent.applyPulledConfig(map[string]interface{}{"policy": map[string]interface{}{"traffic": map[string]interface{}{
				"enabled": index%3 != 0, "interface": iface, "capture_engine": "af_packet", "bpf_filter": "tcp", "promiscuous": index%2 == 0,
			}}})
		}
	}()
	go func() {
		defer workers.Done()
		for index := 0; index < iterations; index++ {
			agent.trafficCaptureEnabledOnCurrentInterface("ens33")
			agent.trafficCaptureInterfaceChanged("ens33")
			agent.captureQualityCapability()
		}
	}()
	workers.Wait()

	// Then
	if agent.trafficQuality == nil {
		t.Fatal("traffic quality monitor disappeared during concurrent config updates")
	}
}
