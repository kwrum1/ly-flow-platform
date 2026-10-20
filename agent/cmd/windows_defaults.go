//go:build windows

package main

import "strings"

func applyPlatformDefaults(cfg *Config) {
	cfg.API = "https://10.1.18.100"
	cfg.Redis = "10.1.18.100:6379"
	cfg.InsecureSkipVerify = true
	cfg.LogFile = "ly-agent.log"
	cfg.CaptureEngine = "pcap"
	cfg.BPFFilter = ""
	cfg.RetentionDir = "packets"
	cfg.HIDSEnabled = false
	cfg.RASPEnabled = false
}

func applyPlatformTrafficPolicy(cfg *Config) {
	if cfg == nil {
		return
	}
	if cfg.BPFFilter == "" || strings.EqualFold(strings.TrimSpace(cfg.BPFFilter), "tcp or udp") {
		cfg.BPFFilter = ""
	}
}
