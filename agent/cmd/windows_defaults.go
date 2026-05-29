//go:build windows

package main

func applyPlatformDefaults(cfg *Config) {
	cfg.API = "https://10.1.18.100"
	cfg.Redis = "10.1.18.100:6379"
	cfg.InsecureSkipVerify = true
	cfg.LogFile = "ly-agent.log"
	cfg.CaptureEngine = "pcap"
	cfg.RetentionDir = "packets"
	cfg.HIDSEnabled = false
	cfg.RASPEnabled = false
}
