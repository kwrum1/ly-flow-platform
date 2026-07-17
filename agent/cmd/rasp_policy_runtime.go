package main

import (
	"time"

	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
)

func (a *Agent) enforceRASPPolicyExpiry(now time.Time) {
	a.cfgMu.Lock()
	if a.raspPolicyExpiresAt.IsZero() || now.Before(a.raspPolicyExpiresAt) || a.raspPolicyExpired {
		a.cfgMu.Unlock()
		return
	}
	a.raspPolicyExpired = true
	disableExecution := false
	if !a.raspPolicyACKed {
		a.cfg.RASPEnabled = false
		a.cfg.RASPMode = string(shared.ModeOff)
		disableExecution = true
	} else {
		switch a.raspFailBehavior {
		case shared.FailMonitor:
			a.cfg.RASPEnabled = true
			a.cfg.RASPMode = string(shared.ModeMonitor)
		case shared.FailDisable:
			a.cfg.RASPEnabled = false
			a.cfg.RASPMode = string(shared.ModeOff)
			disableExecution = true
		default:
			a.cfg.RASPEnabled = false
			a.cfg.RASPMode = string(shared.ModeOff)
			disableExecution = true
		}
	}
	a.cfgMu.Unlock()
	a.setRuntimePreventionEnabled(!disableExecution)
	if disableExecution && a.engines != nil {
		a.engines.Apply(a.ctx, []EngineDesiredState{{Name: EngineRASP, Enabled: false}})
	}
}

func (a *Agent) raspPolicyEnabled() bool {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.cfg.RASPEnabled
}

func (a *Agent) allowRASPEvent(now time.Time) bool {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	if a.raspMaxEventsPerSecond <= 0 {
		return false
	}
	window := now.UTC().Truncate(time.Second)
	if !window.Equal(a.raspRateWindow) {
		a.raspRateWindow = window
		a.raspRateCount = 0
	}
	if a.raspRateCount >= a.raspMaxEventsPerSecond {
		return false
	}
	a.raspRateCount++
	return true
}
