package main

import (
	"context"
	"time"
)

type runtimeSupervisorConfig struct {
	Name       string
	StaleAfter time.Duration
	CheckEvery time.Duration
	Run        func(context.Context)
	OnHealth   func(runtimeControlHealthSnapshot)
}

func runSupervisedRuntime(parent context.Context, health *runtimeControlHealth, config runtimeSupervisorConfig) {
	if parent == nil || health == nil || config.Run == nil {
		return
	}
	if config.StaleAfter <= 0 {
		config.StaleAfter = 15 * time.Second
	}
	if config.CheckEvery <= 0 {
		config.CheckEvery = config.StaleAfter / 3
		if config.CheckEvery <= 0 {
			config.CheckEvery = time.Second
		}
	}
	for {
		child, cancel := context.WithCancel(parent)
		done := make(chan struct{})
		go func() {
			defer close(done)
			config.Run(child)
		}()
		checkInterval := config.CheckEvery / 10
		if checkInterval <= 0 {
			checkInterval = config.CheckEvery
		}
		ticker := time.NewTicker(checkInterval)
		restart := false
		for !restart {
			select {
			case <-parent.Done():
				cancel()
				<-done
				ticker.Stop()
				return
			case <-done:
				cancel()
				if parent.Err() != nil {
					ticker.Stop()
					return
				}
				snapshot := health.Snapshot()
				if snapshot.Status != controlHealthDegraded {
					snapshot = health.Degrade("supervisor_exited", false)
				}
				if config.OnHealth != nil {
					config.OnHealth(snapshot)
				}
				if !health.RecordWatchdogRestart() {
					if config.OnHealth != nil {
						config.OnHealth(health.Snapshot())
					}
					ticker.Stop()
					return
				}
				restart = true
			case <-ticker.C:
				snapshot := health.CheckWatchdog(config.StaleAfter)
				if snapshot.Reason != "watchdog_stale" {
					continue
				}
				if config.OnHealth != nil {
					config.OnHealth(snapshot)
				}
				cancel()
				<-done
				if !health.RecordWatchdogRestart() {
					if config.OnHealth != nil {
						config.OnHealth(health.Snapshot())
					}
					ticker.Stop()
					return
				}
				restart = true
			}
		}
		ticker.Stop()
	}
}
