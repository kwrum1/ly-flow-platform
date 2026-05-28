package main

import (
	"context"
	"time"
)

type EngineName string

const (
	EngineSuricata EngineName = "suricata"
	EngineWazuh    EngineName = "wazuh"
	EngineYARA     EngineName = "yara"
	EngineRASP     EngineName = "rasp"
)

type EngineDesiredState struct {
	Name            EngineName        `json:"name"`
	Enabled         bool              `json:"enabled"`
	Mode            string            `json:"mode,omitempty"`
	ConfigVersion   string            `json:"config_version,omitempty"`
	RulePackVersion string            `json:"rule_pack_version,omitempty"`
	Settings        map[string]string `json:"settings,omitempty"`
}

type EngineStatus struct {
	Name            EngineName `json:"name"`
	Installed       bool       `json:"installed"`
	Running         bool       `json:"running"`
	Version         string     `json:"version,omitempty"`
	ConfigHash      string     `json:"config_hash,omitempty"`
	RulePackVersion string     `json:"rule_pack_version,omitempty"`
	OutputPath      string     `json:"output_path,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	LastEventAt     time.Time  `json:"last_event_at,omitempty"`
}

type EngineSupervisor interface {
	Name() EngineName
	Apply(context.Context, EngineDesiredState) error
	Status(context.Context) EngineStatus
}

type EngineRegistry struct {
	supervisors map[EngineName]EngineSupervisor
}

func NewEngineRegistry(supervisors ...EngineSupervisor) *EngineRegistry {
	registry := &EngineRegistry{supervisors: make(map[EngineName]EngineSupervisor, len(supervisors))}
	for _, supervisor := range supervisors {
		registry.supervisors[supervisor.Name()] = supervisor
	}
	return registry
}

func (r *EngineRegistry) Apply(ctx context.Context, desired []EngineDesiredState) map[EngineName]EngineStatus {
	statuses := make(map[EngineName]EngineStatus, len(r.supervisors))
	for _, state := range desired {
		supervisor, ok := r.supervisors[state.Name]
		if !ok {
			statuses[state.Name] = EngineStatus{Name: state.Name, LastError: "engine supervisor not registered"}
			continue
		}
		if err := supervisor.Apply(ctx, state); err != nil {
			status := supervisor.Status(ctx)
			status.LastError = err.Error()
			statuses[state.Name] = status
			continue
		}
		statuses[state.Name] = supervisor.Status(ctx)
	}
	return statuses
}

func (r *EngineRegistry) Snapshot(ctx context.Context) map[EngineName]EngineStatus {
	statuses := make(map[EngineName]EngineStatus, len(r.supervisors))
	for name, supervisor := range r.supervisors {
		statuses[name] = supervisor.Status(ctx)
	}
	return statuses
}

type staticEngineSupervisor struct {
	name   EngineName
	status EngineStatus
}

func newStaticEngineSupervisor(name EngineName) *staticEngineSupervisor {
	return &staticEngineSupervisor{name: name, status: EngineStatus{Name: name}}
}

func (s *staticEngineSupervisor) Name() EngineName { return s.name }

func (s *staticEngineSupervisor) Apply(_ context.Context, desired EngineDesiredState) error {
	s.status.Name = s.name
	s.status.Running = desired.Enabled
	s.status.RulePackVersion = desired.RulePackVersion
	s.status.LastError = ""
	return nil
}

func (s *staticEngineSupervisor) Status(context.Context) EngineStatus { return s.status }
