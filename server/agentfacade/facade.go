// Package agentfacade merges agent inventories from multiple mature providers
// (Wazuh, Elkeid, OpenRASP) into one product-level view.
package agentfacade

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Agent struct {
	ID           string          `json:"id"`
	SourceID     string          `json:"source_id"`
	Name         string          `json:"name"`
	Platform     string          `json:"platform"`
	Version      string          `json:"version"`
	Status       string          `json:"status"`
	Provider     string          `json:"provider"`
	LastSeen     time.Time       `json:"last_seen"`
	Groups       []string        `json:"groups,omitempty"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`
}

type Provider interface {
	Name() string
	List(context.Context) ([]Agent, error)
}

type Facade struct {
	providers []Provider
}

func New(providers ...Provider) *Facade {
	return &Facade{providers: append([]Provider(nil), providers...)}
}

func (facade *Facade) List(ctx context.Context) ([]Agent, error) {
	if facade == nil {
		return nil, errors.New("agent facade is nil")
	}
	agents := make([]Agent, 0)
	var failures []error
	for _, provider := range facade.providers {
		if provider == nil {
			continue
		}
		items, err := provider.List(ctx)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", provider.Name(), err))
			continue
		}
		for _, item := range items {
			item.Provider = provider.Name()
			if item.ID == "" {
				item.ID = provider.Name() + ":" + item.SourceID
			}
			if item.SourceID == "" {
				item.SourceID = item.ID
			}
			if item.Name == "" {
				item.Name = item.SourceID
			}
			if item.Status == "" {
				item.Status = "unknown"
			}
			agents = append(agents, item)
		}
	}
	sort.Slice(agents, func(left, right int) bool {
		if agents[left].LastSeen.Equal(agents[right].LastSeen) {
			return agents[left].ID < agents[right].ID
		}
		return agents[left].LastSeen.After(agents[right].LastSeen)
	})
	return agents, errors.Join(failures...)
}

func Filter(agents []Agent, query, status, provider string) []Agent {
	query = strings.ToLower(strings.TrimSpace(query))
	status = strings.ToLower(strings.TrimSpace(status))
	provider = strings.ToLower(strings.TrimSpace(provider))
	result := make([]Agent, 0, len(agents))
	for _, agent := range agents {
		if status != "" && strings.ToLower(agent.Status) != status {
			continue
		}
		if provider != "" && strings.ToLower(agent.Provider) != provider {
			continue
		}
		if query != "" {
			haystack := strings.ToLower(strings.Join([]string{agent.ID, agent.SourceID, agent.Name, agent.Platform, agent.Version}, " "))
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		result = append(result, agent)
	}
	return result
}

func Page(agents []Agent, offset, limit int) []Agent {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = 50
	}
	if offset >= len(agents) {
		return []Agent{}
	}
	end := offset + limit
	if end > len(agents) {
		end = len(agents)
	}
	return agents[offset:end]
}
