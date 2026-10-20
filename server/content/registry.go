// Package content models the rule/intelligence source registry and license gate.
// Fetching/compiling is delegated to suricata-update, sigma-cli, yara, etc.
package content

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Kind string

const (
	KindSuricata Kind = "suricata"
	KindYARA     Kind = "yara"
	KindSigma    Kind = "sigma"
	KindWazuh    Kind = "wazuh"
	KindOpenRASP Kind = "openrasp"
	KindElkeid   Kind = "elkeid"
	KindTI       Kind = "ti"
	KindWeb      Kind = "web"
)

type Source struct {
	ID      string
	Name    string
	Kind    Kind
	URL     string
	License string
	Cadence time.Duration
	Enabled bool
}

var (
	ErrInvalidSource = errors.New("content: invalid source")
	ErrLicenseDenied = errors.New("content: license denied")
)

type Registry struct {
	sources map[string]Source
}

func NewRegistry(sources ...Source) (*Registry, error) {
	registry := &Registry{sources: map[string]Source{}}
	for _, source := range sources {
		if err := registry.Add(source); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func (registry *Registry) Add(source Source) error {
	if strings.TrimSpace(source.ID) == "" || strings.TrimSpace(source.Name) == "" || strings.TrimSpace(source.URL) == "" {
		return ErrInvalidSource
	}
	if source.Cadence <= 0 {
		return fmt.Errorf("%w: cadence", ErrInvalidSource)
	}
	if !AllowedLicense(source.License) {
		return fmt.Errorf("%w: %s", ErrLicenseDenied, source.License)
	}
	if _, exists := registry.sources[source.ID]; exists {
		return fmt.Errorf("%w: duplicate %s", ErrInvalidSource, source.ID)
	}
	registry.sources[source.ID] = source
	return nil
}

func (registry *Registry) Sources() []Source {
	result := make([]Source, 0, len(registry.sources))
	for _, source := range registry.sources {
		result = append(result, source)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result
}

func (registry *Registry) Due(now time.Time, lastSync map[string]time.Time) []Source {
	result := make([]Source, 0)
	for _, source := range registry.sources {
		if !source.Enabled {
			continue
		}
		last := lastSync[source.ID]
		if last.IsZero() || now.Sub(last) >= source.Cadence {
			result = append(result, source)
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result
}

// AllowedLicense permits the licenses compatible with the open-source LyFlow
// distribution. Non-distributable vendor licenses are rejected.
func AllowedLicense(license string) bool {
	normalized := strings.ToLower(strings.TrimSpace(license))
	switch {
	case strings.Contains(normalized, "elkeid license"),
		strings.Contains(normalized, "proprietary"),
		strings.Contains(normalized, "unknown"),
		normalized == "":
		return false
	default:
		return true
	}
}
