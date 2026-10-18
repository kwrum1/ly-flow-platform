package content

import (
	"errors"
	"testing"
	"time"
)

func TestRegistryAddAndDue(t *testing.T) {
	registry, err := NewRegistry(
		Source{ID: "et-open", Name: "ET Open", Kind: KindSuricata, URL: "https://example/et.tar.gz", License: "BSD-3-Clause", Cadence: 24 * time.Hour, Enabled: true},
		Source{ID: "openrasp", Name: "OpenRASP", Kind: KindOpenRASP, URL: "https://example/openrasp.zip", License: "Apache-2.0", Cadence: 168 * time.Hour, Enabled: true},
		Source{ID: "disabled", Name: "Disabled", Kind: KindYARA, URL: "https://example/yara.zip", License: "MIT", Cadence: time.Hour, Enabled: false},
	)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	due := registry.Due(now, map[string]time.Time{
		"et-open":  now.Add(-25 * time.Hour),
		"openrasp": now.Add(-time.Hour),
	})
	if len(due) != 1 || due[0].ID != "et-open" {
		t.Fatalf("due = %+v", due)
	}
}

func TestRegistryRejectsElkeidLicense(t *testing.T) {
	_, err := NewRegistry(Source{ID: "hub", Name: "Elkeid HUB", Kind: KindElkeid, URL: "https://example/hub", License: "Elkeid License", Cadence: time.Hour})
	if !errors.Is(err, ErrLicenseDenied) {
		t.Fatalf("err = %v", err)
	}
}

func TestRegistryRejectsInvalidSource(t *testing.T) {
	if _, err := NewRegistry(Source{ID: "", Name: "x", URL: "https://example", License: "MIT", Cadence: time.Hour}); !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("err = %v", err)
	}
}

func TestAllowedLicense(t *testing.T) {
	for _, license := range []string{"BSD-3-Clause", "MIT", "Apache-2.0", "GPL-2.0", "GPL-3.0", "DRL-1.1"} {
		if !AllowedLicense(license) {
			t.Fatalf("expected allowed: %s", license)
		}
	}
	for _, license := range []string{"", "Elkeid License", "proprietary", "unknown"} {
		if AllowedLicense(license) {
			t.Fatalf("expected denied: %s", license)
		}
	}
}
