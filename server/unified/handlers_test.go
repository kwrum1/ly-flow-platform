package unified

import (
	"net/http/httptest"
	"testing"
)

func TestParseQueryBool(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		defaultVal bool
		want       bool
	}{
		{name: "true literal", raw: "true", defaultVal: false, want: true},
		{name: "numeric true", raw: "1", defaultVal: false, want: true},
		{name: "yes true", raw: "yes", defaultVal: false, want: true},
		{name: "false literal", raw: "false", defaultVal: true, want: false},
		{name: "numeric false", raw: "0", defaultVal: true, want: false},
		{name: "unknown uses default", raw: "maybe", defaultVal: true, want: true},
		{name: "missing uses default", raw: "", defaultVal: false, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/?f="+tc.raw, nil)
			if got := parseQueryBool(req, "f", tc.defaultVal); got != tc.want {
				t.Fatalf("parseQueryBool() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParsePathID(t *testing.T) {
	tests := []struct {
		path string
		want int64
	}{
		{path: "/api/v1/unified/events/123", want: 123},
		{path: "events/456", want: 456},
		{path: "/api/v1/unified/events/not-number", want: 0},
		{path: "/", want: 0},
	}

	for _, tc := range tests {
		if got := parsePathID(tc.path); got != tc.want {
			t.Fatalf("parsePathID(%q) = %d, want %d", tc.path, got, tc.want)
		}
	}
}

func TestParseModulesAndSeverities(t *testing.T) {
	req := httptest.NewRequest("GET", "/?module=xdr&module=dpi&severity=high&severity=low", nil)

	mods := parseModules(req)
	if len(mods) != 2 || mods[0] != ModuleType("xdr") || mods[1] != ModuleType("dpi") {
		t.Fatalf("parseModules() = %#v", mods)
	}

	sevs := parseSeverities(req)
	if len(sevs) != 2 || sevs[0] != Severity("high") || sevs[1] != Severity("low") {
		t.Fatalf("parseSeverities() = %#v", sevs)
	}
}
