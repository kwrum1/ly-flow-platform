package main

import (
	"testing"
	"time"
)

// The prefilter must now admit session records without admitting junk, and it
// must never claim a line is both an alert and a session.
func TestSuricataEVELineIsSession(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{"flow record", `{"timestamp":"2026-11-10T17:00:29.670502+0000","flow_id":1212214571055957,"event_type":"flow","src_ip":"10.3.10.42"}`, true},
		{"http record", `{"event_type":"http","flow_id":1668052616947290,"http":{"hostname":"cgzb.sru.edu.cn"}}`, true},
		{"tls record", `{"event_type": "tls", "flow_id": 1703567787411832}`, true},
		{"dns record", `{"event_type":"dns","flow_id":1502897684121709}`, true},
		{"alert is not a session", eveAlertHTTP, false},
		{"stats record", `{"event_type":"stats","stats":{"uptime":123}}`, false},
		{"fileinfo record", `{"event_type":"fileinfo","fileinfo":{"filename":"a.exe"}}`, false},
		{"no event_type", `{"timestamp":"2026-11-10T17:00:29+0000"}`, false},
		{"truncated", `{"event_type":"flo`, false},
		{"empty", ``, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := suricataEVELineIsSession(test.line); got != test.want {
				t.Fatalf("suricataEVELineIsSession=%v, want %v", got, test.want)
			}
		})
	}
}

// The two predicates must partition the input: no line may be handled twice.
func TestSuricataEVEPrefiltersAreDisjoint(t *testing.T) {
	for _, line := range []string{eveAlertHTTP, eveAlertTLS, eveAlertDNSMulti, `{"event_type":"flow","flow_id":1}`} {
		if suricataEVELineIsAlert(line) && suricataEVELineIsSession(line) {
			t.Fatalf("line classified as both alert and session: %s", line[:80])
		}
	}
}

func TestSuricataEVEEventType(t *testing.T) {
	cases := map[string]string{
		`{"event_type":"flow"}`:          "flow",
		`{"event_type": "TLS"}`:          "tls",
		`{"event_type" : "http" }`:       "http",
		`{"x":1,"event_type":"dns","y":2}`: "dns",
	}
	for line, want := range cases {
		got, ok := suricataEVEEventType(line)
		if !ok || got != want {
			t.Fatalf("suricataEVEEventType(%s)=%q,%v want %q", line, got, ok, want)
		}
	}
	if _, ok := suricataEVEEventType(`{"nope":1}`); ok {
		t.Fatal("line without event_type must report !ok")
	}
}

func TestSuricataEVESessionUIDIsStable(t *testing.T) {
	observed := time.Date(2026, 11, 10, 17, 0, 0, 0, time.UTC)
	event := map[string]interface{}{
		"flow_id": float64(1668052616947290),
		"src_ip":  "10.1.18.252",
	}
	first := suricataEVESessionUID(event, "http", "mirror0", 1668052616947290, observed)
	second := suricataEVESessionUID(event, "http", "mirror0", 1668052616947290, observed)
	if first != second {
		t.Fatalf("session UID is not stable: %q vs %q", first, second)
	}
	// Different event types of one flow must not collide, because each carries
	// a different L7 payload and they are separate session rows.
	tls := suricataEVESessionUID(event, "tls", "mirror0", 1668052616947290, observed)
	if first == tls {
		t.Fatal("http and tls rows of one flow share a session UID")
	}
	if first == suricataEVESessionUID(event, "http", "mirror1", 1668052616947290, observed) {
		t.Fatal("the same flow_id on another sensor shares a session UID")
	}
}
