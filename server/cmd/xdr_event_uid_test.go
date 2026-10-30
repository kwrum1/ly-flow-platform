package main

import (
	"strings"
	"testing"
	"time"
)

var uidTestTime = time.Date(2026, 10, 29, 4, 0, 0, 123456789, time.UTC)

func TestEventUIDV2NativeIDIsStable(t *testing.T) {
	a := deterministicEventUIDV2("default", "traffic", "rule-1", "10.0.0.1", "web", "agent-1", uidTestTime, "native-1", "")
	b := deterministicEventUIDV2("default", "traffic", "rule-2", "10.0.0.2", "web", "agent-1", uidTestTime.Add(time.Minute), "native-1", "")
	if a != b {
		t.Fatalf("native id must dominate time/rule changes: %s != %s", a, b)
	}
	if !strings.HasPrefix(a, "xdr2n-") {
		t.Fatalf("unexpected prefix: %s", a)
	}
	c := deterministicEventUIDV2("other-tenant", "traffic", "rule-1", "10.0.0.1", "web", "agent-1", uidTestTime, "native-1", "")
	if a == c {
		t.Fatal("native id must be tenant scoped")
	}
}

func TestEventUIDV2PayloadHashDistinguishesPayloads(t *testing.T) {
	base := deterministicEventUIDV2("default", "traffic", "rule-1", "10.0.0.1", "web", "agent-1", uidTestTime, "", "hash-a")
	same := deterministicEventUIDV2("default", "traffic", "rule-1", "10.0.0.1", "web", "agent-1", uidTestTime, "", "hash-a")
	other := deterministicEventUIDV2("default", "traffic", "rule-1", "10.0.0.1", "web", "agent-1", uidTestTime, "", "hash-b")
	if base != same {
		t.Fatal("identical input must produce identical uid")
	}
	if base == other {
		t.Fatal("different payload hash must not collide")
	}
	if !strings.HasPrefix(base, "xdr2p-") {
		t.Fatalf("unexpected prefix: %s", base)
	}
}

func TestEventUIDV2DoesNotTruncateToSecond(t *testing.T) {
	early := deterministicEventUIDV2("default", "traffic", "rule-1", "10.0.0.1", "web", "agent-1", uidTestTime, "", "")
	late := deterministicEventUIDV2("default", "traffic", "rule-1", "10.0.0.1", "web", "agent-1", uidTestTime.Add(400*time.Millisecond), "", "")
	if early == late {
		t.Fatal("events within the same second must not collapse")
	}
}

func TestResolveEventUIDDefaultsToV1(t *testing.T) {
	t.Setenv("LYFLOW_EVENT_UID_VERSION", "")
	event := map[string]interface{}{"message_id": "native-9"}
	uid, shadow := resolveEventUID(event, "default", "traffic", "rule-1", "10.0.0.1", "web", "agent-1", uidTestTime)
	legacy := deterministicEventUID("default", "traffic", "rule-1", "10.0.0.1", "web", "agent-1", uidTestTime)
	if uid != legacy {
		t.Fatalf("v1 default changed: %s != %s", uid, legacy)
	}
	if shadow == "" {
		t.Fatal("shadow uid must be computed in v1 mode")
	}
}

func TestResolveEventUIDV2Mode(t *testing.T) {
	t.Setenv("LYFLOW_EVENT_UID_VERSION", "v2")
	event := map[string]interface{}{"message_id": "native-9"}
	uid, shadow := resolveEventUID(event, "default", "traffic", "rule-1", "10.0.0.1", "web", "agent-1", uidTestTime)
	if !strings.HasPrefix(uid, "xdr2") {
		t.Fatalf("unexpected uid: %s", uid)
	}
	if shadow != "" {
		t.Fatal("shadow is only produced in v1 mode")
	}
}

func TestXDRNativeEventIDExtraction(t *testing.T) {
	cases := []struct {
		name  string
		event map[string]interface{}
		want  string
	}{
		{"message id", map[string]interface{}{"message_id": "m-1", "raw": map[string]interface{}{"id": "r-1"}}, "m-1"},
		{"native id", map[string]interface{}{"native_event_id": "n-1"}, "n-1"},
		{"raw id", map[string]interface{}{"raw": map[string]interface{}{"id": "r-1"}}, "r-1"},
		{"none", map[string]interface{}{}, ""},
	}
	for _, tc := range cases {
		if got := xdrNativeEventID(tc.event); got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestXDRPayloadHashExtraction(t *testing.T) {
	event := map[string]interface{}{"raw_reference": map[string]interface{}{"hash": "abc"}}
	if got := xdrPayloadHash(event); got != "abc" {
		t.Fatalf("got %q", got)
	}
	if got := xdrPayloadHash(map[string]interface{}{"raw_sha256": "def"}); got != "def" {
		t.Fatalf("got %q", got)
	}
}
