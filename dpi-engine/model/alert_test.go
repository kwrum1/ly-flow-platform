package model

import "testing"

func TestAlertFromFlowCopiesCoreFields(t *testing.T) {
	flow := &FlowData{
		SrcIP:    "10.0.0.10",
		DstIP:    "8.8.4.4",
		SrcPort:  5555,
		DstPort:  53,
		Protocol: "UDP",
		SensorID: "sensor-9",
		HTTPHost: "example.org",
	}

	var a Alert
	a.FromFlow(flow)

	if a.SrcIP != flow.SrcIP || a.DstIP != flow.DstIP || a.Protocol != flow.Protocol {
		t.Fatalf("FromFlow copied unexpected fields: %+v", a)
	}
	if a.SensorID != flow.SensorID {
		t.Fatalf("SensorID = %q, want %q", a.SensorID, flow.SensorID)
	}
	if a.Domain != "example.org" {
		t.Fatalf("Domain = %q, want example.org", a.Domain)
	}
}

func TestSeverityToString(t *testing.T) {
	cases := []struct {
		in   uint8
		want string
	}{
		{AlertSeverityCritical, "critical"},
		{AlertSeverityHigh, "high"},
		{AlertSeverityMedium, "medium"},
		{AlertSeverityLow, "low"},
		{99, "low"},
	}

	for _, tc := range cases {
		if got := SeverityToString(tc.in); got != tc.want {
			t.Fatalf("SeverityToString(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
