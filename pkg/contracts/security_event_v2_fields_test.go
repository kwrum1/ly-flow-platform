package contracts

import (
	"errors"
	"testing"
)

func TestNetworkFieldReportComplete(t *testing.T) {
	report := validV2Event().NetworkFieldReport()
	if !report.IsNetwork {
		t.Fatal("suricata event must be classified as network")
	}
	if !report.Complete || len(report.Issues) != 0 {
		t.Fatalf("complete event reported issues: %v", report.Issues)
	}
}

func TestNetworkFieldReportTreatsZeroPortAsMissing(t *testing.T) {
	event := validV2Event()
	event.Entities.Network.DstPort = 0

	report := event.NetworkFieldReport()
	if report.Complete {
		t.Fatal("dst_port=0 must not be treated as a real port")
	}
	assertIssue(t, report, "network.dst_port", "missing")
	assertFlag(t, report, QualityMissingDstPort)
	assertFlag(t, report, QualityInsufficientTelemetry)
}

func TestNetworkFieldReportRejectsOutOfRangePort(t *testing.T) {
	event := validV2Event()
	event.Entities.Network.SrcPort = 70000

	report := event.NetworkFieldReport()
	assertIssue(t, report, "network.src_port", "out_of_range")
	assertFlag(t, report, QualityMissingSrcPort)
}

func TestNetworkFieldReportMissingAddressesAndProtocol(t *testing.T) {
	event := validV2Event()
	event.Entities.Network.SrcIP = ""
	event.Entities.Network.DstIP = "  "
	event.Entities.Network.Proto = ""

	report := event.NetworkFieldReport()
	assertIssue(t, report, "network.src_ip", "missing")
	assertIssue(t, report, "network.dst_ip", "missing")
	assertIssue(t, report, "network.proto", "missing")
}

func TestNetworkFieldReportRequiresNetworkEntity(t *testing.T) {
	event := validV2Event()
	event.Entities.Network = nil

	report := event.NetworkFieldReport()
	if !report.IsNetwork {
		t.Fatal("suricata source must still be a network event")
	}
	assertIssue(t, report, "entities.network", "missing")
	assertFlag(t, report, QualityInsufficientTelemetry)
}

func TestNonNetworkEventIsAlwaysComplete(t *testing.T) {
	event := validV2Event()
	event.Source = SourceAgentRuntime
	event.EventType = "runtime.process"
	event.Entities.Network = nil

	report := event.NetworkFieldReport()
	if report.IsNetwork {
		t.Fatal("runtime event must not be treated as network")
	}
	if !report.Complete {
		t.Fatal("non-network event should be complete")
	}
}

func TestApplyNetworkFieldFlagsIsIdempotent(t *testing.T) {
	event := validV2Event()
	event.Entities.Network.DstPort = 0

	event.ApplyNetworkFieldFlags()
	first := len(event.QualityFlags)
	event.ApplyNetworkFieldFlags()

	if len(event.QualityFlags) != first {
		t.Fatalf("flags grew on second apply: %v", event.QualityFlags)
	}
	if countFlag(event.QualityFlags, QualityMissingDstPort) != 1 {
		t.Fatal("missing_dst_port must appear exactly once")
	}
	if !event.IsInsufficientTelemetry() {
		t.Fatal("event must be marked insufficient_telemetry")
	}
}

func TestValidateWithMode(t *testing.T) {
	incomplete := validV2Event()
	incomplete.Entities.Network.DstPort = 0

	if err := incomplete.ValidateWithMode(FieldValidationOff); err != nil {
		t.Fatalf("off mode must accept: %v", err)
	}
	if err := incomplete.ValidateWithMode(FieldValidationShadow); err != nil {
		t.Fatalf("shadow mode must accept: %v", err)
	}

	err := incomplete.ValidateWithMode(FieldValidationEnforce)
	if err == nil {
		t.Fatal("enforce mode must reject an incomplete network event")
	}
	var violation *ContractValidationError
	if !errors.As(err, &violation) {
		t.Fatalf("expected structured ContractValidationError, got %T", err)
	}
	if violation.Code != "insufficient_telemetry" || violation.Field == "" {
		t.Fatalf("unexpected violation: %+v", violation)
	}

	complete := validV2Event()
	if err := complete.ValidateWithMode(FieldValidationEnforce); err != nil {
		t.Fatalf("complete event rejected in enforce mode: %v", err)
	}
}

func TestValidateWithModeStillAppliesBaseContract(t *testing.T) {
	event := validV2Event()
	event.EventUID = ""

	if err := event.ValidateWithMode(FieldValidationShadow); err == nil {
		t.Fatal("base contract must still run in shadow mode")
	}
}

func TestParseFieldValidationMode(t *testing.T) {
	cases := map[string]FieldValidationMode{
		"":         FieldValidationShadow,
		"shadow":   FieldValidationShadow,
		"ENFORCE":  FieldValidationEnforce,
		"off":      FieldValidationOff,
		"typo":     FieldValidationShadow,
		"disabled": FieldValidationOff,
	}
	for input, expected := range cases {
		if got := ParseFieldValidationMode(input); got != expected {
			t.Fatalf("ParseFieldValidationMode(%q)=%q want %q", input, got, expected)
		}
	}
}

func assertIssue(t *testing.T, report NetworkFieldReport, field, reason string) {
	t.Helper()
	for _, issue := range report.Issues {
		if issue.Field == field && issue.Reason == reason {
			return
		}
	}
	t.Fatalf("missing issue %s:%s in %v", field, reason, report.Issues)
}

func assertFlag(t *testing.T, report NetworkFieldReport, expected QualityFlag) {
	t.Helper()
	for _, flag := range report.SuggestedFlags {
		if flag == expected {
			return
		}
	}
	t.Fatalf("missing suggested flag %q in %v", expected, report.SuggestedFlags)
}

func countFlag(flags []QualityFlag, expected QualityFlag) int {
	count := 0
	for _, flag := range flags {
		if flag == expected {
			count++
		}
	}
	return count
}
