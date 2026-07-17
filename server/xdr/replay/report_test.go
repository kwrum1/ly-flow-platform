package replay

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestEncodeReports_produces_deterministic_machine_and_human_outputs(t *testing.T) {
	// Given
	report, err := Run(context.Background(), Config{ManifestPath: fixtureManifestPath(t)})
	if err != nil {
		t.Fatalf("run replay: %v", err)
	}

	// When
	firstMachine, firstHuman, firstErr := EncodeReports(report)
	secondMachine, secondHuman, secondErr := EncodeReports(report)

	// Then
	if firstErr != nil || secondErr != nil {
		t.Fatalf("encode reports twice: first=%v second=%v", firstErr, secondErr)
	}
	if !bytes.Equal(firstMachine, secondMachine) || !bytes.Equal(firstHuman, secondHuman) {
		t.Fatal("report encoding changed between identical runs")
	}
	if err := VerifyMachineReport(firstMachine); err != nil {
		t.Fatalf("verify generated machine report: %v", err)
	}
	if !bytes.Contains(firstHuman, []byte("Synthetic regression only")) || !bytes.Contains(firstHuman, []byte("v3-shadow promotion | structurally forbidden")) {
		t.Fatalf("human report omitted scope restrictions:\n%s", firstHuman)
	}
}

func TestVerifyMachineReport_rejects_misleading_pass_only_document(t *testing.T) {
	// Given
	misleading := []byte(`{"status":"PASS"}`)

	// When
	err := VerifyMachineReport(misleading)

	// Then
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("error=%v", err)
	}
}
