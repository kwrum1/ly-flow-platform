package wazuh

import "testing"

func TestNewUsesDefaultPath(t *testing.T) {
	component, err := New(Config{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if component.Name() != "wazuh-agent" {
		t.Fatalf("name = %q", component.Name())
	}
	if err := component.Probe(); err == nil {
		t.Fatal("expected default path to be absent on this machine")
	}
}

func TestNewAcceptsExplicitPath(t *testing.T) {
	component, err := New(Config{BinaryPath: "/tmp/wazuh-agent", Args: []string{"-f"}})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if component == nil {
		t.Fatal("nil component")
	}
}
