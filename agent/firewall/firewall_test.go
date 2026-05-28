package firewall

import (
	"testing"
	"time"
)

func TestValidateBlockRejectsWhitelist(t *testing.T) {
	err := ValidateBlock(BlockRequest{IP: "10.0.0.10", TTL: time.Minute, Temporary: true}, Whitelist{CIDRs: []string{"10.0.0.0/24"}})
	if err == nil {
		t.Fatal("expected whitelist rejection")
	}
}

func TestValidateBlockRequiresTTLForTemporary(t *testing.T) {
	if err := ValidateBlock(BlockRequest{IP: "198.51.100.1", Temporary: true}, Whitelist{}); err == nil {
		t.Fatal("expected ttl validation")
	}
	if err := ValidateBlock(BlockRequest{IP: "198.51.100.1", TTL: time.Minute, Temporary: true}, Whitelist{}); err != nil {
		t.Fatalf("expected valid block: %v", err)
	}
}
