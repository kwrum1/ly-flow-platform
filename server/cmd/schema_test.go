package main

import (
	"strings"
	"testing"
)

func TestAssetSchemaDefinesRuntimeHostTables(t *testing.T) {
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS host_groups",
		"CREATE TABLE IF NOT EXISTS hosts",
		"CREATE TABLE IF NOT EXISTS host_network_interfaces",
		"CREATE TABLE IF NOT EXISTS host_ports",
		"CREATE TABLE IF NOT EXISTS host_processes",
		"CREATE TABLE IF NOT EXISTS host_software",
		"CREATE TABLE IF NOT EXISTS host_tags",
		"CREATE TABLE IF NOT EXISTS host_change_history",
		"CREATE TABLE IF NOT EXISTS host_containers",
		"CREATE TABLE IF NOT EXISTS host_performance",
	} {
		if !strings.Contains(assetSchema, want) {
			t.Fatalf("asset schema missing %q", want)
		}
	}
}

func TestAssetSchemaIsIdempotent(t *testing.T) {
	if strings.Contains(assetSchema, "CREATE INDEX idx_") {
		t.Fatalf("asset schema must use CREATE INDEX IF NOT EXISTS for startup idempotency")
	}
	if strings.Contains(assetSchema, "DROP TABLE") {
		t.Fatalf("asset schema must not drop tables during runtime startup")
	}
}
