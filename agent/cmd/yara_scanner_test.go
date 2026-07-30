package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseYARAOutputLine(t *testing.T) {
	match, ok := parseYARAOutputLine("LyFlow_Harmless_Test [test,malware] /tmp/sample.bin")
	if !ok || match.Rule != "LyFlow_Harmless_Test" || match.FilePath != "/tmp/sample.bin" {
		t.Fatalf("unexpected match: %#v ok=%v", match, ok)
	}
	if len(match.Tags) != 2 || match.Tags[0] != "test" || match.Tags[1] != "malware" {
		t.Fatalf("unexpected tags: %#v", match.Tags)
	}
	if _, ok := parseYARAOutputLine("invalid"); ok {
		t.Fatal("accepted invalid output")
	}
}

func TestSHA256FileEnforcesLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(path, []byte("lyflow"), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := sha256File(path, 64)
	if err != nil || hash != "83e6d315c3614ef65783e84ad1be180eb19f1fe2209dc6510a1ce368a868defb" {
		t.Fatalf("hash=%q err=%v", hash, err)
	}
	if _, err := sha256File(path, 2); err == nil {
		t.Fatal("oversized file was accepted")
	}
}
