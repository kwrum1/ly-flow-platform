package trustroot

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureOnlineRoots_is_idempotent_and_rejects_partial_layout(t *testing.T) {
	// Given
	base := t.TempDir()
	layout := Layout{TrustDir: filepath.Join(base, "trust"), KeyDir: filepath.Join(base, "keys")}
	if err := layout.EnsureOnlineRoots(rand.Reader); err != nil {
		t.Fatalf("ensure roots: %v", err)
	}
	before, err := os.ReadFile(layout.RootPath(PolicyRoot))
	if err != nil {
		t.Fatalf("read policy root: %v", err)
	}

	// When
	repeatErr := layout.EnsureOnlineRoots(rand.Reader)
	after, readErr := os.ReadFile(layout.RootPath(PolicyRoot))
	partial := Layout{TrustDir: filepath.Join(base, "partial-trust"), KeyDir: filepath.Join(base, "partial-keys")}
	if err := os.MkdirAll(partial.TrustDir, 0o755); err != nil {
		t.Fatalf("create partial trust dir: %v", err)
	}
	if err := os.WriteFile(partial.RootPath(PolicyRoot), before, 0o644); err != nil {
		t.Fatalf("write partial root: %v", err)
	}
	partialErr := partial.EnsureOnlineRoots(rand.Reader)

	// Then
	if repeatErr != nil || readErr != nil || !bytes.Equal(before, after) {
		t.Fatalf("repeat ensure changed root: ensure=%v read=%v", repeatErr, readErr)
	}
	if !errors.Is(partialErr, ErrIncompleteLayout) {
		t.Fatalf("partial error = %v, want ErrIncompleteLayout", partialErr)
	}
}
