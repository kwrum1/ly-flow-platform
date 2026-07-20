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

func TestEnsureOnlineRoots_normalizes_public_traversal_and_private_key_modes(t *testing.T) {
	// Given
	base := t.TempDir()
	policyDir := filepath.Join(base, "policy")
	layout := Layout{TrustDir: filepath.Join(policyDir, "trust"), KeyDir: filepath.Join(policyDir, "keys")}
	if err := layout.EnsureOnlineRoots(rand.Reader); err != nil {
		t.Fatalf("bootstrap roots: %v", err)
	}
	if err := os.Chmod(policyDir, 0o700); err != nil {
		t.Fatalf("restrict policy directory: %v", err)
	}
	if err := os.Chmod(layout.TrustDir, 0o700); err != nil {
		t.Fatalf("restrict trust directory: %v", err)
	}
	if err := os.Chmod(layout.KeyDir, 0o755); err != nil {
		t.Fatalf("relax key directory: %v", err)
	}
	if err := os.Chmod(layout.RootPath(RuleRoot), 0o600); err != nil {
		t.Fatalf("restrict rule root: %v", err)
	}
	if err := os.Chmod(layout.KeyPath(RuleSigner), 0o644); err != nil {
		t.Fatalf("relax rule signer: %v", err)
	}

	// When
	err := layout.EnsureOnlineRoots(rand.Reader)

	// Then
	if err != nil {
		t.Fatalf("normalize online roots: %v", err)
	}
	assertFileMode(t, policyDir, 0o755)
	assertFileMode(t, layout.TrustDir, 0o755)
	assertFileMode(t, layout.RootPath(RuleRoot), 0o644)
	assertFileMode(t, layout.KeyDir, 0o700)
	assertFileMode(t, layout.KeyPath(RuleSigner), 0o600)
}

func TestEnsureOnlineRoots_rejects_symlinked_signer_file(t *testing.T) {
	// Given
	base := t.TempDir()
	layout := Layout{TrustDir: filepath.Join(base, "trust"), KeyDir: filepath.Join(base, "keys")}
	if err := layout.Bootstrap(rand.Reader); err != nil {
		t.Fatalf("bootstrap roots: %v", err)
	}
	keyRole, err := RuleRoot.OnlineKeyRole()
	if err != nil {
		t.Fatalf("resolve rule signer role: %v", err)
	}
	external := filepath.Join(base, "external.key")
	if err := os.WriteFile(external, []byte("not the configured signer"), 0o600); err != nil {
		t.Fatalf("write external signer: %v", err)
	}
	if err := os.Remove(layout.KeyPath(keyRole)); err != nil {
		t.Fatalf("remove configured signer: %v", err)
	}
	if err := os.Symlink(external, layout.KeyPath(keyRole)); err != nil {
		t.Fatalf("link configured signer: %v", err)
	}

	// When
	err = layout.EnsureOnlineRoots(rand.Reader)

	// Then
	if !errors.Is(err, ErrMalformedRoot) {
		t.Fatalf("symlink signer error=%v, want ErrMalformedRoot", err)
	}
}
