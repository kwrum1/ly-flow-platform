package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBundleFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, []byte(`{"version":"v1","rules":[{"ID":"r1","Name":"Runtime","Category":"runtime","Severity":"high","ScoreHint":80,"Field":"cmd","Value":"/dev/tcp"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle, err := LoadBundleFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Version != "v1" || len(bundle.Rules) != 1 {
		t.Fatalf("unexpected bundle: %#v", bundle)
	}
}
