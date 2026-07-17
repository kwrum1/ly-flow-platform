package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testFileReference struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type testAlgorithmReference struct {
	Identity         string `json:"identity"`
	DescriptorPath   string `json:"descriptor_path"`
	DescriptorSHA256 string `json:"descriptor_sha256"`
	RulesPath        string `json:"rules_path"`
	RulesSHA256      string `json:"rules_sha256"`
}

type testManifest struct {
	Corpus     testFileReference        `json:"corpus"`
	Baseline   testFileReference        `json:"baseline"`
	Workflow   testFileReference        `json:"representative_workflow"`
	Algorithms []testAlgorithmReference `json:"algorithms"`
}

func fixtureManifestPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "..", "fixtures", "detection-replay", "v1", "manifest.json"))
	if err != nil {
		t.Fatalf("absolute fixture manifest path: %v", err)
	}
	return path
}

func approvedReviewPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(filepath.Dir(fixtureManifestPath(t)), "representative-review.approved.inert-test.json")
}

func copyFixtureTree(t *testing.T) string {
	t.Helper()
	source := filepath.Dir(fixtureManifestPath(t))
	destination := filepath.Join(t.TempDir(), "v1")
	if err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, contents, 0o644)
	}); err != nil {
		t.Fatalf("copy fixture tree: %v", err)
	}
	return filepath.Join(destination, "manifest.json")
}

func readTestManifest(t *testing.T, path string) testManifest {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest testManifest
	if err := json.Unmarshal(contents, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	return manifest
}

func writeTestManifest(t *testing.T, path string, manifest testManifest) {
	t.Helper()
	contents, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	if err := os.WriteFile(path, append(contents, '\n'), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

func replaceShadowRules(t *testing.T, manifestPath, rulesPath string) {
	t.Helper()
	manifest := readTestManifest(t, manifestPath)
	for index := range manifest.Algorithms {
		if manifest.Algorithms[index].Identity == "v3-shadow" {
			manifest.Algorithms[index].RulesPath = rulesPath
			manifest.Algorithms[index].RulesSHA256 = fileSHA256(t, filepath.Join(filepath.Dir(manifestPath), rulesPath))
			writeTestManifest(t, manifestPath, manifest)
			return
		}
	}
	t.Fatal("shadow algorithm reference not found")
}

func refreshManifestChecksum(t *testing.T, manifestPath, reference string, targetPath string) {
	t.Helper()
	manifest := readTestManifest(t, manifestPath)
	switch reference {
	case "corpus":
		manifest.Corpus.SHA256 = fileSHA256(t, targetPath)
	case "baseline":
		manifest.Baseline.SHA256 = fileSHA256(t, targetPath)
	default:
		t.Fatalf("unknown manifest reference %q", reference)
	}
	writeTestManifest(t, manifestPath, manifest)
}

func replaceJSONField(t *testing.T, path, field, replacement string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read JSON: %v", err)
	}
	needle := `"` + field + `":"`
	if !bytesContainIgnoringSpaces(contents, needle) {
		t.Fatalf("JSON field %q not found in %s", field, path)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	encoded, err := json.Marshal(replacement)
	if err != nil {
		t.Fatalf("encode replacement: %v", err)
	}
	document[field] = encoded
	updated, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("encode updated JSON: %v", err)
	}
	if err := os.WriteFile(path, append(updated, '\n'), 0o644); err != nil {
		t.Fatalf("write updated JSON: %v", err)
	}
}

func replaceInFile(t *testing.T, path, old, replacement string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	updated := strings.Replace(string(contents), old, replacement, 1)
	if updated == string(contents) {
		t.Fatalf("fixture token %q not found", old)
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

func appendFile(t *testing.T, path string, suffix []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open file for append: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Fatalf("close appended file: %v", err)
		}
	}()
	if _, err := file.Write(suffix); err != nil {
		t.Fatalf("append file: %v", err)
	}
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read checksum input: %v", err)
	}
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func bytesContainIgnoringSpaces(contents []byte, needle string) bool {
	compact := strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(string(contents))
	return strings.Contains(compact, needle)
}
