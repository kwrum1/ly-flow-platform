package replay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type fileReference struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type algorithmReference struct {
	Identity         string `json:"identity"`
	DescriptorPath   string `json:"descriptor_path"`
	DescriptorSHA256 string `json:"descriptor_sha256"`
	RulesPath        string `json:"rules_path"`
	RulesSHA256      string `json:"rules_sha256"`
}

type manifest struct {
	SchemaVersion string               `json:"schema_version"`
	Revision      string               `json:"revision"`
	Corpus        fileReference        `json:"corpus"`
	Baseline      fileReference        `json:"baseline"`
	Workflow      fileReference        `json:"representative_workflow"`
	Algorithms    []algorithmReference `json:"algorithms"`
}

type corpusRecord struct {
	ID       string `json:"id"`
	Expected bool   `json:"expected_detection"`
	Entity   string `json:"entity"`
	Source   string `json:"source"`
}

type baseline struct {
	ManifestRevision       string  `json:"manifest_revision"`
	Active                 Metrics `json:"v2_active"`
	MinimumShadowRecallBPS int     `json:"minimum_shadow_recall_bps"`
	MinimumCompletenessBPS int     `json:"minimum_completeness_bps"`
	MaximumShadowFPRBPS    int     `json:"maximum_shadow_false_positive_rate_bps"`
}

type descriptor struct {
	Identity string `json:"identity"`
	Mode     string `json:"mode"`
}

type ruleSet struct {
	SchemaVersion string   `json:"schema_version"`
	MatchIDs      []string `json:"match_ids"`
	MatchAll      bool     `json:"match_all"`
}

type loadedAlgorithm struct {
	reference algorithmReference
	rules     ruleSet
}

type loadedInputs struct {
	manifest       manifest
	manifestDigest string
	corpus         []corpusRecord
	baseline       baseline
	algorithms     []loadedAlgorithm
}

func loadInputs(ctx context.Context, path string) (loadedInputs, error) {
	if err := ctx.Err(); err != nil {
		return loadedInputs{}, err
	}
	manifestBytes, err := os.ReadFile(path)
	if err != nil {
		return loadedInputs{}, fmt.Errorf("read replay manifest: %w", err)
	}
	var document manifest
	if err := decodeStrict(path, manifestBytes, &document); err != nil {
		return loadedInputs{}, err
	}
	if document.SchemaVersion == "" {
		document.SchemaVersion = "lyflow.detection-replay-manifest.v1"
	}
	if document.Revision == "" {
		document.Revision = "detection-replay.v1"
	}
	if document.SchemaVersion != "lyflow.detection-replay-manifest.v1" || len(document.Algorithms) != 2 {
		return loadedInputs{}, &MalformedError{Path: path, Reason: "invalid schema, revision, or algorithm count"}
	}
	root := filepath.Dir(path)
	corpusBytes, err := readVerified(root, document.Corpus)
	if err != nil {
		return loadedInputs{}, err
	}
	baselineBytes, err := readVerified(root, document.Baseline)
	if err != nil {
		return loadedInputs{}, err
	}
	if _, err := readVerified(root, document.Workflow); err != nil {
		return loadedInputs{}, err
	}
	records, err := decodeCorpus(filepath.Join(root, document.Corpus.Path), corpusBytes)
	if err != nil {
		return loadedInputs{}, err
	}
	var approved baseline
	if err := decodeStrict(document.Baseline.Path, baselineBytes, &approved); err != nil {
		return loadedInputs{}, err
	}
	if approved.ManifestRevision != document.Revision {
		return loadedInputs{}, &StaleBaselineError{BaselineRevision: approved.ManifestRevision, ManifestRevision: document.Revision}
	}
	algorithms := make([]loadedAlgorithm, 0, len(document.Algorithms))
	for _, reference := range document.Algorithms {
		descriptorBytes, err := readVerified(root, fileReference{Path: reference.DescriptorPath, SHA256: reference.DescriptorSHA256})
		if err != nil {
			return loadedInputs{}, err
		}
		var algorithmDescriptor descriptor
		if err := decodeStrict(reference.DescriptorPath, descriptorBytes, &algorithmDescriptor); err != nil {
			return loadedInputs{}, err
		}
		if algorithmDescriptor.Identity != reference.Identity || (algorithmDescriptor.Mode != "active" && algorithmDescriptor.Mode != "shadow") {
			return loadedInputs{}, &MalformedError{Path: reference.DescriptorPath, Reason: "descriptor identity or mode mismatch"}
		}
		rulesBytes, err := readVerified(root, fileReference{Path: reference.RulesPath, SHA256: reference.RulesSHA256})
		if err != nil {
			return loadedInputs{}, err
		}
		var rules ruleSet
		if err := decodeStrict(reference.RulesPath, rulesBytes, &rules); err != nil {
			return loadedInputs{}, err
		}
		if rules.SchemaVersion != "lyflow.inert-replay-rules.v1" {
			return loadedInputs{}, &MalformedError{Path: reference.RulesPath, Reason: "unsupported inert rule schema"}
		}
		algorithms = append(algorithms, loadedAlgorithm{reference: reference, rules: rules})
	}
	if algorithms[0].reference.Identity != "v2-active" || algorithms[1].reference.Identity != "v3-shadow" {
		return loadedInputs{}, &MalformedError{Path: path, Reason: "algorithms must be ordered v2-active then v3-shadow"}
	}
	return loadedInputs{manifest: document, manifestDigest: digest(manifestBytes), corpus: records, baseline: approved, algorithms: algorithms}, nil
}

func readVerified(root string, reference fileReference) ([]byte, error) {
	if reference.Path == "" || filepath.IsAbs(reference.Path) || strings.Contains(filepath.Clean(reference.Path), "..") || len(reference.SHA256) != 64 {
		return nil, &MalformedError{Path: reference.Path, Reason: "invalid file reference"}
	}
	path := filepath.Join(root, reference.Path)
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read replay input %s: %w", path, err)
	}
	if digest(contents) != reference.SHA256 {
		return nil, &IntegrityError{Path: path}
	}
	return contents, nil
}

func decodeStrict(path string, contents []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return &MalformedError{Path: path, Reason: err.Error()}
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return &MalformedError{Path: path, Reason: "trailing JSON value"}
	}
	return nil
}

func decodeCorpus(path string, contents []byte) ([]corpusRecord, error) {
	lines := bytes.Split(contents, []byte("\n"))
	records := make([]corpusRecord, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	for index, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var record corpusRecord
		if err := decodeStrict(fmt.Sprintf("%s:%d", path, index+1), line, &record); err != nil {
			return nil, err
		}
		if record.ID == "" {
			return nil, &MalformedError{Path: path, Reason: "record id is empty"}
		}
		if _, exists := seen[record.ID]; exists {
			return nil, &MalformedError{Path: path, Reason: "duplicate record id"}
		}
		seen[record.ID] = struct{}{}
		records = append(records, record)
	}
	if len(records) == 0 {
		return nil, &MalformedError{Path: path, Reason: "corpus is empty"}
	}
	return records, nil
}

func digest(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}
