// Package rulecompiler converts a conservative subset of Suricata rules into
// ly_probe servicePlugin threat rules, and can keep the generated JSON fresh.
package rulecompiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Bundle is the JSON consumed by ly_probe's servicePlugin.
type Bundle struct {
	Threat ThreatClass `json:"threat"`
}

type ThreatClass struct {
	Priority int             `json:"priority,omitempty"`
	Rules    map[string]Rule `json:"rules"`
}

// Rule mirrors the subset of fp-patterns/threat.json fields that LyFlow uses.
type Rule struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Desc     string `json:"desc,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Port     int    `json:"port,omitempty"`
	IsHTTP   int    `json:"is_http,omitempty"`
	Part     string `json:"part,omitempty"`
	Regex    string `json:"regex"`
}

type SkippedRule struct {
	SID    int    `json:"sid,omitempty"`
	Msg    string `json:"msg,omitempty"`
	Reason string `json:"reason"`
	Source string `json:"source,omitempty"`
	Line   int    `json:"line,omitempty"`
}

type Result struct {
	Bundle      Bundle        `json:"-"`
	Converted   int           `json:"converted"`
	Skipped     []SkippedRule `json:"skipped"`
	SourceHash  string        `json:"source_hash"`
	SourceFiles []string      `json:"source_files"`
}

type Manifest struct {
	SchemaVersion int           `json:"schema_version"`
	GeneratedAt   time.Time     `json:"generated_at"`
	SourceHash    string        `json:"source_hash"`
	SourceFiles   []string      `json:"source_files"`
	Converted     int           `json:"converted"`
	Skipped       []SkippedRule `json:"skipped"`
	OutputSHA256  string        `json:"output_sha256"`
}

const ManifestSchemaVersion = 1

// ValidateBundle rejects output that ly_probe or Go's regexp engine cannot use.
func ValidateBundle(bundle Bundle) error {
	if len(bundle.Threat.Rules) == 0 {
		return fmt.Errorf("rulecompiler: bundle has no rules")
	}
	ids := make([]string, 0, len(bundle.Threat.Rules))
	for id := range bundle.Threat.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		rule := bundle.Threat.Rules[id]
		if id == "" {
			return fmt.Errorf("rulecompiler: empty rule id")
		}
		if strings.TrimSpace(rule.Type) == "" || strings.TrimSpace(rule.Name) == "" {
			return fmt.Errorf("rulecompiler: rule %s has empty type/name", id)
		}
		if rule.Regex == "" {
			return fmt.Errorf("rulecompiler: rule %s has empty regex", id)
		}
		if _, err := regexp.Compile(rule.Regex); err != nil {
			return fmt.Errorf("rulecompiler: rule %s regex: %w", id, err)
		}
		if rule.Protocol != "" && rule.Protocol != "tcp" && rule.Protocol != "udp" {
			return fmt.Errorf("rulecompiler: rule %s unsupported protocol %q", id, rule.Protocol)
		}
		if rule.IsHTTP != 0 && rule.IsHTTP != 1 {
			return fmt.Errorf("rulecompiler: rule %s is_http must be 0 or 1", id)
		}
		switch rule.Part {
		case "", "head", "body", "total":
		default:
			return fmt.Errorf("rulecompiler: rule %s unsupported part %q", id, rule.Part)
		}
	}
	return nil
}

// WriteBundle atomically writes threat.json and manifest.json.
func WriteBundle(outputPath, manifestPath string, result Result) (string, error) {
	if err := ValidateBundle(result.Bundle); err != nil {
		return "", err
	}
	payload, err := marshalIndent(result.Bundle)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	if err := writeAtomic(outputPath, payload, 0o644); err != nil {
		return "", err
	}
	manifest := Manifest{
		SchemaVersion: ManifestSchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		SourceHash:    result.SourceHash,
		SourceFiles:   result.SourceFiles,
		Converted:     result.Converted,
		Skipped:       result.Skipped,
		OutputSHA256:  digest,
	}
	manifestPayload, err := marshalIndent(manifest)
	if err != nil {
		return "", err
	}
	if err := writeAtomic(manifestPath, manifestPayload, 0o644); err != nil {
		return "", err
	}
	return digest, nil
}

func marshalIndent(value any) ([]byte, error) {
	// encoding/json sorts map keys, which keeps generated rule files stable.
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func writeAtomic(path string, payload []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("rulecompiler: create %s: %w", dir, err)
	}
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("rulecompiler: temp file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return fmt.Errorf("rulecompiler: chmod temp: %w", err)
	}
	if _, err := temp.Write(payload); err != nil {
		temp.Close()
		return fmt.Errorf("rulecompiler: write temp: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("rulecompiler: sync temp: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("rulecompiler: close temp: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("rulecompiler: rename: %w", err)
	}
	if dirHandle, err := os.Open(dir); err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return nil
}
