package engine

import (
	"encoding/json"
	"os"
)

type bundleFile struct {
	Version string        `json:"version"`
	Rules   []RuntimeRule `json:"rules"`
}

func LoadBundleFile(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file bundleFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if file.Version == "" {
		file.Version = "unknown"
	}
	return NewBundle(file.Version, file.Rules)
}
