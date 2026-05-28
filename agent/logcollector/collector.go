package logcollector

import "fmt"

type SourceConfig struct {
	Path       string
	Source     string
	MaxBytes   int64
	Offset     int64
	Inode      uint64
	Checkpoint string
}

func ValidateSource(config SourceConfig) error {
	if config.Path == "" {
		return fmt.Errorf("log path is required")
	}
	if config.MaxBytes <= 0 || config.MaxBytes > 10*1024*1024 {
		return fmt.Errorf("max bytes must be between 1 and 10485760")
	}
	if config.Offset < 0 {
		return fmt.Errorf("offset must be non-negative")
	}
	return nil
}
