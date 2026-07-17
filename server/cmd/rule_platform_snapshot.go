package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unicode"
)

func validRulePlatformPathSegment(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !unicode.IsLetter(character) && !unicode.IsDigit(character) && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func writeImmutableRuleSnapshot(path string, contents []byte) error {
	if existing, err := os.ReadFile(path); err == nil {
		if bytes.Equal(existing, contents) {
			return nil
		}
		return fmt.Errorf("immutable snapshot conflict: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read immutable snapshot: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create snapshot directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create immutable snapshot: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write immutable snapshot: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync immutable snapshot: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close immutable snapshot: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open snapshot directory: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("sync snapshot directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close snapshot directory: %w", err)
	}
	return nil
}
