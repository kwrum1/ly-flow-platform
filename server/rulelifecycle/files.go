package rulelifecycle

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func immutableWrite(path string, contents []byte, mode os.FileMode) error {
	existing, readErr := os.ReadFile(path)
	if readErr == nil {
		if bytes.Equal(existing, contents) {
			return nil
		}
		return fmt.Errorf("immutable lifecycle content conflict: %w", ErrRevision)
	}
	if !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("read immutable lifecycle content: %w", readErr)
	}
	if err := os.MkdirAll(filepath.Dir(path), lifecycleDirMode); err != nil {
		return fmt.Errorf("create immutable lifecycle directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(path), lifecycleDirMode); err != nil {
		return fmt.Errorf("set immutable lifecycle directory mode: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create immutable lifecycle content: %w", err)
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("set immutable lifecycle content mode: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write immutable lifecycle content: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync immutable lifecycle content: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close immutable lifecycle content: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open immutable lifecycle directory: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("sync immutable lifecycle directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close immutable lifecycle directory: %w", err)
	}
	return nil
}

func atomicWrite(path string, contents []byte, mode os.FileMode) (err error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, lifecycleDirMode); err != nil {
		return fmt.Errorf("create lifecycle directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".rule-lifecycle-*")
	if err != nil {
		return fmt.Errorf("create lifecycle temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(mode); err != nil {
		return fmt.Errorf("set lifecycle file mode: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		return fmt.Errorf("write lifecycle file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync lifecycle file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close lifecycle file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("activate lifecycle file: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open lifecycle directory: %w", err)
	}
	defer func() {
		if closeErr := directoryHandle.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close lifecycle directory: %w", closeErr)
		}
	}()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync lifecycle directory: %w", err)
	}
	return nil
}
