package rulecompiler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LoadSources reads rule files from files or directories in a deterministic
// order. Only .rules, .rule and .txt files are considered inside directories.
func LoadSources(paths []string) ([]SourceFile, error) {
	var names []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("rulecompiler: source %s: %w", path, err)
		}
		if !info.IsDir() {
			names = append(names, path)
			continue
		}
		err = filepath.WalkDir(path, func(candidate string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			name := entry.Name()
			if strings.HasPrefix(name, ".") {
				return nil
			}
			switch strings.ToLower(filepath.Ext(name)) {
			case ".rules", ".rule", ".txt":
				names = append(names, candidate)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("rulecompiler: walk %s: %w", path, err)
		}
	}
	sort.Strings(names)
	unique := names[:0]
	for _, name := range names {
		if len(unique) == 0 || unique[len(unique)-1] != name {
			unique = append(unique, name)
		}
	}
	files := make([]SourceFile, 0, len(unique))
	for _, name := range unique {
		payload, err := os.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("rulecompiler: read %s: %w", name, err)
		}
		files = append(files, SourceFile{Name: name, Content: payload})
	}
	return files, nil
}

func HashSources(files []SourceFile) string {
	hash := sha256.New()
	for _, file := range files {
		fmt.Fprintf(hash, "%s\x00%d\x00", file.Name, len(file.Content))
		hash.Write(file.Content)
		hash.Write([]byte{'\n'})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

type Compiler struct {
	Sources      []string
	OutputPath   string
	ManifestPath string
	Reload       func(context.Context) error
	Logger       *log.Logger
}

func (c *Compiler) logger() *log.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return log.New(os.Stderr, "rulecompiler: ", log.LstdFlags)
}

// Sync reads and compiles the configured sources once.
func (c *Compiler) Sync(ctx context.Context) (Result, error) {
	result, _, err := c.SyncIfChanged(ctx, "")
	return result, err
}

// SyncIfChanged compiles only when the source hash differs from previousHash.
func (c *Compiler) SyncIfChanged(ctx context.Context, previousHash string) (Result, bool, error) {
	files, err := LoadSources(c.Sources)
	if err != nil {
		return Result{}, false, err
	}
	if len(files) == 0 {
		return Result{}, false, fmt.Errorf("rulecompiler: no source rule files")
	}
	hash := HashSources(files)
	if previousHash != "" && hash == previousHash {
		return Result{SourceHash: hash}, false, nil
	}
	result := Convert(files)
	result.SourceHash = hash
	if result.Converted == 0 {
		return result, true, fmt.Errorf("rulecompiler: no convertible rules (skipped %d)", len(result.Skipped))
	}
	if err := ValidateBundle(result.Bundle); err != nil {
		return result, true, err
	}
	digest, err := WriteBundle(c.OutputPath, c.ManifestPath, result)
	if err != nil {
		return result, true, err
	}
	c.logger().Printf("compiled %d rules (%d skipped), sha256=%s", result.Converted, len(result.Skipped), digest)
	if c.Reload != nil {
		if err := c.Reload(ctx); err != nil {
			return result, true, fmt.Errorf("rulecompiler: reload: %w", err)
		}
	}
	return result, true, nil
}

type Watcher struct {
	Compiler *Compiler
	Interval time.Duration
	Logger   *log.Logger
}

func (w *Watcher) logger() *log.Logger {
	if w.Logger != nil {
		return w.Logger
	}
	if w.Compiler != nil && w.Compiler.Logger != nil {
		return w.Compiler.Logger
	}
	return log.New(os.Stderr, "rulecompiler: ", log.LstdFlags)
}

// Run performs an initial sync and then polls for source changes until ctx ends.
func (w *Watcher) Run(ctx context.Context) error {
	if w.Compiler == nil {
		return fmt.Errorf("rulecompiler: nil compiler")
	}
	interval := w.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	lastHash := ""
	syncOnce := func() {
		result, changed, err := w.Compiler.SyncIfChanged(ctx, lastHash)
		if result.SourceHash != "" {
			lastHash = result.SourceHash
		}
		if err != nil {
			w.logger().Printf("sync failed (old rules kept): %v", err)
			return
		}
		if changed {
			w.logger().Printf("rules refreshed from %d source files", len(result.SourceFiles))
		}
	}
	syncOnce()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			syncOnce()
		}
	}
}

// CommandReload returns a Reload hook that runs a shell command. It is
// intentionally opt-in so unit tests and one-shot compiles do not restart a
// sensor unexpectedly.
func CommandReload(command string) func(context.Context) error {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil
	}
	return func(ctx context.Context) error {
		cmd := exec.CommandContext(ctx, "sh", "-c", command)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
		}
		return nil
	}
}
