package transportreliability

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (spool *EncryptedSpool) recoverTemps() error {
	entries, err := os.ReadDir(spool.tmpDir)
	if err != nil {
		return fmt.Errorf("read spool temp directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".tmp")
		if err := os.Rename(filepath.Join(spool.tmpDir, entry.Name()), filepath.Join(spool.pendingDir, name)); err != nil {
			return fmt.Errorf("recover spool temp record: %w", err)
		}
	}
	return nil
}

func (spool *EncryptedSpool) size() (int64, error) {
	var total int64
	for _, dir := range []string{spool.pendingDir, spool.tmpDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return 0, fmt.Errorf("measure spool directory: %w", err)
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				return 0, fmt.Errorf("measure spool record: %w", err)
			}
			if !info.IsDir() {
				total += info.Size()
			}
		}
	}
	return total, nil
}

func writeSyncClose(file *os.File, data []byte) error {
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write spool record: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync spool record: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close spool record: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open spool directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync spool directory: %w", err)
	}
	return nil
}

func safeName(value string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_", "\x00", "_")
	return replacer.Replace(value)
}
