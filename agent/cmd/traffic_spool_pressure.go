package main

import (
	"errors"
	"os"
	"path/filepath"
)

type spoolPressure struct {
	PendingFiles uint64
	Bytes        int64
	MaxBytes     int64
	Percent      uint64
	Pressured    bool
	Status       string
	ReadError    string
}

func spoolPressureFromDir(dir string, maxBytes int64) (spoolPressure, error) {
	pressure := spoolPressure{MaxBytes: maxBytes, Status: "healthy"}
	for _, subdir := range []string{filepath.Join(dir, "v2", "pending"), filepath.Join(dir, "v2", "tmp")} {
		entries, err := os.ReadDir(subdir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return spoolPressure{}, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return spoolPressure{}, err
			}
			pressure.Bytes += info.Size()
			if filepath.Base(subdir) == "pending" {
				pressure.PendingFiles++
			}
		}
	}
	if maxBytes > 0 {
		pressure.Percent = uint64(min(int64(100), pressure.Bytes*100/maxBytes))
		pressure.Pressured = pressure.Percent >= 80
		if pressure.Pressured {
			pressure.Status = "pressured"
		}
	}
	return pressure, nil
}
