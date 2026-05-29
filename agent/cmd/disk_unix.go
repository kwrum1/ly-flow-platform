//go:build linux || darwin

package main

import "syscall"

func readDiskUsage(path string) map[string]uint64 {
	var stat syscall.Statfs_t
	result := map[string]uint64{}
	if err := syscall.Statfs(path, &stat); err != nil {
		return result
	}
	result["total_bytes"] = stat.Blocks * uint64(stat.Bsize)
	result["free_bytes"] = stat.Bavail * uint64(stat.Bsize)
	return result
}
