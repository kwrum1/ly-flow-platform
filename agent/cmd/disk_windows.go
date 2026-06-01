//go:build windows

package main

import (
	"strings"
	"syscall"
	"unsafe"
)

func readDiskUsage(path string) map[string]uint64 {
	root := `C:\`
	if strings.TrimSpace(path) != "" && path != "/" {
		root = path
	}
	rootPtr, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return map[string]uint64{}
	}
	var freeAvailable, total, free uint64
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")
	ret, _, _ := proc.Call(
		uintptr(unsafe.Pointer(rootPtr)),
		uintptr(unsafe.Pointer(&freeAvailable)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&free)),
	)
	if ret == 0 || total == 0 {
		return map[string]uint64{}
	}
	return map[string]uint64{"total_bytes": total, "free_bytes": free, "available_bytes": freeAvailable}
}
