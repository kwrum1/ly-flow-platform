//go:build windows

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	lyWindowsInstallDirName = "LyFlow\\Agent"
	lyWindowsInstalledExe   = "ly-agent.exe"
	lyWindowsRunKey         = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	lyWindowsRunValue       = "LyFlowAgent"
	lyWindowsIconFile       = "lyflow.ico"
	lyWindowsUpdateScript   = "ly-agent-update.cmd"
)

const lyFlowIconBase64 = "AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABeZ8/8MofH/JKHv/ySh8f8kofH/JKHx/ySh8f8kofH/JKHx/ySh8f8kofH/JKHx/ySh8f8kofH/JKHx/yqe8v8DAAAAH53z/wyh8f8kofH/JKHx/ySh8f8kofH/JKHx/ySh8f8kofH/JKHx/ySh8f8kofH/JKHx/ySh8f8qn/L/LJ/y/wsd8/8MofH/JKHx/ySh8f8kofH/JKHx/ySh8f8kofH/JKHx/ySh8f8kofH/JKHx/ySh8f8sn/L/zN/y/8zf8v8LIfP/DKHx/ySh8f8kofH/JKHx/ySh8f8kofH/JKHx/ySh8f8kofH/JJ/y/8sn/L/zN/y/8zf8v/M3/L/DKHx/ySh8f8kofH/JKHx/ySh8f8kofH/JKHx/ySh8f8kn/L/yyf8v/M3/L/zN/y/8zf8v/M3/L/DKHx/ySh8f8kofH/JKHx/ySh8f8kofH/JKHx/ySc8v/LJ/y/8zf8v/M3/L/zN/y/8zf8v/M3/L/DKHx/ySh8f8kofH/JKHx/ySh8f8kofH/JJzy/8sn/L/zN/y/8zf8v/M3/L/zN/y/8zf8v8MofH/JKHx/ySh8f8kofH/JKHx/ySc8v/LJ/y/8zf8v/M3/L/zN/y/8zf8v/M3/L/DKHx/ySh8f8kofH/JKHx/ySc8v/LJ/y/8zf8v/M3/L/zN/y/8zf8v/M3/L/zN/y/wsd8/8MofH/JKHx/ySc8v/LJ/y/8zf8v/M3/L/zN/y/8zf8v/M3/L/zN/y8v8LIfP/DKHx/ySc8v/LJ/y/8zf8v/M3/L/zN/y/8zf8v/M3/L/zN/y8v8sn/L/DKHx/yqe8v/LJ/y/8zf8v/M3/L/zN/y/8zf8v/M3/L/zN/y8v8sn/L/DKHx/ySh8f8sn/L/zN/y/8zf8v/M3/L/zN/y/8zf8v/M3/L/yyf8v8MofH/JKHx/ySh8f8sn/L/zN/y/8zf8v/M3/L/zN/y/8zf8v/M3/L/DKHx/ySh8f8kofH/JKHx/ySh8f8qn/L/zN/y/8zf8v/M3/L/zN/y/8zf8v8MofH/JKHx/ySh8f8kofH/JKHx/ySh8f8kofH/LJ/y/8zf8v/M3/L/zN/y/wsd8/8MofH/JKHx/ySh8f8kofH/JKHx/ySh8f8kofH/JKHx/yqe8v8sn/L/yyf8vwyh8f8DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func ensurePlatformInstall() bool {
	installDir := windowsInstallDir()
	installedPath := filepath.Join(installDir, lyWindowsInstalledExe)
	currentPath, err := os.Executable()
	if err != nil {
		return false
	}
	currentPath, _ = filepath.Abs(currentPath)
	installedPath, _ = filepath.Abs(installedPath)

	if sameWindowsPath(currentPath, installedPath) {
		ensureLyFlowIconFile(installDir)
		ensureWindowsAutoStart(installedPath)
		return false
	}

	if err := os.MkdirAll(installDir, 0o755); err != nil {
		fmt.Printf("[agent] Windows install directory unavailable: %v\n", err)
		return false
	}
	if err := copyWindowsAgent(currentPath, installedPath); err != nil {
		if err := scheduleWindowsAgentReplacement(currentPath, installedPath); err != nil {
			fmt.Printf("[agent] Windows self-install failed: %v\n", err)
			return false
		}
		fmt.Printf("[agent] Scheduled Windows agent update for %s\n", installedPath)
		return true
	}
	ensureLyFlowIconFile(installDir)
	ensureWindowsAutoStart(installedPath)
	if err := startInstalledWindowsAgent(installedPath); err != nil {
		fmt.Printf("[agent] Installed Windows agent start failed: %v\n", err)
		return false
	}
	fmt.Printf("[agent] Installed Windows agent to %s and started background instance\n", installedPath)
	return true
}

func windowsInstallDir() string {
	programDataDir := filepath.Join(windowsProgramData(), lyWindowsInstallDirName)
	if err := os.MkdirAll(programDataDir, 0o755); err == nil {
		return programDataDir
	}
	if localAppData := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); localAppData != "" {
		return filepath.Join(localAppData, lyWindowsInstallDirName)
	}
	return programDataDir
}

func windowsProgramData() string {
	if v := strings.TrimSpace(os.Getenv("ProgramData")); v != "" {
		return v
	}
	return `C:\ProgramData`
}

func sameWindowsPath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func copyWindowsAgent(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, input, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func scheduleWindowsAgentReplacement(src, dst string) error {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	staged := filepath.Join(dir, "ly-agent.new.exe")
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(staged, input, 0o755); err != nil {
		return err
	}
	script := filepath.Join(dir, lyWindowsUpdateScript)
	content := strings.Join([]string{
		"@echo off",
		"setlocal",
		"timeout /t 2 /nobreak >nul",
		"taskkill /f /im ly-agent.exe >nul 2>nul",
		"timeout /t 1 /nobreak >nul",
		fmt.Sprintf("copy /y %q %q >nul", staged, dst),
		fmt.Sprintf("start \"\" %q", dst),
		fmt.Sprintf("del /f /q %q >nul 2>nul", staged),
		"del /f /q %~f0 >nul 2>nul",
	}, "\r\n")
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		return err
	}
	cmd := hiddenCommand("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", fmt.Sprintf("Start-Process -WindowStyle Hidden -FilePath %s", powerShellSingleQuote(script)))
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		return err
	}
	time.Sleep(200 * time.Millisecond)
	return nil
}

func powerShellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func ensureWindowsAutoStart(exePath string) {
	cmd := hiddenCommand("reg", "add", lyWindowsRunKey, "/v", lyWindowsRunValue, "/t", "REG_SZ", "/d", exePath, "/f")
	if err := cmd.Run(); err != nil {
		fmt.Printf("[agent] Windows auto-start registration failed: %v\n", err)
	}
}

func startInstalledWindowsAgent(exePath string) error {
	cmd := hiddenCommand(exePath)
	cmd.Dir = filepath.Dir(exePath)
	return cmd.Start()
}

func findLyFlowIconFile() (string, bool) {
	candidates := make([]string, 0, 4)
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates, filepath.Join(dir, lyWindowsIconFile))
	}
	candidates = append(candidates, filepath.Join(windowsInstallDir(), lyWindowsIconFile))
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Size() > 0 {
			return candidate, true
		}
	}
	return "", false
}

func ensureLyFlowIconFile(dir string) {
	data, err := base64.StdEncoding.DecodeString(lyFlowIconBase64)
	if err != nil {
		return
	}
	path := filepath.Join(dir, lyWindowsIconFile)
	_ = os.WriteFile(path, data, 0o644)
}
