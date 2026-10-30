package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

type yaraNativeMatch struct {
	Rule     string
	Tags     []string
	FilePath string
}

func (a *Agent) runYARAScanner() {
	interval := time.Duration(a.cfg.YARAScanIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = time.Minute
	}
	fmt.Printf("[yara] scanner starting: paths=%s interval=%s timeout=%ds\n", a.cfg.YARAScanPaths, interval, a.cfg.YARAScanTimeoutSeconds)
	a.refreshYARARules()
	a.scanWithNativeYARA()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.refreshYARARules()
			if a.cfg.HIDSEnabled {
				a.scanWithNativeYARA()
			}
		}
	}
}

// refreshYARARules pulls the local rule pack published by the platform. The
// pack can be imported from the console; no external upstream is required.
func (a *Agent) refreshYARARules() {
	url := strings.TrimSpace(a.cfg.YARARulesURL)
	if url == "" {
		api := strings.TrimRight(strings.TrimSpace(a.cfg.API), "/")
		if api == "" {
			return
		}
		url = api + "/api/v1/agent/yara/rules"
	}
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if err != nil || len(content) == 0 || !bytes.Contains(content, []byte("rule ")) {
		return
	}
	target := filepath.Clean(a.cfg.YARARulesPath)
	if existing, err := os.ReadFile(target); err == nil && bytes.Equal(existing, content) {
		return
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return
	}
	temporary := target + ".tmp"
	if err := os.WriteFile(temporary, content, 0o640); err != nil {
		return
	}
	if err := os.Rename(temporary, target); err != nil {
		_ = os.Remove(temporary)
		return
	}
	fmt.Printf("[yara] local rule pack refreshed: %d bytes\n", len(content))
}

func (a *Agent) scanWithNativeYARA() {
	binary := firstNonEmpty(strings.TrimSpace(a.cfg.YARACommand), "yara")
	resolved, err := exec.LookPath(binary)
	if err != nil {
		fmt.Printf("[yara] native engine unavailable: %v\n", err)
		return
	}
	rulesPath := filepath.Clean(a.cfg.YARARulesPath)
	if info, err := os.Stat(rulesPath); err != nil || info.IsDir() {
		fmt.Printf("[yara] rule pack unavailable: %s\n", rulesPath)
		return
	}
	timeoutSeconds := a.cfg.YARAScanTimeoutSeconds
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}
	maxFileBytes := a.cfg.YARAMaxFileBytes
	if maxFileBytes <= 0 {
		maxFileBytes = 256 * 1024 * 1024
	}
	maxMatches := a.cfg.YARAMaxMatches
	if maxMatches <= 0 {
		maxMatches = 1000
	}
	for _, configuredPath := range strings.Split(a.cfg.YARAScanPaths, ",") {
		scanPath := filepath.Clean(strings.TrimSpace(configuredPath))
		if scanPath == "." || !filepath.IsAbs(scanPath) {
			continue
		}
		if _, err := os.Stat(scanPath); err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(a.ctx, time.Duration(timeoutSeconds+5)*time.Second)
		args := []string{"-r", "-N", "-g", "-p", "1", "-a", strconv.Itoa(timeoutSeconds), "-z", strconv.FormatInt(maxFileBytes, 10), "-l", strconv.Itoa(maxMatches), rulesPath, scanPath}
		output, scanErr := exec.CommandContext(ctx, resolved, args...).Output()
		timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
		cancel()
		if scanErr != nil {
			if timedOut {
				fmt.Printf("[yara] scan timed out: %s\n", scanPath)
			} else {
				fmt.Printf("[yara] scan failed for %s: %v\n", scanPath, scanErr)
			}
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		scanner.Buffer(make([]byte, 4096), 1024*1024)
		for scanner.Scan() {
			match, ok := parseYARAOutputLine(scanner.Text())
			if !ok {
				continue
			}
			hash, err := sha256File(match.FilePath, maxFileBytes)
			if err != nil {
				fmt.Printf("[yara] hash failed for %s: %v\n", match.FilePath, err)
				continue
			}
			if err := a.appendYARAMatch(match, hash); err != nil {
				fmt.Printf("[yara] persist match failed: %v\n", err)
			}
		}
	}
}

func parseYARAOutputLine(line string) (yaraNativeMatch, bool) {
	line = strings.TrimSpace(line)
	space := strings.IndexByte(line, ' ')
	if space <= 0 {
		return yaraNativeMatch{}, false
	}
	match := yaraNativeMatch{Rule: line[:space]}
	rest := strings.TrimSpace(line[space+1:])
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "] ")
		if end < 0 {
			return yaraNativeMatch{}, false
		}
		for _, tag := range strings.Split(rest[1:end], ",") {
			if tag = strings.TrimSpace(tag); tag != "" {
				match.Tags = append(match.Tags, tag)
			}
		}
		rest = strings.TrimSpace(rest[end+2:])
	}
	if match.Rule == "" || rest == "" || !filepath.IsAbs(rest) {
		return yaraNativeMatch{}, false
	}
	match.FilePath = filepath.Clean(rest)
	return match, true
}

func sha256File(path string, maxBytes int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return "", fmt.Errorf("file is not a regular file within scan limit")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (a *Agent) appendYARAMatch(match yaraNativeMatch, hash string) error {
	dedupKey := match.Rule + "\x00" + match.FilePath + "\x00" + hash
	a.yaraSeenMu.Lock()
	if a.yaraSeen == nil {
		a.yaraSeen = make(map[string]struct{})
	}
	if _, exists := a.yaraSeen[dedupKey]; exists {
		a.yaraSeenMu.Unlock()
		return nil
	}
	a.yaraSeenMu.Unlock()
	path := a.yaraResultPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	result := map[string]interface{}{
		"rule": match.Rule, "namespace": "yara-security", "tags": match.Tags,
		"file_path": match.FilePath, "file_hash": hash, "matched_at": time.Now().UTC().Format(time.RFC3339Nano),
		"agent_id": a.agentID, "hostname": a.hostname, "scan_status": "matched", "source": "native-yara",
	}
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.Write(append(data, '\n')); err != nil {
		return err
	}
	a.yaraSeenMu.Lock()
	a.yaraSeen[dedupKey] = struct{}{}
	a.yaraSeenMu.Unlock()
	alert, alertErr := componentAlertFromYARA(yaraMatchInput{
		Rule: match.Rule, Namespace: "yara-security", Tags: match.Tags,
		FilePath: match.FilePath, FileHash: hash, MatchedAt: time.Now().UTC(),
	}, a, contracts.RawReference{Path: path})
	if alertErr == nil {
		if publishErr := a.publishComponentAlert(alert); publishErr != nil {
			fmt.Printf("[yara] publish match %s failed: %v\n", match.Rule, publishErr)
		}
	}
	return nil
}
