package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultResponseAllowedCIDRs = "203.0.113.0/24,198.51.100.0/24,192.0.2.0/24"
	defaultResponseFileRoots     = "/var/tmp/lyflow-response,/tmp/lyflow-response"
	defaultResponseQuarantine   = "/var/lib/lyflow/quarantine"
	defaultResponseNamespace    = "/var/lib/lyflow/response/namespaces"
)

func (a *Agent) executeResponseTask(task map[string]interface{}) (map[string]interface{}, string, error) {
	action := strings.TrimSpace(fmt.Sprint(task["action"]))
	target := strings.TrimSpace(fmt.Sprint(task["target"]))
	if action == "" {
		return nil, "skipped", fmt.Errorf("response task action is empty")
	}
	result := map[string]interface{}{
		"action": action, "target": target,
		"response_action_id": fmt.Sprint(task["response_action_id"]),
	}
	switch action {
	case "observe":
		result["backend"] = "noop"
		result["verified"] = true
		return result, "ok", nil
	case "block_ip", "unblock_ip":
		if err := validateResponseTarget(target); err != nil {
			return nil, "failed", err
		}
		backend, err := runNFTResponse(action, target)
		if err != nil {
			return nil, "failed", err
		}
		result["backend"] = backend
		result["verified"] = true
		return result, "ok", nil
	case "process_kill":
		metadata, err := responseProcessKill(target)
		if err != nil {
			return nil, "failed", err
		}
		for key, value := range metadata {
			result[key] = value
		}
		return result, "ok", nil
	case "file_delete":
		metadata, err := responseFileDelete(target)
		if err != nil {
			return nil, "failed", err
		}
		for key, value := range metadata {
			result[key] = value
		}
		return result, "ok", nil
	case "file_restore":
		metadata, err := responseFileRestore(target)
		if err != nil {
			return nil, "failed", err
		}
		for key, value := range metadata {
			result[key] = value
		}
		return result, "ok", nil
	case "account_disable":
		metadata, err := responseAccountDisable(target)
		if err != nil {
			return nil, "failed", err
		}
		for key, value := range metadata {
			result[key] = value
		}
		return result, "ok", nil
	case "account_enable":
		metadata, err := responseAccountEnable(target)
		if err != nil {
			return nil, "failed", err
		}
		for key, value := range metadata {
			result[key] = value
		}
		return result, "ok", nil
	case "isolate_host":
		metadata, err := responseHostIsolate(target)
		if err != nil {
			return nil, "failed", err
		}
		for key, value := range metadata {
			result[key] = value
		}
		return result, "ok", nil
	case "host_unisolate":
		metadata, err := responseHostUnisolate(target)
		if err != nil {
			return nil, "failed", err
		}
		for key, value := range metadata {
			result[key] = value
		}
		return result, "ok", nil
	case "namespace_isolate":
		metadata, err := responseNamespaceIsolate(target)
		if err != nil {
			return nil, "failed", err
		}
		for key, value := range metadata {
			result[key] = value
		}
		return result, "ok", nil
	case "namespace_restore":
		metadata, err := responseNamespaceRestore(target)
		if err != nil {
			return nil, "failed", err
		}
		for key, value := range metadata {
			result[key] = value
		}
		return result, "ok", nil
	default:
		return nil, "failed", fmt.Errorf("unsupported response action %q", action)
	}
}

func validateResponseTarget(target string) error {
	ip := net.ParseIP(strings.TrimSpace(target))
	if ip == nil {
		return fmt.Errorf("response target must be an IP: %q", target)
	}
	allowed := strings.TrimSpace(os.Getenv("RESPONSE_ALLOWED_CIDRS"))
	if allowed == "" {
		allowed = defaultResponseAllowedCIDRs
	}
	for _, raw := range strings.Split(allowed, ",") {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err == nil && network.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("response target %s is outside RESPONSE_ALLOWED_CIDRS", target)
}

func runNFTResponse(action, target string) (string, error) {
	path, err := exec.LookPath("nft")
	if err != nil {
		return "", fmt.Errorf("nft is not installed: %w", err)
	}
	table := "lyflow_response"
	commands := [][]string{
		{path, "list", "table", "inet", table},
		{path, "add", "table", "inet", table},
		{path, "add", "set", "inet", table, "blocked", "{ type ipv4_addr; }"},
		{path, "add", "chain", "inet", table, "input", "{ type filter hook input priority 0; policy accept; }"},
		{path, "add", "rule", "inet", table, "input", "ip saddr @blocked drop"},
	}
	for _, command := range commands {
		runCommand(command[0], command[1:]...)
	}
	operation := "add"
	if action == "unblock_ip" {
		operation = "delete"
	}
	output, err := runCommand(path, operation, "element", "inet", table, "blocked", "{ "+target+" }")
	if err != nil {
		return "", fmt.Errorf("nft %s element %s: %w: %s", operation, target, err, strings.TrimSpace(output))
	}
	checkOut, checkErr := runCommand(path, "list", "set", "inet", table, "blocked")
	if checkErr != nil {
		return "", fmt.Errorf("nft verify set: %w: %s", checkErr, strings.TrimSpace(checkOut))
	}
	contains := strings.Contains(checkOut, target)
	if action == "block_ip" && !contains {
		return "", fmt.Errorf("nft block %s was not visible after apply", target)
	}
	if action == "unblock_ip" && contains {
		return "", fmt.Errorf("nft unblock %s is still visible after apply", target)
	}
	return "nft", nil
}

func responseProcessKill(target string) (map[string]interface{}, error) {
	if !envBool("RESPONSE_ENABLE_PROCESS_KILL") {
		return nil, fmt.Errorf("process_kill is disabled; set RESPONSE_ENABLE_PROCESS_KILL=true")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(target))
	if err != nil || pid <= 1 {
		return nil, fmt.Errorf("process_kill target must be a PID greater than 1")
	}
	if pid == os.Getpid() || pid == os.Getppid() {
		return nil, fmt.Errorf("refusing to kill the agent or its parent")
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("find process %d: %w", pid, err)
	}
	if err := process.Kill(); err != nil {
		return nil, fmt.Errorf("kill process %d: %w", pid, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
			return map[string]interface{}{"backend": "signal", "verified": true, "pid": pid, "reversible": false}, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("process %d is still present after kill", pid)
}

func responseFileDelete(target string) (map[string]interface{}, error) {
	path, err := validateResponseFilePath(target)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect response file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("response file must be a regular file")
	}
	quarantineDir := envOrDefault("RESPONSE_QUARANTINE_DIR", defaultResponseQuarantine)
	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		return nil, fmt.Errorf("create quarantine directory: %w", err)
	}
	digest := sha256.Sum256([]byte(path))
	key := hex.EncodeToString(digest[:])
	destination := filepath.Join(quarantineDir, key)
	if err := moveResponseFile(path, destination); err != nil {
		return nil, err
	}
	metadata := map[string]interface{}{
		"original_path": path, "quarantine_path": destination, "sha256": key,
		"size": info.Size(), "mode": info.Mode().Perm(), "quarantined_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	encoded, _ := json.Marshal(metadata)
	if err := os.WriteFile(destination+".json", encoded, 0o600); err != nil {
		return nil, fmt.Errorf("write quarantine metadata: %w", err)
	}
	return map[string]interface{}{"backend": "quarantine", "verified": true, "quarantine_path": destination, "sha256": key}, nil
}

func responseFileRestore(target string) (map[string]interface{}, error) {
	path, err := validateResponseFilePath(target)
	if err != nil {
		return nil, err
	}
	quarantineDir := envOrDefault("RESPONSE_QUARANTINE_DIR", defaultResponseQuarantine)
	digest := sha256.Sum256([]byte(path))
	key := hex.EncodeToString(digest[:])
	destination := filepath.Join(quarantineDir, key)
	metadataPath := destination + ".json"
	if _, err := os.Stat(metadataPath); err != nil {
		return nil, fmt.Errorf("quarantine metadata missing for %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create restore directory: %w", err)
	}
	if err := moveResponseFile(destination, path); err != nil {
		return nil, err
	}
	_ = os.Remove(metadataPath)
	return map[string]interface{}{"backend": "quarantine", "verified": true, "restored_path": path}, nil
}

func responseAccountDisable(target string) (map[string]interface{}, error) {
	if !envBool("RESPONSE_ENABLE_ACCOUNT_DISABLE") {
		return nil, fmt.Errorf("account_disable is disabled; set RESPONSE_ENABLE_ACCOUNT_DISABLE=true")
	}
	username, err := validateResponseAccount(target)
	if err != nil {
		return nil, err
	}
	if output, err := runCommand("chage", "-E", "0", username); err != nil {
		return nil, fmt.Errorf("expire account %s: %w: %s", username, err, strings.TrimSpace(output))
	}
	return map[string]interface{}{"backend": "chage", "verified": true, "username": username, "expired": true}, nil
}

func responseAccountEnable(target string) (map[string]interface{}, error) {
	if !envBool("RESPONSE_ENABLE_ACCOUNT_DISABLE") {
		return nil, fmt.Errorf("account_enable is disabled; set RESPONSE_ENABLE_ACCOUNT_DISABLE=true")
	}
	username, err := validateResponseAccount(target)
	if err != nil {
		return nil, err
	}
	if output, err := runCommand("chage", "-E", "-1", username); err != nil {
		return nil, fmt.Errorf("restore account %s: %w: %s", username, err, strings.TrimSpace(output))
	}
	return map[string]interface{}{"backend": "chage", "verified": true, "username": username, "expired": false}, nil
}

func responseHostIsolate(target string) (map[string]interface{}, error) {
	if !envBool("RESPONSE_ENABLE_HOST_ISOLATION") {
		return nil, fmt.Errorf("isolate_host is disabled; set RESPONSE_ENABLE_HOST_ISOLATION=true")
	}
	management := strings.TrimSpace(os.Getenv("RESPONSE_MANAGEMENT_CIDRS"))
	if management == "" {
		return nil, fmt.Errorf("RESPONSE_MANAGEMENT_CIDRS is required for host isolation")
	}
	nftPath, err := exec.LookPath("nft")
	if err != nil {
		return nil, fmt.Errorf("nft is not installed: %w", err)
	}
	table := "lyflow_host_isolation"
	runCommand(nftPath, "delete", "table", "inet", table)
	commands := [][]string{
		{nftPath, "add", "table", "inet", table},
		{nftPath, "add", "chain", "inet", table, "input", "{ type filter hook input priority 0; policy drop; }"},
		{nftPath, "add", "chain", "inet", table, "output", "{ type filter hook output priority 0; policy drop; }"},
		{nftPath, "add", "rule", "inet", table, "input", "iif lo accept"},
		{nftPath, "add", "rule", "inet", table, "output", "oif lo accept"},
		{nftPath, "add", "rule", "inet", table, "input", "ct state established,related accept"},
		{nftPath, "add", "rule", "inet", table, "output", "ct state established,related accept"},
	}
	for _, cidr := range strings.Split(management, ",") {
		cidr = strings.TrimSpace(cidr)
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			runCommand(nftPath, "delete", "table", "inet", table)
			return nil, fmt.Errorf("invalid management CIDR %q", cidr)
		}
		commands = append(commands,
			[]string{nftPath, "add", "rule", "inet", table, "input", "ip saddr " + cidr + " accept"},
			[]string{nftPath, "add", "rule", "inet", table, "output", "ip daddr " + cidr + " accept"},
		)
	}
	for _, command := range commands {
		if output, err := runCommand(command[0], command[1:]...); err != nil {
			runCommand(nftPath, "delete", "table", "inet", table)
			return nil, fmt.Errorf("apply host isolation: %w: %s", err, strings.TrimSpace(output))
		}
	}
	return map[string]interface{}{"backend": "nft", "verified": true, "management_cidrs": management, "target": target}, nil
}

func responseHostUnisolate(string) (map[string]interface{}, error) {
	nftPath, err := exec.LookPath("nft")
	if err != nil {
		return nil, fmt.Errorf("nft is not installed: %w", err)
	}
	if output, err := runCommand(nftPath, "delete", "table", "inet", "lyflow_host_isolation"); err != nil && !strings.Contains(output, "No such file") {
		return nil, fmt.Errorf("remove host isolation: %w: %s", err, strings.TrimSpace(output))
	}
	return map[string]interface{}{"backend": "nft", "verified": true, "isolated": false}, nil
}

func responseNamespaceIsolate(target string) (map[string]interface{}, error) {
	if !envBool("RESPONSE_ENABLE_NAMESPACE_ISOLATION") {
		return nil, fmt.Errorf("namespace_isolate is disabled; set RESPONSE_ENABLE_NAMESPACE_ISOLATION=true")
	}
	container := strings.TrimSpace(target)
	if container == "" {
		return nil, fmt.Errorf("namespace_isolate target container is required")
	}
	if output, err := runCommand("docker", "inspect", "--format", "{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}", container); err != nil {
		return nil, fmt.Errorf("inspect container %s: %w: %s", container, err, strings.TrimSpace(output))
	} else {
		networks := strings.Fields(output)
		metadataDir := envOrDefault("RESPONSE_NAMESPACE_STATE_DIR", defaultResponseNamespace)
		if err := os.MkdirAll(metadataDir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(metadataDir, container+".json"), []byte(strings.Join(networks, ",")), 0o600); err != nil {
			return nil, err
		}
		for _, network := range networks {
			if output, err := runCommand("docker", "network", "disconnect", network, container); err != nil {
				return nil, fmt.Errorf("disconnect container %s from %s: %w: %s", container, network, err, strings.TrimSpace(output))
			}
		}
		return map[string]interface{}{"backend": "docker", "verified": true, "networks": networks}, nil
	}
}

func responseNamespaceRestore(target string) (map[string]interface{}, error) {
	if !envBool("RESPONSE_ENABLE_NAMESPACE_ISOLATION") {
		return nil, fmt.Errorf("namespace_restore is disabled; set RESPONSE_ENABLE_NAMESPACE_ISOLATION=true")
	}
	container := strings.TrimSpace(target)
	statePath := filepath.Join(envOrDefault("RESPONSE_NAMESPACE_STATE_DIR", defaultResponseNamespace), container+".json")
	data, err := os.ReadFile(statePath)
	if err != nil {
		return nil, fmt.Errorf("read namespace state for %s: %w", container, err)
	}
	for _, network := range strings.Split(strings.TrimSpace(string(data)), ",") {
		if network == "" {
			continue
		}
		if output, err := runCommand("docker", "network", "connect", network, container); err != nil {
			return nil, fmt.Errorf("connect container %s to %s: %w: %s", container, network, err, strings.TrimSpace(output))
		}
	}
	_ = os.Remove(statePath)
	return map[string]interface{}{"backend": "docker", "verified": true, "restored": true}, nil
}

func validateResponseFilePath(target string) (string, error) {
	path := strings.TrimSpace(target)
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("file response target must be an absolute path")
	}
	path = filepath.Clean(path)
	allowed := strings.TrimSpace(os.Getenv("RESPONSE_ALLOWED_FILE_ROOTS"))
	if allowed == "" {
		allowed = defaultResponseFileRoots
	}
	for _, root := range strings.Split(allowed, ",") {
		root = filepath.Clean(strings.TrimSpace(root))
		if root == "" || root == "." {
			continue
		}
		if path == root || strings.HasPrefix(path, root+string(os.PathSeparator)) {
			return path, nil
		}
	}
	return "", fmt.Errorf("file target %s is outside RESPONSE_ALLOWED_FILE_ROOTS", path)
}

func validateResponseAccount(target string) (string, error) {
	username := strings.TrimSpace(target)
	if username == "" || strings.ContainsAny(username, "/\\ \t\n") {
		return "", fmt.Errorf("invalid account target")
	}
	account, err := user.Lookup(username)
	if err != nil {
		return "", fmt.Errorf("account %s not found: %w", username, err)
	}
	if account.Uid == "0" || account.Uid == strconv.Itoa(os.Getuid()) {
		return "", fmt.Errorf("refusing to disable root or the agent account")
	}
	return username, nil
}

func moveResponseFile(source, destination string) error {
	if err := os.Rename(source, destination); err == nil {
		return nil
	}
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open response file: %w", err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create response file: %w", err)
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return fmt.Errorf("copy response file: %w", err)
	}
	if err := output.Close(); err != nil {
		return err
	}
	return os.Remove(source)
}

func runCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(output), err
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envBool(key string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}
