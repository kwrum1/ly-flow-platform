package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

const defaultResponseAllowedCIDRs = "203.0.113.0/24,198.51.100.0/24,192.0.2.0/24"

func (a *Agent) executeResponseTask(task map[string]interface{}) (map[string]interface{}, string, error) {
	action := strings.TrimSpace(fmt.Sprint(task["action"]))
	target := strings.TrimSpace(fmt.Sprint(task["target"]))
	if action == "" {
		return nil, "skipped", fmt.Errorf("response task action is empty")
	}
	switch action {
	case "observe":
		return map[string]interface{}{"action": action, "target": target, "backend": "noop", "verified": true}, "ok", nil
	case "block_ip", "unblock_ip":
		if err := validateResponseTarget(target); err != nil {
			return nil, "failed", err
		}
		backend, err := runNFTResponse(action, target)
		if err != nil {
			return nil, "failed", err
		}
		return map[string]interface{}{
			"action": action, "target": target, "backend": backend, "verified": true,
			"response_action_id": fmt.Sprint(task["response_action_id"]),
		}, "ok", nil
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
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = exec.CommandContext(ctx, command[0], command[1:]...).Run()
		cancel()
	}
	operation := "add"
	if action == "unblock_ip" {
		operation = "delete"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, operation, "element", "inet", table, "blocked", "{ "+target+" }").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("nft %s element %s: %w: %s", operation, target, err, strings.TrimSpace(string(output)))
	}
	// Verify the set contains (or no longer contains) the target.
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer checkCancel()
	checkOut, checkErr := exec.CommandContext(checkCtx, path, "list", "set", "inet", table, "blocked").CombinedOutput()
	if checkErr != nil {
		return "", fmt.Errorf("nft verify set: %w: %s", checkErr, strings.TrimSpace(string(checkOut)))
	}
	contains := strings.Contains(string(checkOut), target)
	if action == "block_ip" && !contains {
		return "", fmt.Errorf("nft block %s was not visible after apply", target)
	}
	if action == "unblock_ip" && contains {
		return "", fmt.Errorf("nft unblock %s is still visible after apply", target)
	}
	return "nft", nil
}
