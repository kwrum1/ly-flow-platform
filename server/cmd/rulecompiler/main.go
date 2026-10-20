// Command rulecompiler converts Suricata rules into ly_probe threat.json and
// optionally watches the source tree so the sensor rules stay fresh.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/lyflow/ly-flow-platform/server/rulecompiler"
)

func main() {
	source := flag.String("source", "rules/lyprobe/source", "comma-separated rule files or directories")
	output := flag.String("output", "rules/lyprobe/threat.json", "generated ly_probe threat.json")
	manifest := flag.String("manifest", "", "manifest path (default: manifest.json next to output)")
	interval := flag.Duration("interval", 2*time.Second, "source poll interval")
	once := flag.Bool("once", false, "compile once and exit")
	reloadCommand := flag.String("reload-command", "", "optional shell command after a successful refresh")
	jsonLog := flag.Bool("json", false, "emit JSON summaries")
	flag.Parse()

	if strings.TrimSpace(*manifest) == "" {
		*manifest = filepath.Join(filepath.Dir(*output), "manifest.json")
	}
	logger := log.New(os.Stderr, "rulecompiler: ", log.LstdFlags)
	compiler := &rulecompiler.Compiler{
		Sources:      splitSources(*source),
		OutputPath:   *output,
		ManifestPath: *manifest,
		Reload:       rulecompiler.CommandReload(*reloadCommand),
		Logger:       logger,
	}

	if *once {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		result, err := compiler.Sync(ctx)
		printResult(logger, result, *jsonLog)
		if err != nil {
			logger.Printf("compile failed: %v", err)
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	watcher := &rulecompiler.Watcher{Compiler: compiler, Interval: *interval, Logger: logger}
	if err := watcher.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Printf("watcher stopped: %v", err)
		os.Exit(1)
	}
}

func splitSources(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func printResult(logger *log.Logger, result rulecompiler.Result, jsonLog bool) {
	if !jsonLog {
		logger.Printf("converted=%d skipped=%d hash=%s", result.Converted, len(result.Skipped), result.SourceHash)
		return
	}
	payload, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		logger.Printf("summary: %v", err)
		return
	}
	fmt.Fprintln(os.Stdout, string(payload))
}
