package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/replay"
)

func main() {
	os.Exit(run())
}

func run() int {
	manifestPath := flag.String("manifest", "", "path to an immutable detection replay manifest")
	outputDirectory := flag.String("output-dir", "", "directory for machine and human reports")
	reviewPath := flag.String("representative-review", "", "path to approved redacted representative-data review metadata")
	reviewAsOf := flag.String("review-as-of", "", "RFC3339 instant used to evaluate representative review validity")
	flag.Parse()
	if *manifestPath == "" || *outputDirectory == "" {
		fmt.Fprintln(os.Stderr, "detection replay requires -manifest and -output-dir")
		return 2
	}
	config := replay.Config{ManifestPath: *manifestPath, RepresentativeReviewPath: *reviewPath}
	if *reviewPath != "" {
		parsed, err := time.Parse(time.RFC3339, *reviewAsOf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse -review-as-of: %v\n", err)
			return 2
		}
		config.ReviewAsOf = parsed
	}
	report, replayErr := replay.Run(context.Background(), config)
	if report.SchemaVersion == "" {
		fmt.Fprintf(os.Stderr, "run detection replay: %v\n", replayErr)
		return 1
	}
	machine, human, err := replay.EncodeReports(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode detection replay reports: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(*outputDirectory, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create report directory: %v\n", err)
		return 1
	}
	if err := os.WriteFile(filepath.Join(*outputDirectory, "report.json"), machine, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write machine report: %v\n", err)
		return 1
	}
	if err := os.WriteFile(filepath.Join(*outputDirectory, "report.md"), human, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write human report: %v\n", err)
		return 1
	}
	if replayErr != nil {
		fmt.Fprintf(os.Stderr, "detection replay failed: %v\n", replayErr)
		return 1
	}
	fmt.Printf("detection replay %s qualification=%s reports=%s\n", report.Status, report.Qualification, *outputDirectory)
	return 0
}
