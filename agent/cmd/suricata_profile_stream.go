package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

type boundedSuricataLine struct {
	data      []byte
	sample    []byte
	bytesRead int64
	complete  bool
	oversized bool
}

type suricataDeadLetter struct {
	SchemaVersion string    `json:"schema_version"`
	Reason        string    `json:"reason"`
	Path          string    `json:"path"`
	Offset        int64     `json:"offset"`
	LineBytes     int64     `json:"line_bytes"`
	SampleSHA256  string    `json:"sample_sha256"`
	Sample        string    `json:"sample"`
	EngineVersion string    `json:"engine_version"`
	RecordedAt    time.Time `json:"recorded_at"`
}

func readBoundedSuricataLine(reader *bufio.Reader) (boundedSuricataLine, error) {
	result := boundedSuricataLine{data: make([]byte, 0, reader.Size())}
	for {
		fragment, err := reader.ReadSlice('\n')
		result.bytesRead += int64(len(fragment))
		if len(result.sample) < suricataDeadLetterSampleSize {
			remaining := suricataDeadLetterSampleSize - len(result.sample)
			result.sample = append(result.sample, fragment[:min(len(fragment), remaining)]...)
		}
		if !result.oversized {
			if result.bytesRead > suricataMaxLineBytes {
				result.oversized = true
				result.data = nil
			} else {
				result.data = append(result.data, fragment...)
			}
		}
		switch {
		case err == nil:
			result.complete = true
			return result, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return result, nil
		default:
			return result, fmt.Errorf("read EVE line: %w", err)
		}
	}
}

func (a *Agent) publishSuricataRecord(record suricataProfileRecord) error {
	switch typed := record.(type) {
	case suricataAlertRecord:
		return a.publishComponentAlert(typed.Alert)
	case suricataTelemetryRecord:
		stream := firstNonEmpty(a.cfg.TrafficTelemetryStream, "telemetry:traffic")
		if err := a.publishAgentStream(a.ctx, stream, structToMap(typed.Telemetry), "telemetry_traffic"); err != nil {
			return fmt.Errorf("publish Suricata traffic event: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("record variant %T: %w", record, contracts.ErrInvalidEnum)
	}
}

func (a *Agent) deadLetterSuricata(path string, offset int64, line boundedSuricataLine, reason string) {
	digest := sha256.Sum256(line.sample)
	record := suricataDeadLetter{
		SchemaVersion: "lyflow.suricata_dead_letter.v1", Reason: reason, Path: path, Offset: offset,
		LineBytes: line.bytesRead, SampleSHA256: hex.EncodeToString(digest[:]), Sample: string(bytes.TrimSpace(line.sample)),
		EngineVersion: suricataProfileVersion, RecordedAt: time.Now().UTC(),
	}
	deadLetterPath := firstNonEmpty(os.Getenv("SURICATA_DEAD_LETTER_PATH"), path+suricataDeadLetterSuffix)
	info, err := os.Stat(deadLetterPath)
	if err == nil && info.Size() >= suricataMaxDeadLetterBytes {
		atomic.AddUint64(&a.suricataProfile.deadLetterDropped, 1)
		return
	}
	file, err := os.OpenFile(deadLetterPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		atomic.AddUint64(&a.suricataProfile.deadLetterDropped, 1)
		a.suricataProfile.lastError.Store(err.Error())
		return
	}
	encodeErr := json.NewEncoder(file).Encode(record)
	closeErr := file.Close()
	if encodeErr != nil || closeErr != nil {
		atomic.AddUint64(&a.suricataProfile.deadLetterDropped, 1)
		a.suricataProfile.lastError.Store(errors.Join(encodeErr, closeErr).Error())
		return
	}
	atomic.AddUint64(&a.suricataProfile.deadLetteredLines, 1)
}

func (a *Agent) noteSuricataParseError(err error) string {
	a.suricataProfile.lastError.Store(err.Error())
	switch {
	case errors.Is(err, errSuricataVersionDrift):
		atomic.AddUint64(&a.suricataProfile.versionDriftLines, 1)
		return "version_drift"
	case errors.Is(err, errUnsupportedSuricataEventType):
		atomic.AddUint64(&a.suricataProfile.unsupportedLines, 1)
		return "unsupported_event_type"
	default:
		atomic.AddUint64(&a.suricataProfile.malformedLines, 1)
		return "malformed_json"
	}
}
