package analytics

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

func reconciliationReport(postgresEvents, clickHouseEvents []EventRecord) ReconciliationReport {
	postgresChecksum := checksumEvents(postgresEvents)
	clickHouseChecksum := checksumEvents(clickHouseEvents)
	return ReconciliationReport{
		PostgresCount: len(postgresEvents), ClickHouseCount: len(clickHouseEvents),
		PostgresChecksum: postgresChecksum, ClickHouseChecksum: clickHouseChecksum,
		Match: len(postgresEvents) == len(clickHouseEvents) && postgresChecksum == clickHouseChecksum,
	}
}

func checksumEvents(events []EventRecord) string {
	stable := append([]EventRecord(nil), events...)
	sort.Slice(stable, func(left, right int) bool {
		if stable[left].ID == stable[right].ID {
			return stable[left].Version < stable[right].Version
		}
		return stable[left].ID < stable[right].ID
	})
	digest := sha256.New()
	for _, event := range stable {
		payloadJSON := event.PayloadJSON
		var compact bytes.Buffer
		if json.Compact(&compact, []byte(payloadJSON)) == nil {
			payloadJSON = compact.String()
		}
		payload, _ := json.Marshal(struct {
			ID           string
			Version      uint64
			TimestampMS  int64
			SourceModule string
			EventType    string
			Severity     string
			AgentID      string
			HostID       string
			ChainID      string
			EntityID     string
			RawReference string
			Message      string
			PayloadJSON  string
		}{
			ID: event.ID, Version: event.Version, TimestampMS: event.Timestamp.UnixMilli(),
			SourceModule: event.SourceModule, EventType: event.EventType, Severity: event.Severity,
			AgentID: event.AgentID, HostID: event.HostID, ChainID: event.ChainID, EntityID: event.EntityID,
			RawReference: event.RawReference, Message: event.Message, PayloadJSON: payloadJSON,
		})
		_, _ = digest.Write(payload)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func boolCount(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func mismatchMessage(report ReconciliationReport) string {
	if report.Match {
		return ""
	}
	return fmt.Sprintf("count/checksum mismatch postgres=%d/%s clickhouse=%d/%s", report.PostgresCount,
		report.PostgresChecksum, report.ClickHouseCount, report.ClickHouseChecksum)
}
